//! AEAD-corruption integration test.
//!
//! An in-process TCP proxy sits between client and server, parses TLS
//! record headers (their outer 5-byte framing is plaintext even after the
//! handshake), and flips one byte inside the *second* `application_data`
//! record from the client. In a TLS 1.3 client flight that record is the
//! first post-Finished application data — the encrypted Finished message
//! itself is the first 0x17 record, so corrupting #1 would break the
//! handshake and we never reach the kTLS recv path we want to exercise.
//!
//! The server must be in kTLS mode before the corrupted record arrives,
//! otherwise rustls drains it as `pending_plaintext` during the handshake
//! loop and surfaces `Rustls(DecryptError)` from `handshake()` — a
//! different code path. To force the right ordering, the server sends
//! "ready" first (over kTLS) and the client only sends after reading it,
//! which both guarantees the server has finished the handshake and
//! prevents the client from coalescing its payload into the same TCP
//! segment as Finished.
//!
//! Once the corrupted record reaches the kernel, kTLS recv yields
//! `EBADMSG` and the stream surfaces `Err(InvalidData)` then `None`. No
//! alert is sent: kTLS has already put the socket in error.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Once, mpsc};
use std::thread;
use std::time::Duration;

use slopio_tls::{
    Config, ServerName, ServerSettings, client_config_dangerous_no_verification, connect,
    handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use slopio::main_thread_with;
use slopio::net::MultiAccept;
use slopio::streams::StreamExt;

mod common;
use common::MediumRing;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

static INIT: Once = Once::new();

fn init_provider() {
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    });
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

fn make_server_config() -> Config {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    server_config(ServerSettings {
        certs: vec![cert_der],
        key: key_der,
        alpn_protocols: None,
    })
    .expect("server config")
}

/// Forward bytes from `from` to `to`, parsing TLS record headers and
/// flipping the first byte of the payload on the second `application_data`
/// (0x17) record. Exits when either side closes.
fn forward_corrupting(mut from: TcpStream, mut to: TcpStream) {
    let mut header = [0u8; 5];
    let mut payload = vec![0u8; 32 * 1024];
    let mut app_data_seen = 0u32;
    let mut corrupted = false;

    loop {
        if from.read_exact(&mut header).is_err() {
            return;
        }
        let typ = header[0];
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if to.write_all(&header).is_err() {
            return;
        }
        if payload_len > payload.len() {
            payload.resize(payload_len, 0);
        }
        if from.read_exact(&mut payload[..payload_len]).is_err() {
            return;
        }
        if typ == 0x17 {
            app_data_seen += 1;
            // #1 = wrapped Finished (keep intact, the handshake must succeed)
            // #2 = first real application_data (flip a byte → AEAD fails)
            if !corrupted && app_data_seen == 2 && payload_len > 0 {
                payload[0] ^= 0xff;
                corrupted = true;
            }
        }
        if to.write_all(&payload[..payload_len]).is_err() {
            return;
        }
    }
}

fn forward_plain(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

#[test]
fn aead_corruption_triggers_fatal_alert() {
    init_provider();
    let server_port = pick_port();
    let proxy_port = pick_port();

    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<()>();
    let (server_err_tx, server_err_rx) = mpsc::channel::<std::io::Error>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(server_port).unwrap();
            server_ready_tx.send(()).unwrap();
            let socket = common::accept(&mut acc).await;
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            let mut stream = ktls.into_messages::<MediumRing>();
            stream.send(b"ready").await.0.expect("send ready");
            match stream.next().await {
                Some(Err(e)) => server_err_tx.send(e).unwrap(),
                Some(Ok(frame)) => panic!(
                    "expected AEAD error, got frame: {:?}",
                    String::from_utf8_lossy(frame.as_ref())
                ),
                None => panic!("stream ended before AEAD failure surfaced"),
            }
            assert!(
                stream.next().await.is_none(),
                "stream must end after the error"
            );
        });
    });

    server_ready_rx.recv().unwrap();

    let proxy = thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", proxy_port)).unwrap();
        proxy_ready_tx.send(()).unwrap();
        let (client_conn, _) = listener.accept().unwrap();
        let server_conn = TcpStream::connect(("127.0.0.1", server_port)).unwrap();

        // Each direction owns its own fd clones. When a forwarding thread
        // exits, it calls shutdown(Both) on the other-direction's clones to
        // unblock the sibling — otherwise a thread blocked in read_exact()
        // never sees FIN (the cloned fds keep the kernel socket open even
        // after the original handle drops).
        let c2s_from = client_conn.try_clone().unwrap();
        let c2s_to = server_conn.try_clone().unwrap();
        let s2c_from = server_conn.try_clone().unwrap();
        let s2c_to = client_conn.try_clone().unwrap();

        let shutdown_for_h1_client = client_conn.try_clone().unwrap();
        let shutdown_for_h1_server = server_conn.try_clone().unwrap();
        let shutdown_for_h2_client = client_conn.try_clone().unwrap();
        let shutdown_for_h2_server = server_conn.try_clone().unwrap();

        let h1 = thread::spawn(move || {
            forward_corrupting(c2s_from, c2s_to);
            let _ = shutdown_for_h1_client.shutdown(Shutdown::Both);
            let _ = shutdown_for_h1_server.shutdown(Shutdown::Both);
        });
        let h2 = thread::spawn(move || {
            forward_plain(s2c_from, s2c_to);
            let _ = shutdown_for_h2_client.shutdown(Shutdown::Both);
            let _ = shutdown_for_h2_server.shutdown(Shutdown::Both);
        });
        let _ = h1.join();
        let _ = h2.join();
    });

    proxy_ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = client_config_dangerous_no_verification(None).expect("client config");
            let server_name = ServerName::try_from("localhost").unwrap();
            let ktls = connect(
                format!("127.0.0.1:{proxy_port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect");

            let mut stream = ktls.into_messages::<MediumRing>();
            let ready = stream.next().await.expect("ready frame").expect("ready ok");
            assert_eq!(ready.as_ref(), b"ready");
            let _ = stream.send(b"payload that will be tampered").await;
            // Drain whatever the peer surfaces (fatal alert → End, or FIN
            // → None). We don't assert on the client side; the server's
            // EBADMSG is the contract under test.
            while let Some(item) = stream.next().await {
                let _ = item;
            }
        });
    });

    let err = server_err_rx
        .recv()
        .expect("server thread should report an error");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "expected InvalidData from kTLS EBADMSG, got {err:?}"
    );

    client.join().expect("client thread");
    server.join().expect("server thread");
    proxy.join().expect("proxy thread");
}
