//! Coalesced-app-data-behind-Finished delivery test.
//!
//! When the client coalesces an application-data record into the same TCP
//! segment as its Finished, the server's bounded handshake read must stop at
//! the Finished and leave the request in the kernel queue, where the
//! multishot recv then delivers it as `Frame::Borrowed`. This checks the data
//! survives that boundary intact (it used to be decrypted in software and
//! surface as `Frame::Owned`, before bounded reads).
//!
//! The kernel doesn't naturally guarantee this coalescing (separate `send`
//! syscalls usually land in separate TCP segments), so we drive it with a TCP
//! proxy that holds the client's Finished record until the *next* record
//! arrives, then flushes both with a single `write_all` — the
//! highest-fidelity way to put both records into the server's first post-CCS
//! recv.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Once, mpsc};
use std::thread;
use std::time::Duration;

use slopio_tls::{
    Config, Frame, ServerName, ServerSettings, client_config_dangerous_no_verification, connect,
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

/// Forward client→server, but hold the first `application_data` (0x17)
/// record (the wrapped Finished) until the next record from the client
/// arrives. Then flush both with a single `write_all` so the server's
/// first post-CCS recv reads them together.
fn forward_coalesce_finished(mut from: TcpStream, mut to: TcpStream) {
    let mut header = [0u8; 5];
    let mut payload = vec![0u8; 32 * 1024];
    let mut held: Option<Vec<u8>> = None;

    loop {
        if from.read_exact(&mut header).is_err() {
            if let Some(buf) = held.take() {
                let _ = to.write_all(&buf);
            }
            return;
        }
        let typ = header[0];
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if payload_len > payload.len() {
            payload.resize(payload_len, 0);
        }
        if from.read_exact(&mut payload[..payload_len]).is_err() {
            if let Some(buf) = held.take() {
                let _ = to.write_all(&buf);
            }
            return;
        }

        if let Some(mut buf) = held.take() {
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&payload[..payload_len]);
            if to.write_all(&buf).is_err() {
                return;
            }
        } else if typ == 0x17 {
            let mut buf = Vec::with_capacity(5 + payload_len);
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&payload[..payload_len]);
            held = Some(buf);
        } else {
            if to.write_all(&header).is_err() {
                return;
            }
            if to.write_all(&payload[..payload_len]).is_err() {
                return;
            }
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
fn coalesced_app_data_behind_finished_is_delivered() {
    init_provider();
    let server_port = pick_port();
    let proxy_port = pick_port();

    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<()>();
    let (first_frame_tx, first_frame_rx) = mpsc::channel::<(bool, Vec<u8>)>();
    // Keeps the client connection open until the server has yielded its
    // first frame. Otherwise the client's drop-after-send races the server:
    // the proxy relays the FIN, the server socket lands in CLOSE_WAIT while
    // it is still processing the coalesced Finished + app-data, and the
    // kTLS attach (`setsockopt(TCP_ULP)`) fails with ENOTCONN because the
    // kernel only accepts the TLS ULP on an ESTABLISHED socket.
    let (client_release_tx, client_release_rx) = mpsc::channel::<()>();

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
            let frame = stream.next().await.expect("frame").expect("frame ok");
            // Report which variant we got so the assertion proves the
            // coalesced-into-pending_plaintext path actually fired.
            match frame {
                Frame::Owned(v) => first_frame_tx.send((true, v)).unwrap(),
                Frame::Borrowed(b) => first_frame_tx.send((false, b.as_ref().to_vec())).unwrap(),
                _ => unreachable!("unknown Frame variant"),
            }
        });
    });

    server_ready_rx.recv().unwrap();

    let proxy = thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", proxy_port)).unwrap();
        proxy_ready_tx.send(()).unwrap();
        let (client_conn, _) = listener.accept().unwrap();
        let server_conn = TcpStream::connect(("127.0.0.1", server_port)).unwrap();

        let c2s_from = client_conn.try_clone().unwrap();
        let c2s_to = server_conn.try_clone().unwrap();
        let s2c_from = server_conn.try_clone().unwrap();
        let s2c_to = client_conn.try_clone().unwrap();
        let shutdown_for_h1_client = client_conn.try_clone().unwrap();
        let shutdown_for_h1_server = server_conn.try_clone().unwrap();
        let shutdown_for_h2_client = client_conn;
        let shutdown_for_h2_server = server_conn;

        let h1 = thread::spawn(move || {
            forward_coalesce_finished(c2s_from, c2s_to);
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
            stream
                .send(b"coalesced-with-finished")
                .await
                .0
                .expect("send");
            // Block until the server has reported its frame. The client has
            // nothing else to drive, so blocking the runtime thread is fine.
            let _ = client_release_rx.recv();
            drop(stream);
        });
    });

    let (is_owned, first) = first_frame_rx.recv().expect("server should report a frame");
    let _ = client_release_tx.send(());
    // The bounded handshake read stops at the Finished, so the coalesced
    // request stays queued and the multishot delivers it as `Frame::Borrowed`.
    assert!(
        !is_owned,
        "expected Frame::Borrowed (kernel/multishot path after bounded read), \
         got Frame::Owned — the server decrypted app data during the handshake"
    );
    assert_eq!(first, b"coalesced-with-finished");

    client.join().expect("client thread");
    server.join().expect("server thread");
    proxy.join().expect("proxy thread");
}
