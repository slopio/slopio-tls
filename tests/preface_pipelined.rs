//! Repro of the real HTTP/2 bug: the connection-preface "magic" is coalesced
//! into the SAME TCP segment as the client's Finished (so the server software-
//! decrypts it during the handshake drain → `pending_plaintext`), while the
//! SETTINGS frame arrives as a SEPARATE later record (→ kTLS). The mixed
//! handoff must surface BOTH, in order.
//!
//! A TCP proxy on the client→server path holds the client's first wrapped-
//! handshake record (the Finished, content type 0x17 on the wire in TLS 1.3)
//! until the next record (the magic) arrives, flushes both together, then lets
//! everything after (the SETTINGS) pass straight through.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Once, mpsc};
use std::thread;
use std::time::Duration;

use popple_tls::{
    Config, ServerName, ServerSettings, client_config_dangerous_no_verification, connect,
    handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime::runtime::time::{Sleep, timeout};
use runtime_streams::StreamExt;

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

const MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Coalesce the client's first wrapped-handshake record (Finished, 0x17) with
/// the next record (the magic), flush both as one write, then pass everything
/// after straight through.
fn forward_coalesce_finished_then_pass(mut from: TcpStream, mut to: TcpStream) {
    let mut header = [0u8; 5];
    let mut payload = vec![0u8; 64 * 1024];
    let mut held: Option<Vec<u8>> = None;
    let mut done = false;

    loop {
        if from.read_exact(&mut header).is_err() {
            if let Some(buf) = held.take() {
                let _ = to.write_all(&buf);
            }
            return;
        }
        let typ = header[0];
        let plen = u16::from_be_bytes([header[3], header[4]]) as usize;
        if plen > payload.len() {
            payload.resize(plen, 0);
        }
        if from.read_exact(&mut payload[..plen]).is_err() {
            if let Some(buf) = held.take() {
                let _ = to.write_all(&buf);
            }
            return;
        }

        if done {
            if to.write_all(&header).is_err() || to.write_all(&payload[..plen]).is_err() {
                return;
            }
            continue;
        }

        if let Some(mut buf) = held.take() {
            // `buf` = held Finished; append this record (the magic) and flush.
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&payload[..plen]);
            if to.write_all(&buf).is_err() {
                return;
            }
            done = true;
        } else if typ == 0x17 {
            let mut buf = Vec::with_capacity(5 + plen);
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&payload[..plen]);
            held = Some(buf);
        } else if to.write_all(&header).is_err() || to.write_all(&payload[..plen]).is_err() {
            return;
        }
    }
}

fn forward_plain(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
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
fn pipelined_magic_then_separate_settings() {
    init_provider();
    let server_port = pick_port();
    let proxy_port = pick_port();

    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<()>();
    let (got_tx, got_rx) = mpsc::channel::<Vec<u8>>();

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
            let mut got = Vec::new();
            let collected = timeout(Duration::from_secs(5), async {
                let mut first = true;
                while let Some(frame) = stream.next().await {
                    let f = frame.expect("frame ok");
                    got.extend_from_slice(f.as_ref());
                    if first {
                        // Mimic the HTTP/2 server: after the preface/magic,
                        // immediately SEND a reply before reading the next
                        // frame — exercising the read→send→read interleave.
                        first = false;
                        stream
                            .send(b"server-preface".to_vec())
                            .await
                            .0
                            .expect("send reply");
                    }
                    if got.len() >= MAGIC.len() + SETTINGS.len() {
                        break;
                    }
                }
                got
            })
            .await;
            got_tx.send(collected.unwrap_or_default()).unwrap();
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
        let sc1 = client_conn.try_clone().unwrap();
        let ss1 = server_conn.try_clone().unwrap();
        let sc2 = client_conn;
        let ss2 = server_conn;

        let h1 = thread::spawn(move || {
            forward_coalesce_finished_then_pass(c2s_from, c2s_to);
            let _ = sc1.shutdown(Shutdown::Both);
            let _ = ss1.shutdown(Shutdown::Both);
        });
        let h2 = thread::spawn(move || {
            forward_plain(s2c_from, s2c_to);
            let _ = sc2.shutdown(Shutdown::Both);
            let _ = ss2.shutdown(Shutdown::Both);
        });
        let _ = h1.join();
        let _ = h2.join();
    });
    proxy_ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = client_config_dangerous_no_verification(None).expect("client config");
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut ktls = connect(
                format!("127.0.0.1:{proxy_port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect")
            .into_messages::<MediumRing>();

            // Magic — gets coalesced with the Finished by the proxy.
            ktls.send(MAGIC).await.0.expect("send magic");
            // Gap so SETTINGS arrives AFTER the server has attached kTLS and
            // is past the handshake drain → magic alone in pending_plaintext,
            // SETTINGS strictly via kTLS (the split case).
            Sleep::during(Duration::from_millis(80)).await;
            ktls.send(SETTINGS).await.0.expect("send settings");
            Sleep::during(Duration::from_millis(300)).await;
        });
    });

    let got = got_rx.recv().expect("server reports collected bytes");
    let mut expected = Vec::new();
    expected.extend_from_slice(MAGIC);
    expected.extend_from_slice(SETTINGS);

    client.join().expect("client thread");
    server.join().expect("server thread");
    proxy.join().expect("proxy thread");

    assert_eq!(
        got,
        expected,
        "\nLOST DATA: server got {} bytes, expected {}.\n got     = {:?}\n expected= {:?}",
        got.len(),
        expected.len(),
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected),
    );
}
