use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use popple_tls::{Config, HandshakeError, ServerSettings, handshake, server_config};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::{MultiAccept, socket_send};
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

fn make_config(alpn_protocols: Option<&'static [&'static [u8]]>) -> Config {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    server_config(ServerSettings {
        certs: vec![cert_der],
        key: key_der,
        alpn_protocols,
    })
    .expect("server config")
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[test]
fn handshake_then_send_response() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            socket_send(ktls.as_socket(), b"HELLO_FROM_KTLS\n")
                .await
                .0
                .expect("send");
        });
    });

    ready_rx.recv().unwrap();

    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("HELLO_FROM_KTLS"),
        "unexpected output: {stdout:?}"
    );
}

#[test]
fn echo_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            let mut stream = ktls.into_messages::<MediumRing>();
            let frame = stream
                .next()
                .await
                .expect("stream ended")
                .expect("recv");
            stream.send(frame.as_ref().to_vec()).await.0.expect("send");
            // dropping stream here sends close_notify and closes the socket;
            // openssl client sees the close and exits.
        });
    });

    ready_rx.recv().unwrap();

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
            "-quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl");

    {
        let mut stdin = child.stdin.take().unwrap();
        write!(stdin, "PING\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PING"),
        "echo missing in output: {stdout:?}"
    );
}

#[test]
fn handshake_times_out_on_silent_peer() {
    init_provider();
    let port = pick_port();
    let timeout_ms: u64 = 2000;
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let result = handshake(socket, cfg, Duration::from_millis(timeout_ms)).await;
            match result {
                Err(HandshakeError::Timeout) => {}
                Err(other) => panic!("expected Timeout, got error {other:?}"),
                Ok(_) => panic!("expected Timeout, got Ok"),
            }
        });
    });

    ready_rx.recv().unwrap();

    let start = Instant::now();
    let _stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    server.join().expect("server thread");
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(timeout_ms - 100),
        "timeout fired too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout fired too late: {elapsed:?}"
    );
}

#[test]
fn alpn_match_succeeds_and_exposes_negotiated_protocol() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(Some(&[b"http/1.1"]));
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            assert_eq!(ktls.alpn(), Some(b"http/1.1" as &[u8]));
            socket_send(ktls.as_socket(), b"ALPN_OK\n")
                .await
                .0
                .expect("send");
        });
    });

    ready_rx.recv().unwrap();

    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
            "-alpn",
            "http/1.1",
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ALPN_OK"), "missing response: {stdout:?}");
}

#[test]
fn alpn_mismatch_rejects_handshake() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(Some(&[b"http/1.1"]));
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let result = handshake(socket, cfg, Duration::from_secs(5)).await;
            match result {
                Err(HandshakeError::Rustls(rustls::Error::NoApplicationProtocol)) => {}
                Err(other) => panic!("expected NoApplicationProtocol, got error {other:?}"),
                Ok(_) => panic!("expected NoApplicationProtocol, got Ok"),
            }
        });
    });

    ready_rx.recv().unwrap();

    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
            "-alpn",
            "h2",
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");

    server.join().expect("server thread");
    assert!(
        !out.status.success(),
        "openssl exited successfully but should have failed on ALPN mismatch"
    );
}

#[test]
fn stream_echo_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            let mut stream = ktls.into_messages::<MediumRing>();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(frame) => {
                        let data: &[u8] = frame.as_ref();
                        if stream.send(data.to_vec()).await.0.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    });

    ready_rx.recv().unwrap();

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl");

    {
        let mut stdin = child.stdin.take().unwrap();
        write!(stdin, "STREAM_PING\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "Q\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("STREAM_PING"),
        "missing echo via KtlsMessages: {stdout:?}"
    );
}

#[test]
fn peer_initiated_key_update_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            let mut stream = ktls.into_messages::<MediumRing>();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(frame) => {
                        let data: &[u8] = frame.as_ref();
                        if stream.send(data.to_vec()).await.0.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    });

    ready_rx.recv().unwrap();

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl");

    {
        let mut stdin = child.stdin.take().unwrap();
        write!(stdin, "BEFORE_PEER_KU\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "k\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "AFTER_PEER_KU\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "Q\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BEFORE_PEER_KU"),
        "missing pre-KU echo: {stdout:?}"
    );
    assert!(
        stdout.contains("AFTER_PEER_KU"),
        "missing post-KU echo (KeyUpdate handling failed?): {stdout:?}"
    );
}

/// Peer sends a KeyUpdate with `update_requested` (OpenSSL's uppercase `K`),
/// so we must rekey RX *and* send our own KeyUpdate + rotate TX. This drives
/// the async `SendingKeyUpdate` path in `poll_next`; the echo must keep
/// working in both directions afterwards.
#[test]
fn peer_requested_key_update_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            let mut stream = ktls.into_messages::<MediumRing>();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(frame) => {
                        let data: &[u8] = frame.as_ref();
                        if stream.send(data.to_vec()).await.0.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    });

    ready_rx.recv().unwrap();

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl");

    {
        let mut stdin = child.stdin.take().unwrap();
        write!(stdin, "BEFORE_REQ_KU\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        // Uppercase K: KeyUpdate requesting the peer to update too.
        write!(stdin, "K\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "AFTER_REQ_KU\n").unwrap();
        thread::sleep(Duration::from_millis(200));
        write!(stdin, "Q\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BEFORE_REQ_KU"),
        "missing pre-KU echo: {stdout:?}"
    );
    assert!(
        stdout.contains("AFTER_REQ_KU"),
        "missing post-KU echo (reciprocal KeyUpdate handling failed?): {stdout:?}"
    );
}

#[test]
fn server_initiated_key_update_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_config(None);
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");

            let mut stream = ktls.into_messages::<MediumRing>();

            stream
                .send(b"BEFORE_ROTATION\n")
                .await
                .0
                .expect("send before");
            assert!(
                stream.tx_records() > 0,
                "tx_records should have incremented after first send"
            );

            stream.initiate_key_update().await.expect("initiate_key_update");
            assert_eq!(
                stream.tx_records(),
                0,
                "tx_records should reset to 0 after key update"
            );

            stream.send(b"AFTER_ROTATION\n").await.0.expect("send after");
            assert!(
                stream.tx_records() > 0,
                "tx_records should increment again after post-rotation send"
            );
        });
    });

    ready_rx.recv().unwrap();

    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-servername",
            "localhost",
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");

    server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BEFORE_ROTATION"),
        "missing pre-rotation message: {stdout:?}"
    );
    assert!(
        stdout.contains("AFTER_ROTATION"),
        "missing post-rotation message (decrypt failure?): {stdout:?}"
    );
}
