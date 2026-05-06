use std::io::Write;
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, Instant};

use popple_tls::{HandshakeError, handshake};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread;
use runtime::net::{MultiAccept, socket_recv, socket_send};
use runtime_streams::StreamExt;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

static INIT: Once = Once::new();

fn init_provider() {
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    });
}

fn make_config() -> Arc<ServerConfig> {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("bad cert/key");
    cfg.enable_secret_extraction = true;
    Arc::new(cfg)
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
        main_thread(async move {
            let cfg = make_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            socket_send(ktls.as_socket(), b"HELLO_FROM_KTLS\n")
                .await
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
        main_thread(async move {
            let cfg = make_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("handshake");
            let mut buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(4096);
            let n = socket_recv(ktls.as_socket(), &mut buf, 4096)
                .await
                .expect("recv");
            let data = unsafe { buf[..n].assume_init_ref() };
            socket_send(ktls.as_socket(), data).await.expect("send");
            // dropping ktls here sends close_notify and closes the socket;
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
        main_thread(async move {
            let cfg = make_config();
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
