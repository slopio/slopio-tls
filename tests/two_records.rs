//! Repro: client sends two *separate* small application records right after
//! the handshake (the HTTP/2 case: the 24-byte connection preface "magic" in
//! one TLS record, the SETTINGS frame in the next). The server must surface
//! BOTH, in order, with nothing lost.

use std::net::TcpListener;
use std::sync::Once;
use std::sync::mpsc;
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
const SETTINGS: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"; // empty SETTINGS frame

#[test]
fn two_separate_records_both_delivered() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (got_tx, got_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = common::accept(&mut acc).await;
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages::<MediumRing>();
            let mut got = Vec::new();
            // Read frames until EOF (client drops) or overall timeout.
            let collected = timeout(Duration::from_secs(5), async {
                while let Some(frame) = stream.next().await {
                    let f = frame.expect("frame ok");
                    got.extend_from_slice(f.as_ref());
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

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = client_config_dangerous_no_verification(None).expect("client config");
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut ktls = connect(
                format!("127.0.0.1:{port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect")
            .into_messages::<MediumRing>();

            // Record #1: the magic, sent immediately (arrives around the
            // server's handshake/attach boundary).
            ktls.send(MAGIC).await.0.expect("send magic");
            // Force the SETTINGS into a separate TLS record *and* a separate
            // TCP segment so the server sees two distinct records.
            Sleep::during(Duration::from_millis(50)).await;
            // Record #2: SETTINGS.
            ktls.send(SETTINGS).await.0.expect("send settings");
            // Keep the connection open a moment so the server can read both
            // before we tear down.
            Sleep::during(Duration::from_millis(200)).await;
        });
    });

    let got = got_rx.recv().expect("server reports collected bytes");
    let mut expected = Vec::new();
    expected.extend_from_slice(MAGIC);
    expected.extend_from_slice(SETTINGS);

    client.join().expect("client thread");
    server.join().expect("server thread");

    assert_eq!(
        got,
        expected,
        "\nLOST DATA: server got {} bytes, expected {} (magic={}, settings={}).\n\
         got     = {:?}\nexpected= {:?}",
        got.len(),
        expected.len(),
        MAGIC.len(),
        SETTINGS.len(),
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected),
    );
}
