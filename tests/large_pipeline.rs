//! Stress the post-attach path with a large volume of application data
//! pipelined right after the client's Finished, most of it already queued in
//! the kernel before the server arms its multishot recv.
//!
//! This is the case the handshake-exit drain was meant to cover. With the
//! server bounding its reads at the Finished (RX seq 0) and the multishot
//! delivering queued records itself, everything must still arrive intact,
//! in order, whether or not the drain runs. The payload is a position-keyed
//! byte pattern, so any loss, duplication or reordering fails the exact
//! comparison.

use std::net::TcpListener;
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
use slopio::runtime::time::{Sleep, timeout};
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
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
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

/// 512 KiB: many TLS records (~32 of 16 KiB), and larger than a default
/// socket receive buffer, so a big chunk is queued before the multishot
/// arms while the tail keeps arriving afterwards.
const PAYLOAD_LEN: usize = 512 * 1024;

fn payload() -> Vec<u8> {
    // Position-keyed with a prime period so a dropped or reordered record
    // (16 KiB, not a multiple of 251) shifts the pattern and is caught.
    (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect()
}

#[test]
fn large_pipeline_after_finished_arrives_intact() {
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
            // Let the client's data pile up in the kernel queue before arming.
            Sleep::during(Duration::from_millis(200)).await;
            let mut stream = ktls.into_messages::<MediumRing>();
            let mut got = Vec::with_capacity(PAYLOAD_LEN);
            let _ = timeout(Duration::from_secs(5), async {
                while got.len() < PAYLOAD_LEN {
                    match stream.next().await {
                        Some(Ok(frame)) => got.extend_from_slice(frame.as_ref()),
                        Some(Err(_)) | None => break,
                    }
                }
            })
            .await;
            got_tx.send(got).unwrap();
        });
    });
    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = client_config_dangerous_no_verification(None).expect("client config");
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut stream = connect(
                format!("127.0.0.1:{port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect")
            .into_messages::<MediumRing>();
            // Send immediately, while the server is still in its pre-arm sleep,
            // so the bulk lands in the server's kernel queue before the recv.
            let (res, _) = stream.send(payload()).await;
            res.expect("client send");
            // Hold the connection open until the server has read everything.
            Sleep::during(Duration::from_secs(1)).await;
        });
    });

    let got = got_rx.recv().expect("server result");
    client.join().unwrap();
    server.join().unwrap();

    assert_eq!(
        got.len(),
        PAYLOAD_LEN,
        "server received {} of {PAYLOAD_LEN} bytes",
        got.len()
    );
    assert!(
        got == payload(),
        "payload mismatch: a record was lost, duplicated or reordered"
    );
}

/// Mirror direction: the server sends the large payload right after the
/// handshake, and the client delays arming its multishot so the bulk is
/// queued in the client's kernel first. Validates the same multishot
/// delivery on the client's receive side.
#[test]
fn large_pipeline_to_client_arrives_intact() {
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
            let mut stream = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake")
                .into_messages::<MediumRing>();
            // Send immediately, while the client is still in its pre-arm sleep.
            let (res, _) = stream.send(payload()).await;
            res.expect("server send");
            Sleep::during(Duration::from_secs(1)).await;
        });
    });
    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = client_config_dangerous_no_verification(None).expect("client config");
            let server_name = ServerName::try_from("localhost").unwrap();
            let ktls = connect(
                format!("127.0.0.1:{port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect");
            // Let the server's data queue in our kernel before arming.
            Sleep::during(Duration::from_millis(200)).await;
            let mut stream = ktls.into_messages::<MediumRing>();
            let mut got = Vec::with_capacity(PAYLOAD_LEN);
            let _ = timeout(Duration::from_secs(5), async {
                while got.len() < PAYLOAD_LEN {
                    match stream.next().await {
                        Some(Ok(frame)) => got.extend_from_slice(frame.as_ref()),
                        Some(Err(_)) | None => break,
                    }
                }
            })
            .await;
            got_tx.send(got).unwrap();
        });
    });

    let got = got_rx.recv().expect("client result");
    server.join().unwrap();
    client.join().unwrap();

    assert_eq!(
        got.len(),
        PAYLOAD_LEN,
        "client received {} bytes",
        got.len()
    );
    assert!(
        got == payload(),
        "payload mismatch on the client receive side"
    );
}
