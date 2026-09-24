//! Does the io_uring multishot recv (`MultiRecv`, created by `into_messages`)
//! pick up a kTLS record that was ALREADY queued in the kernel before the
//! multishot was armed? The handshake-exit drain was removed on the proof that
//! the *kernel* reprocesses queued ciphertext — but that proof used a blocking
//! `read()`. The live HTTP/2 path reads via `MultiRecv`, and h2spec loses the
//! first post-attach record. This isolates that: the server delays
//! `into_messages()` while the client sends one record, so it is sitting in the
//! kernel kTLS queue when the multishot recv first submits.

use std::net::TcpListener;
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

#[test]
fn multirecv_picks_up_record_queued_before_arming() {
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
            // Delay arming the multishot recv: by the time `into_messages`
            // submits it, the client's record is already in the kernel queue.
            Sleep::during(Duration::from_millis(150)).await;
            let mut stream = ktls.into_messages::<MediumRing>();

            let mut got = Vec::new();
            let collected = timeout(Duration::from_secs(5), async {
                while let Some(frame) = stream.next().await {
                    got.extend_from_slice(frame.expect("frame ok").as_ref());
                    if got.len() >= 5 {
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
            // Send immediately — lands in the server's kernel queue while the
            // server is still in its 150ms pre-into_messages sleep.
            ktls.send(b"HELLO".to_vec()).await.0.expect("send");
            Sleep::during(Duration::from_millis(400)).await;
        });
    });

    let got = got_rx.recv().expect("server result");
    client.join().unwrap();
    server.join().unwrap();

    assert_eq!(
        got,
        b"HELLO",
        "\nMultiRecv missed a record queued before it armed: got {:?}",
        String::from_utf8_lossy(&got)
    );
}
