//! `close()` sends close_notify then FIN and leaves the read side open (TLS
//! 1.3 half-close). The peer sees `None`, moves to `WriteOnly`, can still
//! send, and its own `close()` brings both sides to `Closed`.

use std::net::TcpListener;
use std::sync::{Once, mpsc};
use std::thread;
use std::time::Duration;

use popple_tls::{
    Config, ServerName, ServerSettings, StreamState, client_config_dangerous_no_verification,
    connect, handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
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

#[test]
fn close_notify_half_close_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages::<MediumRing>();
            assert_eq!(stream.state(), StreamState::Open);
            let first = stream.next().await.expect("frame").expect("frame ok");
            assert_eq!(first.as_ref(), b"ping");
            stream.send(b"pong").await.0.expect("send pong");

            stream.close().await.expect("close");
            assert_eq!(stream.state(), StreamState::ReadOnly);
            stream.close().await.expect("close is idempotent");
            let (result, _) = stream.send(b"late").await;
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::NotConnected,
                "send after close must fail"
            );

            let bye = stream
                .next()
                .await
                .expect("frame after our close")
                .expect("bye ok");
            assert_eq!(
                bye.as_ref(),
                b"bye",
                "read side must stay open after close()"
            );
            assert!(
                stream.next().await.is_none(),
                "peer close_notify ends the stream"
            );
            assert_eq!(stream.state(), StreamState::Closed);
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

            let mut stream = ktls.into_messages::<MediumRing>();
            stream.send(b"ping").await.0.expect("send ping");
            let reply = stream.next().await.expect("reply").expect("reply ok");
            assert_eq!(reply.as_ref(), b"pong");

            assert!(
                stream.next().await.is_none(),
                "server close_notify ends the stream"
            );
            assert_eq!(stream.state(), StreamState::WriteOnly);
            stream.send(b"bye").await.0.expect("send after peer close");
            stream.close().await.expect("client close");
            assert_eq!(stream.state(), StreamState::Closed);
        });
    });

    client.join().expect("client thread");
    server.join().expect("server thread");
}
