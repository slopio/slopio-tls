//! Is `KtlsMessages::next()` cancel-safe under `select`? The HTTP/2
//! connection loop drives reads as `select(tls.next(), <other>)`, so on every
//! iteration where the other branch wins, a *polled* `tls.next()` future is
//! dropped. If dropping it can swallow an already-read kTLS record, records go
//! missing — exactly the "settings lost" symptom.
//!
//! Here the server reads via `select(stream.next(), Sleep)` in a tight loop:
//! the short timer constantly races the read, so `next()` is repeatedly
//! polled-then-dropped while the client streams many small records. Every
//! record must still arrive, in order.

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
use runtime::runtime::select::{SelectResult, select};
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

const N: usize = 60;

#[test]
fn next_is_cancel_safe_under_select() {
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
            let collected = timeout(Duration::from_secs(5), async {
                loop {
                    // Race every read against a short timer → next() is
                    // constantly polled then dropped when the timer wins.
                    match select(stream.next(), Sleep::during(Duration::from_micros(300))).await {
                        SelectResult::First(Some(frame)) => {
                            let f = frame.expect("frame ok");
                            got.extend_from_slice(f.as_ref());
                            if got.len() >= N * 6 {
                                break;
                            }
                        }
                        SelectResult::First(None) => break, // EOF
                        SelectResult::Second(()) => continue, // timer won; next() dropped
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

            // Stream N small records, each its own TLS record, with tiny gaps
            // so they spread across many separate reads on the server.
            for i in 0..N {
                let rec = format!("r{i:05}");
                ktls.send(rec.into_bytes()).await.0.expect("send");
                Sleep::during(Duration::from_micros(200)).await;
            }
            Sleep::during(Duration::from_millis(300)).await;
        });
    });

    let got = got_rx.recv().expect("server result");
    let mut expected = Vec::new();
    for i in 0..N {
        expected.extend_from_slice(format!("r{i:05}").as_bytes());
    }

    client.join().unwrap();
    server.join().unwrap();

    assert_eq!(
        got.len(),
        expected.len(),
        "\nRECORD LOSS under select: got {} bytes, expected {}.\n got     = {:?}\n expected= {:?}",
        got.len(),
        expected.len(),
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected),
    );
    assert_eq!(
        got, expected,
        "records arrived but out of order / corrupted"
    );
}
