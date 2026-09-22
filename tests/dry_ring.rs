//! An empty buffer ring is not a dead connection.
//!
//! The ring is shared by every connection on a worker, and a recv completion
//! that finds it empty comes back `ENOBUFS`. The runtime classifies that as
//! `Continuation::ContinueLater`: armable still, but only once another holder
//! recycles a buffer — which no poll of *this* stream can bring about. So it
//! is handed up without ending the stream, and the consumer decides when to
//! come back.
//!
//! Treating it as fatal drops healthy connections under ring pressure, and
//! drops them at random: the one that dies is whichever drew the empty ring,
//! not the one that emptied it. It used to close the *write* side too, so a
//! peer mid-response lost that as well, for a reason on the read side.
//!
//! The ring here holds two buffers and nothing else on the thread uses it, so
//! holding two frames empties it exactly.

use std::net::TcpListener;
use std::sync::Once;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use popple_tls::{
    Config, ServerName, ServerSettings, StreamState, client_config_dangerous_no_verification,
    connect, handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime::runtime::time::{Sleep, timeout};
use runtime_streams::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// Two buffers, no reserve: the smallest ring that can run dry on purpose.
runtime::define_buf_ring!(DryRing, bgid = 2, buffer_size = 4096, ring_size = 2);

// The client's ring is its own business; it only has to be able to send.
runtime::define_buf_ring!(ClientRing, bgid = 3, buffer_size = 16384, ring_size = 64);

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

/// Records the client sends, one per TLS record, spaced so each is its own
/// recv completion. More than the ring holds, so the ring runs out part way.
const RECORDS: usize = 6;
const RECORD: &[u8] = b"0123456789abcdef";

/// What the server made of the exchange.
#[derive(Debug)]
struct Outcome {
    bytes: usize,
    /// The ring ran dry and said so: `WouldBlock` rather than a failure.
    saw_retry: bool,
    /// The session state once it had.
    state_after: Option<StreamState>,
    /// Whether the write side still worked once it had.
    could_still_send: Option<bool>,
    /// Anything the stream reported as fatal.
    fatal: Option<String>,
}

/// Runs the exchange and reports what the server saw. `resume` asks the server
/// to keep reading after the dry spell, which is the part that depends on the
/// recv being re-armed.
fn exchange(resume: bool) -> Outcome {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<Outcome>();

    let server = thread::spawn(move || {
        main_thread_with::<DryRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            let mut stream = ktls.into_messages::<DryRing>();

            let mut outcome = Outcome {
                bytes: 0,
                saw_retry: false,
                state_after: None,
                could_still_send: None,
                fatal: None,
            };
            // Every frame is *held*, which is what takes its buffer out of the
            // ring. Two of them and there is nothing left to receive into.
            let mut held = Vec::new();

            let _ = timeout(Duration::from_secs(5), async {
                while outcome.bytes < RECORDS * RECORD.len() {
                    match stream.next().await {
                        Some(Ok(frame)) => {
                            outcome.bytes += frame.as_ref().len();
                            held.push(frame);
                        }
                        Some(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            outcome.saw_retry = true;
                            // Asked while the ring is still empty: a dry ring
                            // must leave the session exactly as it was.
                            outcome.state_after = Some(stream.state());
                            outcome.could_still_send =
                                Some(stream.send(&b"still here"[..]).await.0.is_ok());
                            // Hand the buffers back and come round again.
                            // No yield: the buffers are already recycled, so
                            // the next poll re-arms the recv and picks up what
                            // the socket still holds. (Yielding here would park
                            // this root future with an empty task list, which
                            // nothing wakes.)
                            held.clear();
                            if !resume {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            outcome.fatal = Some(format!("{e} (kind {:?})", e.kind()));
                            break;
                        }
                        None => break,
                    }
                }
            })
            .await;

            done_tx.send(outcome).unwrap();
        });
    });

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
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
            .into_messages::<ClientRing>();

            for _ in 0..RECORDS {
                // Spaced so the kernel does not coalesce several records into
                // one completion, which would spend fewer buffers than this is
                // counting on.
                Sleep::during(Duration::from_millis(30)).await;
                // A send that fails is not the verdict here: a server that gave
                // up on the dry ring has already closed the socket, and the
                // broken pipe would only hide what it reported.
                if ktls.send(RECORD).await.0.is_err() {
                    break;
                }
            }
            Sleep::during(Duration::from_millis(300)).await;
        });
    });

    let outcome = done_rx.recv().expect("the server reports");
    client.join().expect("client thread");
    server.join().expect("server thread");
    outcome
}

/// What the stream owes its caller when the ring runs out: an error that says
/// "come back", and a session left untouched — both directions still open, the
/// write side still usable.
#[test]
fn an_empty_ring_is_retryable_not_fatal() {
    let outcome = exchange(false);

    assert_eq!(
        outcome.fatal, None,
        "an empty ring must not fail the connection"
    );
    assert!(
        outcome.saw_retry,
        "the ring never ran dry, so this proved nothing: \
         {} bytes arrived with two buffers held",
        outcome.bytes,
    );
    assert_eq!(
        outcome.state_after,
        Some(StreamState::Open),
        "a dry ring closes neither direction"
    );
    assert_eq!(
        outcome.could_still_send,
        Some(true),
        "and the write side never had anything to do with it"
    );
}

/// The other half: having got its buffers back, the stream goes on reading the
/// same connection.
///
/// The terminal `ENOBUFS` completion ends the kernel op, and the next poll
/// re-arms it — nothing queued on the socket is lost in between, which is what
/// makes "come back later" a real answer rather than a polite way to drop a
/// connection.
#[test]
fn the_stream_resumes_once_the_ring_refills() {
    let outcome = exchange(true);

    assert_eq!(outcome.fatal, None, "nothing fatal happened");
    assert!(outcome.saw_retry, "the ring ran dry");
    assert_eq!(
        outcome.bytes,
        RECORDS * RECORD.len(),
        "everything sent arrived, across the dry spell"
    );
}
