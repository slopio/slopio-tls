//! An empty buffer ring does not stop a stream.
//!
//! The ring is shared by every connection on a worker, and a recv completion
//! that finds it empty comes back `ENOBUFS`, which ends the multishot. Waiting
//! for a buffer to come back lost each one to the recvs still armed on other
//! connections, for seconds at a time, and a peer holding the ring's buffers
//! slowed everyone. So the stream reads into buffers of its own instead, until
//! the socket has nothing more, then re-arms the multishot.
//!
//! The ring here holds two buffers and nothing else on the thread uses it, so
//! holding two frames empties it exactly; every frame is held, so from then on
//! every byte has to come through the stream's own buffers.

use std::net::TcpListener;
use std::sync::Once;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use popple_tls::{
    Config, Frame, ServerName, ServerSettings, StreamState,
    client_config_dangerous_no_verification, connect, handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime::runtime::time::{Sleep, timeout};
use runtime_streams::StreamExt;

mod common;
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
    /// Frames that came in a buffer of the stream's own: the ring ran dry.
    owned: usize,
    /// Anything the stream reported as an error.
    error: Option<String>,
    /// The session state once everything had arrived.
    state_after: Option<StreamState>,
    /// Whether the write side still worked then.
    could_still_send: Option<bool>,
}

/// Runs the exchange and reports what the server saw. The client sends
/// `RECORDS` records, and as many again after a KeyUpdate if `key_update`.
fn exchange(key_update: bool) -> Outcome {
    init_provider();
    let rounds = if key_update { 2 } else { 1 };
    let expected = rounds * RECORDS * RECORD.len();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<Outcome>();

    let server = thread::spawn(move || {
        main_thread_with::<DryRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = common::accept(&mut acc).await;
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            let mut stream = ktls.into_messages::<DryRing>();

            let mut outcome = Outcome {
                bytes: 0,
                owned: 0,
                error: None,
                state_after: None,
                could_still_send: None,
            };
            // Every frame is *held*, which is what takes its buffer out of the
            // ring. Two of them and there is nothing left to receive into.
            let mut held = Vec::new();

            let _ = timeout(Duration::from_secs(5), async {
                while outcome.bytes < expected {
                    match stream.next().await {
                        Some(Ok(frame)) => {
                            outcome.bytes += frame.as_ref().len();
                            if matches!(frame, Frame::Owned(_)) {
                                outcome.owned += 1;
                            }
                            held.push(frame);
                        }
                        Some(Err(e)) => {
                            outcome.error = Some(format!("{e} (kind {:?})", e.kind()));
                            break;
                        }
                        None => break,
                    }
                }
            })
            .await;
            outcome.state_after = Some(stream.state());
            outcome.could_still_send = Some(stream.send(&b"still here"[..]).await.0.is_ok());

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

            for round in 0..rounds {
                if round > 0 {
                    ktls.initiate_key_update().await.expect("key update");
                }
                for _ in 0..RECORDS {
                    // Spaced so the kernel does not coalesce several records
                    // into one completion, which would spend fewer buffers than
                    // this is counting on.
                    Sleep::during(Duration::from_millis(30)).await;
                    // A send that fails is not the verdict here: what the
                    // server reported is.
                    if ktls.send(RECORD).await.0.is_err() {
                        return;
                    }
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

/// With every ring buffer held, the stream still reads everything: in
/// buffers of its own, with the session untouched.
#[test]
fn an_empty_ring_does_not_stop_the_stream() {
    let outcome = exchange(false);

    assert_eq!(
        outcome.error, None,
        "an empty ring must not fail the stream"
    );
    assert!(
        outcome.owned > 0,
        "the ring never ran dry, so this proved nothing: {outcome:?}"
    );
    assert_eq!(
        outcome.bytes,
        RECORDS * RECORD.len(),
        "everything sent arrived, ring or no ring"
    );
    assert_eq!(
        outcome.state_after,
        Some(StreamState::Open),
        "both directions open"
    );
    assert_eq!(
        outcome.could_still_send,
        Some(true),
        "and the write side usable"
    );
}

/// A control record met by a recv of the stream's own is read and applied as
/// one met by the multishot is: here a KeyUpdate, after which every record is
/// under the new key and would fail AEAD verification if it had been missed.
#[test]
fn a_key_update_outside_the_ring_still_applies() {
    let outcome = exchange(true);

    assert_eq!(
        outcome.error, None,
        "the KeyUpdate was applied: {outcome:?}"
    );
    assert!(outcome.owned > 0, "the ring ran dry: {outcome:?}");
    assert_eq!(
        outcome.bytes,
        2 * RECORDS * RECORD.len(),
        "everything sent arrived, before and after the KeyUpdate"
    );
}
