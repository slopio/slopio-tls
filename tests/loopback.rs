use std::io::IoSlice;
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
use runtime::main_thread;
use runtime::net::{BufGroup, MultiAccept};
use runtime_streams::StreamExt;
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

/// Deterministic pseudo-random byte stream (xorshift64*). We want a payload
/// that is incompressible and non-trivially patterned so any byte-level
/// corruption shows up as a mismatch, but reproducible so the assertion can
/// regenerate the expected bytes without ferrying them across threads.
fn deterministic_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn client_and_server_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let first = stream.next().await.expect("frame").expect("frame ok");
            let data: &[u8] = first.as_ref();
            assert_eq!(data, b"ping");
            stream.send(b"pong").await.expect("send pong");
        });
    });

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread(async move {
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

            let mut stream = ktls.into_messages(BufGroup::Medium);
            stream.send(b"ping").await.expect("send ping");
            let reply = stream.next().await.expect("reply").expect("reply ok");
            let data: &[u8] = reply.as_ref();
            assert_eq!(data, b"pong");
        });
    });

    client.join().expect("client thread");
    server.join().expect("server thread");
}

/// Server "serves" a 4 MiB file (deterministic xorshift bytes), client
/// downloads the whole thing over TLS 1.3 + kTLS and re-derives the same
/// bytes locally to verify there's no corruption. 4 MiB spans ~256 TLS
/// records (16 KiB max each) so this exercises multi-record streaming, the
/// multishot recv buffer ring refilling, and frame reassembly across many
/// kernel-decrypted reads.
#[test]
fn client_downloads_large_file_intact() {
    init_provider();
    const FILE_LEN: usize = 4 * 1024 * 1024;
    const SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let payload = deterministic_payload(FILE_LEN, SEED);
            stream.send(&payload).await.expect("send payload");
            // Drop stream → socket → TCP FIN. Client sees end-of-stream.
        });
    });

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread(async move {
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

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let mut received = Vec::with_capacity(FILE_LEN);
            while let Some(item) = stream.next().await {
                let frame = item.expect("frame ok");
                received.extend_from_slice(frame.as_ref());
            }

            let expected = deterministic_payload(FILE_LEN, SEED);
            assert_eq!(
                received.len(),
                expected.len(),
                "length mismatch: got {}, expected {}",
                received.len(),
                expected.len()
            );
            if let Some(i) = received.iter().zip(&expected).position(|(a, b)| a != b) {
                panic!(
                    "byte mismatch at offset {i}: got {:#04x}, expected {:#04x}",
                    received[i], expected[i]
                );
            }
        });
    });

    client.join().expect("client thread");
    server.join().expect("server thread");
}

/// Server gathers three plaintext slices into a single `send_vectored` call;
/// the middle slice is 2 MiB of deterministic bytes, large enough to span
/// many 16 KiB TLS records and force the partial-write `advance_slices`
/// loop to run multiple times. Client reassembles and verifies the
/// concatenation byte-for-byte.
#[test]
fn vectored_send_round_trip() {
    init_provider();
    const MID_LEN: usize = 2 * 1024 * 1024;
    const SEED: u64 = 0x1234_5678_ABCD_EF01;
    const PREFIX: &[u8] = b"PREFIX|";
    const SUFFIX: &[u8] = b"|SUFFIX";

    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let body = deterministic_payload(MID_LEN, SEED);
            let mut slices = [
                IoSlice::new(PREFIX),
                IoSlice::new(&body),
                IoSlice::new(SUFFIX),
            ];
            stream
                .send_vectored(&mut slices)
                .await
                .expect("send_vectored");
        });
    });

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread(async move {
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

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let mut received = Vec::with_capacity(MID_LEN + PREFIX.len() + SUFFIX.len());
            while let Some(item) = stream.next().await {
                let frame = item.expect("frame ok");
                received.extend_from_slice(frame.as_ref());
            }

            let body = deterministic_payload(MID_LEN, SEED);
            let mut expected = Vec::with_capacity(MID_LEN + PREFIX.len() + SUFFIX.len());
            expected.extend_from_slice(PREFIX);
            expected.extend_from_slice(&body);
            expected.extend_from_slice(SUFFIX);
            assert_eq!(
                received.len(),
                expected.len(),
                "length mismatch: got {}, expected {}",
                received.len(),
                expected.len()
            );
            if let Some(i) = received.iter().zip(&expected).position(|(a, b)| a != b) {
                panic!(
                    "byte mismatch at offset {i}: got {:#04x}, expected {:#04x}",
                    received[i], expected[i]
                );
            }
        });
    });

    client.join().expect("client thread");
    server.join().expect("server thread");
}

/// Server sends "before", initiates a TLS 1.3 KeyUpdate (rotating its
/// TX secret and rearming `kTLS_TX`), then sends "after" under the new
/// key. Client must transparently process the KeyUpdate control record
/// — `handle_control_record` decodes it, rotates `kTLS_RX`, and the
/// stream re-arms its MultiRecv — and surface both payloads as ordinary
/// frames. If the rekey on either side were broken, "after" would
/// either fail to decrypt (EBADMSG → stream error) or never decode.
#[test]
fn server_initiated_key_update_round_trip() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");

            let mut stream = ktls.into_messages(BufGroup::Medium);
            stream.send(b"before").await.expect("send before");
            stream.initiate_key_update().expect("initiate_key_update");
            stream.send(b"after").await.expect("send after");
        });
    });

    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        main_thread(async move {
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

            let mut stream = ktls.into_messages(BufGroup::Medium);
            let mut received = Vec::new();
            while let Some(item) = stream.next().await {
                let frame = item.expect("frame ok");
                received.extend_from_slice(frame.as_ref());
            }
            assert_eq!(
                received, b"beforeafter",
                "client missed a frame across the KeyUpdate boundary"
            );
        });
    });

    client.join().expect("client thread");
    server.join().expect("server thread");
}
