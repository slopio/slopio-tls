//! tlsfuzzer-driven conformance + adversarial tests.
//!
//! Each test boots an ephemeral kTLS echo server and shells out to a single
//! tlsfuzzer script (https://github.com/tlsfuzzer/tlsfuzzer). The script
//! opens many TLS 1.3 connections — happy-path and adversarial — and exits
//! non-zero if any subtest fails.
//!
//! Gating: tests are `#[ignore]`'d. To run, set `TLSFUZZER` to a tlsfuzzer
//! checkout (with deps installed) and run:
//!
//!     TLSFUZZER=/path/to/tlsfuzzer cargo test --test tlsfuzzer -- --ignored
//!
//! Optionally set `PYTHON=python3.11` to pick the interpreter.
//!
//! The curated list is intentionally small. Most of the TLS protocol surface
//! (handshake, record parsing, crypto) lives in rustls and is fuzzed upstream.
//! What this library actually owns is the kTLS offload path, post-handshake
//! records (KeyUpdate, alerts, padding), and the ktls<->rustls handoff. The
//! scripts below target those areas.

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use popple_tls::{Config, ServerSettings, handshake, server_config};
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
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

/// tlsfuzzer's TLS 1.3 scripts (except `test-tls13-conversation.py`) hardcode
/// RSA-only sig algs in their ClientHello, so the server cert must be RSA or
/// rustls aborts the handshake with `no suitable signature scheme`. RSA-2048
/// keygen is ~100ms so we cache it across all tests.
fn rsa_cert() -> &'static (CertificateDer<'static>, PrivateKeyDer<'static>) {
    static CERT: OnceLock<(CertificateDer<'static>, PrivateKeyDer<'static>)> = OnceLock::new();
    CERT.get_or_init(|| {
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key = KeyPair::generate_for(&PKCS_RSA_SHA256).expect("rsa keygen");
        let cert = params.self_signed(&key).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (cert_der, key_der)
    })
}

fn make_config() -> Config {
    let (cert, key) = rsa_cert();
    server_config(ServerSettings {
        certs: vec![cert.clone()],
        key: key.clone_key(),
        alpn_protocols: None,
    })
    .expect("server config")
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Long-running multi-connection kTLS echo server. tlsfuzzer scripts open
/// many sequential connections per run, so the accept loop spawns one task
/// per connection and stays alive until [`EchoServer::stop`].
struct EchoServer {
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    port: u16,
}

impl EchoServer {
    fn start() -> Self {
        let port = pick_port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();

        let handle = thread::spawn(move || {
            main_thread_with::<MediumRing, _>(async move {
                let cfg = make_config();
                let mut acc = MultiAccept::new(port).expect("bind");
                ready_tx.send(()).unwrap();
                while let Some(socket) = acc.next().await {
                    if stop_for_thread.load(Ordering::Relaxed) {
                        break;
                    }
                    let cfg = cfg.clone();
                    runtime::spawn(async move {
                        let Ok(ktls) = handshake(socket, cfg, Duration::from_secs(5)).await
                        else {
                            return;
                        };
                        let mut stream = ktls.into_messages::<MediumRing>();
                        while let Some(item) = stream.next().await {
                            let Ok(frame) = item else { break };
                            let data: &[u8] = frame.as_ref();
                            if stream.send(data.to_vec()).await.0.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
        });

        ready_rx.recv().unwrap();
        EchoServer {
            handle: Some(handle),
            stop,
            port,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the accept loop with a sentinel connection so it observes
        // the stop flag and returns.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        // If a test panicked before calling stop(), still tear down the
        // server thread so other tests can run.
        if self.handle.is_some() {
            self.stop.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(("127.0.0.1", self.port));
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
}

fn tlsfuzzer_root() -> String {
    std::env::var("TLSFUZZER").unwrap_or_else(|_| {
        panic!(
            "TLSFUZZER env var not set. Point it at a tlsfuzzer checkout \
             (with deps installed) and run:\n  \
             TLSFUZZER=/path/to/tlsfuzzer cargo test --test tlsfuzzer -- --ignored"
        )
    })
}

/// Invoke a tlsfuzzer script against the running server. Returns the child's
/// exit status; on failure, prints captured stdout/stderr so `cargo test`
/// surfaces the script's per-test report.
fn run_script(script: &str, port: u16, extra_args: &[&str]) -> bool {
    let root = tlsfuzzer_root();
    let script_path = format!("{root}/scripts/{script}");
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string());

    let port_str = port.to_string();
    let mut cmd = Command::new(&python);
    cmd.env("PYTHONPATH", &root)
        .arg(&script_path)
        .args(["-h", "127.0.0.1", "-p", &port_str])
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn {python} {script_path}: {e}"));

    if !out.status.success() {
        eprintln!("--- tlsfuzzer {script} stdout ---");
        eprintln!("{}", String::from_utf8_lossy(&out.stdout));
        eprintln!("--- tlsfuzzer {script} stderr ---");
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    }
    out.status.success()
}

fn run_against_echo(script: &str, extra_args: &[&str]) {
    init_provider();
    let server = EchoServer::start();
    let port = server.port();
    let ok = run_script(script, port, extra_args);
    server.stop();
    assert!(ok, "tlsfuzzer script failed: {script}");
}

// ---------------------------------------------------------------------------
// Curated script list
//
// Each entry lists which part of *this* library it exercises beyond what
// rustls fuzzes upstream. Add scripts here as new code paths land.
// ---------------------------------------------------------------------------

/// TLS 1.3 baseline: handshake, application data round-trip, close_notify.
/// Sanity check that the kTLS offload path is correct end-to-end.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_conversation() {
    run_against_echo("test-tls13-conversation.py", &[]);
}

/// All three TLS 1.3 AEAD ciphers — the suites we explicitly pin in
/// config.rs (`KTLS_SUPPORTED_SUITES`). Verifies every kTLS-compatible
/// cipher works through the offload path, not just the default.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_symmetric_ciphers() {
    run_against_echo("test-tls13-symetric-ciphers.py", &[]);
}

/// Peer-initiated KeyUpdate handling. ktls.rs decrypts the control record
/// in userspace via rustls, then re-keys the kernel socket — this is a
/// path entirely owned by this library, not rustls.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_keyupdate() {
    run_against_echo("test-tls13-keyupdate.py", &[]);
}

/// Zero-length application_data records. Stresses the multishot recv ring
/// and the kTLS path's handling of empty payloads.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_zero_length_data() {
    run_against_echo("test-tls13-zero-length-data.py", &[]);
}

/// Padded innerPlaintext records. The kernel strips padding; this verifies
/// the offload path delivers correct lengths to userspace.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_record_padding() {
    run_against_echo("test-tls13-record-padding.py", &[]);
}

/// Empty / malformed alert records. Exercises the post-handshake control
/// path in stream.rs (`handle_control_record`).
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_empty_alert() {
    run_against_echo("test-tls13-empty-alert.py", &[]);
}

/// Version negotiation. Confirms TLS 1.3-only enforcement is correctly
/// surfaced through the handshake — clients offering only older versions
/// must be rejected.
#[test]
#[ignore = "requires TLSFUZZER env var"]
fn tls13_version_negotiation() {
    run_against_echo("test-tls13-version-negotiation.py", &[]);
}
