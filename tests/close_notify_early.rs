//! A peer that sends `request` then `close_notify` in one burst right after
//! its Finished must always produce the same stream: one frame with the
//! request, then `None` — regardless of *where* the alert is consumed.
//!
//! `close_notify_data_loss.rs` covers the multishot path. These two tests
//! cover the two earlier timings, where the alert is swallowed before any
//! recv is armed. The server bounds its handshake reads at the client's
//! Finished, so in both cases the request and close_notify pipelined behind
//! it stay in the kernel queue and are consumed by the post-attach drain
//! (`drain_queued_records`), not the software handshake:
//!
//! 1. The client sends the burst a little after the handshake, so it is
//!    plainly queued when `into_messages` runs.
//! 2. The client coalesces the burst into the same TCP segment as its
//!    Finished; the server still stops at the Finished and drains the rest.
//!
//! In both cases the client keeps its TCP socket open: a server that only
//! ends the stream on FIN hangs, and a server that loses the queued request
//! fails the assertion.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Once, mpsc};
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

const REQUEST: &[u8] = b"REQUEST-BEFORE-CLOSE";
const RESPONSE: &[u8] = b"RESPONSE-AFTER-PEER-CLOSE";

const SOL_TLS: libc::c_int = 282;
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_RECORD_TYPE_ALERT: u8 = 21;

#[repr(C)]
struct TlsCmsg {
    hdr: libc::cmsghdr,
    record_type: u8,
}

/// Send `payload` as a TLS record of `record_type` over a kTLS TX socket.
fn send_record(fd: i32, record_type: u8, payload: &[u8]) {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cmsg = TlsCmsg {
        hdr: unsafe { std::mem::zeroed() },
        record_type,
    };
    cmsg.hdr.cmsg_len = unsafe { libc::CMSG_LEN(1) } as _;
    cmsg.hdr.cmsg_level = SOL_TLS;
    cmsg.hdr.cmsg_type = TLS_SET_RECORD_TYPE;
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &mut cmsg as *mut _ as *mut libc::c_void;
    msg.msg_controllen = size_of::<TlsCmsg>() as _;
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    assert!(n >= 0, "sendmsg failed: {}", std::io::Error::last_os_error());
}

/// Timing 1: request + close_notify are already in the kernel queue when the
/// server calls `into_messages`, so the drain consumes both.
#[test]
fn drained_close_notify_ends_stream_without_tcp_fin() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (got_tx, got_rx) = mpsc::channel::<(Vec<u8>, bool)>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            // Let both records queue in the kernel before arming anything.
            Sleep::during(Duration::from_millis(250)).await;
            let mut stream = ktls.into_messages::<MediumRing>();
            let mut got = Vec::new();
            let ended = timeout(Duration::from_secs(2), async {
                while let Some(frame) = stream.next().await {
                    match frame {
                        Ok(f) => got.extend_from_slice(f.as_ref()),
                        Err(_) => break,
                    }
                }
            })
            .await
            .is_ok();
            got_tx.send((got, ended)).unwrap();
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
            let fd = ktls.fd();
            // Past the server handshake, inside its pre-into_messages sleep.
            Sleep::during(Duration::from_millis(50)).await;
            send_record(fd, 23, REQUEST);
            send_record(fd, TLS_RECORD_TYPE_ALERT, &[1, 0]); // close_notify
            // Keep the TCP connection open well past the server's timeout:
            // the stream must end on the alert alone, not on FIN.
            Sleep::during(Duration::from_secs(4)).await;
            drop(ktls);
        });
    });

    let (got, ended) = got_rx.recv().expect("server result");
    client.join().unwrap();
    server.join().unwrap();

    assert_eq!(got, REQUEST, "request before close_notify was lost");
    assert!(
        ended,
        "stream did not yield None after a drained close_notify; it hung until timeout"
    );
}

/// Timing 2: Finished, request and close_notify arrive in one TCP write, so
/// all three are in the server's software handshake buffer. A raw rustls
/// client is used so the burst can be assembled before anything is written.
#[test]
fn close_notify_coalesced_with_finished_delivers_request_then_ends() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (result_tx, result_rx) = mpsc::channel::<Result<(), String>>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let outcome = async {
                let ktls = handshake(socket, cfg, Duration::from_secs(5))
                    .await
                    .map_err(|e| format!("handshake failed on pipelined close_notify: {e}"))?;
                // The server bounds its reads at the client's Finished, so the
                // request and close_notify pipelined behind it stay in the
                // kernel queue; the post-attach drain in `into_messages`
                // picks them up. `peer_closed()` therefore reflects the drain,
                // not the handshake — the contract is the observable sequence
                // below: the request frame, then `None`, with TX still usable.
                let mut stream = ktls.into_messages::<MediumRing>();
                let first = timeout(Duration::from_secs(2), stream.next())
                    .await
                    .map_err(|_| "hung waiting for the first frame".to_string())?
                    .ok_or("stream ended before delivering the request")?
                    .map_err(|e| format!("first frame error: {e}"))?;
                if first.as_ref() != REQUEST {
                    return Err(format!("wrong request: {:?}", first.as_ref()));
                }
                let end = timeout(Duration::from_secs(2), stream.next())
                    .await
                    .map_err(|_| "hung after the request instead of yielding None".to_string())?;
                if end.is_some() {
                    return Err("expected None after the request".into());
                }
                // TX must still work: answer the pipelined request.
                stream
                    .send(RESPONSE.to_vec())
                    .await
                    .0
                    .map_err(|e| format!("send after peer close failed: {e}"))?;
                Ok(())
            }
            .await;
            result_tx.send(outcome).unwrap();
        });
    });
    ready_rx.recv().unwrap();

    let client = thread::spawn(move || {
        let cfg = client_config_dangerous_no_verification(None).expect("client config");
        let rustls_cfg: Arc<rustls::ClientConfig> = cfg.rustls;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
        let mut conn = rustls::ClientConnection::new(
            rustls_cfg,
            ServerName::try_from("localhost").unwrap(),
        )
        .expect("client conn");

        // ClientHello goes out on its own.
        while conn.wants_write() {
            conn.write_tls(&mut sock).expect("write ClientHello");
        }
        // Consume the server flight. Once the handshake is complete, the
        // client's Finished is queued in rustls but NOT yet on the wire.
        while conn.is_handshaking() {
            let n = conn.read_tls(&mut sock).expect("read server flight");
            assert!(n > 0, "server closed during handshake");
            conn.process_new_packets().expect("process server flight");
        }
        // Queue request + close_notify behind Finished, then flush all of
        // it in a single write so the server reads it in one recv.
        conn.writer().write_all(REQUEST).unwrap();
        conn.send_close_notify();
        let mut burst = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut burst).unwrap();
        }
        sock.write_all(&burst).expect("write burst");

        // Keep the socket open and read the response.
        let mut response = Vec::new();
        while response.len() < RESPONSE.len() {
            match conn.read_tls(&mut sock) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => panic!("read_tls: {e}"),
            }
            let state = conn.process_new_packets().expect("process response");
            let n = state.plaintext_bytes_to_read();
            if n > 0 {
                let mut chunk = vec![0u8; n];
                conn.reader().read_exact(&mut chunk).unwrap();
                response.extend_from_slice(&chunk);
            }
        }
        response
    });

    let outcome = result_rx.recv().expect("server result");
    let response = client.join().unwrap();
    server.join().unwrap();

    outcome.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(response, RESPONSE, "client did not get the reply to its pipelined request");
}
