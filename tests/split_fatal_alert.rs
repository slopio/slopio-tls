//! Nothing may follow a fatal alert (RFC 8446 §6.2). With split halves the
//! reader sends the alert while the writer can be mid-send; the writer's
//! in-flight send must fail instead of carrying on after the alert.

use std::net::TcpListener;
use std::sync::{Once, mpsc};
use std::thread;
use std::time::Duration;

use popple_tls::{
    Config, ServerName, ServerSettings, client_config_dangerous_no_verification, connect,
    handshake, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::channels::unbounded_channel;
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime::runtime::time::timeout;
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

/// Send one handshake record over kTLS with a plain blocking `sendmsg`.
fn send_handshake_record(fd: i32, payload: &[u8]) {
    const SOL_TLS: libc::c_int = 282;
    const TLS_SET_RECORD_TYPE: libc::c_int = 1;
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut ctrl = [0usize; 4];
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(1) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = SOL_TLS;
        (*cmsg).cmsg_type = TLS_SET_RECORD_TYPE;
        (*cmsg).cmsg_len = libc::CMSG_LEN(1) as _;
        *libc::CMSG_DATA(cmsg) = 22;
        assert_eq!(libc::sendmsg(fd, &msg, 0), payload.len() as isize);
    }
}

#[test]
fn fatal_alert_fails_the_writers_inflight_send() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = common::accept(&mut acc).await;
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            let (mut reader, mut writer) = ktls.into_messages::<MediumRing>().split();

            let (seen_tx, seen_rx) = unbounded_channel::<std::io::Result<()>>();
            runtime::spawn(async move {
                let outcome = match reader.next().await {
                    Some(Err(e)) => Err(e),
                    _ => Ok(()),
                };
                seen_tx.send(outcome);
            });

            let sent = timeout(Duration::from_secs(3), writer.send(vec![0u8; 64 << 20])).await;
            let kind = match sent {
                Ok((Err(e), _)) => e.kind(),
                Ok((Ok(()), _)) => panic!("64 MiB went through despite the fatal alert"),
                Err(()) => panic!("writer's send still pending after the fatal alert"),
            };
            assert_eq!(kind, std::io::ErrorKind::BrokenPipe);
            assert!(
                seen_rx.recv().await.expect("reader outcome").is_err(),
                "reader must surface the protocol violation"
            );
            assert!(!writer.is_open());
            done_tx.send(()).unwrap();
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
            let mut stream = ktls.into_messages::<MediumRing>();

            let mut received = 0usize;
            let mut violated = false;
            while let Some(Ok(frame)) = stream.next().await {
                received += frame.as_ref().len();
                if !violated && received >= 1 << 20 {
                    // KeyUpdateRequest 2 is illegal_parameter.
                    send_handshake_record(fd, &[24, 0, 0, 1, 2]);
                    violated = true;
                }
            }
            assert!(violated, "server stopped before 1 MiB: {received} B");
            // Keep the socket open until the server has checked its writer.
            done_rx.recv().unwrap();
        });
    });

    server.join().expect("server thread");
    client.join().expect("client thread");
}
