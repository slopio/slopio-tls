//! Regression repro for the h2spec "settings lost" bug.
//!
//! When the peer sends an application-data record IMMEDIATELY followed by a
//! `close_notify` alert (exactly what h2spec / Go's TLS do at end of test),
//! the data record must still be delivered before the stream ends. The kTLS
//! read path surfaces the alert as an `EIO` control record; if that path
//! discards an app-data record the multishot recv had already buffered, the
//! last frame before the close is lost.
//!
//! The client here sends both records back-to-back over the raw kTLS fd so
//! they land together in the server's RX queue.

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
    assert!(
        n >= 0,
        "sendmsg failed: {}",
        std::io::Error::last_os_error()
    );
}

#[test]
fn data_record_before_close_notify_is_not_lost() {
    init_provider();
    let port = pick_port();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (got_tx, got_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || {
        main_thread_with::<MediumRing, _>(async move {
            let cfg = make_server_config();
            let mut acc = MultiAccept::new(port).unwrap();
            ready_tx.send(()).unwrap();
            let socket = acc.next().await.expect("accept");
            let ktls = handshake(socket, cfg, Duration::from_secs(5))
                .await
                .expect("server handshake");
            // Delay arming the multishot recv so the client's data + close_notify
            // are BOTH already queued in the kernel when it submits.
            Sleep::during(Duration::from_millis(250)).await;
            let mut stream = ktls.into_messages::<MediumRing>();
            let mut got = Vec::new();
            let collected = timeout(Duration::from_secs(5), async {
                while let Some(frame) = stream.next().await {
                    match frame {
                        Ok(f) => got.extend_from_slice(f.as_ref()),
                        Err(_) => break,
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
            let ktls = connect(
                format!("127.0.0.1:{port}").parse().unwrap(),
                server_name,
                cfg,
                Duration::from_secs(5),
            )
            .await
            .expect("client connect");
            let fd = ktls.fd();
            // Wait just long enough for the server handshake to finish (so the
            // close_notify isn't seen mid-handshake), but send while the server
            // is still in its pre-into_messages sleep → both records queue
            // before the multishot recv arms.
            Sleep::during(Duration::from_millis(50)).await;
            // App-data record, then close_notify, back-to-back.
            send_record(fd, 23, b"PAYLOAD-BEFORE-CLOSE");
            send_record(fd, TLS_RECORD_TYPE_ALERT, &[1, 0]); // warning, close_notify
            Sleep::during(Duration::from_millis(400)).await;
            drop(ktls);
        });
    });

    let got = got_rx.recv().expect("server result");
    client.join().unwrap();
    server.join().unwrap();

    assert_eq!(
        got,
        b"PAYLOAD-BEFORE-CLOSE",
        "\nDATA LOST: the app-data record before close_notify was dropped. got={:?}",
        String::from_utf8_lossy(&got)
    );
}
