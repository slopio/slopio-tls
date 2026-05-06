use std::mem::MaybeUninit;
use std::sync::Arc;
use std::time::Duration;

use popple_tls::{ControlOutcome, handshake};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use runtime::main_thread;
use runtime::net::{MultiAccept, SocketWrapper, socket_recv, socket_send};
use runtime_streams::StreamExt;

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let (cert, key) = self_signed_cert();

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("bad cert/key");
    config.enable_secret_extraction = true;
    let config = Arc::new(config);

    println!("listening on 0.0.0.0:9091 (TLS 1.3, kTLS, echo mode)");
    println!("test with: openssl s_client -connect 127.0.0.1:9091 -tls1_3 -servername localhost");
    println!("then type some text, then 'k' on a line by itself to trigger a KeyUpdate");

    main_thread(async move {
        let mut acceptor = MultiAccept::new(9091).expect("bind 9091");
        while let Some(socket) = acceptor.next().await {
            let cfg = config.clone();
            match handshake(socket, cfg, Duration::from_secs(10)).await {
                Ok(ktls) => {
                    if let Err(e) = echo_loop(ktls).await {
                        eprintln!("connection error: {}", e);
                    }
                }
                Err(e) => eprintln!("handshake failed: {:?}", e),
            }
        }
    });
}

async fn echo_loop(mut ktls: popple_tls::KtlsSocket) -> std::io::Result<()> {
    let mut buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(4096);
    loop {
        match socket_recv(ktls.as_socket(), &mut buf, 4096).await {
            Ok(0) => {
                println!("peer closed (EOF)");
                return Ok(());
            }
            Ok(n) => {
                let data = unsafe { buf[..n].assume_init_ref() };
                println!("recv {} bytes: {:?}", n, std::str::from_utf8(data).unwrap_or("<non-utf8>"));
                send_all(ktls.as_socket(), data).await?;
            }
            Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                println!("EIO -> control record on RX queue, draining");
                match ktls.handle_control_record()? {
                    ControlOutcome::KeyUpdate => {
                        println!("KeyUpdate handled, new RX key installed");
                    }
                    ControlOutcome::KeyUpdateAndRefresh => {
                        println!("KeyUpdate(request) handled — TX rotation not implemented, closing");
                        return Ok(());
                    }
                    ControlOutcome::Eof => {
                        println!("control drain returned EOF");
                        return Ok(());
                    }
                    ControlOutcome::Alert { level, description } => {
                        println!("peer alert level={} desc={}", level, description);
                        return Ok(());
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}

async fn send_all(socket: &SocketWrapper, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = socket_send(socket, data).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "send returned 0",
            ));
        }
        data = &data[n..];
    }
    Ok(())
}

fn self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key).expect("self sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert_der, key_der)
}
