use std::time::Duration;

use popple_tls::{ServerSettings, handshake, ktls_available, server_config};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn main() {
    if !ktls_available() {
        eprintln!("kTLS is not available on this system.");
        eprintln!("Try: sudo modprobe tls");
        std::process::exit(1);
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let (cert, key) = self_signed_cert();

    let config = server_config(ServerSettings {
        certs: vec![cert],
        key,
        alpn_protocols: None,
    })
    .expect("server config");

    println!("listening on 0.0.0.0:9091 (TLS 1.3, kTLS, KtlsMessages echo)");
    println!("test with: openssl s_client -connect 127.0.0.1:9091 -tls1_3 -servername localhost");

    main_thread_with::<MediumRing, _>(async move {
        let mut acceptor = MultiAccept::new(9091).expect("bind 9091");
        while let Some(socket) = acceptor.next().await {
            let Ok(socket) = socket else { continue };
            let cfg = config.clone();
            match handshake(socket, cfg, Duration::from_secs(5)).await {
                Ok(ktls) => {
                    let mut stream = ktls.into_messages::<MediumRing>();
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(buf) => {
                                let data: &[u8] = buf.as_ref();
                                println!(
                                    "recv {} bytes: {:?}",
                                    data.len(),
                                    std::str::from_utf8(data).unwrap_or("<non-utf8>")
                                );
                                let (result, _) = stream.send(data.to_vec()).await;
                                if let Err(e) = result {
                                    eprintln!("send: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("stream error: {}", e);
                                break;
                            }
                        }
                    }
                    println!("connection done");
                }
                Err(e) => eprintln!("handshake failed: {:?}", e),
            }
        }
    });
}

fn self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key).expect("self sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert_der, key_der)
}
