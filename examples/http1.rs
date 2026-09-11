use std::time::Duration;

use popple_tls::{ServerSettings, handshake, server_config};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime_streams::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

runtime::define_buf_ring!(MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nhello via h1\n\n";

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let (cert, key) = self_signed_cert();

    let config = server_config(ServerSettings {
        certs: vec![cert],
        key,
        alpn_protocols: Some(&[b"http/1.1"]),
    })
    .expect("server config");

    println!("listening on 0.0.0.0:9092 (TLS 1.3 + ALPN http/1.1)");
    println!(
        "test with: openssl s_client -connect 127.0.0.1:9092 -tls1_3 \
         -servername localhost -alpn http/1.1 -quiet </dev/null"
    );

    main_thread_with::<MediumRing, _>(async move {
        let mut acceptor = MultiAccept::new(9092).expect("bind 9092");
        while let Some(socket) = acceptor.next().await {
            let cfg = config.clone();
            match handshake(socket, cfg, Duration::from_secs(5)).await {
                Ok(ktls) => {
                    let alpn = ktls
                        .alpn()
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .unwrap_or_else(|| "<none>".to_string());
                    println!("handshake done, negotiated ALPN = {}", alpn);

                    let mut stream = ktls.into_messages::<MediumRing>();
                    let (result, _) = stream.send(RESPONSE).await;
                    if let Err(e) = result {
                        eprintln!("send: {}", e);
                    }
                    drop(stream);
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
