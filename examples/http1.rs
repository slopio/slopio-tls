use std::sync::Arc;
use std::time::Duration;

use popple_tls::{ServerSettings, handshake, server_config};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use runtime::main_thread;
use runtime::net::{BufGroup, MultiAccept};
use runtime_streams::StreamExt;

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nhello via h1\n\n";

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let (cert, key) = self_signed_cert();

    let config = Arc::new(
        server_config(ServerSettings {
            certs: vec![cert],
            key,
            alpn_protocols: Some(vec![b"http/1.1".to_vec()]),
        })
        .expect("server config"),
    );

    println!("listening on 0.0.0.0:9092 (TLS 1.3 + ALPN http/1.1)");
    println!(
        "test with: openssl s_client -connect 127.0.0.1:9092 -tls1_3 \
         -servername localhost -alpn http/1.1 -quiet </dev/null"
    );

    main_thread(async move {
        let mut acceptor = MultiAccept::new(9092).expect("bind 9092");
        while let Some(socket) = acceptor.next().await {
            let cfg = config.clone();
            match handshake(socket, cfg, Duration::from_secs(10)).await {
                Ok(ktls) => {
                    let alpn = ktls
                        .alpn()
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .unwrap_or_else(|| "<none>".to_string());
                    println!("handshake done, negotiated ALPN = {}", alpn);

                    let stream = ktls.into_messages(BufGroup::Small);
                    if let Err(e) = stream.send(RESPONSE).await {
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
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key).expect("self sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert_der, key_der)
}
