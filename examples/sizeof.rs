use std::future::Future;
use std::time::Duration;

use popple_tls::{ServerSettings, handshake, server_config};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use runtime::net::SocketWrapper;

runtime::define_buf_ring!(MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

fn fsize<F: Future>(_: F) -> usize {
    std::mem::size_of::<F>()
}

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cfg = server_config(ServerSettings {
        certs: vec![CertificateDer::from(cert.der().to_vec())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        alpn_protocols: None,
    })
    .unwrap();

    let dummy_sock = SocketWrapper { fd: -1 };
    let f_handshake = handshake(dummy_sock, cfg.clone(), Duration::from_secs(1));
    println!("handshake future: {} B", fsize(f_handshake));

    println!("UnbufferedServerConnection: {} B", std::mem::size_of::<rustls::server::UnbufferedServerConnection>());
    println!("Arc<rustls::ServerConfig>:  {} B", std::mem::size_of::<std::sync::Arc<rustls::ServerConfig>>());
    println!("popple_tls::Config:         {} B", std::mem::size_of::<popple_tls::Config>());
    println!("popple_tls::KtlsSocket:     {} B", std::mem::size_of::<popple_tls::KtlsSocket>());
    println!("popple_tls::KtlsMessages:   {} B", std::mem::size_of::<popple_tls::KtlsMessages<MediumRing>>());
}
