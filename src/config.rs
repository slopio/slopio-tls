use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, ServerConfig, SupportedCipherSuite};

pub struct ServerSettings {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub alpn_protocols: Option<Vec<Vec<u8>>>,
}

const KTLS_SUPPORTED_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
];

pub fn server_config(settings: ServerSettings) -> Result<ServerConfig, rustls::Error> {
    let default = CryptoProvider::get_default().ok_or_else(|| {
        rustls::Error::General(
            "no default CryptoProvider installed; \
             call rustls::crypto::aws_lc_rs::default_provider().install_default() at startup"
                .into(),
        )
    })?;

    let pinned: Vec<SupportedCipherSuite> = default
        .cipher_suites
        .iter()
        .filter(|cs| KTLS_SUPPORTED_SUITES.contains(&cs.suite()))
        .copied()
        .collect();

    if pinned.is_empty() {
        return Err(rustls::Error::General(
            "default crypto provider exposes no kTLS-compatible cipher suites".into(),
        ));
    }

    let provider = Arc::new(CryptoProvider {
        cipher_suites: pinned,
        ..(**default).clone()
    });

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(settings.certs, settings.key)?;
    cfg.enable_secret_extraction = true;
    if let Some(alpn) = settings.alpn_protocols {
        if alpn.is_empty() {
            return Err(rustls::Error::General(
                "alpn_protocols was Some but empty; use None to disable ALPN".into(),
            ));
        }
        cfg.alpn_protocols = alpn;
    }
    Ok(cfg)
}
