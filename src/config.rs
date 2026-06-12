use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    SupportedCipherSuite,
};

pub struct ServerSettings {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub alpn_protocols: Option<&'static [&'static [u8]]>,
}

#[derive(Clone)]
pub struct Config {
    pub rustls: Arc<ServerConfig>,
    pub alpn_protocols: &'static [&'static [u8]],
}

pub struct ClientSettings {
    pub roots: RootCertStore,
    pub alpn_protocols: Option<&'static [&'static [u8]]>,
}

#[derive(Clone)]
pub struct ClientConfig {
    pub rustls: Arc<rustls::ClientConfig>,
    pub alpn_protocols: &'static [&'static [u8]],
}

const KTLS_SUPPORTED_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
];

pub fn server_config(settings: ServerSettings) -> Result<Config, rustls::Error> {
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
    // No session resumption: we configure no real ticketer/store (rustls would
    // otherwise fall back to an in-memory, single-process, restart-volatile
    // cache), and sending tickets only adds post-handshake round-trips that
    // delay the kTLS switch. Disable them entirely.
    cfg.send_tls13_tickets = 0;
    let alpn_protocols: &'static [&'static [u8]] = match settings.alpn_protocols {
        Some(list) if list.is_empty() => {
            return Err(rustls::Error::General(
                "alpn_protocols was Some but empty; use None to disable ALPN".into(),
            ));
        }
        Some(list) => {
            cfg.alpn_protocols = list.iter().map(|s| s.to_vec()).collect();
            list
        }
        None => &[],
    };
    Ok(Config {
        rustls: Arc::new(cfg),
        alpn_protocols,
    })
}

pub fn client_config(settings: ClientSettings) -> Result<ClientConfig, rustls::Error> {
    let provider = ktls_only_provider()?;
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(settings.roots)
        .with_no_client_auth();
    finalize_client_config(cfg, settings.alpn_protocols)
}

/// **Dangerous**: skips server certificate verification entirely. Intended for
/// loopback tests and local examples; never use in production — it disables
/// authentication and exposes the connection to active MITM.
pub fn client_config_dangerous_no_verification(
    alpn_protocols: Option<&'static [&'static [u8]]>,
) -> Result<ClientConfig, rustls::Error> {
    let provider = ktls_only_provider()?;
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification { schemes }))
        .with_no_client_auth();
    finalize_client_config(cfg, alpn_protocols)
}

fn finalize_client_config(
    mut cfg: rustls::ClientConfig,
    alpn_protocols: Option<&'static [&'static [u8]]>,
) -> Result<ClientConfig, rustls::Error> {
    cfg.enable_secret_extraction = true;
    let alpn_protocols: &'static [&'static [u8]] = match alpn_protocols {
        Some(list) if list.is_empty() => {
            return Err(rustls::Error::General(
                "alpn_protocols was Some but empty; use None to disable ALPN".into(),
            ));
        }
        Some(list) => {
            cfg.alpn_protocols = list.iter().map(|s| s.to_vec()).collect();
            list
        }
        None => &[],
    };
    Ok(ClientConfig {
        rustls: Arc::new(cfg),
        alpn_protocols,
    })
}

fn ktls_only_provider() -> Result<Arc<CryptoProvider>, rustls::Error> {
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
    Ok(Arc::new(CryptoProvider {
        cipher_suites: pinned,
        ..(**default).clone()
    }))
}

#[derive(Debug)]
struct NoVerification {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
