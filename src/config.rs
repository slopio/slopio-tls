use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub struct ServerSettings {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub alpn_protocols: Option<Vec<Vec<u8>>>,
}

pub fn server_config(settings: ServerSettings) -> Result<ServerConfig, rustls::Error> {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
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
