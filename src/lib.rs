pub mod config;
pub mod connect;
pub mod handshake;
pub mod ktls;
mod pool;
pub mod probe;
pub mod stream;

pub use config::{
    ClientConfig, ClientSettings, Config, ServerSettings, client_config,
    client_config_dangerous_no_verification, server_config,
};
pub use connect::{connect, handshake_client};
pub use handshake::{HandshakeError, handshake};
pub use ktls::KtlsSocket;
pub use probe::ktls_available;
pub use rustls::pki_types::ServerName;
pub use stream::{Frame, KtlsMessages, StreamState};
