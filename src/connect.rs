use std::net::SocketAddr;
use std::time::Duration;

use runtime::net::{SocketWrapper, connect_tcp};
use runtime::runtime::time::timeout;
use rustls::ExtractedSecrets;
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::kernel::KernelConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::UnbufferedStatus;

use crate::config::ClientConfig;
use crate::handshake::{HandshakeError, UnbufferedDriver, drive_handshake};
use crate::ktls::KtlsSocket;

impl UnbufferedDriver for UnbufferedClientConnection {
    type Data = ClientConnectionData;
    fn step<'c, 'i>(&'c mut self, in_buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(in_buf)
    }
    fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.alpn_protocol()
    }
    fn handshake_complete(&self) -> bool {
        !self.is_handshaking()
    }
    fn bounded_reads(&self) -> bool {
        false
    }
    fn into_kernel(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error> {
        self.dangerous_into_kernel_connection()
    }
}

pub async fn connect(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    config: ClientConfig,
    deadline: Duration,
) -> Result<KtlsSocket<ClientConnectionData>, HandshakeError> {
    let socket = connect_tcp(addr).await?;
    // `connect_tcp` leaves Nagle on; accepted sockets get this from `MultiAccept`.
    socket.set_nodelay(true)?;
    handshake_client(socket, server_name, config, deadline).await
}

/// Drive a TLS client handshake over an already-connected socket.
///
/// Like [`connect`], but takes a `SocketWrapper` the caller has already
/// established (TCP connected) instead of dialing the address itself. kTLS
/// attach requires a connected socket, so the peer's TCP handshake must be
/// complete before calling this.
pub async fn handshake_client(
    socket: SocketWrapper,
    server_name: ServerName<'static>,
    config: ClientConfig,
    deadline: Duration,
) -> Result<KtlsSocket<ClientConnectionData>, HandshakeError> {
    let ClientConfig {
        rustls,
        alpn_protocols,
    } = config;
    let conn = UnbufferedClientConnection::new(rustls, server_name)?;
    match timeout(deadline, drive_handshake(socket, conn, alpn_protocols)).await {
        Ok(result) => result,
        Err(()) => Err(HandshakeError::Timeout),
    }
}
