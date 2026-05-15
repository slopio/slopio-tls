use std::time::Duration;

use runtime::net::{SocketWrapper, socket_recv_init, socket_send};
use runtime::runtime::time::timeout;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};

use crate::config::Config;
use crate::ktls::KtlsSocket;
use crate::pool::{BUFFER_SIZE as RECORD_BUF, PooledBuf};

#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    Rustls(rustls::Error),
    Encode(EncodeError),
    Io(std::io::Error),
    PeerClosed,
    UnexpectedState(&'static str),
    LeftoverBytes,
    Timeout,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Rustls(e) => write!(f, "TLS error: {e}"),
            HandshakeError::Encode(e) => write!(f, "TLS encode error: {e:?}"),
            HandshakeError::Io(e) => write!(f, "I/O error: {e}"),
            HandshakeError::PeerClosed => f.write_str("peer closed connection during handshake"),
            HandshakeError::UnexpectedState(name) => {
                write!(f, "unexpected TLS state during handshake: {name}")
            }
            HandshakeError::LeftoverBytes => {
                f.write_str("leftover bytes after handshake could not be processed")
            }
            HandshakeError::Timeout => f.write_str("handshake timed out"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::Rustls(e) => Some(e),
            HandshakeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rustls::Error> for HandshakeError {
    fn from(e: rustls::Error) -> Self {
        HandshakeError::Rustls(e)
    }
}

impl From<EncodeError> for HandshakeError {
    fn from(e: EncodeError) -> Self {
        HandshakeError::Encode(e)
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        HandshakeError::Io(e)
    }
}

pub async fn handshake(
    socket: SocketWrapper,
    config: Config,
    deadline: Duration,
) -> Result<KtlsSocket, HandshakeError> {
    match timeout(deadline, handshake_inner(socket, config)).await {
        Ok(result) => result,
        Err(()) => Err(HandshakeError::Timeout),
    }
}

async fn handshake_inner(
    socket: SocketWrapper,
    config: Config,
) -> Result<KtlsSocket, HandshakeError> {
    let Config {
        rustls,
        alpn_protocols,
    } = config;
    let mut conn = UnbufferedServerConnection::new(rustls)?;
    let mut in_buf = PooledBuf::new();
    let mut out_buf = PooledBuf::new();
    let mut filled: usize = 0;
    let mut pending_plaintext: Option<Vec<u8>> = None;
    let mut handshake_done = false;

    loop {
        let UnbufferedStatus { discard, state } =
            conn.process_tls_records(&mut in_buf[..filled]);

        match state? {
            ConnectionState::EncodeTlsData(mut enc) => {
                let n = enc.encode(&mut out_buf)?;
                send_all(&socket, &out_buf[..n]).await?;
            }
            ConnectionState::TransmitTlsData(t) => t.done(),
            ConnectionState::BlockedHandshake if handshake_done => {
                return Err(HandshakeError::UnexpectedState("BlockedHandshake after handshake"));
            }
            ConnectionState::BlockedHandshake => {
                shift(&mut in_buf, &mut filled, discard);
                recv_more(&socket, &mut in_buf, &mut filled).await?;
                continue;
            }
            ConnectionState::WriteTraffic(_) => handshake_done = true,
            ConnectionState::ReadTraffic(mut rt) => {
                let acc = pending_plaintext.get_or_insert_with(Vec::new);
                while let Some(rec) = rt.next_record() {
                    acc.extend_from_slice(rec?.payload);
                }
                handshake_done = true;
            }
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(HandshakeError::PeerClosed);
            }
            ConnectionState::ReadEarlyData(_) => {
                return Err(HandshakeError::UnexpectedState("ReadEarlyData (0-RTT)"));
            }
            _ => return Err(HandshakeError::UnexpectedState("unknown ConnectionState")),
        }

        shift(&mut in_buf, &mut filled, discard);

        if handshake_done {
            if filled == 0 {
                break;
            }
            if discard == 0 {
                recv_more(&socket, &mut in_buf, &mut filled).await?;
            }
        }
    }

    let alpn = conn
        .alpn_protocol()
        .and_then(|neg| alpn_protocols.iter().copied().find(|p| *p == neg));
    let (secrets, kernel_conn) = conn.dangerous_into_kernel_connection()?;
    KtlsSocket::establish(socket, secrets, kernel_conn, alpn, pending_plaintext)
        .map_err(HandshakeError::Io)
}

fn shift(in_buf: &mut PooledBuf, filled: &mut usize, discard: usize) {
    if discard > 0 {
        in_buf[..*filled].copy_within(discard.., 0);
        *filled -= discard;
    }
}

async fn recv_more(
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: &mut usize,
) -> Result<(), HandshakeError> {
    if *filled == RECORD_BUF {
        return Err(HandshakeError::LeftoverBytes);
    }
    let n = socket_recv_init(socket, &mut in_buf[*filled..], RECORD_BUF - *filled).await?;
    if n == 0 {
        return Err(HandshakeError::PeerClosed);
    }
    *filled += n;
    Ok(())
}

async fn send_all(socket: &SocketWrapper, mut data: &[u8]) -> Result<(), HandshakeError> {
    while !data.is_empty() {
        let n = socket_send(socket, data).await?;
        if n == 0 {
            return Err(HandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "socket_send returned 0",
            )));
        }
        data = &data[n..];
    }
    Ok(())
}
