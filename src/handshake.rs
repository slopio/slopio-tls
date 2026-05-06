use std::mem::MaybeUninit;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use runtime::net::{SocketWrapper, socket_recv, socket_send};
use runtime::runtime::time::timeout;

use crate::ktls::KtlsSocket;

const RECORD_BUF: usize = 17 * 1024;

#[derive(Debug)]
pub enum HandshakeError {
    Rustls(rustls::Error),
    Encode(EncodeError),
    Io(std::io::Error),
    PeerClosed,
    UnexpectedState,
    LeftoverBytes,
    Timeout,
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
    config: Arc<ServerConfig>,
    deadline: Duration,
) -> Result<KtlsSocket, HandshakeError> {
    match timeout(deadline, handshake_inner(socket, config)).await {
        Ok(result) => result,
        Err(()) => Err(HandshakeError::Timeout),
    }
}

async fn handshake_inner(
    socket: SocketWrapper,
    config: Arc<ServerConfig>,
) -> Result<KtlsSocket, HandshakeError> {
    let mut conn = UnbufferedServerConnection::new(config)?;
    let mut in_buf: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(RECORD_BUF);
    let mut filled: usize = 0;
    let mut out_buf = vec![0u8; RECORD_BUF];

    enum Step {
        Continue,
        Recv,
        Done,
    }

    loop {
        let view: &mut [u8] = unsafe { in_buf[..filled].assume_init_mut() };
        let UnbufferedStatus { discard, state } = conn.process_tls_records(view);

        let step = match state? {
            ConnectionState::EncodeTlsData(mut enc) => {
                let n = enc.encode(&mut out_buf)?;
                send_all(&socket, &out_buf[..n]).await?;
                Step::Continue
            }
            ConnectionState::TransmitTlsData(t) => {
                t.done();
                Step::Continue
            }
            ConnectionState::BlockedHandshake => Step::Recv,
            ConnectionState::WriteTraffic(_) => Step::Done,
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(HandshakeError::PeerClosed);
            }
            _ => return Err(HandshakeError::UnexpectedState),
        };

        if discard > 0 {
            let init = unsafe { in_buf[..filled].assume_init_mut() };
            init.copy_within(discard.., 0);
            filled -= discard;
        }

        match step {
            Step::Continue => {}
            Step::Recv => {
                if filled == RECORD_BUF {
                    return Err(HandshakeError::LeftoverBytes);
                }
                let n =
                    socket_recv(&socket, &mut in_buf[filled..], RECORD_BUF - filled).await?;
                if n == 0 {
                    return Err(HandshakeError::PeerClosed);
                }
                filled += n;
            }
            Step::Done => {
                if filled > 0 {
                    return Err(HandshakeError::LeftoverBytes);
                }
                break;
            }
        }
    }

    let (secrets, kernel_conn) = conn.dangerous_into_kernel_connection()?;
    let mut ktls = KtlsSocket::try_from(socket)?;
    ktls.install_keys(secrets)?;
    ktls.kernel_conn = Some(kernel_conn);
    Ok(ktls)
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
