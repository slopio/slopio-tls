use std::time::Duration;

use runtime::net::{IoBuf, SocketWrapper, send_all as runtime_send_all, socket_recv};
use runtime::runtime::time::{Sleep, timeout};
use rustls::ExtractedSecrets;
use rustls::kernel::KernelConnection;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};

use crate::config::Config;
use crate::ktls::KtlsSocket;
use crate::pool::{BUFFER_SIZE as RECORD_BUF, PooledBuf, PooledScratch};

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

pub(crate) trait UnbufferedDriver: Sized {
    type Data;
    fn step<'c, 'i>(&'c mut self, in_buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data>;
    fn negotiated_alpn(&self) -> Option<&[u8]>;
    fn into_kernel(self)
    -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error>;
}

impl UnbufferedDriver for UnbufferedServerConnection {
    type Data = ServerConnectionData;
    fn step<'c, 'i>(&'c mut self, in_buf: &'i mut [u8]) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(in_buf)
    }
    fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.alpn_protocol()
    }
    fn into_kernel(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error> {
        self.dangerous_into_kernel_connection()
    }
}

pub async fn handshake(
    socket: SocketWrapper,
    config: Config,
    deadline: Duration,
) -> Result<KtlsSocket, HandshakeError> {
    let Config {
        rustls,
        alpn_protocols,
    } = config;
    let conn = UnbufferedServerConnection::new(rustls)?;
    match timeout(deadline, drive_handshake(socket, conn, alpn_protocols)).await {
        Ok(result) => result,
        Err(()) => Err(HandshakeError::Timeout),
    }
}

pub(crate) async fn drive_handshake<C: UnbufferedDriver>(
    socket: SocketWrapper,
    mut conn: C,
    alpn_protocols: &'static [&'static [u8]],
) -> Result<KtlsSocket<C::Data>, HandshakeError> {
    let mut in_buf = PooledBuf::new();
    let mut out_buf = PooledBuf::new();
    let mut filled: usize = 0;
    let mut pending_plaintext: Option<Vec<u8>> = None;
    let mut handshake_done = false;

    loop {
        let UnbufferedStatus { discard, state } = conn.step(&mut in_buf[..filled]);

        let s = match state {
            Ok(s) => s,
            Err(e) => {
                // rustls stages a fatal alert into its outbound queue before
                // surfacing the error; one more pass drains that alert as
                // EncodeTlsData so the peer learns *why* the handshake aborted
                // instead of just seeing the TCP close. We must pass the same
                // buffer rustls saw, because its internal BufferProgress is
                // re-derived from `hs_deframer.outer_discard` each call and
                // indexes into the buffer (passing `&mut []` here panics in
                // rustls when partial handshake data is buffered).
                //
                // Note: rustls does NOT queue an alert for every error. Some
                // record-layer violations (e.g.
                // `PeerMisbehaved::MessageInterleavedWithHandshakeMessage` at
                // rustls-0.23.40/src/conn.rs:1062) return a bare `Err` without
                // calling `send_fatal_alert`. For those, this drain finds an
                // empty `sendable_tls`, returns the same error again, and the
                // peer sees a TCP close instead of a fatal alert. That is a
                // rustls upstream gap, not something we can fix here without
                // hand-encoding alerts with rustls's internal handshake keys.
                drain_pending_alert(&mut conn, &socket, &mut in_buf, filled, out_buf).await;
                return Err(HandshakeError::Rustls(e));
            }
        };

        match s {
            ConnectionState::EncodeTlsData(mut enc) => {
                let n = enc.encode(&mut out_buf)?;
                let (result, recovered) = send_all(&socket, out_buf, n).await;
                out_buf = recovered;
                result?;
            }
            ConnectionState::TransmitTlsData(t) => t.done(),
            ConnectionState::BlockedHandshake if handshake_done => {
                return Err(HandshakeError::UnexpectedState(
                    "BlockedHandshake after handshake",
                ));
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
            // We must drain every record that has already reached the peer's
            // first post-handshake flight into `pending_plaintext` (software)
            // BEFORE attaching kTLS. The kernel itself *would* reprocess queued
            // ciphertext after attach (see the `ktls_queue_premise` test, which
            // confirms it via blocking reads) — but the io_uring **multishot
            // recv** we use for reads (`MultiRecv`) drops records that are
            // queued at the instant it first arms. h2spec reproduces this: with
            // the magic alone in `pending_plaintext` (rx_seq=1) and the client
            // SETTINGS left for the kTLS read path, the SETTINGS is silently
            // lost ~40% of the time. Pulling it through rustls here (rx_seq
            // advances, plaintext lands in `pending_plaintext`) sidesteps the
            // multishot path entirely and makes h2spec deterministic.
            if discard > 0 {
                // rustls consumed a record this step; loop so it can slice the
                // next complete one out of `in_buf` into `pending_plaintext`.
                continue;
            }
            // rustls can't progress on what's buffered. Poll the kernel queue
            // (with a short grace for a pipelined flight still in flight): pull
            // anything that's there through rustls, attach only once it's idle
            // and we sit on a clean record boundary.
            match drain_more(&socket, &mut in_buf, &mut filled).await? {
                DrainMore::Got => continue,
                DrainMore::Idle if filled == 0 => break,
                DrainMore::Idle => return Err(HandshakeError::LeftoverBytes),
            }
        }
    }

    let alpn = conn
        .negotiated_alpn()
        .and_then(|neg| alpn_protocols.iter().copied().find(|p| *p == neg));
    let (secrets, kernel_conn) = conn.into_kernel()?;
    KtlsSocket::switch_to_ktls(socket, secrets, kernel_conn, alpn, pending_plaintext)
        .map_err(HandshakeError::Io)
}

const DRAIN_GRACE: Duration = Duration::from_millis(2);
const DRAIN_POLL: Duration = Duration::from_micros(200);

/// Bytes the kernel TCP receive queue holds right now (`FIONREAD`). A failed
/// ioctl — e.g. `ENOTCONN` once the peer has closed — is reported as `0`: there
/// is simply nothing more to drain, which lets the caller attach and surface
/// the close on the read path instead of failing the handshake.
fn kernel_recv_pending(socket: &SocketWrapper) -> usize {
    let mut pending: libc::c_int = 0;
    if unsafe { libc::ioctl(socket.fd, libc::FIONREAD, &mut pending) } != 0 {
        return 0;
    }
    pending.max(0) as usize
}

enum DrainMore {
    Got,
    Idle,
}

async fn drain_more(
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: &mut usize,
) -> Result<DrainMore, HandshakeError> {
    let mut waited = Duration::ZERO;
    loop {
        if kernel_recv_pending(socket) > 0 {
            // Best-effort: if the read fails because the peer closed/reset
            // mid-drain, there is nothing more to pull — stop and attach with
            // what we already moved into `pending_plaintext`. The real read
            // path surfaces the close.
            return match recv_more(socket, in_buf, filled).await {
                Ok(()) => Ok(DrainMore::Got),
                Err(_) => Ok(DrainMore::Idle),
            };
        }
        if waited >= DRAIN_GRACE {
            return Ok(DrainMore::Idle);
        }
        Sleep::during(DRAIN_POLL).await;
        waited += DRAIN_POLL;
    }
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
    recv_into(socket, in_buf, filled, RECORD_BUF - *filled).await
}

/// Pull up to `cap` bytes from `socket` into `in_buf` starting at `filled`,
/// advancing `filled` by what the kernel actually delivered. `cap` bounds the
/// kernel's write via the scratch buffer's `bytes_total`, so we never overrun
/// `in_buf`'s remaining room — the caller is responsible for sizing `cap`
/// against `RECORD_BUF - *filled`.
async fn recv_into(
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: &mut usize,
    cap: usize,
) -> Result<(), HandshakeError> {
    let scratch = PooledScratch::new(cap);
    let (result, scratch) = socket_recv(socket, scratch).await;
    let n = result.map_err(HandshakeError::Io)?;
    if n == 0 {
        return Err(HandshakeError::PeerClosed);
    }
    in_buf[*filled..*filled + n].copy_from_slice(&scratch[..n]);
    *filled += n;
    Ok(())
}

/// After `process_tls_records` returns `Err`, rustls has queued a fatal alert
/// in its outbound buffer. Drain it (encrypted with the keys negotiated so far)
/// so the peer gets a TLS-level reason for the handshake failure. Best-effort:
/// any further error here is swallowed — we're already on the error path.
///
/// We pass the same buffer rustls saw on the failing call (must be the same
/// slice contents and length, because rustls's `BufferProgress` is re-derived
/// from `hs_deframer.outer_discard` each call and indexes into the buffer).
/// The sendable_tls check inside rustls runs *before* the deframer, so the
/// queued alert surfaces as `EncodeTlsData` on the next call. A fatal alert
/// is a single record, so one pass is enough; calling again after sending
/// would land in the deframer with a stale buffer and panic.
async fn drain_pending_alert<C: UnbufferedDriver>(
    conn: &mut C,
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: usize,
    mut out_buf: PooledBuf,
) {
    let UnbufferedStatus { state, .. } = conn.step(&mut in_buf[..filled]);
    if let Ok(ConnectionState::EncodeTlsData(mut enc)) = state {
        if let Ok(n) = enc.encode(&mut out_buf) {
            let _ = send_all(socket, out_buf, n).await;
        }
    }
}

/// Send the first `len` bytes of `out_buf` over `socket`, threading ownership
/// of the pooled buffer through the io_uring submission so the kernel reads
/// straight from the box (no copy, no extra alloc) and the buffer is handed
/// back to the caller for reuse on the next encode/send pass.
async fn send_all(
    socket: &SocketWrapper,
    out_buf: PooledBuf,
    len: usize,
) -> (Result<(), HandshakeError>, PooledBuf) {
    if len == 0 {
        return (Ok(()), out_buf);
    }
    let slice = out_buf.slice(0..len);
    let (result, slice) = runtime_send_all(socket, slice).await;
    (result.map_err(HandshakeError::Io), slice.into_inner())
}
