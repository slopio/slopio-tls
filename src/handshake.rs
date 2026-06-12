use std::time::Duration;

use runtime::net::{IoBuf, SocketWrapper, send_all as runtime_send_all, socket_recv};
use runtime::runtime::time::timeout;
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

/// Abstracts the two `UnbufferedXxxConnection` types so the handshake loop is
/// written once. rustls's `process_tls_records` is split into side-specific
/// inherent impls — only the early-data handling differs — so a trait is the
/// cheapest way to dedupe without forking the loop body.
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
            // Linux's TCP_ULP "tls" attach does not reprocess ciphertext
            // already sitting in the TCP receive queue: the strparser
            // initialized by set_crypto_info only sees data delivered via
            // sk_data_ready *after* attach, so any queued skbs become
            // unreachable. We must therefore drain the queue here and feed it
            // through rustls before switching. One bulk `recv` grabs whatever
            // is queued; rustls slices it into records on the next `step`. We
            // may only attach once `in_buf` sits on a record boundary
            // (filled == 0) AND the queue is empty.
            match drain_available(&socket, &mut in_buf, &mut filled)? {
                // Got bytes: loop so rustls consumes the complete records.
                DrainStep::Read => {}
                DrainStep::Empty => {
                    if filled == 0 {
                        break; // record-aligned + queue drained → attach kTLS
                    }
                    // A record is split in transit: its head is buffered but
                    // the tail hasn't arrived. Await the rest (won't be
                    // EAGAIN) so we land back on a boundary before attaching —
                    // we cannot hand a half-read record to kTLS.
                    recv_more(&socket, &mut in_buf, &mut filled).await?;
                }
                DrainStep::Eof => {
                    if filled == 0 {
                        break; // clean close on a boundary: nothing to drain
                    }
                    return Err(HandshakeError::PeerClosed); // truncated record
                }
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

/// Outcome of a single non-blocking bulk `recv` during the post-handshake
/// drain. `Read` = bytes landed in `in_buf` (let rustls slice them into
/// records); `Empty` = the kernel queue is momentarily empty (`EAGAIN`);
/// `Eof` = the peer closed cleanly.
enum DrainStep {
    Read,
    Empty,
    Eof,
}

/// One synchronous bulk recv straight into `in_buf`, pulling everything the
/// kernel currently has queued (up to the buffer's remaining room) in a
/// single syscall — no io_uring round-trip, no `PooledScratch`, no copy.
/// rustls does the record framing on the following `step`, so this needn't
/// know record lengths. `MSG_DONTWAIT` keeps it non-blocking independent of
/// the socket's `O_NONBLOCK` flag; `EINTR` retries.
fn drain_available(
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: &mut usize,
) -> Result<DrainStep, HandshakeError> {
    if *filled == RECORD_BUF {
        // Buffer full yet rustls consumed nothing on the last step: a record
        // larger than the buffer, which rustls would reject anyway.
        return Err(HandshakeError::LeftoverBytes);
    }
    let dst = &mut in_buf[*filled..RECORD_BUF];
    let n = loop {
        let r = unsafe {
            libc::recv(
                socket.fd,
                dst.as_mut_ptr() as *mut libc::c_void,
                dst.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => return Ok(DrainStep::Empty),
                _ => return Err(HandshakeError::Io(err)),
            }
        }
        break r as usize;
    };
    if n == 0 {
        return Ok(DrainStep::Eof);
    }
    *filled += n;
    Ok(DrainStep::Read)
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
