use std::time::Duration;

use runtime::net::{IoBuf, SocketWrapper, send_all as runtime_send_all, socket_recv};
use runtime::runtime::time::timeout;
use rustls::ExtractedSecrets;
use rustls::kernel::KernelConnection;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};

use crate::config::Config;
use crate::ktls::{KtlsSocket, Prelude};
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
    /// Ask rustls, not `handshake_done`: a close_notify pipelined right
    /// behind Finished completes the handshake and reports `PeerClosed` in
    /// the same step, before any traffic state is observed.
    fn handshake_complete(&self) -> bool;
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
    fn handshake_complete(&self) -> bool {
        !self.is_handshaking()
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
    // Bytes encoded into `out_buf` but not yet sent.
    let mut pending: usize = 0;

    let prelude = loop {
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
                drain_pending_alert(&mut conn, &socket, &mut in_buf, filled, out_buf, pending)
                    .await;
                return Err(HandshakeError::Rustls(e));
            }
        };

        match s {
            ConnectionState::EncodeTlsData(mut enc) => {
                // One record per step; accumulate and send the whole flight
                // on `TransmitTlsData` (or when `out_buf` is full).
                let n = match enc.encode(&mut out_buf[pending..]) {
                    Ok(n) => n,
                    Err(EncodeError::InsufficientSize(_)) => {
                        // `enc` owns the record, already popped from rustls's
                        // queue: dropping it here would lose it. Flush and
                        // retry on the same `enc`.
                        let (result, recovered) = send_all(&socket, out_buf, pending).await;
                        out_buf = recovered;
                        result?;
                        pending = 0;
                        enc.encode(&mut out_buf[..])?
                    }
                    Err(e) => return Err(e.into()),
                };
                pending += n;
            }
            ConnectionState::TransmitTlsData(t) => {
                let (result, recovered) = send_all(&socket, out_buf, pending).await;
                out_buf = recovered;
                result?;
                pending = 0;
                t.done();
            }
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
                // Error or not depends on whether the handshake had
                // completed; `s` borrows `conn`, so that is checked after
                // the loop.
                break Prelude::closed(pending_plaintext.take());
            }
            ConnectionState::ReadEarlyData(_) => {
                return Err(HandshakeError::UnexpectedState("ReadEarlyData (0-RTT)"));
            }
            _ => return Err(HandshakeError::UnexpectedState("unknown ConnectionState")),
        }

        shift(&mut in_buf, &mut filled, discard);

        if handshake_done {
            // Records already pipelined into `in_buf` during the handshake recv
            // are sliced out into `pending_plaintext` here, in software. Records
            // still in the kernel queue are NOT drained here — they're handled
            // after attach by `KtlsSocket::drain_queued_records` (a non-blocking
            // recvmsg loop), which is the deterministic replacement for the old
            // pre-attach grace-drain.
            if discard > 0 {
                // rustls consumed a record this step; loop so it can slice the
                // next complete one out of `in_buf` into `pending_plaintext`.
                continue;
            }
            if filled == 0 {
                // record-aligned → attach
                break Prelude::open(pending_plaintext.take());
            }
            // discard == 0 && filled > 0: a partial record head sits in `in_buf`
            // (out of the kernel's reach). Finish it in software so we attach on
            // a clean boundary; the loop re-steps and breaks on `filled == 0`.
            recv_more(&socket, &mut in_buf, &mut filled).await?;
        }
    };

    // rustls reports `PeerClosed` ahead of `TransmitTlsData`, so a flight can
    // still be in `out_buf` here. Best-effort once the peer has closed.
    if pending > 0 {
        let (result, _) = send_all(&socket, out_buf, pending).await;
        if !prelude.peer_closed() {
            result?;
        }
    }

    if prelude.peer_closed() && !conn.handshake_complete() {
        return Err(HandshakeError::PeerClosed);
    }
    // close_notify after a complete handshake: attach anyway so the pipelined
    // request can be delivered and answered; the stream then ends.

    let alpn = conn
        .negotiated_alpn()
        .and_then(|neg| alpn_protocols.iter().copied().find(|p| *p == neg));
    let (secrets, kernel_conn) = conn.into_kernel()?;
    KtlsSocket::switch_to_ktls(socket, secrets, kernel_conn, alpn, prelude)
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
///
/// `pending` unsent bytes may sit in `out_buf`: rustls deframes incoming
/// records before asking us to transmit. The alert is appended after them.
async fn drain_pending_alert<C: UnbufferedDriver>(
    conn: &mut C,
    socket: &SocketWrapper,
    in_buf: &mut PooledBuf,
    filled: usize,
    mut out_buf: PooledBuf,
    pending: usize,
) {
    let UnbufferedStatus { state, .. } = conn.step(&mut in_buf[..filled]);
    let mut len = pending;
    if let Ok(ConnectionState::EncodeTlsData(mut enc)) = state {
        if let Ok(n) = enc.encode(&mut out_buf[pending..]) {
            len += n;
        }
    }
    if len > 0 {
        let _ = send_all(socket, out_buf, len).await;
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
