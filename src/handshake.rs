use std::time::Duration;

use runtime::net::{
    IoBuf, SocketWrapper, send_all as runtime_send_all, socket_peek, socket_recv,
};
use runtime::runtime::time::timeout;
use rustls::ExtractedSecrets;
use rustls::kernel::KernelConnection;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};

use crate::config::Config;
use crate::ktls::{KtlsSocket, Prelude};
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
                f.write_str("handshake record buffer full without a complete record")
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
    /// Whether handshake reads should stop at TLS record boundaries (peek +
    /// scan) instead of reading greedily. The server does: it must stop
    /// exactly at the client's Finished so it can attach kTLS at RX sequence
    /// 0, leaving any pipelined application data in the kernel queue for the
    /// multishot recv. The client reads greedily (a different mechanic).
    fn bounded_reads(&self) -> bool;
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
    fn bounded_reads(&self) -> bool {
        true
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
    // Set once we have transmitted a flight. Application data can only follow
    // the peer's Finished, which the peer sends only after receiving our
    // flight — so before this, no read can contain app data and a greedy read
    // is safe. After it, the server bounds reads at the record boundary.
    let mut flight_sent = false;

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
                flight_sent = true;
                t.done();
            }
            ConnectionState::BlockedHandshake if handshake_done => {
                return Err(HandshakeError::UnexpectedState(
                    "BlockedHandshake after handshake",
                ));
            }
            ConnectionState::BlockedHandshake => {
                shift(&mut in_buf, &mut filled, discard);
                in_buf = if conn.bounded_reads() && flight_sent {
                    recv_bounded(&socket, in_buf, &mut filled).await?
                } else {
                    recv_more(&socket, in_buf, &mut filled).await?
                };
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
            // Records pipelined into `in_buf` during the handshake recv are
            // sliced into `pending_plaintext` here (the client's greedy path;
            // the server's bounded read stops at the Finished, so it sees
            // none). Anything left in the kernel queue is delivered by the
            // multishot recv after attach — no pre-arm drain.
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
            in_buf = recv_more(&socket, in_buf, &mut filled).await?;
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

/// Receive into `in_buf` after the `filled` bytes already there, advancing
/// `filled` by what the kernel delivered. The buffer travels with the io_uring
/// op (it must own it for cancel-safety) and comes back on success; on error
/// it is dropped with the handshake.
async fn recv_more(
    socket: &SocketWrapper,
    in_buf: PooledBuf,
    filled: &mut usize,
) -> Result<PooledBuf, HandshakeError> {
    if *filled == RECORD_BUF {
        return Err(HandshakeError::LeftoverBytes);
    }
    let (result, tail) = socket_recv(socket, in_buf.tail(*filled)).await;
    let n = result.map_err(HandshakeError::Io)?;
    if n == 0 {
        return Err(HandshakeError::PeerClosed);
    }
    *filled += n;
    Ok(tail.into_inner())
}

const TLS_HEADER_LEN: usize = 5;
/// RFC 8446 §5.2: TLSCiphertext.length <= 2^14 + 256.
const MAX_TLS_CIPHERTEXT: usize = (1 << 14) + 256;
/// Outer content type of every encrypted record (handshake or app data).
const TLS_APPLICATION_DATA: u8 = 23;

/// Result of walking the TLS records that begin at the front of `buf`.
enum Scan {
    /// A complete encrypted record (server-side, the client's Finished) ends
    /// at this offset. Consuming exactly this many bytes stops right at the
    /// Finished, leaving any pipelined application data in the kernel queue.
    Finished(usize),
    /// No encrypted record yet: only complete ChangeCipherSpec records, or a
    /// partial record. Nothing here can be application data.
    More,
    /// A record length exceeds the TLS maximum: framing is corrupt.
    Malformed,
}

/// Walk records by jumping over each declared length, starting on a record
/// boundary. Stops at the first encrypted (type 23) record — server-side that
/// is the client's Finished, since TLS ordering forbids application data
/// before it. Skips ChangeCipherSpec and any other cleartext record.
fn scan(buf: &[u8]) -> Scan {
    let mut pos = 0;
    loop {
        let rest = &buf[pos..];
        if rest.len() < TLS_HEADER_LEN {
            return Scan::More;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if len > MAX_TLS_CIPHERTEXT {
            return Scan::Malformed;
        }
        let end = pos + TLS_HEADER_LEN + len;
        if end > buf.len() {
            return Scan::More; // record started but not fully present
        }
        if rest[0] == TLS_APPLICATION_DATA {
            return Scan::Finished(end);
        }
        pos = end; // jump: ChangeCipherSpec or other cleartext record
    }
}

impl std::fmt::Debug for Scan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scan::Finished(n) => write!(f, "Finished({n})"),
            Scan::More => f.write_str("More"),
            Scan::Malformed => f.write_str("Malformed"),
        }
    }
}

/// Server-side handshake read that never crosses the client's Finished. Peeks
/// the kernel queue, scans the records, and consumes only up to the Finished
/// (or, before it appears, everything peeked — safe, since no application data
/// can precede a complete Finished). Application data pipelined behind the
/// Finished stays queued for the multishot recv, so kTLS attaches at RX seq 0.
///
/// Peeking into `in_buf.window(filled, ..)` places the kernel's next bytes
/// right after the `filled` bytes already held, so `scan` sees a partial
/// record (in `in_buf`) and its continuation (peeked) as one contiguous run.
/// The real read then re-fetches and consumes exactly those bytes, capped at
/// the Finished boundary — so a record arriving between peek and read can
/// never be pulled in.
async fn recv_bounded(
    socket: &SocketWrapper,
    in_buf: PooledBuf,
    filled: &mut usize,
) -> Result<PooledBuf, HandshakeError> {
    if *filled == RECORD_BUF {
        return Err(HandshakeError::LeftoverBytes);
    }
    let (result, tail) = socket_peek(socket, in_buf.tail(*filled)).await;
    let mut in_buf = tail.into_inner();
    let k = result.map_err(HandshakeError::Io)?;
    if k == 0 {
        return Err(HandshakeError::PeerClosed); // EOF
    }
    let cap = match scan(&in_buf[..*filled + k]) {
        Scan::Finished(n) => n,
        Scan::More => *filled + k, // no Finished yet => no app data => safe
        Scan::Malformed => {
            return Err(HandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed TLS record length during handshake",
            )));
        }
    };
    // `cap` is a byte offset into `in_buf`; consume from `filled` up to it.
    // Guard against a degenerate `cap <= filled` by consuming the peeked run.
    let end = if cap > *filled { cap } else { *filled + k };
    let (result, tail) = socket_recv(socket, in_buf.window(*filled, end)).await;
    in_buf = tail.into_inner();
    let n = result.map_err(HandshakeError::Io)?;
    if n == 0 {
        return Err(HandshakeError::PeerClosed);
    }
    *filled += n;
    Ok(in_buf)
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
    if let Ok(ConnectionState::EncodeTlsData(mut enc)) = state
        && let Ok(n) = enc.encode(&mut out_buf[pending..]) {
            len += n;
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

#[cfg(test)]
mod scan_tests {
    use super::{MAX_TLS_CIPHERTEXT, Scan, scan};

    /// Build a TLS record: 5-byte header (type, legacy version, length) + body.
    fn record(content_type: u8, body_len: usize) -> Vec<u8> {
        let mut r = vec![content_type, 0x03, 0x03];
        r.extend_from_slice(&(body_len as u16).to_be_bytes());
        r.extend(std::iter::repeat_n(0u8, body_len));
        r
    }

    const CCS: u8 = 20;
    const APPDATA: u8 = 23; // encrypted handshake (Finished) or app data on the wire

    #[test]
    fn empty_is_more() {
        assert!(matches!(scan(&[]), Scan::More));
    }

    #[test]
    fn partial_header_is_more() {
        assert!(matches!(scan(&[APPDATA, 0x03, 0x03]), Scan::More));
    }

    #[test]
    fn ccs_alone_is_more() {
        // A complete ChangeCipherSpec with no Finished yet: keep reading.
        assert!(matches!(scan(&record(CCS, 1)), Scan::More));
    }

    #[test]
    fn ccs_then_finished_stops_at_finished_end() {
        let mut buf = record(CCS, 1);
        let ccs_end = buf.len();
        buf.extend(record(APPDATA, 40));
        match scan(&buf) {
            Scan::Finished(n) => assert_eq!(n, ccs_end + 5 + 40),
            other => panic!("expected Finished, got {other:?}"),
        }
    }

    #[test]
    fn finished_without_ccs() {
        let buf = record(APPDATA, 40);
        assert!(matches!(scan(&buf), Scan::Finished(n) if n == 45));
    }

    #[test]
    fn app_data_after_finished_is_left_out() {
        // Finished then a pipelined request, both type 23. scan must stop at
        // the FIRST one so the request stays queued for the kernel.
        let finished = record(APPDATA, 40);
        let finished_end = finished.len();
        let mut buf = finished;
        buf.extend(record(APPDATA, 500)); // the request
        assert!(matches!(scan(&buf), Scan::Finished(n) if n == finished_end));
    }

    #[test]
    fn partial_finished_is_more() {
        // CCS complete, Finished header present but body truncated.
        let mut buf = record(CCS, 1);
        buf.extend(record(APPDATA, 40));
        buf.truncate(buf.len() - 10); // chop the Finished body
        assert!(matches!(scan(&buf), Scan::More));
    }

    #[test]
    fn oversized_length_is_malformed() {
        let mut buf = vec![APPDATA, 0x03, 0x03];
        buf.extend_from_slice(&(MAX_TLS_CIPHERTEXT as u16 + 1).to_be_bytes());
        assert!(matches!(scan(&buf), Scan::Malformed));
    }
}
