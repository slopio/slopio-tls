use std::pin::Pin;
use std::task::{Context, Poll};

use runtime::io_driver::operations::sockets::multi_recv::CompletionError;
use runtime::io_driver::operations::sockets::send_vectored::send_vectored_all;
use runtime::net::{
    BorrowedBuffer, BufRingSpec, IoBuf, MultiRecv, OwnedReadHalf, PooledBuf, WriteControlRecord,
    send_all, socket_send_control_record, socket_write_fixed, socket_write_fixed_zc,
};
use runtime_streams::Stream;
use rustls::server::ServerConnectionData;

use crate::ktls::{
    CLOSE_NOTIFY, ControlAction, KEY_UPDATE_NOT_REQUESTED, KtlsSocket, Prelude,
    TLS_RECORD_TYPE_ALERT, TLS_RECORD_TYPE_HANDSHAKE,
};

/// A decrypted application-data frame yielded by [`KtlsMessages`].
///
/// `Owned` is plaintext that was decrypted by rustls in userspace during the
/// handshake (the leftover-after-Finished case). `Borrowed` is plaintext
/// decrypted by the kernel via kTLS and delivered through the multishot recv
/// buffer ring. Both implement `AsRef<[u8]>`, so callers can treat them
/// uniformly.
#[non_exhaustive]
pub enum Frame<R: BufRingSpec> {
    Owned(Vec<u8>),
    Borrowed(BorrowedBuffer<R>),
}

impl<R: BufRingSpec> AsRef<[u8]> for Frame<R> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Frame::Owned(v) => v.as_ref(),
            Frame::Borrowed(b) => b.as_ref(),
        }
    }
}

/// Which directions of the TLS session are still open. See
/// [`KtlsMessages::state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    /// Both directions open.
    Open,
    /// We sent `close_notify` (or lost the write side); the peer may still
    /// send and `next()` keeps yielding.
    ReadOnly,
    /// The peer ended its side (`close_notify`, `FIN` or an alert); we may
    /// still send, and `next()` yields `None`.
    WriteOnly,
    /// Both directions closed.
    Closed,
}

/// A Stream of decrypted application-data frames over a kTLS-enabled socket.
///
/// Yields [`Frame`] items: kernel-decrypted records (the common case) plus any
/// pending plaintext that came from the handshake leftover (the very first
/// item, if the client coalesced its first request with the Finished record).
/// `None` indicates the stream has ended. `Err` items signal transport-level
/// failures (RST, etc.).
///
/// TLS 1.3 control records are handled internally:
/// - **KeyUpdate**: transparent re-keying; the stream keeps yielding frames.
/// - **Peer alert** (close_notify or any other, since TLS 1.3 treats every
///   non-close_notify alert as fatal per RFC 8446 §6): the stream ends with
///   `None`. No reciprocal alert is sent — the peer initiated the close.
/// - **Local-side protocol violation** (malformed control record): a fatal
///   alert is sent over kTLS before the stream surfaces `Some(Err(_))`.
/// - **AEAD verification failure** (`EBADMSG`): no alert can be sent, the
///   socket is already in error. The stream yields `Some(Err(_))` with
///   `ErrorKind::InvalidData`, then `None`; the peer sees a TCP RST.
///
/// # Session state
///
/// [`state`](Self::state) reports which directions are open. `next()` yields
/// `None` once the peer's side is closed; the send methods fail with
/// `ErrorKind::NotConnected` once ours is. [`close`](Self::close) closes our
/// side cleanly (close_notify, then FIN); keep polling `next()` afterwards
/// until `None` if the protocol expects the peer to finish talking. Dropping
/// the stream closes the fd without close_notify.
///
/// # Key updates
///
/// Key updates are the caller's responsibility; nothing here rekeys on a
/// record-count threshold. The one rule: a record must never be encrypted
/// under the old key after the KeyUpdate that announces the new one. The
/// kernel does not enforce it, and with io_uring a send is encrypted when
/// its SQE runs, not when it is submitted. So do not call a send method, or
/// [`initiate_key_update`], while a send you dropped before completion may
/// still be in flight.
///
/// KeyUpdates the stream sends itself (a reply to the peer's
/// `request_update`, or [`initiate_key_update`]) live in the stream, not in
/// the caller's future: if that future is dropped, the next `send`, `next()`
/// or `close()` finishes the KeyUpdate and the key rotation before its own
/// work.
///
/// [`initiate_key_update`]: Self::initiate_key_update
///
/// # Truncation detection
///
/// This Stream **does not distinguish** between three different ways the
/// peer's side can end:
///
/// 1. The peer sent a TLS `close_notify` alert (the proper TLS shutdown
///    signal). The Stream yields `None`.
/// 2. The peer closed the TCP socket without sending `close_notify` (clean
///    FIN, but no TLS-layer end-of-stream signal). The Stream also yields
///    `None`.
/// 3. The connection was reset (TCP `RST`, possibly attacker-injected). The
///    Stream yields `Some(Err(ConnectionReset))` then ends.
///
/// In particular, cases (1) and (2) look identical to the caller. This is the
/// classic **TLS truncation attack** surface: a network attacker who can drop
/// TCP packets or inject a `RST` *between* the last legitimate application
/// record and a `close_notify` can make case (1) look like case (2). The
/// receiver thinks the peer ended the conversation cleanly when in reality the
/// stream was cut short.
///
/// Whether this matters depends entirely on the **application protocol on top
/// of TLS**:
///
/// - **Length-framed protocols** (HTTP/1.1 with `Content-Length` or chunked,
///   HTTP/2, HTTP/3, WebSockets, gRPC, any protocol where each message is
///   length-prefixed) are protected at the application layer. A truncated
///   stream just means an incomplete message, which the protocol parser
///   detects and rejects on its own. The Stream not distinguishing (1) from
///   (2) is harmless here.
///
/// - **Stream-without-framing** protocols (HTTP/1.0 with `Connection: close`,
///   raw bidirectional binary streams, anything that uses "the socket closed"
///   as the end-of-message signal) are **vulnerable**. An attacker can
///   truncate the last response or message and the receiver has no way to
///   detect it from this Stream API alone.
///
/// ## Recommendation
///
/// **Use a protocol with its own end-of-message framing.** Length-prefix your
/// messages, or use HTTP/2+, WebSockets, or similar. This is the right fix
/// regardless of TLS — truncation resistance becomes a property of the
/// application protocol rather than depending on lower-level TLS hygiene that
/// implementations have historically gotten wrong.
///
/// ## If you must detect truncation here
///
/// This crate does not currently surface the close_notify vs. plain-FIN
/// distinction. To add it, the Stream would need to expose either a separate
/// error variant (e.g., `io::ErrorKind::UnexpectedEof` for case 2) or a
/// post-end query method (`ended_gracefully() -> bool`). Neither is currently
/// implemented because the application-level fix above is strictly better.
pub struct KtlsMessages<R: BufRingSpec, S = ServerConnectionData> {
    ktls: KtlsSocket<S>,
    /// Plaintext decrypted before the recv was armed; the first frame.
    pending: Option<Vec<u8>>,
    rx: Rx<R>,
    tx: Tx,
}

enum Rx<R: BufRingSpec> {
    /// The multishot recv owns the read half while armed.
    Recving(MultiRecv<R, OwnedReadHalf>),
    /// Recv terminated (EIO) while `tx` answers a peer KeyUpdate; re-armed
    /// once the rotation is done.
    Paused(OwnedReadHalf),
    /// A fatal alert is on its way out; `err` is surfaced once it lands.
    Failing {
        alert: WriteControlRecord<'static>,
        err: Option<std::io::Error>,
    },
    Closed,
}

enum Tx {
    Idle,
    /// Our KeyUpdate is in flight under the old key; `rotate_tx_key` follows.
    Rekeying(WriteControlRecord<'static>),
    Closed,
}

impl<R: BufRingSpec, S> Unpin for KtlsMessages<R, S> {}

impl<S> KtlsSocket<S> {
    pub fn into_messages<R: BufRingSpec>(mut self) -> KtlsMessages<R, S> {
        let Prelude { plaintext, action } = std::mem::take(&mut self.prelude);
        let read_half = self
            .read_half
            .take()
            .expect("read half is only taken by into_messages");
        let mut stream = KtlsMessages {
            ktls: self,
            pending: plaintext,
            rx: Rx::Closed,
            tx: Tx::Idle,
        };
        // `tx` is Idle here, so `apply` never has an error to hand back.
        let _ = stream.apply(read_half, action);
        stream
    }
}

fn write_closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotConnected, "TLS write side closed")
}

impl<R: BufRingSpec, S> KtlsMessages<R, S> {
    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.ktls.alpn()
    }

    pub fn tx_records(&self) -> u64 {
        self.ktls.tx_records()
    }

    pub fn state(&self) -> StreamState {
        let rx_open = matches!(self.rx, Rx::Recving(_) | Rx::Paused(_));
        let tx_open = !matches!(self.tx, Tx::Closed);
        match (rx_open, tx_open) {
            (true, true) => StreamState::Open,
            (true, false) => StreamState::ReadOnly,
            (false, true) => StreamState::WriteOnly,
            (false, false) => StreamState::Closed,
        }
    }

    /// React to a control record read off the socket. `read` is the read
    /// half handed back by the terminated multishot. Returns an error to
    /// surface right away when no alert can be sent.
    fn apply(&mut self, read: OwnedReadHalf, action: ControlAction) -> Option<std::io::Error> {
        match action {
            ControlAction::Continue => self.rx = Rx::Recving(MultiRecv::new(read)),
            ControlAction::End => self.rx = Rx::Closed,
            ControlAction::SendFatal { err, .. } if matches!(self.tx, Tx::Closed) => {
                self.rx = Rx::Closed;
                return Some(err);
            }
            ControlAction::SendFatal { payload, err } => {
                self.tx = Tx::Closed;
                self.rx = Rx::Failing {
                    alert: socket_send_control_record(
                        self.ktls.as_socket(),
                        TLS_RECORD_TYPE_ALERT,
                        payload,
                    ),
                    err: Some(err),
                };
            }
            // RX is already rekeyed; after our close_notify we may not reply.
            ControlAction::SendKeyUpdate if matches!(self.tx, Tx::Closed) => {
                self.rx = Rx::Recving(MultiRecv::new(read));
            }
            ControlAction::SendKeyUpdate => {
                self.rx = Rx::Paused(read);
                self.tx = Tx::Rekeying(socket_send_control_record(
                    self.ktls.as_socket(),
                    TLS_RECORD_TYPE_HANDSHAKE,
                    &KEY_UPDATE_NOT_REQUESTED,
                ));
            }
        }
        None
    }

    fn poll_rekey(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Tx::Rekeying(send) = &mut self.tx else {
            return Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(Pin::new(send).poll(cx));
        self.tx = Tx::Idle;
        let result = result.and_then(|_| self.ktls.rotate_tx_key());
        if result.is_err() {
            self.tx = Tx::Closed;
        }
        Poll::Ready(result)
    }

    /// Finish a KeyUpdate left in flight, then rotate the key.
    async fn finish_rekey(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| self.poll_rekey(cx)).await
    }

    async fn ready_to_send(&mut self) -> std::io::Result<()> {
        self.finish_rekey().await?;
        match self.tx {
            Tx::Closed => Err(write_closed()),
            _ => Ok(()),
        }
    }

    /// Rotate our TX key: send a KeyUpdate over kTLS, then install the next
    /// sending key. The KeyUpdate goes out under the old key, as RFC 8446
    /// §4.6.3 requires, before the rotation. Cancel-safe: see the type-level
    /// "Key updates" section.
    pub async fn initiate_key_update(&mut self) -> std::io::Result<()> {
        self.ready_to_send().await?;
        self.tx = Tx::Rekeying(socket_send_control_record(
            self.ktls.as_socket(),
            TLS_RECORD_TYPE_HANDSHAKE,
            &KEY_UPDATE_NOT_REQUESTED,
        ));
        self.finish_rekey().await
    }

    /// Close our side: send `close_notify`, then `shutdown(SHUT_WR)`. The
    /// stream moves to `ReadOnly` (or `Closed` if the peer's side was already
    /// closed); `next()` keeps working. Idempotent.
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.finish_rekey().await?;
        if matches!(self.tx, Tx::Closed) {
            return Ok(());
        }
        self.tx = Tx::Closed;
        socket_send_control_record(self.ktls.as_socket(), TLS_RECORD_TYPE_ALERT, &CLOSE_NOTIFY)
            .await?;
        if unsafe { libc::shutdown(self.ktls.fd(), libc::SHUT_WR) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send the entire plaintext buffer over the kTLS socket, looping over
    /// short writes internally. The buffer is handed back alongside the result
    /// so the caller keeps their allocation regardless of success or failure.
    ///
    /// Takes ownership of `buf` because io_uring may keep reading from it after
    /// the future is dropped (cancel-safety). Callers with `&[u8]` should
    /// `.to_vec()` at the boundary; callers with `&'static [u8]` /
    /// `&'static [u8; N]` can pass them directly (no allocation).
    pub async fn send<B: IoBuf>(&mut self, buf: B) -> (std::io::Result<()>, B) {
        if let Err(e) = self.ready_to_send().await {
            return (Err(e), buf);
        }
        let (result, buf) = send_all(self.ktls.as_socket(), buf).await;
        if result.is_ok() {
            self.ktls.tx_records += (buf.bytes_init() as u64).div_ceil(16384);
        }
        (result, buf)
    }

    /// Gather-write the supplied plaintext chunks into the kTLS socket.
    ///
    /// The kernel packs the concatenated plaintext into TLS 1.3 records (up
    /// to 16 384 bytes of plaintext each) before encrypting and emitting them
    /// on the wire, so a vectored send is the cheapest way to coalesce
    /// scattered buffers into the minimum number of records.
    ///
    /// Takes ownership of `bufs` for io_uring cancel-safety; the `Vec` is
    /// handed back alongside the result.
    pub async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (std::io::Result<()>, Vec<B>) {
        if let Err(e) = self.ready_to_send().await {
            return (Err(e), bufs);
        }
        let (result, bufs) = send_vectored_all(self.ktls.as_socket(), bufs).await;
        if result.is_ok() {
            let total: usize = bufs.iter().map(|b| b.bytes_init()).sum();
            self.ktls.tx_records += (total as u64).div_ceil(16384);
        }
        (result, bufs)
    }

    /// Zero-copy send of a registered (fixed) buffer over the kTLS socket.
    ///
    /// `buf` comes from the runtime's `FixedSendBufPool`, so the kernel can transmit it
    /// without copying into its own send buffers (`SEND_ZC`). The buffer is
    /// handed back alongside the result for cancel-safety, just like [`send`].
    ///
    /// [`send`]: Self::send
    pub async fn send_fixed_zc(&mut self, buf: PooledBuf) -> (std::io::Result<usize>, PooledBuf) {
        if let Err(e) = self.ready_to_send().await {
            return (Err(e), buf);
        }
        let (result, buf) = socket_write_fixed_zc(self.ktls.as_socket(), buf).await;
        if result.is_ok() {
            self.ktls.tx_records += (buf.len() as u64).div_ceil(16384);
        }
        (result, buf)
    }

    /// Send a registered (fixed) buffer over the kTLS socket without the
    /// zero-copy `SEND_ZC` path. The buffer still avoids the fixed-buffer
    /// registration cost; the kernel copies it into its send buffers as usual.
    ///
    /// The buffer is handed back alongside the result for cancel-safety.
    pub async fn send_fixed(&mut self, buf: PooledBuf) -> (std::io::Result<usize>, PooledBuf) {
        if let Err(e) = self.ready_to_send().await {
            return (Err(e), buf);
        }
        let (result, buf) = socket_write_fixed(self.ktls.as_socket(), buf).await;
        if result.is_ok() {
            self.ktls.tx_records += (buf.len() as u64).div_ceil(16384);
        }
        (result, buf)
    }
}

impl<R: BufRingSpec, S> Stream for KtlsMessages<R, S> {
    type Item = std::io::Result<Frame<R>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(buf) = this.pending.take() {
            return Poll::Ready(Some(Ok(Frame::Owned(buf))));
        }

        loop {
            if let Err(e) = std::task::ready!(this.poll_rekey(cx)) {
                this.rx = Rx::Closed;
                return Poll::Ready(Some(Err(e)));
            }
            match &mut this.rx {
                Rx::Closed => return Poll::Ready(None),
                Rx::Paused(_) => {
                    let Rx::Paused(read) = std::mem::replace(&mut this.rx, Rx::Closed) else {
                        unreachable!()
                    };
                    this.rx = Rx::Recving(MultiRecv::new(read));
                }
                Rx::Failing { alert, err } => {
                    // Best-effort: the original error is surfaced either way.
                    let _ = std::task::ready!(Pin::new(alert).poll(cx));
                    let e = err
                        .take()
                        .unwrap_or_else(|| std::io::Error::other("fatal alert sent"));
                    this.rx = Rx::Closed;
                    return Poll::Ready(Some(Err(e)));
                }
                Rx::Recving(recv) => match std::task::ready!(Pin::new(recv).poll_next(cx)) {
                    None => {
                        this.rx = Rx::Closed;
                        return Poll::Ready(None);
                    }
                    Some(Ok(buf)) => return Poll::Ready(Some(Ok(Frame::Borrowed(buf)))),
                    Some(Err(CompletionError::Other(code))) if code == -libc::EIO => {
                        let Rx::Recving(old) = std::mem::replace(&mut this.rx, Rx::Closed) else {
                            unreachable!()
                        };
                        let read = old.into_inner();
                        match this.ktls.handle_control_record() {
                            Ok(action) => {
                                if let Some(e) = this.apply(read, action) {
                                    return Poll::Ready(Some(Err(e)));
                                }
                            }
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        }
                    }
                    Some(Err(CompletionError::Other(code))) if code == -libc::EBADMSG => {
                        // AEAD failure: kTLS set sk_err, so no alert can be sent.
                        this.rx = Rx::Closed;
                        this.tx = Tx::Closed;
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "kTLS: record failed AEAD verification (EBADMSG)",
                        ))));
                    }
                    Some(Err(e)) => {
                        this.rx = Rx::Closed;
                        this.tx = Tx::Closed;
                        return Poll::Ready(Some(Err(completion_to_io(e))));
                    }
                },
            }
        }
    }
}

fn completion_to_io(e: CompletionError) -> std::io::Error {
    match e {
        CompletionError::ConnectionReset => {
            std::io::Error::from(std::io::ErrorKind::ConnectionReset)
        }
        CompletionError::BrokenPipe => std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        CompletionError::Cancelled => std::io::Error::from(std::io::ErrorKind::Interrupted),
        CompletionError::Eof { .. } => std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
        CompletionError::Other(code) => std::io::Error::from_raw_os_error(-code),
    }
}
