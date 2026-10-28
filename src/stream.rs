use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use runtime::io_driver::operations::sockets::multi_recv::{CompletionError, Continuation};
use runtime::io_driver::operations::sockets::recv::{ClassicRecv, socket_recv};
use runtime::io_driver::operations::sockets::send_vectored::send_vectored_all;
use runtime::net::{
    BorrowedBuffer, BufRingSpec, IoBuf, MultiRecv, OwnedReadHalf, OwnedWriteHalf, PooledBuf,
    WriteControlRecord, send_all, socket_send_control_record, socket_write_fixed,
    socket_write_fixed_zc,
};
use runtime_streams::Stream;
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;

use crate::ktls::{
    CLOSE_NOTIFY, ControlAction, KEY_UPDATE_NOT_REQUESTED, KtlsSocket, Prelude,
    TLS_RECORD_TYPE_ALERT, TLS_RECORD_TYPE_HANDSHAKE, handle_control_record, rotate_tx_key,
};

/// A decrypted application-data frame yielded by [`KtlsMessages`].
///
/// `Borrowed` is plaintext decrypted by the kernel via kTLS and delivered
/// through the multishot recv buffer ring. `Owned` is plaintext in a buffer
/// of the stream's own: decrypted by rustls in userspace during the
/// handshake (the leftover-after-Finished case), or by the kernel while the
/// ring had no buffer to lend. Both implement `AsRef<[u8]>`, so callers can
/// treat them uniformly.
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
/// An empty buffer ring, which every connection on the thread draws from, is
/// not one: the stream reads into buffers of its own until the socket has
/// nothing more, then goes back to the ring. Waiting for a buffer instead
/// lost each one to the recvs still armed on other connections, for seconds
/// at a time, and a peer holding the ring's buffers slowed everyone.
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
/// # Splitting
///
/// [`split`](Self::split) hands out a [`KtlsReader`] and a [`KtlsWriter`] for
/// separate tasks on the same thread. All TX stays with the writer: a peer's
/// `request_update` is answered before the writer's next send, as RFC 8446
/// §4.6.3 allows, never from the reader.
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
/// A reply to the peer's `request_update` goes out at the start of our next
/// send. A KeyUpdate from [`initiate_key_update`] lives in the stream, not in
/// the caller's future: if that future is dropped, the next send or
/// `close()` finishes the KeyUpdate and the key rotation before its own work.
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
    reader: KtlsReader<R, S>,
    writer: KtlsWriter<S>,
}

/// The receiving half of a [`KtlsMessages`], from [`split`](KtlsMessages::split).
/// Yields the same items; a peer `request_update` is answered by the
/// [`KtlsWriter`] before its next send.
pub struct KtlsReader<R: BufRingSpec, S = ServerConnectionData> {
    shared: Rc<Shared<S>>,
    /// Plaintext decrypted before the recv was armed; the first frame.
    pending: Option<Vec<u8>>,
    rx: Rx<R>,
    /// A recv into a buffer of our own, while the ring has none to lend.
    /// Only ever between a multishot that ended on the empty ring and the
    /// next one: nothing else reads the socket meanwhile.
    own: Option<ClassicRecv<Vec<u8>>>,
    /// The last one filled its buffer: more is likely waiting in the socket,
    /// to be read the same way rather than through a multishot re-armed into
    /// a ring that may still be empty.
    own_again: bool,
}

/// How much a recv of the reader's own takes: a buffer of the bench rings'
/// size, since a reader that keeps them coming back full reads this way for
/// as long as its peer sends. One at a time, handed out as a frame.
const OWN_RECV: usize = 64 * 1024;

/// The sending half of a [`KtlsMessages`], from [`split`](KtlsMessages::split).
/// Owns every TX operation, including KeyUpdates the peer asked for.
pub struct KtlsWriter<S = ServerConnectionData> {
    shared: Rc<Shared<S>>,
    socket: OwnedWriteHalf,
    /// Our KeyUpdate in flight under the old key; `rotate_tx_key` follows.
    rekey: Option<WriteControlRecord<&'static [u8; 5]>>,
    tx_records: u64,
}

/// What both halves touch. Borrows of `kernel_conn` never cross an await.
struct Shared<S> {
    kernel_conn: RefCell<KernelConnection<S>>,
    alpn: Option<&'static [u8]>,
    /// The peer sent `request_update`; the writer answers before its next send.
    rekey_owed: Cell<bool>,
    tx_closed: Cell<bool>,
}

/// Records a reader may have received and not yet taken before its recv
/// pauses. Each holds a buffer of the ring every connection on the worker
/// shares, however few bytes it carries, and a reader whose task is stalled
/// (in a send to a peer that does not read, say) takes nothing: at the
/// runtime's default of 32, a few such connections empty the ring for every
/// connection on the worker. Paused, the peer's bytes wait in the socket, for
/// TCP to push back with.
const RECV_QUEUE_LIMIT: usize = 4;

fn recv<R: BufRingSpec>(read: OwnedReadHalf) -> MultiRecv<R, OwnedReadHalf> {
    MultiRecv::with_queue_limit(read, RECV_QUEUE_LIMIT)
}

enum Rx<R: BufRingSpec> {
    /// The multishot recv owns the read half while armed.
    Recving(MultiRecv<R, OwnedReadHalf>),
    /// A fatal alert is on its way out; `err` is surfaced once it lands.
    /// `read` keeps the fd alive for the `shutdown` that follows the alert.
    Failing {
        alert: WriteControlRecord<&'static [u8; 2]>,
        read: OwnedReadHalf,
        err: Option<std::io::Error>,
    },
    Closed,
}

impl<R: BufRingSpec, S> Unpin for KtlsReader<R, S> {}

impl<S> KtlsSocket<S> {
    pub fn into_messages<R: BufRingSpec>(self) -> KtlsMessages<R, S> {
        let KtlsSocket {
            socket,
            read_half,
            kernel_conn,
            alpn,
            prelude: Prelude { plaintext, action },
        } = self;
        let shared = Rc::new(Shared {
            kernel_conn: RefCell::new(kernel_conn),
            alpn,
            rekey_owed: Cell::new(false),
            tx_closed: Cell::new(false),
        });
        let mut reader = KtlsReader {
            shared: shared.clone(),
            pending: plaintext,
            rx: Rx::Closed,
            own: None,
            own_again: false,
        };
        // TX is open here, so `apply` never has an error to hand back.
        let _ = reader.apply(read_half, action);
        KtlsMessages {
            reader,
            writer: KtlsWriter {
                shared,
                socket,
                rekey: None,
                tx_records: 0,
            },
        }
    }
}

fn write_closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotConnected, "TLS write side closed")
}

impl<R: BufRingSpec, S> KtlsMessages<R, S> {
    /// Split into a reader and a writer that can live in different tasks on
    /// this thread. The fd closes once both are dropped.
    pub fn split(self) -> (KtlsReader<R, S>, KtlsWriter<S>) {
        (self.reader, self.writer)
    }

    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.writer.alpn()
    }

    pub fn tx_records(&self) -> u64 {
        self.writer.tx_records()
    }

    pub fn state(&self) -> StreamState {
        match (self.reader.is_open(), self.writer.is_open()) {
            (true, true) => StreamState::Open,
            (true, false) => StreamState::ReadOnly,
            (false, true) => StreamState::WriteOnly,
            (false, false) => StreamState::Closed,
        }
    }

    /// See [`KtlsWriter::initiate_key_update`].
    pub async fn initiate_key_update(&mut self) -> std::io::Result<()> {
        self.writer.initiate_key_update().await
    }

    /// Close our side: send `close_notify`, then `shutdown(SHUT_WR)`. The
    /// stream moves to `ReadOnly` (or `Closed` if the peer's side was already
    /// closed); `next()` keeps working. Idempotent.
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.writer.close().await
    }

    /// See [`KtlsWriter::send`].
    pub async fn send<B: IoBuf>(&mut self, buf: B) -> (std::io::Result<()>, B) {
        self.writer.send(buf).await
    }

    /// See [`KtlsWriter::send_vectored`].
    pub async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (std::io::Result<()>, Vec<B>) {
        self.writer.send_vectored(bufs).await
    }

    /// See [`KtlsWriter::send_fixed_zc`].
    pub async fn send_fixed_zc(&mut self, buf: PooledBuf) -> (std::io::Result<usize>, PooledBuf) {
        self.writer.send_fixed_zc(buf).await
    }

    /// See [`KtlsWriter::send_fixed`].
    pub async fn send_fixed(&mut self, buf: PooledBuf) -> (std::io::Result<usize>, PooledBuf) {
        self.writer.send_fixed(buf).await
    }
}

impl<R: BufRingSpec, S> Stream for KtlsMessages<R, S> {
    type Item = std::io::Result<Frame<R>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.reader).poll_next(cx)
    }
}

impl<R: BufRingSpec, S> KtlsReader<R, S> {
    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.shared.alpn
    }

    /// Whether the peer's side is still open: `false` once `next()` has
    /// yielded `None` or a fatal error.
    pub fn is_open(&self) -> bool {
        matches!(self.rx, Rx::Recving(_))
    }

    /// React to a control record read off the socket. `read` is the read
    /// half handed back by the terminated multishot. Returns an error to
    /// surface right away when no alert can be sent.
    fn apply(&mut self, read: OwnedReadHalf, action: ControlAction) -> Option<std::io::Error> {
        match action {
            ControlAction::Continue => self.rx = Rx::Recving(recv(read)),
            ControlAction::End => self.rx = Rx::Closed,
            ControlAction::SendFatal { err, .. } if self.shared.tx_closed.get() => {
                self.rx = Rx::Closed;
                return Some(err);
            }
            ControlAction::SendFatal { payload, err } => {
                self.shared.tx_closed.set(true);
                self.rx = Rx::Failing {
                    alert: socket_send_control_record(
                        read.socket(),
                        TLS_RECORD_TYPE_ALERT,
                        payload,
                    ),
                    read,
                    err: Some(err),
                };
            }
            ControlAction::SendKeyUpdate => {
                self.shared.rekey_owed.set(true);
                self.rx = Rx::Recving(recv(read));
            }
        }
        None
    }

    fn fail(&mut self, err: std::io::Error) -> Poll<Option<std::io::Result<Frame<R>>>> {
        self.rx = Rx::Closed;
        self.shared.tx_closed.set(true);
        Poll::Ready(Some(Err(err)))
    }

    /// `EIO`: the next record is not application data. The multishot is over
    /// (it ended on it, or on the empty ring before a recv of our own met
    /// it), so its read half is free to read the record and apply it.
    /// Returns an error to surface right away.
    fn on_control_record(&mut self) -> Option<std::io::Error> {
        let Rx::Recving(old) = std::mem::replace(&mut self.rx, Rx::Closed) else {
            unreachable!("only a receiving stream reads records")
        };
        let read = old.into_inner();
        let action = handle_control_record(
            read.socket().fd(),
            &mut self.shared.kernel_conn.borrow_mut(),
        );
        match action {
            Ok(action) => self.apply(read, action),
            Err(e) => Some(e),
        }
    }

    fn read_own(&mut self) {
        let Rx::Recving(recv) = &self.rx else {
            unreachable!("only a receiving stream reads")
        };
        let buf = Vec::with_capacity(OWN_RECV);
        self.own = Some(socket_recv(recv.socket(), buf));
    }
}

impl<R: BufRingSpec, S> Stream for KtlsReader<R, S> {
    type Item = std::io::Result<Frame<R>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(buf) = this.pending.take() {
            return Poll::Ready(Some(Ok(Frame::Owned(buf))));
        }

        loop {
            match &mut this.rx {
                Rx::Closed => return Poll::Ready(None),
                Rx::Failing { alert, read, err } => {
                    // Best-effort: the original error is surfaced either way.
                    let _ = std::task::ready!(Pin::new(alert).poll(cx));
                    // Nothing may follow a fatal alert (RFC 8446 §6.2): fail
                    // any send the writer still has in flight.
                    unsafe { libc::shutdown(read.socket().fd(), libc::SHUT_WR) };
                    let e = err
                        .take()
                        .unwrap_or_else(|| std::io::Error::other("fatal alert sent"));
                    this.rx = Rx::Closed;
                    return Poll::Ready(Some(Err(e)));
                }
                Rx::Recving(_) if this.own.is_some() => {
                    let own = this.own.as_mut().expect("checked");
                    let (result, buf) = std::task::ready!(Pin::new(own).poll(cx));
                    this.own = None;
                    match result {
                        Ok(0) => {
                            this.rx = Rx::Closed;
                            return Poll::Ready(None);
                        }
                        Ok(n) => {
                            this.own_again = n == OWN_RECV;
                            return Poll::Ready(Some(Ok(Frame::Owned(buf))));
                        }
                        // A control record next, read as the multishot's are.
                        Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                            this.own_again = false;
                            if let Some(e) = this.on_control_record() {
                                return Poll::Ready(Some(Err(e)));
                            }
                        }
                        Err(e) if e.raw_os_error() == Some(libc::EBADMSG) => {
                            return this.fail(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "kTLS: record failed AEAD verification (EBADMSG)",
                            ));
                        }
                        Err(e) => return this.fail(e),
                    }
                }
                Rx::Recving(_) if this.own_again => this.read_own(),
                Rx::Recving(recv) => match std::task::ready!(Pin::new(recv).poll_next(cx)) {
                    None => {
                        this.rx = Rx::Closed;
                        return Poll::Ready(None);
                    }
                    Some(Ok(buf)) => return Poll::Ready(Some(Ok(Frame::Borrowed(buf)))),
                    Some(Err(CompletionError::Other(code))) if code == -libc::EIO => {
                        if let Some(e) = this.on_control_record() {
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                    Some(Err(CompletionError::Other(code))) if code == -libc::EBADMSG => {
                        // AEAD failure: kTLS set sk_err, so no alert can be sent.
                        return this.fail(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "kTLS: record failed AEAD verification (EBADMSG)",
                        ));
                    }
                    // The ring was empty, not the connection, and waiting for
                    // a buffer to come back lost each one to the recvs still
                    // armed on other connections, for seconds at a time. The
                    // multishot ended on it (`ContinueLater`), so nothing
                    // else reads the socket until it is re-armed: read into a
                    // buffer of our own meanwhile, and go on so while those
                    // come back full. One that comes back short drained the
                    // socket, and the multishot is re-armed for what follows.
                    Some(Err(e)) if matches!(e.continuation(), Continuation::ContinueLater) => {
                        this.read_own();
                    }
                    Some(Err(e)) => return this.fail(completion_to_io(e)),
                },
            }
        }
    }
}

impl<S> KtlsWriter<S> {
    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.shared.alpn
    }

    pub fn tx_records(&self) -> u64 {
        self.tx_records
    }

    /// Whether our side is still open: `false` after [`close`](Self::close),
    /// a failed send or rekey, or a fatal error on the reader.
    pub fn is_open(&self) -> bool {
        !self.shared.tx_closed.get()
    }

    fn start_rekey(&mut self) {
        self.shared.rekey_owed.set(false);
        self.rekey = Some(socket_send_control_record(
            self.socket.socket(),
            TLS_RECORD_TYPE_HANDSHAKE,
            &KEY_UPDATE_NOT_REQUESTED,
        ));
    }

    fn poll_rekey(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(send) = &mut self.rekey else {
            return Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(Pin::new(send).poll(cx));
        self.rekey = None;
        let result = result.and_then(|_| {
            rotate_tx_key(
                self.socket.socket().fd(),
                &mut self.shared.kernel_conn.borrow_mut(),
            )
        });
        match result {
            Ok(()) => self.tx_records = 0,
            Err(_) => self.shared.tx_closed.set(true),
        }
        Poll::Ready(result)
    }

    /// Finish a KeyUpdate left in flight, then rotate the key.
    async fn finish_rekey(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| self.poll_rekey(cx)).await
    }

    /// Finish any KeyUpdate in flight and fail if our side is closed.
    async fn settle(&mut self) -> std::io::Result<()> {
        self.finish_rekey().await?;
        match self.shared.tx_closed.get() {
            true => Err(write_closed()),
            false => Ok(()),
        }
    }

    async fn ready_to_send(&mut self) -> std::io::Result<()> {
        self.settle().await?;
        if self.shared.rekey_owed.get() {
            self.start_rekey();
            self.finish_rekey().await?;
        }
        Ok(())
    }

    /// Rotate our TX key: send a KeyUpdate over kTLS, then install the next
    /// sending key. The KeyUpdate goes out under the old key, as RFC 8446
    /// §4.6.3 requires, before the rotation. Cancel-safe: see the
    /// "Key updates" section on [`KtlsMessages`].
    pub async fn initiate_key_update(&mut self) -> std::io::Result<()> {
        self.settle().await?;
        self.start_rekey();
        self.finish_rekey().await
    }

    /// Close our side: send `close_notify`, then `shutdown(SHUT_WR)`. The
    /// reader keeps working. Idempotent.
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.finish_rekey().await?;
        if self.shared.tx_closed.get() {
            return Ok(());
        }
        self.shared.tx_closed.set(true);
        socket_send_control_record(self.socket.socket(), TLS_RECORD_TYPE_ALERT, &CLOSE_NOTIFY)
            .await?;
        if unsafe { libc::shutdown(self.socket.socket().fd(), libc::SHUT_WR) } < 0 {
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
        let (result, buf) = send_all(self.socket.socket(), buf).await;
        if result.is_ok() {
            self.tx_records += (buf.bytes_init() as u64).div_ceil(16384);
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
        let (result, bufs) = send_vectored_all(self.socket.socket(), bufs).await;
        if result.is_ok() {
            let total: usize = bufs.iter().map(|b| b.bytes_init()).sum();
            self.tx_records += (total as u64).div_ceil(16384);
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
        let (result, buf) = socket_write_fixed_zc(self.socket.socket(), buf).await;
        if result.is_ok() {
            self.tx_records += (buf.len() as u64).div_ceil(16384);
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
        let (result, buf) = socket_write_fixed(self.socket.socket(), buf).await;
        if result.is_ok() {
            self.tx_records += (buf.len() as u64).div_ceil(16384);
        }
        (result, buf)
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
