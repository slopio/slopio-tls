use std::pin::Pin;
use std::task::{Context, Poll};

use runtime::io_driver::operations::sockets::multi_recv::CompletionError;
use runtime::net::{BorrowedBuffer, BufGroup, MultiRecv, socket_send};
use runtime_streams::Stream;

use crate::ktls::{ControlOutcome, KtlsSocket};

/// A decrypted application-data frame yielded by [`KtlsMessages`].
///
/// `Owned` is plaintext that was decrypted by rustls in userspace during the
/// handshake (the leftover-after-Finished case). `Borrowed` is plaintext
/// decrypted by the kernel via kTLS and delivered through the multishot recv
/// buffer ring. Both implement `AsRef<[u8]>`, so callers can treat them
/// uniformly.
pub enum Frame {
    Owned(Vec<u8>),
    Borrowed(BorrowedBuffer),
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        match self {
            Frame::Owned(v) => v.as_ref(),
            Frame::Borrowed(b) => b.as_ref(),
        }
    }
}

/// A Stream of decrypted application-data frames over a kTLS-enabled socket.
///
/// Yields [`Frame`] items: kernel-decrypted records (the common case) plus any
/// pending plaintext that came from the handshake leftover (the very first
/// item, if the client coalesced its first request with the Finished record).
/// `None` indicates the stream has ended. `Err` items signal transport-level
/// failures (RST, etc.).
///
/// TLS 1.3 control records (KeyUpdate, post-handshake alerts) are handled
/// internally: KeyUpdate causes transparent re-keying and stream continuation;
/// close_notify and fatal alerts cause the stream to end (`None`).
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
pub struct KtlsMessages {
    ktls: KtlsSocket,
    bgid: BufGroup,
    state: State,
}

enum State {
    Recving(MultiRecv),
    Done,
}

impl Unpin for KtlsMessages {}

impl KtlsSocket {
    pub fn into_messages(self, bgid: BufGroup) -> KtlsMessages {
        let recv = MultiRecv::new(self.fd(), bgid);
        KtlsMessages {
            ktls: self,
            bgid,
            state: State::Recving(recv),
        }
    }
}

impl KtlsMessages {
    pub fn alpn(&self) -> Option<&[u8]> {
        self.ktls.alpn()
    }

    pub fn tx_records(&self) -> u64 {
        self.ktls.tx_records()
    }

    pub fn initiate_key_update(&mut self) -> std::io::Result<()> {
        self.ktls.initiate_key_update()
    }

    pub async fn send(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let n = socket_send(self.ktls.as_socket(), data).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "send returned 0",
                ));
            }
            self.ktls.tx_records += n.div_ceil(16384) as u64;
            data = &data[n..];
        }
        Ok(())
    }
}

impl Stream for KtlsMessages {
    type Item = std::io::Result<Frame>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(buf) = this.ktls.pending_plaintext.take() {
            return Poll::Ready(Some(Ok(Frame::Owned(buf))));
        }

        loop {
            match &mut this.state {
                State::Done => return Poll::Ready(None),
                State::Recving(recv) => match Pin::new(recv).poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        this.state = State::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Some(Ok(buf))) => {
                        return Poll::Ready(Some(Ok(Frame::Borrowed(buf))));
                    }
                    Poll::Ready(Some(Err(CompletionError::Other(code))))
                        if code == -libc::EIO =>
                    {
                        this.state = State::Done;
                        match this.ktls.handle_control_record() {
                            Ok(ControlOutcome::KeyUpdate) => {
                                let recv = MultiRecv::new(this.ktls.fd(), this.bgid);
                                this.state = State::Recving(recv);
                            }
                            Ok(ControlOutcome::Eof) | Ok(ControlOutcome::Alert { .. }) => {
                                return Poll::Ready(None);
                            }
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        this.state = State::Done;
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
