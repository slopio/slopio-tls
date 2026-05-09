use std::pin::Pin;
use std::task::{Context, Poll};

use runtime::io_driver::operations::sockets::multi_recv::CompletionError;
use runtime::net::{BorrowedBuffer, BufGroup, MultiRecv, socket_send};
use runtime_streams::Stream;

use crate::ktls::{ControlOutcome, KtlsSocket};

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
