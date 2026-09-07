use runtime::net::{OwnedReadHalf, OwnedWriteHalf, SocketWrapper};
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets};

use crate::pool::PooledBuf;

pub struct KtlsSocket<S = ServerConnectionData> {
    /// Write half of the connection. Also the handle we use for the fd
    /// (sync `recvmsg`/`setsockopt` and async sends).
    socket: OwnedWriteHalf,
    /// Read half, `Some` until `into_messages` hands it to the `MultiRecv`,
    /// which owns it for as long as the multishot recv is armed.
    pub(crate) read_half: Option<OwnedReadHalf>,
    pub(crate) kernel_conn: KernelConnection<S>,
    pub(crate) alpn: Option<&'static [u8]>,
    /// What the software handshake left for the stream. Taken by
    /// `into_messages`, which extends it with the kernel-queue drain.
    pub(crate) prelude: Prelude,
    pub(crate) tx_records: u64,
}

/// Everything the receive side saw *before* a recv could be armed, as a
/// value. Two phases produce one: the software handshake (records rustls
/// decrypted after Finished) and the post-attach kernel-queue drain. Since
/// those phases consume any close_notify or protocol violation they meet,
/// the resulting `action` is the only record of it. `into_messages` picks
/// the stream constructor from it: `KtlsMessages::open` on `Continue`,
/// `KtlsMessages::closed` on `End`, and the fatal-alert path on `SendFatal`.
#[derive(Debug)]
pub(crate) struct Prelude {
    /// Application data decrypted before any recv existed. Yielded as the
    /// first frame (`Frame::Owned`).
    pub plaintext: Option<Vec<u8>>,
    /// How the receive side stands after that data: `Continue` (arm a
    /// recv), `End` (peer closed) or `SendFatal` (violation to report).
    pub action: ControlAction,
}

impl Prelude {
    /// Session still open after `plaintext`.
    pub fn open(plaintext: Option<Vec<u8>>) -> Self {
        Self {
            plaintext,
            action: ControlAction::Continue,
        }
    }

    /// Peer sent close_notify (or EOF) after `plaintext`.
    pub fn closed(plaintext: Option<Vec<u8>>) -> Self {
        Self {
            plaintext,
            action: ControlAction::End,
        }
    }

    pub fn peer_closed(&self) -> bool {
        matches!(self.action, ControlAction::End)
    }
}

impl Default for Prelude {
    fn default() -> Self {
        Self::open(None)
    }
}

/// Result of inspecting a control record delivered via the kTLS recvmsg cmsg
/// path. The caller (the `KtlsMessages` state machine) decides what to do
/// next; this enum carries no I/O of its own.
#[derive(Debug)]
pub(crate) enum ControlAction {
    /// A valid KeyUpdate was processed (RX rekeyed, optional TX rekey already
    /// emitted via the synchronous `initiate_key_update` path). Continue
    /// receiving on the same socket.
    Continue,
    /// Peer ended the stream cleanly (close_notify alert, any other alert
    /// — RFC 8446 §6 treats all non-close_notify alerts as fatal — or zero-
    /// length recv = EOF). No reply needed; move to `Done`.
    End,
    /// Local-side protocol violation detected. Caller should encrypt and
    /// send this 2-byte fatal alert payload over kTLS before surfacing the
    /// accompanying error.
    SendFatal {
        payload: &'static [u8; 2],
        err: std::io::Error,
    },
}

impl<S> KtlsSocket<S> {
    pub fn fd(&self) -> i32 {
        self.socket.socket().fd()
    }

    pub fn as_socket(&self) -> &SocketWrapper {
        self.socket.socket()
    }

    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.alpn
    }

    pub fn tx_records(&self) -> u64 {
        self.tx_records
    }

    /// `true` if the peer already ended the session during the handshake
    /// (close_notify pipelined behind Finished). No more application data
    /// will arrive; anything received before the close is still delivered by
    /// `into_messages`, which then yields `None`. Sending remains possible,
    /// e.g. to answer a pipelined request.
    pub fn peer_closed(&self) -> bool {
        self.prelude.peer_closed()
    }

    pub fn initiate_key_update(&mut self) -> std::io::Result<()> {
        unsafe {
            send_control_record(
                self.fd(),
                TLS_RECORD_TYPE_HANDSHAKE,
                &KEY_UPDATE_NOT_REQUESTED,
            )?;
        }
        let (seq, secret) = self
            .kernel_conn
            .update_tx_secret()
            .map_err(|e| std::io::Error::other(format!("update_tx_secret: {e:?}")))?;
        unsafe {
            set_crypto_info(self.fd(), TLS_TX, seq, &secret)?;
        }
        self.tx_records = 0;
        Ok(())
    }

    pub(crate) fn switch_to_ktls(
        socket: SocketWrapper,
        secrets: ExtractedSecrets,
        kernel_conn: KernelConnection<S>,
        alpn: Option<&'static [u8]>,
        prelude: Prelude,
    ) -> std::io::Result<Self> {
        let ulp = b"tls";
        let fd = socket.fd();
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_ULP,
                ulp.as_ptr() as *const libc::c_void,
                ulp.len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (tx_seq, tx_secret) = secrets.tx;
        let (rx_seq, rx_secret) = secrets.rx;
        unsafe {
            set_crypto_info(fd, TLS_RX, rx_seq, &rx_secret)?;
            set_crypto_info(fd, TLS_TX, tx_seq, &tx_secret)?;
        }
        let (read_half, socket) = socket.into_split();
        Ok(KtlsSocket {
            socket,
            read_half: Some(read_half),
            kernel_conn,
            alpn,
            prelude,
            tx_records: 0,
        })
    }

    /// Walk every TLS 1.3 handshake message inside one post-handshake record,
    /// applying side effects as we go. Returns `Err(ControlAction::SendFatal)`
    /// on protocol violations so the caller can return it up the stack.
    fn process_handshake_messages(&mut self, mut payload: &[u8]) -> Result<(), ControlAction> {
        while !payload.is_empty() {
            if payload.len() < 4 {
                return Err(ControlAction::SendFatal {
                    payload: &FATAL_DECODE_ERROR,
                    err: std::io::Error::other("truncated handshake message"),
                });
            }
            let body_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
            if 4 + body_len > payload.len() {
                return Err(ControlAction::SendFatal {
                    payload: &FATAL_DECODE_ERROR,
                    err: std::io::Error::other("handshake message length overruns record"),
                });
            }
            let msg_type = payload[0];
            let body = &payload[4..4 + body_len];
            match msg_type {
                HANDSHAKE_KEY_UPDATE => {
                    // RFC 8446 §4.6.3: KeyUpdate body is a single byte.
                    if body.len() != 1 {
                        return Err(ControlAction::SendFatal {
                            payload: &FATAL_DECODE_ERROR,
                            err: std::io::Error::other("KeyUpdate: bad length"),
                        });
                    }
                    let request_update = match body[0] {
                        0 => false,
                        1 => true,
                        _ => {
                            return Err(ControlAction::SendFatal {
                                payload: &FATAL_ILLEGAL_PARAMETER,
                                err: std::io::Error::other(
                                    "KeyUpdate: KeyUpdateRequest must be 0 or 1",
                                ),
                            });
                        }
                    };
                    let (seq, secret) = self.kernel_conn.update_rx_secret().map_err(|e| {
                        ControlAction::SendFatal {
                            payload: &FATAL_DECODE_ERROR,
                            err: std::io::Error::other(format!("update_rx_secret: {e:?}")),
                        }
                    })?;
                    unsafe {
                        set_crypto_info(self.fd(), TLS_RX, seq, &secret).map_err(|e| {
                            ControlAction::SendFatal {
                                payload: &FATAL_DECODE_ERROR,
                                err: e,
                            }
                        })?;
                    }
                    if request_update {
                        self.initiate_key_update()
                            .map_err(|e| ControlAction::SendFatal {
                                payload: &FATAL_DECODE_ERROR,
                                err: e,
                            })?;
                    }
                }
                HANDSHAKE_NEW_SESSION_TICKET => {
                    // We don't implement TLS 1.3 resumption (yet), so the
                    // ticket is dropped on the floor. Once resumption is
                    // wired up, this is where the body would be handed to
                    // `KernelConnection<ClientConnectionData>::handle_new_session_ticket`.
                }
                _ => {
                    return Err(ControlAction::SendFatal {
                        payload: &FATAL_UNEXPECTED_MESSAGE,
                        err: std::io::Error::other("unexpected post-handshake handshake message"),
                    });
                }
            }
            payload = &payload[4 + body_len..];
        }
        Ok(())
    }

    /// One `recvmsg` into `buf` with a record-type cmsg attached. Returns
    /// `(record_type, len)`; `record_type` is 0 when the kernel attached no
    /// cmsg, which only happens on TCP EOF (`len == 0`).
    fn recv_record(&self, buf: &mut PooledBuf, flags: libc::c_int) -> std::io::Result<(u8, usize)> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg = TlsCmsg {
            hdr: unsafe { std::mem::zeroed() },
            record_type: 0,
        };
        cmsg.hdr.cmsg_len = unsafe { libc::CMSG_LEN(size_of::<u8>() as u32) } as _;
        cmsg.hdr.cmsg_level = SOL_TLS;
        cmsg.hdr.cmsg_type = TLS_GET_RECORD_TYPE;

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = &mut cmsg as *mut _ as *mut libc::c_void;
        msg.msg_controllen = size_of::<TlsCmsg>() as _;

        let n = unsafe { libc::recvmsg(self.fd(), &mut msg, flags) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((cmsg.record_type, n as usize))
    }

    /// How the stream reacts to one non-application-data record, as
    /// delivered by [`recv_record`](Self::recv_record). Performs any RX rekey
    /// (KeyUpdate) inline, but never sends an alert itself — alert emission
    /// is async and driven by the stream's state machine.
    ///
    /// A zero-length payload is ambiguous: TCP EOF (no cmsg, type 0) or a
    /// zero-byte control record (cmsg present, e.g. a malformed empty
    /// alert). The arms below tell them apart by record type.
    fn control_action(&mut self, record_type: u8, payload: &[u8]) -> ControlAction {
        match record_type {
            TLS_RECORD_TYPE_HANDSHAKE => {
                // RFC 8446 §4: every post-handshake message starts with
                // HandshakeType(1) || uint24 length || body. A single record
                // can carry multiple messages back-to-back (rustls servers
                // coalesce all four default NewSessionTickets into one
                // record), so the parser loops until the record is consumed.
                //
                // Accepted here:
                //   - KeyUpdate (24): rekey RX, optionally TX.
                //   - NewSessionTicket (4): silently discarded. We don't
                //     implement resumption yet, and servers send these by
                //     default in TLS 1.3.
                // Anything else is unexpected_message; malformed framing is
                // decode_error.
                match self.process_handshake_messages(payload) {
                    Ok(()) => ControlAction::Continue,
                    Err(action) => action,
                }
            }
            // Per RFC 8446 §6, alert records carry exactly 2 bytes
            // (level + description); shorter is malformed → decode_error.
            TLS_RECORD_TYPE_ALERT if payload.len() < 2 => ControlAction::SendFatal {
                payload: &FATAL_DECODE_ERROR,
                err: std::io::Error::other("truncated alert record"),
            },
            // Any peer alert ends the stream. TLS 1.3 treats every alert
            // except close_notify/user_canceled as fatal anyway; we simply
            // stop receiving and let the caller surface `None`.
            TLS_RECORD_TYPE_ALERT => ControlAction::End,
            // No cmsg, no bytes: TCP EOF.
            0 if payload.is_empty() => ControlAction::End,
            _ => ControlAction::SendFatal {
                payload: &FATAL_UNEXPECTED_MESSAGE,
                err: std::io::Error::other("unexpected TLS record type"),
            },
        }
    }

    /// Read the control record the kernel is holding (signalled by an EIO
    /// completion on the recv ring) and decide how the stream should react.
    /// The record is already decrypted and parked on the socket's rx list,
    /// so the blocking `recvmsg` returns immediately.
    pub(crate) fn handle_control_record(&mut self) -> std::io::Result<ControlAction> {
        let mut buf = PooledBuf::new();
        let (record_type, n) = self.recv_record(&mut buf, 0)?;
        Ok(self.control_action(record_type, &buf[..n]))
    }

    /// Synchronously drain every TLS record already queued in the kernel right
    /// after attach, extending `prelude`: application data is appended to its
    /// plaintext, control records are dispatched through
    /// [`control_action`](Self::control_action), and the first non-`Continue`
    /// action ends the drain and becomes the prelude's action. Uses
    /// non-blocking `recvmsg`, stopping the instant the queue is empty
    /// (`EAGAIN`) — no timing involved. A prelude that is already closed is
    /// returned untouched.
    ///
    /// This is the deterministic replacement for a pre-attach grace-drain. The
    /// io_uring multishot recv (`MultiRecv`) drops application-data records that
    /// are already queued when it first arms on a kTLS socket whose RX sequence
    /// is non-zero (which happens whenever the handshake software-decrypted a
    /// pipelined record). Emptying the queue here means the multishot only ever
    /// arms on an idle socket, where its post-arm delivery is reliable. The
    /// blocking-`recvmsg` path used here has no such issue (verified by the
    /// `ktls_queue_premise` tests). Call immediately before arming the recv.
    ///
    /// Because this consumes any close_notify or violation it meets, the
    /// returned action is the only trace of it: a recv armed afterwards would
    /// never see the alert and would wait for a TCP FIN that a half-closed
    /// peer may never send.
    pub(crate) fn drain_queued_records(&mut self, prelude: Prelude) -> Prelude {
        let Prelude {
            mut plaintext,
            action,
        } = prelude;
        if !matches!(action, ControlAction::Continue) {
            return Prelude { plaintext, action };
        }
        let mut buf = PooledBuf::new();
        let action = loop {
            let (record_type, n) = match self.recv_record(&mut buf, libc::MSG_DONTWAIT) {
                Ok(rec) => rec,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // EAGAIN/EWOULDBLOCK: queue drained. Any other error resurfaces
                // on the real read path once the recv is armed.
                Err(_) => break ControlAction::Continue,
            };
            if record_type == TLS_RECORD_TYPE_APPLICATION_DATA {
                plaintext
                    .get_or_insert_with(Vec::new)
                    .extend_from_slice(&buf[..n]);
                continue;
            }
            match self.control_action(record_type, &buf[..n]) {
                ControlAction::Continue => continue, // KeyUpdate / NewSessionTicket handled
                action => break action,
            }
        };
        Prelude { plaintext, action }
    }
}

const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
pub(crate) const TLS_RECORD_TYPE_ALERT: u8 = 21;
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
const TLS_RECORD_TYPE_APPLICATION_DATA: u8 = 23;
const HANDSHAKE_KEY_UPDATE: u8 = 24;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const TLS_1_3_VERSION: u16 = 0x0304;

const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0];

// RFC 8446 §6 fatal alert payloads. Static so the async send future can
// borrow them with a `'static` lifetime and live in the `KtlsMessages`
// state machine without a self-referential struct.
pub(crate) static FATAL_UNEXPECTED_MESSAGE: [u8; 2] = [2, 10];
pub(crate) static FATAL_BAD_RECORD_MAC: [u8; 2] = [2, 20];
pub(crate) static FATAL_ILLEGAL_PARAMETER: [u8; 2] = [2, 47];
pub(crate) static FATAL_DECODE_ERROR: [u8; 2] = [2, 50];

const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

#[repr(C)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
struct Tls12CryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
struct Tls12CryptoInfoChacha20Poly1305 {
    info: TlsCryptoInfo,
    iv: [u8; 12],
    key: [u8; 32],
    rec_seq: [u8; 8],
}

fn arr_ref<'a, const N: usize>(
    slice: &'a [u8],
    what: &'static str,
) -> std::io::Result<&'a [u8; N]> {
    slice.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what}: expected {N} bytes, got {}", slice.len()),
        )
    })
}

unsafe fn set_crypto_info(
    fd: i32,
    dir: libc::c_int,
    seq: u64,
    secret: &ConnectionTrafficSecrets,
) -> std::io::Result<()> {
    let rec_seq = seq.to_be_bytes();
    let ret = match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let iv: &[u8; 12] = arr_ref(iv.as_ref(), "Aes128Gcm IV")?;
            let key: &[u8; 16] = arr_ref(key.as_ref(), "Aes128Gcm key")?;
            let info = Tls12CryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                salt: iv[..4].try_into().expect("12 >= 4"),
                iv: iv[4..12].try_into().expect("12 >= 8"),
                key: *key,
                rec_seq,
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    dir,
                    &info as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            }
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let iv: &[u8; 12] = arr_ref(iv.as_ref(), "Aes256Gcm IV")?;
            let key: &[u8; 32] = arr_ref(key.as_ref(), "Aes256Gcm key")?;
            let info = Tls12CryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                salt: iv[..4].try_into().expect("12 >= 4"),
                iv: iv[4..12].try_into().expect("12 >= 8"),
                key: *key,
                rec_seq,
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    dir,
                    &info as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            }
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let iv: &[u8; 12] = arr_ref(iv.as_ref(), "Chacha20Poly1305 IV")?;
            let key: &[u8; 32] = arr_ref(key.as_ref(), "Chacha20Poly1305 key")?;
            let info = Tls12CryptoInfoChacha20Poly1305 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv: *iv,
                key: *key,
                rec_seq,
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    dir,
                    &info as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            }
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported AEAD for kTLS",
            ));
        }
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct TlsCmsg {
    hdr: libc::cmsghdr,
    record_type: u8,
}

/// Synchronous control-record send. Used only by `initiate_key_update`,
/// which is application-initiated and not on the error path, so a blocking
/// sendmsg syscall (returns immediately on a non-blocking socket for a
/// 5-byte payload) is acceptable. Fatal-alert sends go through the async
/// `runtime::net::socket_send_control_record` path instead.
unsafe fn send_control_record(fd: i32, record_type: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    let mut cmsg = TlsCmsg {
        hdr: unsafe { std::mem::zeroed() },
        record_type,
    };
    cmsg.hdr.cmsg_len = unsafe { libc::CMSG_LEN(size_of::<u8>() as u32) } as _;
    cmsg.hdr.cmsg_level = SOL_TLS;
    cmsg.hdr.cmsg_type = TLS_SET_RECORD_TYPE;

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &mut cmsg as *mut _ as *mut libc::c_void;
    msg.msg_controllen = size_of::<TlsCmsg>() as _;

    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
