use runtime::net::SocketWrapper;
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets};

use crate::pool::PooledBuf;

pub struct KtlsSocket<S = ServerConnectionData> {
    socket: SocketWrapper,
    pub(crate) kernel_conn: KernelConnection<S>,
    pub(crate) alpn: Option<&'static [u8]>,
    pub(crate) pending_plaintext: Option<Vec<u8>>,
    pub(crate) tx_records: u64,
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
        self.socket.fd
    }

    pub fn as_socket(&self) -> &SocketWrapper {
        &self.socket
    }

    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.alpn
    }

    pub fn tx_records(&self) -> u64 {
        self.tx_records
    }

    pub fn initiate_key_update(&mut self) -> std::io::Result<()> {
        unsafe {
            send_control_record(
                self.socket.fd,
                TLS_RECORD_TYPE_HANDSHAKE,
                &KEY_UPDATE_NOT_REQUESTED,
            )?;
        }
        let (seq, secret) = self
            .kernel_conn
            .update_tx_secret()
            .map_err(|e| std::io::Error::other(format!("update_tx_secret: {e:?}")))?;
        unsafe {
            set_crypto_info(self.socket.fd, TLS_TX, seq, &secret)?;
        }
        self.tx_records = 0;
        Ok(())
    }

    pub(crate) fn switch_to_ktls(
        socket: SocketWrapper,
        secrets: ExtractedSecrets,
        kernel_conn: KernelConnection<S>,
        alpn: Option<&'static [u8]>,
        pending_plaintext: Option<Vec<u8>>,
    ) -> std::io::Result<Self> {
        let ulp = b"tls";
        let ret = unsafe {
            libc::setsockopt(
                socket.fd,
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
            set_crypto_info(socket.fd, TLS_RX, rx_seq, &rx_secret)?;
            set_crypto_info(socket.fd, TLS_TX, tx_seq, &tx_secret)?;
        }
        Ok(KtlsSocket {
            socket,
            kernel_conn,
            alpn,
            pending_plaintext,
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
                        set_crypto_info(self.socket.fd, TLS_RX, seq, &secret).map_err(|e| {
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

    /// Read the control record the kernel is holding (signalled by an EIO
    /// completion on the recv ring) and decide how the stream should react.
    /// This function performs the sync recvmsg and any RX rekey (KeyUpdate)
    /// inline, but never sends an alert itself — alert emission is async and
    /// driven by the caller's state machine.
    pub(crate) fn handle_control_record(&mut self) -> std::io::Result<ControlAction> {
        let mut payload = PooledBuf::new();
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
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

        let n = unsafe { libc::recvmsg(self.socket.fd, &mut msg, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n = n as usize;

        // `n == 0` is ambiguous: it can be a TCP EOF (no cmsg attached) or a
        // zero-byte control-record payload (cmsg present, e.g. a malformed
        // empty alert). We let the match dispatch handle both correctly:
        // ALERT/HANDSHAKE arms validate length and emit the right fatal
        // alert; the catch-all treats `n == 0` with no cmsg as End.
        match cmsg.record_type {
            TLS_RECORD_TYPE_HANDSHAKE => {
                // RFC 8446 §4: every post-handshake message starts with
                // HandshakeType(1) || uint24 length || body. A single record
                // can carry multiple messages back-to-back (rustls servers
                // coalesce all four default NewSessionTickets into one
                // record), so we loop until the record is consumed.
                //
                // We accept two message types here:
                //   - KeyUpdate (24): rekey RX, optionally TX.
                //   - NewSessionTicket (4): silently discard. We don't
                //     implement resumption yet, and the server sends these
                //     by default in TLS 1.3.
                // Anything else is unexpected_message; malformed framing is
                // decode_error.
                if let Err(action) = self.process_handshake_messages(&payload[..n]) {
                    return Ok(action);
                }
                Ok(ControlAction::Continue)
            }
            TLS_RECORD_TYPE_ALERT => {
                // Per RFC 8446 §6, alert records carry exactly 2 bytes
                // (level + description); shorter is malformed → decode_error.
                if n < 2 {
                    return Ok(ControlAction::SendFatal {
                        payload: &FATAL_DECODE_ERROR,
                        err: std::io::Error::other("truncated alert record"),
                    });
                }
                // Any peer alert ends the stream. TLS 1.3 treats every alert
                // except close_notify/user_canceled as fatal anyway; we
                // simply stop receiving and let the caller surface `None`.
                Ok(ControlAction::End)
            }
            0 if n == 0 => {
                // No cmsg, no bytes — TCP EOF on a connection where kTLS
                // had signalled a control record waiting but the peer
                // disappeared before recvmsg could pull it.
                Ok(ControlAction::End)
            }
            _ => Ok(ControlAction::SendFatal {
                payload: &FATAL_UNEXPECTED_MESSAGE,
                err: std::io::Error::other("unexpected TLS record type"),
            }),
        }
    }

    /// Synchronously drain every TLS record already queued in the kernel right
    /// after attach: application data into `pending_plaintext`, control records
    /// dispatched inline. Uses non-blocking `recvmsg`, stopping the instant the
    /// queue is empty (`EAGAIN`) — no timing involved.
    ///
    /// This is the deterministic replacement for a pre-attach grace-drain. The
    /// io_uring multishot recv (`MultiRecv`) drops application-data records that
    /// are already queued when it first arms on a kTLS socket whose RX sequence
    /// is non-zero (which happens whenever the handshake software-decrypted a
    /// pipelined record). Emptying the queue here means the multishot only ever
    /// arms on an idle socket, where its post-arm delivery is reliable. The
    /// blocking-`recvmsg` path used here has no such issue (verified by the
    /// `ktls_queue_premise` tests). Call immediately before arming the recv.
    pub(crate) fn drain_queued_records(&mut self) {
        loop {
            let mut payload = PooledBuf::new();
            let mut iov = libc::iovec {
                iov_base: payload.as_mut_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
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

            let n = unsafe { libc::recvmsg(self.socket.fd, &mut msg, libc::MSG_DONTWAIT) };
            if n < 0 {
                // EAGAIN/EWOULDBLOCK: queue drained — done. EINTR: retry. Any
                // other error: stop; it resurfaces on the real read path.
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if n == 0 {
                return; // EOF
            }
            let n = n as usize;
            match cmsg.record_type {
                TLS_RECORD_TYPE_APPLICATION_DATA => {
                    self.pending_plaintext
                        .get_or_insert_with(Vec::new)
                        .extend_from_slice(&payload[..n]);
                }
                TLS_RECORD_TYPE_HANDSHAKE => {
                    // KeyUpdate (rekey RX inline) / NewSessionTicket (dropped).
                    // On a protocol violation, stop draining; the read path
                    // surfaces the error on the next poll.
                    if self.process_handshake_messages(&payload[..n]).is_err() {
                        return;
                    }
                }
                // Alert (close_notify or fatal) or anything unexpected: stop.
                // The multishot then observes the resulting EOF and ends the
                // stream after `pending_plaintext` is delivered.
                _ => return,
            }
        }
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
