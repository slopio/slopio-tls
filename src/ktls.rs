use runtime::net::{OwnedReadHalf, OwnedWriteHalf, SocketWrapper};
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets};
use zeroize::Zeroize;

use crate::pool::PooledBuf;

pub struct KtlsSocket<S = ServerConnectionData> {
    /// Write half of the connection. Also the handle we use for the fd
    /// (sync `recvmsg`/`setsockopt` and async sends).
    pub(crate) socket: OwnedWriteHalf,
    pub(crate) read_half: OwnedReadHalf,
    pub(crate) kernel_conn: KernelConnection<S>,
    pub(crate) alpn: Option<&'static [u8]>,
    /// What the software handshake left for the stream; see `Prelude`.
    pub(crate) prelude: Prelude,
}

/// What the receive side saw before a recv could be armed: plaintext
/// decrypted by the software handshake or the kernel-queue drain, and how
/// the session stands after it. Both phases consume any close_notify or
/// violation they meet, so `action` is the only record of it.
#[derive(Debug)]
pub(crate) struct Prelude {
    pub plaintext: Option<Vec<u8>>,
    pub action: ControlAction,
}

impl Prelude {
    pub fn open(plaintext: Option<Vec<u8>>) -> Self {
        Self {
            plaintext,
            action: ControlAction::Continue,
        }
    }

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

/// Result of inspecting a control record delivered via the kTLS recvmsg cmsg
/// path. The caller (the `KtlsReader` state machine) decides what to do
/// next; this enum carries no I/O of its own.
#[derive(Debug)]
pub(crate) enum ControlAction {
    /// A valid KeyUpdate was processed (RX rekeyed). Continue receiving on
    /// the same socket.
    Continue,
    /// A peer KeyUpdate asked us to rekey our TX too (`request_update`). RX is
    /// already rekeyed; we owe a KeyUpdate, then `rotate_tx_key`, before our
    /// next application data (RFC 8446 §4.6.3).
    SendKeyUpdate,
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

    /// The peer sent close_notify during the handshake. `into_messages` still
    /// delivers what arrived before it, then ends; sending remains possible.
    pub fn peer_closed(&self) -> bool {
        self.prelude.peer_closed()
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
        // The ULP is on: every send from here is a `tls_sw_sendmsg`, which
        // rejects the runtime's default `MSG_WAITALL` with `EOPNOTSUPP`.
        socket.set_default_msg_flags(0);
        let (tx_seq, tx_secret) = secrets.tx;
        let (rx_seq, rx_secret) = secrets.rx;
        unsafe {
            set_crypto_info(fd, TLS_RX, rx_seq, &rx_secret)?;
            set_crypto_info(fd, TLS_TX, tx_seq, &tx_secret)?;
        }
        let (read_half, socket) = socket.into_split();
        Ok(KtlsSocket {
            socket,
            read_half,
            kernel_conn,
            alpn,
            prelude,
        })
    }
}

/// Rotate the TX key: derive the next sending secret and install it in the
/// kernel. Call this only *after* the KeyUpdate record announcing the
/// change has been sent over kTLS (RFC 8446 §4.6.3 order: the peer must
/// still decrypt that record under the old key). The send itself is async
/// and lives in the caller (`KtlsWriter`); this is the synchronous
/// `setsockopt` tail, which never blocks.
pub(crate) fn rotate_tx_key<S>(fd: i32, conn: &mut KernelConnection<S>) -> std::io::Result<()> {
    let (seq, secret) = conn
        .update_tx_secret()
        .map_err(|e| std::io::Error::other(format!("update_tx_secret: {e:?}")))?;
    unsafe { set_crypto_info(fd, TLS_TX, seq, &secret) }
}

/// Read the control record the kernel is holding (signalled by an EIO
/// completion on the recv ring) and decide how the stream should react.
/// The record is already decrypted and parked on the socket's rx list,
/// so the blocking `recvmsg` returns immediately.
pub(crate) fn handle_control_record<S>(
    fd: i32,
    conn: &mut KernelConnection<S>,
) -> std::io::Result<ControlAction> {
    let mut buf = PooledBuf::new();
    let (record_type, n) = recv_record(fd, &mut buf, 0)?;
    Ok(control_action(fd, conn, record_type, &buf[..n]))
}

/// Walk every TLS 1.3 handshake message inside one post-handshake record,
/// applying side effects as we go. Rekeys RX inline (a non-blocking
/// `setsockopt`). Returns `Ok(true)` if any KeyUpdate asked us to rekey TX
/// too — the TX send is async, so the caller drives it — `Ok(false)`
/// otherwise, or `Err(ControlAction::SendFatal)` on a protocol violation.
fn process_handshake_messages<S>(
    fd: i32,
    conn: &mut KernelConnection<S>,
    mut payload: &[u8],
) -> Result<bool, ControlAction> {
    let mut tx_rekey_owed = false;
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
                let (seq, secret) =
                    conn.update_rx_secret()
                        .map_err(|e| ControlAction::SendFatal {
                            payload: &FATAL_DECODE_ERROR,
                            err: std::io::Error::other(format!("update_rx_secret: {e:?}")),
                        })?;
                unsafe {
                    set_crypto_info(fd, TLS_RX, seq, &secret).map_err(|e| {
                        ControlAction::SendFatal {
                            payload: &FATAL_DECODE_ERROR,
                            err: e,
                        }
                    })?;
                }
                if request_update {
                    tx_rekey_owed = true;
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
    Ok(tx_rekey_owed)
}

/// One `recvmsg` into `buf`, returning `(record_type, len)`. The kernel
/// attaches no cmsg on TCP EOF, so that case reads as type 0, `len == 0`.
fn recv_record(fd: i32, buf: &mut PooledBuf, flags: libc::c_int) -> std::io::Result<(u8, usize)> {
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

    let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((cmsg.record_type, n as usize))
}

/// How the stream reacts to a non-application-data record. Rekeys RX
/// inline on KeyUpdate; never sends an alert itself (that is async, in
/// the stream's state machine). A zero-length payload is either TCP EOF
/// (type 0) or an empty control record (cmsg present), hence the arms
/// match on the type.
fn control_action<S>(
    fd: i32,
    conn: &mut KernelConnection<S>,
    record_type: u8,
    payload: &[u8],
) -> ControlAction {
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
            match process_handshake_messages(fd, conn, payload) {
                Ok(true) => ControlAction::SendKeyUpdate,
                Ok(false) => ControlAction::Continue,
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

const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
pub(crate) const TLS_RECORD_TYPE_ALERT: u8 = 21;
pub(crate) const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_KEY_UPDATE: u8 = 24;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const TLS_1_3_VERSION: u16 = 0x0304;

// The KeyUpdate we emit (RFC 8446 §4.6.3): HandshakeType(24) || uint24 len(1)
// || update_not_requested(0). `request_update` is 0 — replying to a peer's
// request with another request would loop. Static so the async send future
// can borrow it with a `'static` lifetime.
pub(crate) static KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0];

// RFC 8446 §6 fatal alert payloads. Static so the async send future can
// borrow them with a `'static` lifetime and live in the `KtlsMessages`
// state machine without a self-referential struct.
pub(crate) static CLOSE_NOTIFY: [u8; 2] = [1, 0];
pub(crate) static FATAL_UNEXPECTED_MESSAGE: [u8; 2] = [2, 10];
pub(crate) static FATAL_ILLEGAL_PARAMETER: [u8; 2] = [2, 47];
pub(crate) static FATAL_DECODE_ERROR: [u8; 2] = [2, 50];

const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

// These structs carry the AEAD key into the kernel. They are the only place
// key material lands in this crate's own memory (rustls and the kernel hold
// the rest), so `setsockopt_crypto` wipes them right after `setsockopt` copies
// them in.
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

/// `setsockopt(SOL_TLS, dir, info)` then wipe the local `info`: the kernel has
/// copied the key by the time the syscall returns, so our copy must not linger
/// in the stack frame. Wiping the whole `#[repr(C)]` struct as raw bytes (via
/// `Zeroize for [u8]`, volatile so it is not optimised away) avoids a derive.
///
/// # Safety
/// `dir` must be `TLS_TX` or `TLS_RX` and `fd` a kTLS-attached socket. `T` must
/// be one of the `#[repr(C)]` `Tls12CryptoInfo*` structs (plain bytes, no
/// `Drop`, no padding invariants), so wiping its whole footprint is sound.
unsafe fn setsockopt_crypto<T>(fd: i32, dir: libc::c_int, mut info: T) -> libc::c_int {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            dir,
            &info as *const _ as *const libc::c_void,
            std::mem::size_of_val(&info) as libc::socklen_t,
        )
    };
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(&mut info as *mut T as *mut u8, size_of::<T>()) };
    bytes.zeroize();
    ret
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
            unsafe { setsockopt_crypto(fd, dir, info) }
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
            unsafe { setsockopt_crypto(fd, dir, info) }
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
            unsafe { setsockopt_crypto(fd, dir, info) }
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
