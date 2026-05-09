use runtime::net::SocketWrapper;
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets};

pub struct KtlsSocket {
    socket: SocketWrapper,
    pub(crate) kernel_conn: Option<KernelConnection<ServerConnectionData>>,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) pending_plaintext: Option<Vec<u8>>,
    pub(crate) tx_records: u64,
}

#[derive(Debug)]
pub enum ControlOutcome {
    Eof,
    KeyUpdate,
    Alert { level: u8, description: u8 },
}

impl KtlsSocket {
    pub fn fd(&self) -> i32 {
        self.socket.fd
    }

    pub fn as_socket(&self) -> &SocketWrapper {
        &self.socket
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
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
        let kc = self
            .kernel_conn
            .as_mut()
            .ok_or_else(|| std::io::Error::other("KeyUpdate requires KernelConnection"))?;
        let (seq, secret) = kc
            .update_tx_secret()
            .map_err(|e| std::io::Error::other(format!("update_tx_secret: {e:?}")))?;
        unsafe { set_crypto_info(self.socket.fd, TLS_TX, seq, &secret)?; }
        self.tx_records = 0;
        Ok(())
    }

    pub fn install_keys(&self, secrets: ExtractedSecrets) -> std::io::Result<()> {
        let (tx_seq, tx_secret) = secrets.tx;
        let (rx_seq, rx_secret) = secrets.rx;
        unsafe {
            set_crypto_info(self.socket.fd, TLS_TX, tx_seq, &tx_secret)?;
            set_crypto_info(self.socket.fd, TLS_RX, rx_seq, &rx_secret)?;
        }
        Ok(())
    }

    pub fn handle_control_record(&mut self) -> std::io::Result<ControlOutcome> {
        let mut payload = vec![0u8; 17 * 1024];
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
        if n == 0 {
            return Ok(ControlOutcome::Eof);
        }
        let n = n as usize;

        match cmsg.record_type {
            TLS_RECORD_TYPE_HANDSHAKE => {
                if n != 5 || payload[0] != HANDSHAKE_KEY_UPDATE {
                    return Err(std::io::Error::other("malformed post-handshake record"));
                }
                let request_update = payload[4] == 1;
                {
                    let kc = self.kernel_conn.as_mut().ok_or_else(|| {
                        std::io::Error::other("KeyUpdate received but no KernelConnection stored")
                    })?;
                    let (seq, secret) = kc.update_rx_secret().map_err(|e| {
                        std::io::Error::other(format!("update_rx_secret: {e:?}"))
                    })?;
                    unsafe { set_crypto_info(self.socket.fd, TLS_RX, seq, &secret)?; }
                }
                if request_update {
                    self.initiate_key_update()?;
                }
                Ok(ControlOutcome::KeyUpdate)
            }
            TLS_RECORD_TYPE_ALERT => {
                if n < 2 {
                    return Err(std::io::Error::other("truncated alert record"));
                }
                Ok(ControlOutcome::Alert {
                    level: payload[0],
                    description: payload[1],
                })
            }
            other => Err(std::io::Error::other(format!(
                "unexpected TLS record type {other}"
            ))),
        }
    }
}

impl Drop for KtlsSocket {
    fn drop(&mut self) {
        unsafe {
            let _ = send_close_notify(self.socket.fd);
        }
    }
}

impl TryFrom<SocketWrapper> for KtlsSocket {
    type Error = std::io::Error;

    fn try_from(socket: SocketWrapper) -> Result<Self, Self::Error> {
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
        Ok(KtlsSocket {
            socket,
            kernel_conn: None,
            alpn: None,
            pending_plaintext: None,
            tx_records: 0,
        })
    }
}

const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
const TLS_RECORD_TYPE_ALERT: u8 = 21;
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_KEY_UPDATE: u8 = 24;
const TLS_1_3_VERSION: u16 = 0x0304;

const CLOSE_NOTIFY_PAYLOAD: [u8; 2] = [1, 0];
const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0];

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

unsafe fn set_crypto_info(
    fd: i32,
    dir: libc::c_int,
    seq: u64,
    secret: &ConnectionTrafficSecrets,
) -> std::io::Result<()> {
    let rec_seq = seq.to_be_bytes();
    let ret = match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let iv_bytes = iv.as_ref();
            let info = Tls12CryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                salt: iv_bytes[..4].try_into().unwrap(),
                iv: iv_bytes[4..12].try_into().unwrap(),
                key: key.as_ref().try_into().unwrap(),
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
            let iv_bytes = iv.as_ref();
            let info = Tls12CryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                salt: iv_bytes[..4].try_into().unwrap(),
                iv: iv_bytes[4..12].try_into().unwrap(),
                key: key.as_ref().try_into().unwrap(),
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
            let info = Tls12CryptoInfoChacha20Poly1305 {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv: iv.as_ref().try_into().unwrap(),
                key: key.as_ref().try_into().unwrap(),
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

unsafe fn send_close_notify(fd: i32) -> std::io::Result<()> {
    unsafe { send_control_record(fd, TLS_RECORD_TYPE_ALERT, &CLOSE_NOTIFY_PAYLOAD) }
}

unsafe fn send_control_record(
    fd: i32,
    record_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
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
