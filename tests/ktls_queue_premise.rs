//! Decisive experiment: does kTLS RX reprocess ciphertext that was **already
//! sitting in the TCP receive queue** at the moment `TLS_RX` is attached?
//!
//! This is the premise the handshake exit rests on: the server stops its
//! reads at the client's Finished and lets the kernel deliver whatever was
//! already queued. These tests settle it directly, with no rustls / io_uring
//! in the way — just loopback TCP sockets and the kernel TLS ULP driven via
//! `libc`.
//!
//! Cases:
//! * `control_rx_before_data`: RX attached first (sanity: proves our
//!   hand-built crypto_info works).
//! * `premise_single_record_queued`: one full record queued, then RX.
//! * `premise_multiple_records_queued`: two full records queued, then RX.
//! * `premise_record_fragmented_across_attach`: half a record queued, RX
//!   attached, then the tail sent.
//!
//! Run with output:  cargo test --test ktls_queue_premise -- --nocapture

use std::io::{Read, Write};
use std::mem::size_of_val;
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

// --- kTLS ABI (mirrors src/ktls.rs) ---
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_1_3_VERSION: u16 = 0x0304;
const TLS_CIPHER_AES_GCM_128: u16 = 51;

const KEY: [u8; 16] = [0x42; 16];
const IV: [u8; 12] = [0x24; 12];

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

fn tcp_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let a = TcpStream::connect(addr).unwrap();
    let (b, _) = l.accept().unwrap();
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    (a, b)
}

fn attach_ulp(fd: i32) -> std::io::Result<()> {
    let ulp = b"tls";
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_ULP,
            ulp.as_ptr() as *const libc::c_void,
            ulp.len() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set an AES-128-GCM TLS 1.3 key for direction `dir`. TX and RX use the same
/// key/iv/seq so the kernel's own encrypt and decrypt are guaranteed to match
/// (we don't follow any external spec — only internal consistency).
fn set_tls(fd: i32, dir: libc::c_int, seq: u64) -> std::io::Result<()> {
    let info = Tls12CryptoInfoAesGcm128 {
        info: TlsCryptoInfo {
            version: TLS_1_3_VERSION,
            cipher_type: TLS_CIPHER_AES_GCM_128,
        },
        salt: IV[..4].try_into().unwrap(),
        iv: IV[4..12].try_into().unwrap(),
        key: KEY,
        rec_seq: seq.to_be_bytes(),
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            dir,
            &info as *const _ as *const libc::c_void,
            size_of_val(&info) as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fionread(fd: i32) -> i32 {
    let mut n: libc::c_int = 0;
    unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) };
    n
}

/// Poll FIONREAD until it is non-zero and unchanged across one interval — i.e.
/// every in-flight byte has landed in the queue. Returns the queued byte count.
fn wait_until_queue_stable(fd: i32) -> i32 {
    let mut last = -1;
    let mut waited = Duration::ZERO;
    loop {
        let n = fionread(fd);
        if n > 0 && n == last {
            return n;
        }
        last = n;
        thread::sleep(Duration::from_millis(10));
        waited += Duration::from_millis(10);
        assert!(waited < Duration::from_secs(2), "queue never stabilized");
    }
}

fn read_decrypted(b: &mut TcpStream, want: usize) -> std::io::Result<Vec<u8>> {
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 512];
    while out.len() < want {
        match b.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Capture the raw ciphertext bytes of a single TLS 1.3 record carrying
/// `plaintext`, by letting the kernel kTLS TX path encrypt it and reading the
/// wire bytes off a plain (non-kTLS) peer. Sequence number 0.
fn capture_record(plaintext: &[u8]) -> Vec<u8> {
    let (mut tx, mut sink) = tcp_pair();
    attach_ulp(tx.as_raw_fd()).expect("ulp tx");
    set_tls(tx.as_raw_fd(), TLS_TX, 0).expect("TLS_TX");
    tx.write_all(plaintext).expect("write tx");

    sink.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while buf.len() < 5 {
        let n = sink.read(&mut tmp).expect("read header");
        buf.extend_from_slice(&tmp[..n]);
    }
    let total = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
    while buf.len() < total {
        let n = sink.read(&mut tmp).expect("read body");
        buf.extend_from_slice(&tmp[..n]);
    }
    buf.truncate(total);
    buf
}

#[test]
fn control_rx_before_data() {
    let (mut a, mut b) = tcp_pair();
    attach_ulp(a.as_raw_fd()).unwrap();
    set_tls(a.as_raw_fd(), TLS_TX, 0).unwrap();
    attach_ulp(b.as_raw_fd()).unwrap();
    set_tls(b.as_raw_fd(), TLS_RX, 0).unwrap();

    a.write_all(b"control-payload").unwrap();
    let got = read_decrypted(&mut b, 15).unwrap();
    assert_eq!(
        got, b"control-payload",
        "RX-before-data must decrypt — otherwise crypto_info is wrong and the \
         premise tests are meaningless"
    );
    eprintln!("\n[CONTROL] kTLS RX decrypts data delivered AFTER attach — setup valid\n");
}

#[test]
fn premise_single_record_queued() {
    let (mut a, mut b) = tcp_pair();
    attach_ulp(a.as_raw_fd()).unwrap();
    set_tls(a.as_raw_fd(), TLS_TX, 0).unwrap();

    a.write_all(b"single-queued-record").unwrap();
    let queued = wait_until_queue_stable(b.as_raw_fd());
    eprintln!("[single]   {queued} ciphertext bytes queued before RX attach");

    attach_ulp(b.as_raw_fd()).expect("ulp B (data already queued)");
    set_tls(b.as_raw_fd(), TLS_RX, 0).expect("TLS_RX (data already queued)");

    let got = read_decrypted(&mut b, 20).unwrap();
    assert_eq!(
        got, b"single-queued-record",
        "kTLS did NOT recover a full record queued before attach"
    );
    eprintln!("[single]   RECOVERED — one pre-attach record decrypts fine\n");
}

#[test]
fn premise_multiple_records_queued() {
    let (mut a, mut b) = tcp_pair();
    attach_ulp(a.as_raw_fd()).unwrap();
    set_tls(a.as_raw_fd(), TLS_TX, 0).unwrap();

    // Two separate writes → two TLS records (seq 0 and seq 1).
    a.write_all(b"first-record|").unwrap();
    a.write_all(b"second-record").unwrap();
    let queued = wait_until_queue_stable(b.as_raw_fd());
    eprintln!("[multi]    {queued} ciphertext bytes (2 records) queued before RX attach");

    attach_ulp(b.as_raw_fd()).expect("ulp B");
    set_tls(b.as_raw_fd(), TLS_RX, 0).expect("TLS_RX");

    let got = read_decrypted(&mut b, 26).unwrap();
    assert_eq!(
        got, b"first-record|second-record",
        "kTLS did NOT recover BOTH queued records (seq continuity across the queue)"
    );
    eprintln!("[multi]    RECOVERED — both pre-attach records decrypt, seq stays aligned\n");
}

#[test]
fn premise_record_queued_between_ulp_and_rx_key() {
    // The attach is two syscalls: setsockopt(TCP_ULP,"tls") then
    // set_crypto_info(TLS_RX). What happens to a record that lands in the
    // queue *between* them — ULP attached but no RX key yet? This is the
    // window the live h2spec failures point at.
    let (mut a, mut b) = tcp_pair();
    attach_ulp(a.as_raw_fd()).unwrap();
    set_tls(a.as_raw_fd(), TLS_TX, 0).unwrap();

    attach_ulp(b.as_raw_fd()).expect("ulp B"); // ULP on, no RX key yet
    a.write_all(b"between-ulp-and-key").unwrap();
    thread::sleep(Duration::from_millis(50)); // record lands in B's queue
    let rx = set_tls(b.as_raw_fd(), TLS_RX, 0); // now arm RX
    eprintln!("[ulpwin]   set_crypto_info(RX) after data queued -> {rx:?}");
    rx.expect("TLS_RX");

    let res = read_decrypted(&mut b, 19);
    eprintln!("\n=========== VERDICT (ULP→key window) ===========");
    match &res {
        Ok(v) if v == b"between-ulp-and-key" => {
            eprintln!("RECOVERED — record queued in the ULP→key window survives.")
        }
        Ok(v) => eprintln!("MISMATCH ({} bytes) -> BUG: {:?}", v.len(), v),
        Err(e) => eprintln!(
            "read failed: {e} -> THIS is the bug: a record landing after TCP_ULP\n\
             but before the RX key is LOST. That's the h2spec settings-lost case."
        ),
    }
    eprintln!("================================================\n");
    assert_eq!(
        res.unwrap_or_default(),
        b"between-ulp-and-key",
        "record queued between TCP_ULP and TLS_RX setup was lost"
    );
}

#[test]
fn premise_queued_record_at_nonzero_seq() {
    // The HTTP/2 bug shape: the first app record (magic, seq 0) was decrypted
    // in software during the handshake drain, so rustls hands kTLS rx_seq = 1.
    // The NEXT record (settings, seq 1) is already sitting in the queue when we
    // attach RX at rec_seq = 1. Does the kernel apply the non-zero starting seq
    // to the ALREADY-QUEUED record, or does it (mis)count queued data from 0?
    let (mut a, mut b) = tcp_pair();
    attach_ulp(a.as_raw_fd()).unwrap();
    set_tls(a.as_raw_fd(), TLS_TX, 1).unwrap(); // TX emits this record as seq 1

    a.write_all(b"settings-at-seq-one").unwrap();
    let queued = wait_until_queue_stable(b.as_raw_fd());
    eprintln!("[nzseq]    {queued} bytes (record seq 1) queued before RX attach");

    attach_ulp(b.as_raw_fd()).expect("ulp B");
    let rx = set_tls(b.as_raw_fd(), TLS_RX, 1); // RX starts at rec_seq 1
    eprintln!("[nzseq]    set_crypto_info(RX, seq=1) -> {rx:?}");
    rx.expect("TLS_RX seq 1");

    let res = read_decrypted(&mut b, 19);
    eprintln!("\n================= VERDICT (non-zero seq) =================");
    match &res {
        Ok(v) if v == b"settings-at-seq-one" => eprintln!(
            "RECOVERED — kTLS applies rec_seq=1 to the queued record. Not the bug."
        ),
        Ok(v) => eprintln!(
            "MISMATCH ({} bytes) -> THIS is the bug: queued data at non-zero seq is\n\
             mishandled. {:?}",
            v.len(),
            v
        ),
        Err(e) => eprintln!(
            "read failed: {e} -> THIS is the bug: a record queued at attach with a\n\
             non-zero rec_seq is NOT decrypted (the HTTP/2 settings-lost case)."
        ),
    }
    eprintln!("=========================================================\n");
    assert_eq!(
        res.unwrap_or_default(),
        b"settings-at-seq-one",
        "queued record at non-zero rec_seq was not recovered"
    );
}

#[test]
fn premise_record_fragmented_across_attach() {
    // Raw bytes of one record (seq 0), captured via the kernel's own encrypt.
    let cipher = capture_record(b"fragmented-record-xyz");
    let split = cipher.len() / 2;
    assert!(split > 5, "record too small to fragment meaningfully");

    // Plain sender D, plain receiver B (we feed raw ciphertext bytes by hand
    // so we control exactly where the record is cut on the wire).
    let (mut d, mut b) = tcp_pair();

    // Queue only the HEAD of the record, then wait for it to land.
    d.write_all(&cipher[..split]).unwrap();
    let queued = wait_until_queue_stable(b.as_raw_fd());
    eprintln!(
        "[frag]     {queued}/{} bytes (partial record head) queued before RX attach",
        cipher.len()
    );

    // Attach RX while only half a record is in the queue.
    let ulp = attach_ulp(b.as_raw_fd());
    let rx = set_tls(b.as_raw_fd(), TLS_RX, 0);
    eprintln!("[frag]     TCP_ULP -> {ulp:?}, set_crypto_info(RX) -> {rx:?}");
    ulp.expect("ulp B with partial record queued");
    rx.expect("TLS_RX with partial record queued");

    // Now deliver the TAIL.
    d.write_all(&cipher[split..]).unwrap();

    let got = read_decrypted(&mut b, 21).unwrap();
    assert_eq!(
        got, b"fragmented-record-xyz",
        "kTLS did NOT reassemble a record split across the attach boundary"
    );
    eprintln!("[frag]     RECOVERED — strparser waited for the tail, no corruption\n");
}
