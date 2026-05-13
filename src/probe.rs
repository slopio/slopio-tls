pub fn ktls_available() -> bool {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return false;
    }
    let ulp = b"tls";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_ULP,
            ulp.as_ptr() as *const libc::c_void,
            ulp.len() as libc::socklen_t,
        )
    };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd); }
    if ret == 0 {
        return true;
    }
    matches!(err.raw_os_error(), Some(libc::ENOTCONN))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ktls_is_available_on_this_system() {
        assert!(super::ktls_available(), "kTLS must be available for tests to run");
    }
}
