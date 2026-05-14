use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

pub(crate) const BUFFER_SIZE: usize = 17 * 1024;
const POOL_MAX_LEN: usize = 32;

thread_local! {
    static POOL: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
}

pub(crate) struct PooledBuf {
    inner: Option<Box<[u8]>>,
}

impl PooledBuf {
    pub fn new() -> Self {
        let buf = POOL
            .with(|p| p.borrow_mut().pop())
            .unwrap_or_else(|| vec![0u8; BUFFER_SIZE].into_boxed_slice());
        PooledBuf { inner: Some(buf) }
    }
}

impl Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.inner.as_deref().unwrap()
    }
}

impl DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.inner.as_deref_mut().unwrap()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.inner.take() {
            POOL.with(|p| {
                let mut pool = p.borrow_mut();
                if pool.len() < POOL_MAX_LEN {
                    pool.push(buf);
                }
            });
        }
    }
}
