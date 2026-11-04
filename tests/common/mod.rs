//! Shared buf ring used across integration tests.
//!
//! Matches the dimensions of the historical `BufGroup::Medium`: 16 KiB
//! buffers, 2048-slot ring. Install via
//! `slopio::main_thread_with::<MediumRing, _>(...)`.
#![allow(dead_code)]

use slopio::net::{MultiAccept, SocketWrapper};
use slopio::streams::StreamExt;

slopio::define_buf_ring!(pub MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

pub async fn accept(acc: &mut MultiAccept) -> SocketWrapper {
    acc.next().await.expect("listener ended").expect("accept")
}
