//! Shared buf ring used across integration tests.
//!
//! Matches the dimensions of the historical `BufGroup::Medium`: 16 KiB
//! buffers, 2048-slot ring. Install via
//! `runtime::main_thread_with::<MediumRing, _>(...)`.

runtime::define_buf_ring!(pub MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);
