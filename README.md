# popple-tls

TLS 1.3 for the [slopio](https://github.com/slopio/slopio) runtime, with the record layer in the kernel. rustls runs the handshake, then the session keys are handed to kTLS and every record after that is encrypted and decrypted by Linux. Server and client.

## Why

Once kTLS holds the keys, a TLS socket is a plain socket to io_uring: multishot receive into the shared buffer ring, vectored sends, registered and zero-copy sends all work on plaintext, and no userspace copy or crypto sits between the ring and the wire.

What that implies:

- **TLS 1.3 only**, with the three suites kTLS implements: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. The configs pin them; nothing else is offered.
- **No session resumption.** Tickets would only add post-handshake round trips before the switch to kTLS, so none are sent.
- **No client certificates.** Server auth only.
- **Thread-per-core.** A connection lives on the worker that accepted or dialed it; nothing is `Send`.

## Status

Experimental. Not on crates.io, and the API follows slopio's, which changes without notice.

## Requirements

- Linux with the `tls` module loaded: `sudo modprobe tls`. `ktls_available()` tells you at runtime.
- **6.14 or later** for TLS 1.3 key updates in kTLS. On older kernels everything else works, but a KeyUpdate in either direction ends the connection.
- slopio's own [requirements](https://github.com/slopio/slopio/blob/main/docs/requirements.md): a 6.1 kernel at least, and io_uring allowed by the container's seccomp profile.
- A default rustls `CryptoProvider` installed before building a config.

## Usage

```toml
[dependencies]
popple-tls = { git = "ssh://git@github.com/slopio/slopio-tls.git" }
runtime = { git = "ssh://git@github.com/slopio/slopio.git" }
runtime-streams = { git = "ssh://git@github.com/slopio/slopio.git" }
rustls = "0.23"
```

An echo server:

```rust
use std::time::Duration;

use popple_tls::{ServerSettings, handshake, server_config};
use runtime::main_thread_with;
use runtime::net::MultiAccept;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 2048);

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    let (certs, key) = load_cert_and_key();
    let config = server_config(ServerSettings { certs, key, alpn_protocols: None }).unwrap();

    main_thread_with::<Ring, _>(async move {
        let mut acceptor = MultiAccept::new(9091).unwrap();
        while let Some(Ok(socket)) = acceptor.next().await {
            let Ok(tls) = handshake(socket, config.clone(), Duration::from_secs(5)).await else {
                continue;
            };
            let mut stream = tls.into_messages::<Ring>();
            while let Some(Ok(frame)) = stream.next().await {
                let (result, _) = stream.send(frame.as_ref().to_vec()).await;
                if result.is_err() {
                    break;
                }
            }
        }
    });
}
```

A client calls `connect(addr, server_name, client_config(..)?, deadline)` and gets the same kind of socket back. Both yield a `KtlsSocket`; `into_messages` turns it into a `KtlsMessages`, a `Stream` of decrypted frames with `send`, `send_vectored`, `send_fixed` and `send_fixed_zc` alongside. `split()` gives a reader and a writer for two tasks on the same thread.

## Behaviour worth knowing

- **`WouldBlock` is not an error.** It means the buffer ring every connection on the thread shares was empty when a record arrived. Nothing is lost; poll again once other connections have returned their buffers. Treating it as fatal drops healthy connections at random under load.
- **Control records are handled for you.** A peer KeyUpdate rekeys transparently, and a `request_update` is answered before the next send. Any alert from the peer ends the stream with `None`. A malformed record gets a fatal alert sent before the error surfaces.
- **Key updates are yours to start.** Nothing rekeys on a record count; call `initiate_key_update` when you want one. `tx_records` counts records sent under the current key. Do not start one while a send whose future you dropped may still be in flight.
- **Closing.** `close()` sends `close_notify`, then shuts down the write side, and `next()` keeps working until the peer finishes. Dropping the stream closes the fd without `close_notify`. `state()` reports which directions are still open.
- **Truncation is not detected.** A `close_notify` and a bare FIN both end the stream with `None`. Use a protocol with its own message framing; the doc comment on `KtlsMessages` covers why.

## Configuration

`POPPLE_POOL_MAX_LEN` caps the per-thread pool of handshake buffers (default 32). It is read at build time, so set it in your application's `.cargo/config.toml`:

```toml
[env]
POPPLE_POOL_MAX_LEN = "64"
```

## Examples

```sh
cargo run --example server               # echo server on 9091, self-signed cert
cargo run --example client               # talks to it
cargo run --example http1                # HTTP/1.1 with ALPN on 9092
cargo run --example https_get -- host    # GET / from a real host, no cert verification
```

## Testing

```sh
sudo modprobe tls
cargo test
```

The tests run real connections over loopback, some against the `openssl` CLI, so both kTLS and `openssl` must be available.
