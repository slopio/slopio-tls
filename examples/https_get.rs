use std::net::ToSocketAddrs;
use std::time::Duration;

use popple_tls::{ServerName, client_config_dangerous_no_verification, connect, ktls_available};
use runtime::main_thread_with;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

fn main() {
    if !ktls_available() {
        eprintln!("kTLS is not available on this system.");
        std::process::exit(1);
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".into());
    let port: u16 = 443;

    // DNS lookup is sync — fine for a one-shot example.
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("no addrs");
    println!("resolved {host} -> {addr}");

    let config =
        client_config_dangerous_no_verification(Some(&[b"http/1.1"])).expect("client config");

    main_thread_with::<MediumRing, _>(async move {
        let server_name = ServerName::try_from(host.clone()).expect("server name");
        let ktls = match connect(addr, server_name, config, Duration::from_secs(5)).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        };
        println!(
            "handshake done, ALPN = {:?}",
            ktls.alpn()
                .map(|p| std::str::from_utf8(p).unwrap_or("<bin>"))
        );

        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: popple-tls/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        );

        let mut stream = ktls.into_messages::<MediumRing>();
        stream.send(req.into_bytes()).await.0.expect("send request");

        let mut total = 0usize;
        let mut first_chunk = true;
        while let Some(item) = stream.next().await {
            match item {
                Ok(frame) => {
                    let data: &[u8] = frame.as_ref();
                    total += data.len();
                    if first_chunk {
                        // Print just the response headers so the example output is short.
                        let text = String::from_utf8_lossy(data);
                        let headers_end =
                            text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
                        print!("{}", &text[..headers_end]);
                        first_chunk = false;
                    }
                }
                Err(e) => {
                    eprintln!("stream error: {e}");
                    break;
                }
            }
        }
        println!("---");
        println!("received {total} bytes total");
    });
}
