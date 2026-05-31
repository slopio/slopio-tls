use std::time::Duration;

use popple_tls::{
    ServerName, client_config_dangerous_no_verification, connect, ktls_available,
};
use runtime::main_thread_with;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(MediumRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

fn main() {
    if !ktls_available() {
        eprintln!("kTLS is not available on this system.");
        eprintln!("Try: sudo modprobe tls");
        std::process::exit(1);
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default crypto provider");

    let config = client_config_dangerous_no_verification(None).expect("client config");

    println!("connecting to 127.0.0.1:9091 (matches examples/server.rs)");

    main_thread_with::<MediumRing, _>(async move {
        let server_name = ServerName::try_from("localhost").expect("server name");
        let ktls = match connect(
            "127.0.0.1:9091".parse().unwrap(),
            server_name,
            config,
            Duration::from_secs(10),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        };
        println!("handshake done");

        let mut stream = ktls.into_messages::<MediumRing>();
        stream
            .send(b"hello from popple client\n")
            .await
            .0
            .expect("send");

        match stream.next().await {
            Some(Ok(frame)) => {
                let data: &[u8] = frame.as_ref();
                println!(
                    "recv {} bytes: {:?}",
                    data.len(),
                    std::str::from_utf8(data).unwrap_or("<non-utf8>")
                );
            }
            Some(Err(e)) => eprintln!("stream error: {e}"),
            None => eprintln!("stream ended before reply"),
        }
    });
}
