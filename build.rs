use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=SLOPIO_TLS_POOL_MAX_LEN");

    let pool_max_len: usize = match env::var("SLOPIO_TLS_POOL_MAX_LEN") {
        Ok(v) => v
            .parse()
            .expect("SLOPIO_TLS_POOL_MAX_LEN must be a non-negative integer"),
        Err(_) => 32,
    };

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("pool_config.rs");
    fs::write(
        &dest,
        format!("pub(crate) const POOL_MAX_LEN: usize = {pool_max_len};\n"),
    )
    .expect("failed to write pool_config.rs");
}
