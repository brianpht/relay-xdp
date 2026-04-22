fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=src/ffi/mod.rs");

    let config = cbindgen::Config::from_file("cbindgen.toml").unwrap_or_default();
    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            std::fs::create_dir_all("include").unwrap();
            bindings.write_to_file("include/relay_generated.h");
        }
        Err(e) => {
            // Don't block the build - FFI layer is still a stub.
            eprintln!("cbindgen warning (non-fatal): {}", e);
        }
    }
}
