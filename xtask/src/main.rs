//! Build helper for the relay-xdp project.
//!
//! For Phase 2a, we use the existing C-compiled relay_xdp.o.
//! This xtask can build it from the C source if needed.

use std::process::Command;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf()?,
        Some("build-ebpf-rust") => build_ebpf_rust()?,
        Some("func-test") => func_test()?,
        Some("help") | None => {
            println!("Usage: cargo xtask <command>");
            println!();
            println!("Commands:");
            println!("  build-ebpf       Build the XDP eBPF program from C source (legacy)");
            println!("  build-ebpf-rust  Build the Rust XDP eBPF program (requires nightly)");
            println!("  func-test        Run functional parity tests (RELAY_NO_BPF mode)");
            println!("  help             Show this help");
        }
        Some(cmd) => {
            eprintln!("Unknown command: {cmd}");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Build relay_xdp.o from the C source using clang.
fn build_ebpf() -> anyhow::Result<()> {
    let xdp_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("xdp");

    println!(
        "Building relay_xdp.o from C source in {}",
        xdp_dir.display()
    );

    let status = Command::new("make")
        .arg("relay_xdp.o")
        .current_dir(&xdp_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build relay_xdp.o");
    }

    // Copy to relay-xdp project root
    let src = xdp_dir.join("relay_xdp.o");
    let dst = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("relay_xdp.o");

    std::fs::copy(&src, &dst)?;
    println!("Copied {} -> {}", src.display(), dst.display());

    Ok(())
}

/// Build the Rust eBPF program targeting bpfel-unknown-none.
fn build_ebpf_rust() -> anyhow::Result<()> {
    let ebpf_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("relay-xdp-ebpf");

    println!("Building Rust eBPF program in {}", ebpf_dir.display());

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--release",
        ])
        .current_dir(&ebpf_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build Rust eBPF program");
    }

    // The output is at target/bpfel-unknown-none/release/relay-xdp-ebpf
    let src = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("relay-xdp-ebpf");
    let dst = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("relay_xdp_rust.o");

    if src.exists() {
        std::fs::copy(&src, &dst)?;
        println!("Copied {} -> {}", src.display(), dst.display());
    } else {
        println!("Warning: eBPF binary not found at {}", src.display());
    }

    Ok(())
}

/// Run functional parity tests (no BPF required).
fn func_test() -> anyhow::Result<()> {
    let workspace_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    println!(
        "Running functional parity tests in {}",
        workspace_dir.display()
    );

    let status = Command::new("cargo")
        .args([
            "test",
            "--test",
            "func_parity",
            "--",
            "--ignored",
            "--test-threads=1",
        ])
        .current_dir(workspace_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("Functional parity tests failed");
    }

    Ok(())
}
