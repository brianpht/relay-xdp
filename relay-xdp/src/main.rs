//! Network Next XDP Relay - Rust implementation using Aya.
//!
//! Loads the C-compiled relay_xdp.o eBPF program and runs the userspace
//! control plane (main thread + ping thread).

mod bpf;
mod config;
mod encoding;
mod main_thread;
mod manager;
mod packet_filter;
mod ping_history;
mod ping_thread;
mod platform;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use relay_xdp::RELAY_VERSION;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    platform::init();

    println!("Network Next Relay ({RELAY_VERSION})");

    // Setup signal handlers
    let quit = Arc::new(AtomicBool::new(false));
    let clean_shutdown = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGINT, quit.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, clean_shutdown.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, clean_shutdown.clone())?;

    println!("Reading config");

    let config = Arc::new(config::read_config().context("failed to read config")?);

    // Determine XDP object file path (default is now the Rust-compiled one)
    let xdp_obj_path = std::env::var("RELAY_XDP_OBJ")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("relay_xdp_rust.o"));

    // Check for no-BPF mode (for functional testing without root/BPF)
    let no_bpf = std::env::var("RELAY_NO_BPF")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let bpf = if no_bpf {
        println!("Running in no-BPF mode (RELAY_NO_BPF=1)");
        None
    } else {
        println!("Initializing BPF");

        let bpf_ctx = bpf::BpfContext::init(
            &xdp_obj_path,
            config.relay_public_address,
            config.relay_internal_address,
        )
        .context("failed to initialize BPF")?;

        Some(Arc::new(Mutex::new(bpf_ctx)))
    };

    println!("Starting relay");

    let control_queue = main_thread::new_queue();
    let stats_queue = main_thread::new_queue();

    // Create ping thread
    let mut ping = ping_thread::PingThread::new(
        config.clone(),
        bpf.clone(),
        control_queue.clone(),
        stats_queue.clone(),
        quit.clone(),
    )
    .context("failed to create ping thread")?;

    let ping_handle = std::thread::Builder::new()
        .name("ping".to_string())
        .spawn(move || {
            ping.run();
        })
        .context("failed to start ping thread")?;

    // Run main thread (blocks until quit)
    let mut main_thread = main_thread::MainThread::new(
        config.clone(),
        bpf.clone(),
        control_queue,
        stats_queue,
        quit.clone(),
        clean_shutdown.clone(),
    )
    .context("failed to create main thread")?;

    let result = main_thread.run();

    // Wait for ping thread
    println!("Waiting for ping thread");
    let _ = ping_handle.join();

    println!("Relay shutdown complete");

    result
}

