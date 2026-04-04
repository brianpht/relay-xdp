//! Configuration from environment variables.

use anyhow::{bail, Context, Result};

pub struct Config {
    pub max_jitter: i32,
    pub max_packet_loss: f32,
    pub route_matrix_interval_ms: u64,
    pub initial_delay: u64,
    pub http_port: u16,
    pub enable_relay_history: bool,
    pub redis_hostname: String,
    pub internal_address: String,
    pub internal_port: String,
    pub relay_backend_public_key: Vec<u8>,
    pub relay_backend_private_key: Vec<u8>,
}

fn get_env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn get_env_int(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn get_env_float(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn get_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(default)
}

fn get_env_base64(name: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let value = std::env::var(name).with_context(|| format!("{} not set", name))?;
    if value.is_empty() {
        bail!("{} is empty", name);
    }
    base64::engine::general_purpose::STANDARD
        .decode(&value)
        .with_context(|| format!("invalid base64 for {}", name))
}

pub fn read_config() -> Result<Config> {
    let max_jitter = get_env_int("MAX_JITTER", 1000) as i32;
    let max_packet_loss = get_env_float("MAX_PACKET_LOSS", 100.0) as f32;
    let route_matrix_interval_ms = get_env_int("ROUTE_MATRIX_INTERVAL_MS", 1000) as u64;
    let initial_delay = get_env_int("INITIAL_DELAY", 15) as u64;
    let http_port = get_env_int("HTTP_PORT", 80) as u16;
    let enable_relay_history = get_env_bool("ENABLE_RELAY_HISTORY", false);
    let redis_hostname = get_env_string("REDIS_HOSTNAME", "127.0.0.1:6379");
    let internal_address = get_env_string("INTERNAL_ADDRESS", "127.0.0.1");
    let internal_port = get_env_string("INTERNAL_PORT", &http_port.to_string());

    let relay_backend_public_key = get_env_base64("RELAY_BACKEND_PUBLIC_KEY")
        .unwrap_or_default();
    let relay_backend_private_key = get_env_base64("RELAY_BACKEND_PRIVATE_KEY")
        .unwrap_or_default();

    if relay_backend_public_key.is_empty() {
        log::warn!("RELAY_BACKEND_PUBLIC_KEY not set — relay update crypto disabled");
    }
    if relay_backend_private_key.is_empty() {
        log::warn!("RELAY_BACKEND_PRIVATE_KEY not set — relay update crypto disabled");
    }

    log::info!("max_jitter: {}", max_jitter);
    log::info!("max_packet_loss: {:.1}", max_packet_loss);
    log::info!("route_matrix_interval_ms: {}", route_matrix_interval_ms);
    log::info!("initial_delay: {}", initial_delay);
    log::info!("http_port: {}", http_port);
    log::info!("enable_relay_history: {}", enable_relay_history);
    log::info!("redis_hostname: {}", redis_hostname);
    log::info!("internal_address: {}", internal_address);

    Ok(Config {
        max_jitter,
        max_packet_loss,
        route_matrix_interval_ms,
        initial_delay,
        http_port,
        enable_relay_history,
        redis_hostname,
        internal_address,
        internal_port,
        relay_backend_public_key,
        relay_backend_private_key,
    })
}

