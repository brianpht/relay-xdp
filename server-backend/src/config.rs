//! Configuration from environment variables.

use anyhow::{Context, Result};

pub struct Config {
    /// HTTP port for the server-backend API. Default: 8180.
    pub http_port: u16,
    /// Base URL of the relay-backend admin endpoint (no trailing slash).
    /// Example: "http://127.0.0.1:8081"
    /// Used for GET /route_matrix and GET /bench_token.
    pub relay_backend_admin_url: String,
    /// Interval in milliseconds between route matrix polls. Default: 1000 (1 Hz).
    pub poll_interval_ms: u64,
    /// Timeout in milliseconds for the game server webhook call.
    /// POST {callback_url}/notify_session must succeed within this limit.
    /// Default: 3000 ms.
    pub webhook_timeout_ms: u64,
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

pub fn read_config() -> Result<Config> {
    let http_port = get_env_int("HTTP_PORT", 8180) as u16;
    let relay_backend_admin_url = {
        let raw = get_env_string("RELAY_BACKEND_ADMIN_URL", "http://127.0.0.1:8081");
        raw.trim_end_matches('/').to_string()
    };
    let poll_interval_ms = get_env_int("POLL_INTERVAL_MS", 1000) as u64;
    let webhook_timeout_ms = get_env_int("WEBHOOK_TIMEOUT_MS", 3000) as u64;

    // Validate relay_backend_admin_url starts with http:// or https://
    if !relay_backend_admin_url.starts_with("http://")
        && !relay_backend_admin_url.starts_with("https://")
    {
        anyhow::bail!(
            "RELAY_BACKEND_ADMIN_URL must start with http:// or https://: {}",
            relay_backend_admin_url
        );
    }

    // Validate URL parses (basic sanity - reqwest will do deeper validation at call time)
    relay_backend_admin_url
        .parse::<reqwest::Url>()
        .with_context(|| {
            format!(
                "invalid RELAY_BACKEND_ADMIN_URL: {}",
                relay_backend_admin_url
            )
        })?;

    log::info!("http_port: {}", http_port);
    log::info!("relay_backend_admin_url: {}", relay_backend_admin_url);
    log::info!("poll_interval_ms: {}", poll_interval_ms);
    log::info!("webhook_timeout_ms: {}", webhook_timeout_ms);

    Ok(Config {
        http_port,
        relay_backend_admin_url,
        poll_interval_ms,
        webhook_timeout_ms,
    })
}
