//! server-backend - matchmaking / relay session broker.
//!
//! Responsibilities:
//!   - Accept game server registrations (POST /servers).
//!   - Compute the optimal relay chain for each game session using the
//!     route matrix fetched from relay-backend.
//!   - Delegate token minting to relay-backend GET /bench_token.
//!   - Notify the game server via webhook before returning tokens to the client.

use std::sync::Arc;
use std::time::Duration;

use crate::config::read_config;
use crate::poller::run_poller;
use crate::state::AppState;

mod config;
mod handlers;
mod poller;
mod selector;
mod state;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("server-backend starting...");

    let config = Arc::new(read_config()?);
    let http_port = config.http_port;

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let state = Arc::new(AppState::new(config, http_client));

    // Spawn 1 Hz route matrix poller.
    {
        let s = state.clone();
        tokio::spawn(async move {
            run_poller(s).await;
        });
    }

    // Build and start HTTP server.
    let router = handlers::create_router(state);
    let addr = format!("0.0.0.0:{}", http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    log::info!("server-backend listening on {}", addr);

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    log::info!("server-backend shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install signal handler");
    log::info!("received shutdown signal");
}
