//! 1 Hz route matrix poller.
//! Fetches the binary route matrix from relay-backend GET /route_matrix,
//! parses it via RouteMatrix::read(), and stores it in AppState.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use relay_backend::route_matrix::RouteMatrix;

use crate::state::AppState;

/// Background task - polls relay-backend admin GET /route_matrix at the
/// configured interval (default 1 Hz). On success the parsed RouteMatrix is
/// stored in AppState and last_matrix_update_ms is updated.
///
/// This function loops forever and should be spawned with tokio::spawn.
pub async fn run_poller(state: Arc<AppState>) {
    let interval_ms = state.config.poll_interval_ms;
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    let url = format!("{}/route_matrix", state.config.relay_backend_admin_url);

    loop {
        ticker.tick().await;

        let response = state
            .http_client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let bytes = match response {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("poller: failed to read route_matrix body: {}", e);
                    continue;
                }
            },
            Ok(r) => {
                log::warn!("poller: route_matrix returned HTTP {}", r.status());
                continue;
            }
            Err(e) => {
                log::warn!("poller: GET {} failed: {}", url, e);
                continue;
            }
        };

        if bytes.is_empty() {
            log::debug!("poller: route_matrix response is empty, skipping");
            continue;
        }

        match RouteMatrix::read(&bytes) {
            Ok(matrix) => {
                let num_relays = matrix.relay_addresses.len();
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                *state
                    .route_matrix
                    .write()
                    .expect("route_matrix lock poisoned") = Some(matrix);
                state.last_matrix_update_ms.store(now_ms, Ordering::Relaxed);

                log::debug!("poller: route_matrix updated ({} relays)", num_relays);
            }
            Err(e) => {
                log::warn!("poller: failed to parse route_matrix: {}", e);
            }
        }
    }
}
