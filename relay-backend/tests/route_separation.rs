//! Public / admin route separation - in-process verification (P1-14).
//!
//! Production binds two routers to two listeners; this test exercises each
//! router independently via `tower::oneshot` and asserts that:
//!   - `/relay_update` is reachable on the **public** router only.
//!   - Topology / cost matrix / `/metrics` endpoints are reachable on the
//!     **admin** router only.
//!   - A request for an admin path on the public router returns 404 (the
//!     route is not registered there).
//!   - A request for `/relay_update` on the admin router returns 404.
//!
//! See `docs/sessions/2026-05-04-project-audit-plan-v2.md` P1-14.

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use relay_backend::config::Config;
use relay_backend::database::RelayData;
use relay_backend::handlers::{create_admin_router, create_public_router};
use relay_backend::magic::MagicRotator;
use relay_backend::redis_client::RedisLeaderElection;
use relay_backend::relay_manager::RelayManager;
use relay_backend::state::AppState;

fn test_state() -> Arc<AppState> {
    let config = Config {
        max_jitter: 1000,
        max_packet_loss: 100.0,
        route_matrix_interval_ms: 1000,
        initial_delay: 0,
        http_port: 0,
        admin_http_port: 0,
        admin_bind_address: "127.0.0.1".to_string(),
        enable_relay_history: false,
        redis_hostname: "127.0.0.1:6379".to_string(),
        internal_address: "127.0.0.1".to_string(),
        internal_port: "0".to_string(),
        relay_backend_public_key: vec![],
        relay_backend_private_key: vec![],
        relay_data_file: None,
    };
    Arc::new(AppState {
        config: Arc::new(config),
        relay_data: Arc::new(RelayData::empty()),
        relay_manager: Arc::new(RelayManager::new(false)),
        relays_csv: RwLock::new(vec![]),
        cost_matrix_data: RwLock::new(vec![]),
        route_matrix_data: RwLock::new(vec![]),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(true),
        leader_election: Arc::new(RedisLeaderElection::new("127.0.0.1:6379", "test", 0)),
        magic_rotator: Arc::new(MagicRotator::new()),
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: relay_backend::replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    })
}

async fn status_for(app: axum::Router, method: &str, path: &str) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn public_router_serves_relay_update_and_health_only() {
    let state = test_state();
    // /relay_update with empty body returns 400 (body too small) - not 404 -
    // proving the route is registered on the public router.
    assert_eq!(
        status_for(create_public_router(state.clone()), "POST", "/relay_update").await,
        StatusCode::BAD_REQUEST
    );
    // Health checks reachable on public.
    for path in &["/health", "/lb_health", "/vm_health", "/ready", "/status"] {
        let s = status_for(create_public_router(state.clone()), "GET", path).await;
        assert!(
            s.is_success() || s == StatusCode::SERVICE_UNAVAILABLE,
            "public {} returned {}",
            path,
            s
        );
    }
    // Sensitive admin paths must NOT be reachable on the public router.
    for path in &[
        "/relays",
        "/relay_data",
        "/cost_matrix",
        "/route_matrix",
        "/costs",
        "/active_relays",
        "/metrics",
    ] {
        assert_eq!(
            status_for(create_public_router(state.clone()), "GET", path).await,
            StatusCode::NOT_FOUND,
            "public router unexpectedly served sensitive path {}",
            path
        );
    }
}

#[tokio::test]
async fn admin_router_serves_topology_and_metrics() {
    let state = test_state();
    // Topology / cost / metrics paths reachable on admin router.
    for path in &[
        "/relays",
        "/relay_data",
        "/cost_matrix",
        "/route_matrix",
        "/costs",
        "/active_relays",
        "/metrics",
    ] {
        let s = status_for(create_admin_router(state.clone()), "GET", path).await;
        assert!(
            s.is_success() || s == StatusCode::SERVICE_UNAVAILABLE,
            "admin {} returned {}",
            path,
            s
        );
    }
    // /relay_update must NOT be on the admin router (only on public).
    assert_eq!(
        status_for(create_admin_router(state.clone()), "POST", "/relay_update").await,
        StatusCode::NOT_FOUND,
        "admin router unexpectedly served /relay_update"
    );
}
