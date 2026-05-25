//! Integration tests for server-backend.
//!
//! Tests are self-contained: mock relay-backend and game-server webhook
//! endpoints are spun up on random loopback ports so no live services
//! are required.
//!
//! In-process requests to the server-backend router use
//! `tower::ServiceExt::oneshot`; outbound reqwest calls from the handlers
//! target the real bound mock servers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::Query,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use server_backend::handlers::create_router;
use server_backend::state::AppState;

// -------------------------------------------------------
// Fixture helpers
// -------------------------------------------------------

/// Create a minimal AppState wired to a given relay-backend admin URL.
/// No route matrix is pre-loaded; callers that need one must write directly
/// into `state.route_matrix`.
fn make_state(relay_backend_admin_url: &str) -> Arc<AppState> {
    use server_backend::config::Config;

    let config = Arc::new(Config {
        http_port: 0,
        relay_backend_admin_url: relay_backend_admin_url.trim_end_matches('/').to_string(),
        poll_interval_ms: 60_000, // disable in-test polling
        webhook_timeout_ms: 3_000,
    });

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client build failed");

    Arc::new(AppState::new(config, http_client))
}

/// Minimum fake bench_token JSON that the server-backend BenchTokenResponse
/// deserializer accepts. All hex fields are zero-padded to the correct length.
fn fake_bench_token_json(session_id: u64) -> Value {
    serde_json::json!({
        "session_id": session_id,
        "session_version": 1u8,
        "session_private_key": "00".repeat(32),
        "relay_backend_public_key": "00".repeat(32),
        "relay_address": "127.0.0.1:40000",
        "relay_secret_key": "00".repeat(32),
        "client_route_token": "00".repeat(111),
        "wire_route_token": "00".repeat(111),
        "relay_chain_tokens": ["00".repeat(111)],
        "encrypted_route_token": "00".repeat(111),
        "current_magic": "00".repeat(8),
        "ping_key": "00".repeat(32),
        "client_public_address": "192.0.2.1"
    })
}

/// Build a two-relay RouteMatrix fixture (London / Singapore) identical to
/// the one used in selector unit tests. Used to exercise the full create-
/// session path without a live relay-backend route matrix endpoint.
fn fixture_route_matrix() -> relay_backend::route_matrix::RouteMatrix {
    let relay_addresses = vec![
        "51.0.0.1:40000".parse().unwrap(),
        "1.0.0.1:40000".parse().unwrap(),
    ];
    let mut entry = relay_backend::optimizer::RouteEntry::default();
    entry.direct_cost = 80;
    entry.num_routes = 0;

    relay_backend::route_matrix::RouteMatrix {
        version: 4,
        created_at: 0,
        bin_file_bytes: 0,
        bin_file_data: vec![],
        relay_ids: vec![0, 1],
        relay_id_to_index: [(0, 0), (1, 1)].into_iter().collect(),
        relay_addresses,
        relay_names: vec!["london".into(), "singapore".into()],
        relay_latitudes: vec![51.5f32, 1.3f32],
        relay_longitudes: vec![-0.1f32, 103.8f32],
        relay_datacenter_ids: vec![0, 0],
        dest_relays: vec![false, true],
        route_entries: vec![entry],
        cost_matrix_size: 0,
        optimize_time: 0,
        costs: vec![0],
        relay_price: vec![0, 0],
    }
}

/// Spawn a mock game-server webhook endpoint on a random loopback port.
/// Accepts POST /notify_session and returns 200 OK.
/// Returns the base URL (e.g. "http://127.0.0.1:PORT").
async fn spawn_mock_game_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock game server");
    let addr = listener.local_addr().expect("local_addr");

    let app = Router::new().route(
        "/notify_session",
        post(|| async { StatusCode::OK.into_response() }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock game server serve failed");
    });

    format!("http://127.0.0.1:{}", addr.port())
}

/// Spawn a mock relay-backend admin endpoint on a random loopback port.
/// Handles GET /bench_token and returns a synthetically generated token JSON.
/// `next_session_id` is incremented on each call so refresh sessions get
/// a distinct relay session_id (mirrors real bench_token behaviour).
async fn spawn_mock_relay_backend() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock relay-backend");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");

    let counter = Arc::new(AtomicU64::new(1));

    let app = Router::new().route(
        "/bench_token",
        get({
            let counter = counter.clone();
            move |_: Query<HashMap<String, String>>| {
                let counter = counter.clone();
                async move {
                    let id = counter.fetch_add(1, Ordering::Relaxed);
                    Json(fake_bench_token_json(id)).into_response()
                }
            }
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock relay-backend serve failed");
    });

    format!("http://127.0.0.1:{}", addr.port())
}

// -------------------------------------------------------
// Helper: read response body as serde_json::Value
// -------------------------------------------------------

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("parse body as JSON")
}

// -------------------------------------------------------
// Test 1: register_and_list_servers
// -------------------------------------------------------

/// Register one game server via POST /servers, then verify it appears in
/// GET /servers. No external services needed.
#[tokio::test]
async fn test_register_and_list_servers() {
    let state = make_state("http://127.0.0.1:1"); // unused URL - no external calls needed
    let router = create_router(state);

    // POST /servers
    let register_body = serde_json::json!({
        "udp_addr": "10.0.0.1:7777",
        "lat": 37.7749,
        "lng": -122.4194,
        "region": "us-west",
        "callback_url": "http://10.0.0.1:8080"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/servers")
        .header("content-type", "application/json")
        .body(Body::from(register_body.to_string()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "POST /servers should return 201"
    );

    let register_json = body_json(resp).await;
    let server_id = register_json["server_id"]
        .as_str()
        .expect("server_id must be a string UUID");
    assert!(!server_id.is_empty(), "server_id must not be empty");

    // GET /servers
    let req = Request::builder()
        .method("GET")
        .uri("/servers")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /servers should return 200"
    );

    let list = body_json(resp).await;
    let entries = list.as_array().expect("GET /servers must return an array");
    assert_eq!(entries.len(), 1, "exactly one server should be registered");
    assert_eq!(
        entries[0]["server_id"].as_str().unwrap(),
        server_id,
        "listed server_id must match the registered one"
    );
    assert_eq!(
        entries[0]["udp_addr"].as_str().unwrap(),
        "10.0.0.1:7777",
        "udp_addr must round-trip correctly"
    );
}

// -------------------------------------------------------
// Test 2: select_chain_with_fixture_matrix
// -------------------------------------------------------

/// Verify that the selector produces the expected relay chain when the route
/// matrix is pre-populated.  Client is in New York (40.7, -74.0), server is
/// in Tokyo (35.7, 139.7).  With our two-relay fixture (London + Singapore)
/// London should be selected as the entry relay because it is geographically
/// closer to New York.
#[tokio::test]
async fn test_select_chain_with_fixture_matrix() {
    use server_backend::selector::select_chain;

    let matrix = fixture_route_matrix();

    let chain = select_chain(
        40.7, -74.0, // client: New York
        35.7, 139.7, // server: Tokyo
        &matrix,
    )
    .expect("select_chain should succeed with a valid fixture matrix");

    assert_eq!(chain.len(), 2, "chain must contain entry + exit relay");

    // relay_addresses[0] = London proxy (51.0.0.1)
    assert_eq!(
        chain[0].ip(),
        &std::net::Ipv4Addr::new(51, 0, 0, 1),
        "entry relay must be London (closest to New York)"
    );
    // relay_addresses[1] = Singapore proxy (1.0.0.1)
    assert_eq!(
        chain[1].ip(),
        &std::net::Ipv4Addr::new(1, 0, 0, 1),
        "exit relay must be Singapore (closest to Tokyo)"
    );
}

// -------------------------------------------------------
// Test 3: session_reject_unknown_server
// -------------------------------------------------------

/// POST /sessions with a server_id that was never registered must return
/// HTTP 404.  No relay-backend or webhook calls should be made.
#[tokio::test]
async fn test_session_reject_unknown_server() {
    let state = make_state("http://127.0.0.1:1");
    let router = create_router(state);

    let body = serde_json::json!({
        "server_id": "00000000-0000-0000-0000-000000000000",
        "client_lat": 40.7,
        "client_lng": -74.0
    });
    let req = Request::builder()
        .method("POST")
        .uri("/sessions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unknown server_id must return 404"
    );
}

// -------------------------------------------------------
// Test 4: session_refresh_increments_version
// -------------------------------------------------------

/// Full round-trip: create session -> refresh -> check session_version increments.
///
/// Uses a real mock relay-backend (GET /bench_token) and a real mock game-server
/// webhook (POST /notify_session), both bound to random loopback ports so no
/// live infrastructure is needed.
#[tokio::test]
async fn test_session_refresh_increments_version() {
    // Spin up mock external services.
    let relay_backend_url = spawn_mock_relay_backend().await;
    let game_server_url = spawn_mock_game_server().await;

    // Give the mock servers a moment to bind.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Build state with mock relay-backend URL.
    let state = make_state(&relay_backend_url);

    // Pre-populate route matrix so select_chain succeeds without polling.
    *state.route_matrix.write().expect("route_matrix lock") = Some(fixture_route_matrix());

    // Register the game server using the mock callback URL.
    let register_body = serde_json::json!({
        "udp_addr": "10.0.0.1:7777",
        "lat": 35.7,
        "lng": 139.7,
        "region": "ap-northeast",
        "callback_url": &game_server_url
    });
    let router = create_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/servers")
        .header("content-type", "application/json")
        .body(Body::from(register_body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let register_json = body_json(resp).await;
    let server_id = register_json["server_id"].as_str().unwrap().to_string();

    // POST /sessions - creates session (version 1).
    let session_body = serde_json::json!({
        "server_id": server_id,
        "client_lat": 40.7,
        "client_lng": -74.0
    });
    let req = Request::builder()
        .method("POST")
        .uri("/sessions")
        .header("content-type", "application/json")
        .body(Body::from(session_body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "POST /sessions should return 201"
    );
    let session_json = body_json(resp).await;
    let session_id = session_json["session_id"]
        .as_u64()
        .expect("session_id must be u64");
    let v1 = session_json["session_version"]
        .as_u64()
        .expect("session_version must be u64");
    assert_eq!(v1, 1, "initial session_version must be 1");
    assert!(
        !session_json["relay_chain"].as_array().unwrap().is_empty(),
        "relay_chain must not be empty"
    );
    assert!(
        !session_json["client_route_token"]
            .as_str()
            .unwrap()
            .is_empty(),
        "client_route_token must not be empty"
    );

    // POST /sessions/{id}/refresh - version must increment to 2.
    let refresh_body = serde_json::json!({
        "client_lat": 40.7,
        "client_lng": -74.0
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/sessions/{}/refresh", session_id))
        .header("content-type", "application/json")
        .body(Body::from(refresh_body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /sessions/{{id}}/refresh should return 200"
    );
    let refresh_json = body_json(resp).await;
    let v2 = refresh_json["session_version"]
        .as_u64()
        .expect("session_version must be u64 after refresh");
    assert_eq!(v2, 2, "session_version must increment to 2 after refresh");
    assert_eq!(
        refresh_json["session_id"].as_u64().unwrap(),
        session_id,
        "session_id must remain stable across refresh"
    );
}

// -------------------------------------------------------
// Test 5: refresh_webhook_uses_token_session_version
// -------------------------------------------------------

/// Regression test for the CLIENT_ROUTE_TIMEOUT = 20s drop in server-backend mode.
///
/// Root cause: refresh_session was sending `session_version = new_version` (the
/// server-backend's internal counter = 2, 3, ...) in the game-server webhook.
/// relay-backend embeds session_version = 1 inside every RouteToken it generates.
/// The relay's session_map is keyed by (session_id, session_version). So the key
/// created from the ROUTE_REQUEST token is {new_session_id, 1}. bench_server built
/// ROUTE_RESPONSE with the webhook's session_version = 2. Relay looked up
/// {new_session_id, 2}: not found -> dropped every ROUTE_RESPONSE ->
/// bench_client's RouteManager hit ROUTE_REQUEST_TIMEOUT (10s) and set
/// fallback_to_direct permanently.
///
/// Fix: WebhookPayload.session_version must equal token_resp.session_version
/// (i.e. the version embedded in the token from relay-backend, currently always 1).
///
/// This test verifies that both the initial /notify_session and every
/// /notify_session fired from /sessions/{id}/refresh carry session_version = 1
/// (matching the token), not the server-backend's internal counter.
#[tokio::test]
async fn test_refresh_webhook_uses_token_session_version() {
    use std::sync::Mutex;

    // Mock game server that records the session_version from each notify_session call.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture server");
    let addr = listener.local_addr().expect("local_addr");

    let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);

    let app = Router::new().route(
        "/notify_session",
        post({
            let captured_clone = captured_clone.clone();
            move |Json(body): Json<Value>| {
                let captured_clone = captured_clone.clone();
                async move {
                    if let Some(v) = body["session_version"].as_u64() {
                        captured_clone.lock().unwrap().push(v);
                    }
                    StatusCode::OK.into_response()
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("capture server failed");
    });
    let game_server_url = format!("http://127.0.0.1:{}", addr.port());

    let relay_backend_url = spawn_mock_relay_backend().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    let state = make_state(&relay_backend_url);
    *state.route_matrix.write().expect("lock") = Some(fixture_route_matrix());
    let router = create_router(state);

    // Register game server.
    let reg = serde_json::json!({
        "udp_addr": "10.0.0.2:7777",
        "lat": 0.0, "lng": 0.0,
        "callback_url": &game_server_url
    });
    let req = Request::builder()
        .method("POST")
        .uri("/servers")
        .header("content-type", "application/json")
        .body(Body::from(reg.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let reg_json = body_json(resp).await;
    let server_id = reg_json["server_id"].as_str().unwrap().to_string();

    // POST /sessions - triggers initial notify_session (should be version=1).
    let session_body = serde_json::json!({
        "server_id": server_id,
        "client_lat": 0.0, "client_lng": 0.0
    });
    let req = Request::builder()
        .method("POST")
        .uri("/sessions")
        .header("content-type", "application/json")
        .body(Body::from(session_body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let session_json = body_json(resp).await;
    let session_id = session_json["session_id"].as_u64().unwrap();

    // POST /sessions/{id}/refresh - triggers refresh notify_session.
    let refresh_body = serde_json::json!({ "client_lat": 0.0, "client_lng": 0.0 });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/sessions/{}/refresh", session_id))
        .header("content-type", "application/json")
        .body(Body::from(refresh_body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The refresh webhook is now fired in the background (tokio::spawn) so the
    // response returns before the webhook is delivered. Give the background task
    // time to make the loopback HTTP call to the mock server.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let versions = captured.lock().unwrap().clone();
    assert_eq!(
        versions.len(),
        2,
        "exactly two notify_session calls expected (create + refresh); got {:?}",
        versions
    );
    // Both webhooks must carry session_version = 1 (the version embedded in the
    // RouteToken by relay-backend). If either uses the server-backend's internal
    // counter (2 after refresh), the relay's session_map lookup will fail and
    // bench_server's ROUTE_RESPONSE will be dropped -> ROUTE_REQUEST_TIMEOUT.
    for (i, &v) in versions.iter().enumerate() {
        assert_eq!(
            v,
            1,
            "notify_session call #{} must carry session_version=1 (token version), got {}",
            i + 1,
            v
        );
    }
}
