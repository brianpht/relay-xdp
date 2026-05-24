//! HTTP handlers for server-backend.
//!
//! Route summary:
//!   POST   /servers                - register a game server
//!   DELETE /servers/{id}           - deregister a game server
//!   GET    /servers                - list registered game servers
//!   POST   /sessions               - create a relay session for a game client
//!   POST   /sessions/{id}/refresh  - refresh tokens for an active session
//!   DELETE /sessions/{id}          - terminate a session
//!   GET    /health                 - liveness probe
//!   GET    /relay_status           - relay matrix health summary

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{connect_info::ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::selector::select_chain;
use crate::state::{AppState, GameServer, StoredSession};

// -------------------------------------------------------
// Router
// -------------------------------------------------------

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/servers", post(register_server))
        .route("/servers", get(list_servers))
        .route("/servers/{id}", delete(deregister_server))
        .route("/sessions", post(create_session))
        .route("/sessions/{id}/refresh", post(refresh_session))
        .route("/sessions/{id}", delete(delete_session))
        .route("/health", get(health_handler))
        .route("/relay_status", get(relay_status_handler))
        .with_state(state)
}

// -------------------------------------------------------
// Error helper
// -------------------------------------------------------

fn err(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

// -------------------------------------------------------
// Request / response types
// -------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterServerRequest {
    pub server_id: Option<Uuid>,
    pub udp_addr: String,
    pub lat: f64,
    pub lng: f64,
    pub region: Option<String>,
    pub callback_url: String,
}

#[derive(Serialize)]
pub struct RegisterServerResponse {
    pub server_id: Uuid,
}

#[derive(Serialize)]
pub struct ServerInfo {
    pub server_id: Uuid,
    pub udp_addr: String,
    pub region: Option<String>,
    pub registered_at: u64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub server_id: Uuid,
    pub client_lat: f64,
    pub client_lng: f64,
    /// Optional client post-NAT public IPv4. When provided, forwarded to
    /// relay-backend as the prev_address in the RouteToken so the relay's
    /// eBPF data plane can validate ROUTE_REQUEST packets from the real client
    /// IP. If omitted, ConnectInfo (peer IP) is used as fallback.
    pub client_ip: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshSessionRequest {
    /// Client latitude at refresh time - reserved for future chain re-selection.
    #[allow(dead_code)]
    pub client_lat: f64,
    /// Client longitude at refresh time - reserved for future chain re-selection.
    #[allow(dead_code)]
    pub client_lng: f64,
}

/// Full response returned to the game client on session create / refresh.
#[derive(Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: u64,
    pub session_version: u8,
    pub session_private_key: String,
    pub relay_secret_key: String,
    pub client_route_token: String,
    pub relay_chain_tokens: Vec<String>,
    pub relay_chain: Vec<String>,
    pub server_udp_addr: String,
    pub current_magic: String,
    pub ping_key: String,
    pub client_public_address: String,
}

/// JSON body forwarded to game server webhook POST {callback_url}/notify_session.
#[derive(Serialize)]
struct WebhookPayload {
    session_id: u64,
    session_version: u8,
    session_private_key_hex: String,
    // First relay address in the chain
    relay_address: String,
    ping_key_hex: String,
    current_magic_hex: String,
}

/// Subset of fields returned by relay-backend GET /bench_token.
#[derive(Deserialize)]
struct BenchTokenResponse {
    session_id: u64,
    /// Session version embedded inside the RouteToken (currently always 1 from
    /// relay-backend). Must be forwarded verbatim to game server via webhook so
    /// the ROUTE_RESPONSE session_version matches the relay's session_map entry.
    #[serde(default = "default_session_version")]
    session_version: u8,
    session_private_key: String,
    relay_secret_key: String,
    client_route_token: String,
    relay_chain_tokens: Vec<String>,
    current_magic: String,
    ping_key: String,
    client_public_address: String,
}

fn default_session_version() -> u8 {
    1
}

// -------------------------------------------------------
// GET /health
// -------------------------------------------------------

async fn health_handler() -> &'static str {
    "OK"
}

// -------------------------------------------------------
// GET /relay_status
// -------------------------------------------------------

#[derive(Serialize)]
struct RelayStatus {
    num_relays: usize,
    last_matrix_update_ms: u64,
    matrix_age_ms: u64,
}

async fn relay_status_handler(State(state): State<Arc<AppState>>) -> Response {
    let last_ms = state.last_matrix_update_ms.load(Ordering::Relaxed);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let age_ms = if last_ms == 0 { 0 } else { now_ms - last_ms };

    let num_relays = state
        .route_matrix
        .read()
        .expect("route_matrix lock poisoned")
        .as_ref()
        .map(|m| m.relay_addresses.len())
        .unwrap_or(0);

    Json(RelayStatus {
        num_relays,
        last_matrix_update_ms: last_ms,
        matrix_age_ms: age_ms,
    })
    .into_response()
}

// -------------------------------------------------------
// POST /servers
// -------------------------------------------------------

async fn register_server(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterServerRequest>,
) -> Response {
    let server_id = req.server_id.unwrap_or_else(Uuid::new_v4);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let server = GameServer {
        server_id,
        udp_addr: req.udp_addr,
        lat: req.lat,
        lng: req.lng,
        region: req.region,
        callback_url: req.callback_url.trim_end_matches('/').to_string(),
        registered_at: now,
    };

    state
        .servers
        .write()
        .expect("servers lock poisoned")
        .insert(server_id, server);

    log::info!("registered server {}", server_id);

    (
        StatusCode::CREATED,
        Json(RegisterServerResponse { server_id }),
    )
        .into_response()
}

// -------------------------------------------------------
// DELETE /servers/{id}
// -------------------------------------------------------

async fn deregister_server(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> Response {
    let removed = state
        .servers
        .write()
        .expect("servers lock poisoned")
        .remove(&id)
        .is_some();

    if removed {
        log::info!("deregistered server {}", id);
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "server not found")
    }
}

// -------------------------------------------------------
// GET /servers
// -------------------------------------------------------

async fn list_servers(State(state): State<Arc<AppState>>) -> Response {
    let list: Vec<ServerInfo> = state
        .servers
        .read()
        .expect("servers lock poisoned")
        .values()
        .map(|s| ServerInfo {
            server_id: s.server_id,
            udp_addr: s.udp_addr.clone(),
            region: s.region.clone(),
            registered_at: s.registered_at,
        })
        .collect();

    Json(list).into_response()
}

// -------------------------------------------------------
// Token minting helpers
// -------------------------------------------------------

/// Call relay-backend GET /bench_token to mint route tokens for the given chain.
/// `client_ip` - optional IPv4 of the game client; forwarded as `client_ip`
/// query param so relay-backend can embed the real client address in the
/// RouteToken instead of the backend's loopback IP.
async fn mint_tokens(
    state: &AppState,
    relay_chain: &[String],
    server_udp_addr: &str,
    client_ip: Option<&str>,
) -> anyhow::Result<BenchTokenResponse> {
    let relay_chain_param = relay_chain.join(",");
    let mut url = format!(
        "{}/bench_token?relay_chain={}&bench_server_addr={}",
        state.config.relay_backend_admin_url,
        urlencoding_simple(&relay_chain_param),
        urlencoding_simple(server_udp_addr),
    );
    if let Some(ip) = client_ip {
        url.push_str("&client_ip=");
        url.push_str(&urlencoding_simple(ip));
    }

    let resp = state
        .http_client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "bench_token returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let token_resp: BenchTokenResponse = resp.json().await?;
    Ok(token_resp)
}

/// Minimal percent-encoding for URL query parameter values.
/// Only encodes characters that are not safe in query values.
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' | b',' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
            }
        }
    }
    out
}

/// Notify game server of new session via webhook.
/// Returns Err if the webhook call fails or the server returns non-2xx.
async fn notify_game_server(
    state: &AppState,
    callback_url: &str,
    payload: &WebhookPayload,
) -> anyhow::Result<()> {
    let url = format!("{}/notify_session", callback_url);
    let resp = state
        .http_client
        .post(&url)
        .timeout(Duration::from_millis(state.config.webhook_timeout_ms))
        .json(payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "notify_session webhook returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    Ok(())
}

// -------------------------------------------------------
// POST /sessions
// -------------------------------------------------------

async fn create_session(
    State(state): State<Arc<AppState>>,
    // ConnectInfo is read as an optional extension so the handler works both
    // in production (into_make_service_with_connect_info) and in tests that
    // use tower::oneshot without ConnectInfo support.
    raw_req: axum::extract::Request,
) -> Response {
    // Extract JSON body manually after consuming the raw request.
    let (parts, body) = raw_req.into_parts();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let req: CreateSessionRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("invalid JSON: {e}"),
            )
        }
    };
    // Extract caller IPv4 from ConnectInfo extension (absent in tests).
    let peer_addr: Option<SocketAddr> = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(sa)| *sa);
    // 1. Look up registered server.
    let server = {
        let guard = state.servers.read().expect("servers lock poisoned");
        match guard.get(&req.server_id) {
            Some(s) => s.clone(),
            None => return err(StatusCode::NOT_FOUND, "server not found"),
        }
    };

    // 2. Read route matrix and select chain.
    let relay_chain = {
        let guard = state
            .route_matrix
            .read()
            .expect("route_matrix lock poisoned");
        match guard.as_ref() {
            Some(matrix) => {
                match select_chain(
                    req.client_lat,
                    req.client_lng,
                    server.lat,
                    server.lng,
                    matrix,
                ) {
                    Ok(chain) => chain
                        .into_iter()
                        .map(|addr| addr.to_string())
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        log::warn!("select_chain failed: {}", e);
                        return err(StatusCode::SERVICE_UNAVAILABLE, "no relay path available");
                    }
                }
            }
            None => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route matrix not yet available",
                );
            }
        }
    };

    // 3. Mint tokens via relay-backend /bench_token.
    //    Pass the game client's IP so relay-backend embeds it as prev_address
    //    in the RouteToken instead of this backend's loopback address.
    //    client_ip from the request body takes priority; ConnectInfo is used
    //    as fallback when the caller did not supply an explicit IP.
    let client_ipv4_str: Option<String> = req.client_ip.filter(|s| !s.is_empty()).or_else(|| {
        peer_addr.and_then(|sa| match sa.ip() {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v| v.to_string()),
        })
    });
    let token_resp = match mint_tokens(
        &state,
        &relay_chain,
        &server.udp_addr,
        client_ipv4_str.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!("mint_tokens failed: {}", e);
            return err(StatusCode::BAD_GATEWAY, "token minting failed");
        }
    };

    // Use session_version from the token (relay-backend embeds this in the RouteToken;
    // bench_server ROUTE_RESPONSE must use the same version so the relay's session_map
    // lookup succeeds). relay-backend currently always returns 1.
    let session_version = token_resp.session_version;

    // 4. Notify game server via webhook BEFORE returning tokens to client.
    //    Required: game server must call register_session() before the client
    //    sends ROUTE_REQUEST or the relay's eBPF drops the packet.
    //
    //    relay_address MUST be the LAST hop in the chain - that is the relay
    //    directly forwarding packets to the game server. The game server pings
    //    this relay so its IP:port is whitelisted there; otherwise the last
    //    relay drops every forwarded ROUTE_REQUEST + CLIENT_TO_SERVER. Mirrors
    //    bench_client relay-mode behaviour (see bench_client.rs: server_relay
    //    = relay_chain.last()).
    let relay_address = relay_chain.last().cloned().unwrap_or_default();
    let webhook = WebhookPayload {
        session_id: token_resp.session_id,
        session_version,
        session_private_key_hex: token_resp.session_private_key.clone(),
        relay_address: relay_address.clone(),
        ping_key_hex: token_resp.ping_key.clone(),
        current_magic_hex: token_resp.current_magic.clone(),
    };

    if let Err(e) = notify_game_server(&state, &server.callback_url, &webhook).await {
        log::warn!(
            "notify_game_server failed for server {}: {}",
            server.server_id,
            e
        );
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "game server webhook failed",
        );
    }

    // 5. Store session.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let stored = StoredSession {
        session_id: token_resp.session_id,
        server_id: server.server_id,
        relay_chain: relay_chain.clone(),
        session_version,
        created_at: now,
        client_ip: client_ipv4_str.clone(),
    };
    state
        .sessions
        .write()
        .expect("sessions lock poisoned")
        .insert(token_resp.session_id, stored);

    log::info!(
        "session {} created for server {} via {} relay(s)",
        token_resp.session_id,
        server.server_id,
        relay_chain.len()
    );

    // 6. Return full session response to client.
    let response = SessionResponse {
        session_id: token_resp.session_id,
        session_version,
        session_private_key: token_resp.session_private_key,
        relay_secret_key: token_resp.relay_secret_key,
        client_route_token: token_resp.client_route_token,
        relay_chain_tokens: token_resp.relay_chain_tokens,
        relay_chain,
        server_udp_addr: server.udp_addr,
        current_magic: token_resp.current_magic,
        ping_key: token_resp.ping_key,
        client_public_address: token_resp.client_public_address,
    };

    (StatusCode::CREATED, Json(response)).into_response()
}

// -------------------------------------------------------
// POST /sessions/{id}/refresh
// -------------------------------------------------------

async fn refresh_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<u64>,
    Json(_req): Json<RefreshSessionRequest>,
) -> Response {
    // 1. Load existing session.
    let stored = {
        let guard = state.sessions.read().expect("sessions lock poisoned");
        match guard.get(&session_id) {
            Some(s) => s.clone(),
            None => return err(StatusCode::NOT_FOUND, "session not found"),
        }
    };

    // 2. Load server info.
    let server = {
        let guard = state.servers.read().expect("servers lock poisoned");
        match guard.get(&stored.server_id) {
            Some(s) => s.clone(),
            None => {
                return err(
                    StatusCode::GONE,
                    "server associated with session no longer registered",
                );
            }
        }
    };

    // 3. Mint fresh tokens using the same relay chain.
    let token_resp = match mint_tokens(
        &state,
        &stored.relay_chain,
        &server.udp_addr,
        stored.client_ip.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "refresh mint_tokens failed for session {}: {}",
                session_id,
                e
            );
            return err(StatusCode::BAD_GATEWAY, "token minting failed");
        }
    };

    let new_version = stored.session_version.saturating_add(1);

    // 4. Notify game server of refreshed session (new relay session_id in tokens).
    //    relay_address = LAST hop (the relay that forwards to the game server);
    //    see create_session for rationale.
    //
    //    IMPORTANT: session_version in the webhook MUST match the version embedded
    //    inside the RouteToken (token_resp.session_version from relay-backend /bench_token).
    //    relay-backend currently always sets session_version = 1 inside the token.
    //    If we used new_version here instead, bench_server would build ROUTE_RESPONSE
    //    with session_version = new_version (2, 3, ...) but the relay's session_map
    //    entry was created from the token with session_version = 1, causing a lookup
    //    miss and the relay dropping every ROUTE_RESPONSE → CLIENT_ROUTE_TIMEOUT at 20s.
    let relay_address = stored.relay_chain.last().cloned().unwrap_or_default();
    let webhook = WebhookPayload {
        session_id: token_resp.session_id,
        session_version: token_resp.session_version,
        session_private_key_hex: token_resp.session_private_key.clone(),
        relay_address,
        ping_key_hex: token_resp.ping_key.clone(),
        current_magic_hex: token_resp.current_magic.clone(),
    };

    if let Err(e) = notify_game_server(&state, &server.callback_url, &webhook).await {
        log::warn!(
            "notify_game_server on refresh failed for session {}: {}",
            session_id,
            e
        );
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "game server webhook failed",
        );
    }

    // 5. Update stored session version.
    {
        let mut guard = state.sessions.write().expect("sessions lock poisoned");
        if let Some(s) = guard.get_mut(&session_id) {
            s.session_version = new_version;
        }
    }

    log::info!("session {} refreshed (version {})", session_id, new_version);

    // 6. Return updated session response.
    let response = SessionResponse {
        session_id,
        session_version: new_version,
        session_private_key: token_resp.session_private_key,
        relay_secret_key: token_resp.relay_secret_key,
        client_route_token: token_resp.client_route_token,
        relay_chain_tokens: token_resp.relay_chain_tokens,
        relay_chain: stored.relay_chain,
        server_udp_addr: server.udp_addr,
        current_magic: token_resp.current_magic,
        ping_key: token_resp.ping_key,
        client_public_address: token_resp.client_public_address,
    };

    Json(response).into_response()
}

// -------------------------------------------------------
// DELETE /sessions/{id}
// -------------------------------------------------------

async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<u64>,
) -> Response {
    let removed = state
        .sessions
        .write()
        .expect("sessions lock poisoned")
        .remove(&session_id)
        .is_some();

    if removed {
        log::info!("session {} deleted", session_id);
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "session not found")
    }
}
