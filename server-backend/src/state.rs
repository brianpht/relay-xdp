//! Shared application state.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use relay_backend::route_matrix::RouteMatrix;

// -------------------------------------------------------
// Game server registry
// -------------------------------------------------------

/// A game server registered with server-backend via POST /servers.
#[derive(Clone, Serialize, Deserialize)]
pub struct GameServer {
    /// Unique ID for this registration.
    pub server_id: Uuid,
    /// UDP address of the game server (IP:PORT) that relays forward game traffic to.
    pub udp_addr: String,
    /// Geographic latitude (decimal degrees) of the server.
    pub lat: f64,
    /// Geographic longitude (decimal degrees) of the server.
    pub lng: f64,
    /// Optional datacenter region label (e.g. "us-east-1").
    pub region: Option<String>,
    /// URL base for receiving session webhooks.
    /// server-backend POSTs to {callback_url}/notify_session before returning tokens.
    pub callback_url: String,
    /// Unix timestamp (seconds) when this server was registered.
    pub registered_at: u64,
}

// -------------------------------------------------------
// Active sessions
// -------------------------------------------------------

/// Minimal per-session state stored server-side.
/// Fields needed to service refresh and delete are stored here;
/// the full SessionResponse is not cached to avoid stale crypto state.
#[derive(Clone)]
pub struct StoredSession {
    /// Session ID returned by relay-backend /bench_token (embedded in route tokens).
    /// Used as the URL key for refresh/delete and reported back to the client.
    #[allow(dead_code)]
    pub session_id: u64,
    /// Registered server for this session.
    pub server_id: Uuid,
    /// The relay chain selected at session creation time.
    /// Reused on refresh so the route does not change unless the client
    /// deletes and recreates the session.
    pub relay_chain: Vec<String>,
    /// Monotonic version - starts at 1, increments on each successful refresh.
    pub session_version: u8,
    /// Unix timestamp (seconds) of session creation.
    /// Retained for future session timeout/eviction logic.
    #[allow(dead_code)]
    pub created_at: u64,
}

// -------------------------------------------------------
// AppState
// -------------------------------------------------------

pub struct AppState {
    pub config: Arc<Config>,
    /// Latest route matrix fetched from relay-backend. None until first poll completes.
    pub route_matrix: RwLock<Option<RouteMatrix>>,
    /// Unix millisecond timestamp of the last successful route matrix update.
    /// 0 = no update yet.
    pub last_matrix_update_ms: AtomicU64,
    /// In-memory game server registry.
    pub servers: RwLock<HashMap<Uuid, GameServer>>,
    /// In-memory active session map keyed by session_id.
    pub sessions: RwLock<HashMap<u64, StoredSession>>,
    /// Shared reqwest client (connection pool reuse across polling + handlers).
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: Arc<Config>, http_client: reqwest::Client) -> Self {
        AppState {
            config,
            route_matrix: RwLock::new(None),
            last_matrix_update_ms: AtomicU64::new(0),
            servers: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            http_client,
        }
    }
}
