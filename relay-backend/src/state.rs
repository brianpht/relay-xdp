//! Shared application state.

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::config::Config;
use crate::database::RelayData;
use crate::magic::MagicRotator;
use crate::redis_client::RedisLeaderElection;
use crate::relay_manager::RelayManager;
use crate::replay::NonceCache;

pub struct AppState {
    pub config: Arc<Config>,
    pub relay_data: Arc<RelayData>,
    pub relay_manager: Arc<RelayManager>,
    pub relays_csv: RwLock<Vec<u8>>,
    pub cost_matrix_data: RwLock<Vec<u8>>,
    pub route_matrix_data: RwLock<Vec<u8>>,
    pub start_time: SystemTime,
    pub delay_completed: AtomicBool,
    pub leader_election: Arc<RedisLeaderElection>,
    pub magic_rotator: Arc<MagicRotator>,
    /// Last route matrix optimization duration in milliseconds.
    /// Updated by `update_route_matrix()` after each optimization cycle.
    pub last_optimize_ms: AtomicU64,
    /// Per-relay nonce cache for `/relay_update` replay protection. See
    /// ADR-004 / P1-01.
    pub nonce_cache: NonceCache,
    /// Number of `/relay_update` requests rejected because the
    /// `(relay_index, nonce)` tuple was already in `nonce_cache`.
    pub relay_update_replay_rejected: AtomicU64,
    /// Number of `/relay_update` requests rejected because the relay's
    /// `current_time` payload field was outside the freshness window.
    pub relay_update_clock_skew_rejected: AtomicU64,
}
