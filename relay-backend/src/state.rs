//! Shared application state.

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::config::Config;
use crate::database::RelayData;
use crate::magic::MagicRotator;
use crate::redis_client::RedisLeaderElection;
use crate::relay_manager::RelayManager;

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
}
