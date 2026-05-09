//! Relay backend - Rust implementation.
//! Port of `cmd/relay_backend/relay_backend.go`.

mod config;
mod constants;
mod cost_matrix;
mod database;
mod encoding;
mod handlers;
mod magic;
mod metrics;
mod optimizer;
mod redis_client;
mod relay_manager;
mod relay_update;
mod replay;
mod route_matrix;
mod state;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::cost_matrix::{CostMatrix, COST_MATRIX_VERSION_WRITE};
use crate::database::RelayData;
use crate::magic::MagicRotator;
use crate::redis_client::RedisLeaderElection;
use crate::relay_manager::RelayManager;
use crate::route_matrix::{RouteMatrix, ROUTE_MATRIX_VERSION_WRITE};
use crate::state::AppState;

/// Spawn a long-running async task that restarts itself if it panics.
/// On panic the error is logged and the task sleeps `restart_delay` before
/// the next attempt. Normal return (Ok(())) exits without restart.
fn spawn_restart<F, Fut>(name: &'static str, restart_delay: Duration, make_fut: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let handle = tokio::spawn(make_fut());
            match handle.await {
                Ok(()) => break,
                Err(e) if e.is_panic() => {
                    log::error!(
                        "background task '{}' panicked, restarting in {:?}: {:?}",
                        name,
                        restart_delay,
                        e
                    );
                    tokio::time::sleep(restart_delay).await;
                }
                Err(_) => break, // task was cancelled
            }
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("relay_backend (rust) starting...");

    let config = config::read_config()?;
    let http_port = config.http_port;

    // Load relay data from JSON file if configured, otherwise start empty.
    let relay_data = match &config.relay_data_file {
        Some(path) => {
            log::info!("loading relay data from: {}", path);
            Arc::new(RelayData::load_json(path)?)
        }
        None => {
            log::info!("no RELAY_DATA_FILE set - starting with empty relay data");
            Arc::new(RelayData::empty())
        }
    };

    // Create relay manager
    let relay_manager = Arc::new(RelayManager::new(config.enable_relay_history));

    // Create leader election
    let leader_election = Arc::new(RedisLeaderElection::new(
        &config.redis_hostname,
        "relay_backend",
        config.initial_delay,
    ));

    // Create magic rotator (generates magic bytes + ping key for DDoS filter)
    let magic_rotator = Arc::new(MagicRotator::new());

    // Create shared state
    let state = Arc::new(AppState {
        config: Arc::new(config),
        relay_data: relay_data.clone(),
        relay_manager: relay_manager.clone(),
        relays_csv: RwLock::new(Vec::new()),
        cost_matrix_data: RwLock::new(Vec::new()),
        route_matrix_data: RwLock::new(Vec::new()),
        start_time: SystemTime::now(),
        delay_completed: AtomicBool::new(false),
        leader_election: leader_election.clone(),
        magic_rotator,
        last_optimize_ms: AtomicU64::new(0),
        nonce_cache: replay::NonceCache::new(),
        relay_update_replay_rejected: AtomicU64::new(0),
        relay_update_clock_skew_rejected: AtomicU64::new(0),
    });

    // Spawn background tasks.
    // update_initial_delay runs once - no restart needed.
    // The three loop tasks use spawn_restart so a panic is logged and the loop
    // resumes after 1 second rather than killing the backend silently.
    tokio::spawn(update_initial_delay(state.clone()));
    {
        let s = state.clone();
        spawn_restart("leader_election_loop", Duration::from_secs(1), move || {
            leader_election_loop(s.clone())
        });
    }
    {
        let s = state.clone();
        spawn_restart(
            "update_relay_backend_instance",
            Duration::from_secs(1),
            move || update_relay_backend_instance(s.clone()),
        );
    }
    {
        let s = state.clone();
        spawn_restart("update_route_matrix", Duration::from_secs(1), move || {
            update_route_matrix(s.clone())
        });
    }

    // Start web servers - two routers on two ports.
    // Public: /relay_update + health checks, bound to 0.0.0.0
    // Admin:  topology, cost/route matrices, /metrics, bound to admin_bind_address (default 127.0.0.1)
    // See P1-14 in docs/sessions/2026-05-04-project-audit-plan-v2.md.
    let public_router = handlers::create_public_router(state.clone());
    let admin_router = handlers::create_admin_router(state.clone());

    let public_addr = format!("0.0.0.0:{}", http_port);
    let admin_addr = format!(
        "{}:{}",
        state.config.admin_bind_address, state.config.admin_http_port
    );

    let public_listener = tokio::net::TcpListener::bind(&public_addr).await?;
    log::info!("relay_backend public listening on {}", public_addr);
    let admin_listener = tokio::net::TcpListener::bind(&admin_addr).await?;
    log::info!("relay_backend admin listening on {}", admin_addr);

    let public_server =
        axum::serve(public_listener, public_router).with_graceful_shutdown(shutdown_signal());
    // ConnectInfo<SocketAddr> is needed by /bench_token to detect the caller's
    // post-NAT public IPv4 (used as CLIENT_PING source_address).
    let admin_server = axum::serve(
        admin_listener,
        admin_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    let (public_result, admin_result) = tokio::join!(public_server, admin_server);
    public_result?;
    admin_result?;

    log::info!("relay_backend shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install signal handler");
    log::info!("received shutdown signal");
}

async fn update_initial_delay(state: Arc<AppState>) {
    let delay = state.config.initial_delay;
    tokio::time::sleep(Duration::from_secs(delay)).await;
    state.delay_completed.store(true, Ordering::Relaxed);
    log::debug!("initial delay completed");
}

async fn leader_election_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        state.leader_election.update().await;
    }
}

async fn update_relay_backend_instance(state: Arc<AppState>) {
    let redis_url = state.config.redis_hostname.clone();
    let internal_address = state.config.internal_address.clone();
    let internal_port = state.config.internal_port.clone();

    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let client = match redis::Client::open(format!("redis://{}", redis_url)) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("redis connect error: {}", e);
                continue;
            }
        };
        let mut con = match client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("redis connection error: {}", e);
                continue;
            }
        };

        let minutes = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs()
            / 60;

        let key = format!("relay-backends-{}", minutes);
        let field = format!("{}:{}", internal_address, internal_port);

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg(&field)
            .arg("1")
            .query_async(&mut con)
            .await;

        log::debug!("updated relay backend instance");
    }
}

async fn update_route_matrix(state: Arc<AppState>) {
    let interval_ms = state.config.route_matrix_interval_ms;
    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

    loop {
        interval.tick().await;

        let time_start = std::time::Instant::now();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as i64;

        let relay_data = &state.relay_data;

        if relay_data.num_relays == 0 {
            log::debug!("no relays loaded, skipping route matrix update");
            continue;
        }

        // Build relays CSV
        let relays_csv = state.relay_manager.get_relays_csv(
            current_time,
            &relay_data.relay_ids,
            &relay_data.relay_names,
            &relay_data.relay_addresses,
        );

        // Build cost matrix
        let costs = state.relay_manager.get_costs(
            current_time,
            &relay_data.relay_ids,
            state.config.max_jitter as f32,
            state.config.max_packet_loss,
        );

        let relay_price = relay_data.relay_price.clone();

        let cost_matrix = CostMatrix {
            version: COST_MATRIX_VERSION_WRITE,
            relay_ids: relay_data.relay_ids.clone(),
            relay_addresses: relay_data.relay_addresses.clone(),
            relay_names: relay_data.relay_names.clone(),
            relay_latitudes: relay_data.relay_latitudes.clone(),
            relay_longitudes: relay_data.relay_longitudes.clone(),
            relay_datacenter_ids: relay_data.relay_datacenter_ids.clone(),
            dest_relays: relay_data.dest_relays.clone(),
            costs: costs.clone(),
            relay_price: relay_price.clone(),
        };

        let cost_matrix_data = match cost_matrix.write() {
            Ok(d) => d,
            Err(e) => {
                log::error!("could not write cost matrix: {}", e);
                continue;
            }
        };

        // Optimize
        let num_relays = relay_data.num_relays;
        let num_cpus = num_cpus::get().max(1);
        let num_segments = if num_cpus < num_relays {
            (num_relays / 5).max(1)
        } else {
            num_relays.max(1)
        };

        // Optimize. Wrap in catch_unwind so a panic in the optimizer (e.g. from
        // a thread spawned inside optimize2) skips one iteration rather than
        // unwinding the whole task. spawn_restart at the call site provides the
        // outer safety net if this catch_unwind is somehow bypassed.
        let route_entries = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            optimizer::optimize2(
                num_relays,
                num_segments,
                &costs,
                &relay_price,
                &relay_data.relay_datacenter_ids,
                &relay_data.dest_relays,
            )
        })) {
            Ok(entries) => entries,
            Err(_) => {
                log::error!("optimizer::optimize2 panicked - skipping route matrix update for this iteration");
                continue;
            }
        };

        let optimize_duration = time_start.elapsed();

        state
            .last_optimize_ms
            .store(optimize_duration.as_millis() as u64, Ordering::Relaxed);

        log::debug!(
            "updated route matrix: {} relays in {}ms",
            num_relays,
            optimize_duration.as_millis()
        );

        // Create route matrix
        let route_matrix = RouteMatrix {
            version: ROUTE_MATRIX_VERSION_WRITE,
            created_at: current_time as u64,
            relay_ids: relay_data.relay_ids.clone(),
            relay_id_to_index: relay_data
                .relay_ids
                .iter()
                .enumerate()
                .map(|(i, &id)| (id, i as i32))
                .collect(),
            relay_addresses: relay_data.relay_addresses.clone(),
            relay_names: relay_data.relay_names.clone(),
            relay_latitudes: relay_data.relay_latitudes.clone(),
            relay_longitudes: relay_data.relay_longitudes.clone(),
            relay_datacenter_ids: relay_data.relay_datacenter_ids.clone(),
            dest_relays: relay_data.dest_relays.clone(),
            route_entries,
            bin_file_bytes: relay_data.database_bin_file.len() as i32,
            bin_file_data: relay_data.database_bin_file.clone(),
            cost_matrix_size: cost_matrix_data.len() as u32,
            optimize_time: optimize_duration.as_millis() as u32,
            costs: costs.clone(),
            relay_price: relay_price.clone(),
        };

        let route_matrix_data = match route_matrix.write() {
            Ok(d) => d,
            Err(e) => {
                log::error!("could not write route matrix: {}", e);
                continue;
            }
        };

        // Store in Redis
        state.leader_election.store("relays", &relays_csv).await;
        state
            .leader_election
            .store("cost_matrix", &cost_matrix_data)
            .await;
        state
            .leader_election
            .store("route_matrix", &route_matrix_data)
            .await;

        // Load leader data from Redis
        let relays_csv_final = state.leader_election.load("relays").await;
        let cost_matrix_final = state.leader_election.load("cost_matrix").await;
        let route_matrix_final = state.leader_election.load("route_matrix").await;

        // Update shared state
        if let Some(d) = relays_csv_final {
            *state.relays_csv.write().expect("relays_csv lock poisoned") = d;
        }
        if let Some(d) = cost_matrix_final {
            *state
                .cost_matrix_data
                .write()
                .expect("cost_matrix lock poisoned") = d;
        }
        if let Some(d) = route_matrix_final {
            *state
                .route_matrix_data
                .write()
                .expect("route_matrix lock poisoned") = d;
        }

        // Analyze
        let analysis = route_matrix.analyze();
        log::debug!(
            "route matrix analysis: total_routes={}, avg_routes={:.1}, avg_length={:.1}",
            analysis.total_routes,
            analysis.average_num_routes,
            analysis.average_route_length,
        );
    }
}
