//! HTTP handlers for the relay backend.
//! Port of `cmd/relay_backend/relay_backend.go` handler functions.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::constants::*;
use crate::magic::MagicSnapshot;
use crate::relay_update::{relay_id, RelayUpdateRequest, RelayUpdateResponse};
use crate::route_matrix::RouteMatrix;
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/relay_update", post(relay_update_handler))
        .route("/relays", get(relays_handler))
        .route("/relay_data", get(relay_data_handler))
        .route("/cost_matrix", get(cost_matrix_handler))
        .route("/route_matrix", get(route_matrix_handler))
        .route("/relay_counters/{relay_name}", get(relay_counters_handler))
        .route("/relay_history/{src}/{dest}", get(relay_history_handler))
        .route("/costs", get(costs_handler))
        .route("/active_relays", get(active_relays_handler))
        // Prometheus metrics
        .route("/metrics", get(metrics_handler))
        // Health checks
        .route("/health", get(health_handler))
        .route("/lb_health", get(lb_health_handler))
        .route("/vm_health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/status", get(status_handler))
        .with_state(state)
}

async fn relay_update_handler(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    // Upper bound check to prevent abuse (2MB)
    if body.len() > 2 * 1024 * 1024 {
        log::error!("relay update too large: {} bytes", body.len());
        return StatusCode::BAD_REQUEST.into_response();
    }

    if body.len() < 64 {
        log::error!("relay update is too small to be valid");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Decrypt if backend private key is configured (direct mode).
    // Otherwise pass through plaintext (legacy gateway proxy mode).
    let has_crypto = state.config.relay_backend_private_key.len() == 32;
    let plaintext = if has_crypto {
        match decrypt_relay_request(&state, &body) {
            Ok(p) => p,
            Err(e) => {
                log::error!("could not decrypt relay update: {}", e);
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    } else {
        body.to_vec()
    };

    let request = match RelayUpdateRequest::read(&plaintext) {
        Ok(r) => r,
        Err(e) => {
            log::error!("could not read relay update: {}", e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64;

    // Look up relay
    let relay_data = &state.relay_data;
    let addr_str = format!("{}", request.address);
    let rid = relay_id(&addr_str);

    let relay_index = match relay_data.relay_id_to_index.get(&rid) {
        Some(&idx) => idx,
        None => {
            log::error!("unknown relay id {:016x}", rid);
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    let relay_name = &relay_data.relay_names[relay_index];

    log::debug!(
        "[{}] received update for {} [{:016x}]",
        request.address,
        relay_name,
        rid
    );

    let num_samples = request.num_samples as usize;

    state.relay_manager.process_relay_update(
        current_time,
        rid,
        relay_name,
        relay_data.relay_addresses[relay_index],
        request.session_count,
        &request.relay_version,
        request.relay_flags,
        num_samples,
        &request.sample_relay_id[..num_samples],
        &request.sample_rtt[..num_samples],
        &request.sample_jitter[..num_samples],
        &request.sample_packet_loss[..num_samples],
        &request.relay_counters,
    );

    // Rotate magic bytes (cheap check, actual rotation every 10s)
    state.magic_rotator.rotate_if_needed();

    // Build response body
    let magic = state.magic_rotator.get();
    let response_bytes = build_relay_response(&state, relay_index, &request, &magic);

    (StatusCode::OK, response_bytes).into_response()
}

// -------------------------------------------------------
// Request decryption (NaCl crypto_box / SalsaBox)
// -------------------------------------------------------

/// Decrypt an encrypted relay update request.
///
/// Wire format from relay-xdp:
///   [header 8B plaintext] + [MAC 16B] + [ciphertext] + [nonce 24B]
///
/// Header: version(1) + addr_type(1) + ip(4) + port(2)
fn decrypt_relay_request(state: &AppState, body: &[u8]) -> Result<Vec<u8>, String> {
    const HEADER_SIZE: usize = 8; // version(1) + addr_type(1) + ip(4) + port(2)
    const MAC_SIZE: usize = 16;
    const NONCE_SIZE: usize = 24;
    const MIN_ENCRYPTED_SIZE: usize = HEADER_SIZE + MAC_SIZE + NONCE_SIZE + 1;

    if body.len() < MIN_ENCRYPTED_SIZE {
        return Err(format!(
            "body too small for encrypted request: {} < {}",
            body.len(),
            MIN_ENCRYPTED_SIZE
        ));
    }

    let header = &body[..HEADER_SIZE];
    let mac = &body[HEADER_SIZE..HEADER_SIZE + MAC_SIZE];
    let nonce_start = body.len() - NONCE_SIZE;
    let ciphertext = &body[HEADER_SIZE + MAC_SIZE..nonce_start];
    let nonce_bytes = &body[nonce_start..];

    // Parse address from plaintext header to look up relay's public key.
    // Header bytes: [version, addr_type, ip[0], ip[1], ip[2], ip[3], port_lo, port_hi]
    // On LE machines, relay-xdp's LE(BE(host)) produces raw IP octets (network order).
    let addr_type = header[1];
    if addr_type != IP_ADDRESS_IPV4 as u8 {
        return Err(format!("unsupported address type in header: {}", addr_type));
    }

    let ip = Ipv4Addr::new(header[2], header[3], header[4], header[5]);
    let port = u16::from_le_bytes([header[6], header[7]]);
    let addr = SocketAddrV4::new(ip, port);
    let addr_str = format!("{}", addr);
    let rid = relay_id(&addr_str);

    let relay_index = state
        .relay_data
        .relay_id_to_index
        .get(&rid)
        .ok_or_else(|| format!("unknown relay for decrypt: {:016x} ({})", rid, addr_str))?;

    if *relay_index >= state.relay_data.relay_public_keys.len() {
        return Err(format!(
            "no public key for relay index {} ({})",
            relay_index, addr_str
        ));
    }

    let relay_pk_bytes = state.relay_data.relay_public_keys[*relay_index];
    let backend_sk_bytes: [u8; 32] = state.config.relay_backend_private_key[..32]
        .try_into()
        .map_err(|_| "invalid backend private key length".to_string())?;

    // Build SalsaBox: server (backend) decrypts using client (relay) public key
    let relay_pk = crypto_box::PublicKey::from(relay_pk_bytes);
    let backend_sk = crypto_box::SecretKey::from(backend_sk_bytes);
    let salsa_box = crypto_box::SalsaBox::new(&relay_pk, &backend_sk);

    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);
    let tag = crypto_box::aead::Tag::<crypto_box::SalsaBox>::from_slice(mac);

    let mut plaintext_body = ciphertext.to_vec();

    use crypto_box::aead::AeadInPlace;
    salsa_box
        .decrypt_in_place_detached(nonce, b"", &mut plaintext_body, tag)
        .map_err(|_| "crypto_box decrypt failed - invalid key or corrupted data".to_string())?;

    // Reconstruct full plaintext: header + decrypted body
    let mut full = Vec::with_capacity(HEADER_SIZE + plaintext_body.len());
    full.extend_from_slice(header);
    full.extend_from_slice(&plaintext_body);
    Ok(full)
}

// -------------------------------------------------------
// Response building
// -------------------------------------------------------

/// Build a RelayUpdateResponse for the requesting relay.
fn build_relay_response(
    state: &AppState,
    relay_index: usize,
    request: &RelayUpdateRequest,
    magic: &MagicSnapshot,
) -> Vec<u8> {
    let relay_data = &state.relay_data;
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64;

    // Build relay list: all active relays except the requesting relay.
    let active_relays = state.relay_manager.get_active_relays(current_time);
    let requesting_rid = relay_id(&format!("{}", request.address));

    let mut relay_ids = Vec::new();
    let mut relay_addresses = Vec::new();
    let mut relay_internal = Vec::new();

    for relay in &active_relays {
        if relay.id == requesting_rid {
            continue;
        }
        relay_ids.push(relay.id);
        relay_addresses.push(relay.address);
        // Look up internal address from relay data (source of truth is JSON config).
        let has_internal = relay_data
            .relay_id_to_index
            .get(&relay.id)
            .and_then(|&idx| relay_data.relay_internal_addresses.get(idx))
            .map(|ia| ia.is_some())
            .unwrap_or(false);
        relay_internal.push(if has_internal { 1u8 } else { 0u8 });
    }

    // Relay public key: use stored key if available, otherwise zeros.
    let expected_relay_pk = if relay_index < relay_data.relay_public_keys.len() {
        relay_data.relay_public_keys[relay_index]
    } else {
        [0u8; 32]
    };

    // Backend public key
    let mut expected_backend_pk = [0u8; 32];
    if state.config.relay_backend_public_key.len() == 32 {
        expected_backend_pk.copy_from_slice(&state.config.relay_backend_public_key);
    }

    let response = RelayUpdateResponse {
        version: 1,
        timestamp: current_time as u64,
        num_relays: relay_ids.len() as u32,
        relay_ids,
        relay_addresses,
        relay_internal,
        target_version: String::new(),
        upcoming_magic: magic.upcoming_magic,
        current_magic: magic.current_magic,
        previous_magic: magic.previous_magic,
        expected_public_address: request.address,
        // Set internal address from relay data JSON config. relay-xdp only
        // validates when has_internal != 0, so 0 is safe when not configured.
        expected_has_internal_address: if relay_data
            .relay_internal_addresses
            .get(relay_index)
            .and_then(|ia| ia.as_ref())
            .is_some()
        {
            1
        } else {
            0
        },
        expected_internal_address: relay_data
            .relay_internal_addresses
            .get(relay_index)
            .and_then(|ia| *ia)
            .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        expected_relay_public_key: expected_relay_pk,
        expected_relay_backend_public_key: expected_backend_pk,
        test_token: [0u8; ENCRYPTED_ROUTE_TOKEN_BYTES],
        ping_key: magic.ping_key,
    };

    response.write()
}

async fn relays_handler(State(state): State<Arc<AppState>>) -> Response {
    let data = state.relays_csv.read().expect("relays_csv lock poisoned");
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        data.clone(),
    )
        .into_response()
}

async fn relay_data_handler(State(state): State<Arc<AppState>>) -> Response {
    let rd = &state.relay_data;

    let mut relay_ids: Vec<String> = Vec::new();
    let mut relay_addresses: Vec<String> = Vec::new();
    let mut relay_datacenter_ids: Vec<String> = Vec::new();
    let mut relay_id_to_index: Vec<String> = Vec::new();
    let mut dest_relays: Vec<String> = Vec::new();
    let mut dest_relay_names: Vec<String> = Vec::new();

    for i in 0..rd.num_relays {
        relay_ids.push(format!("{:016x}", rd.relay_ids[i]));
        relay_addresses.push(format!("{}", rd.relay_addresses[i]));
        relay_datacenter_ids.push(format!("{:016x}", rd.relay_datacenter_ids[i]));
        relay_id_to_index.push(format!("{:016x} - {}", rd.relay_ids[i], i));
        if rd.dest_relays[i] {
            dest_relays.push("1".to_string());
            dest_relay_names.push(rd.relay_names[i].clone());
        } else {
            dest_relays.push("0".to_string());
        }
    }

    let json = serde_json::json!({
        "relay_ids": relay_ids,
        "relay_names": rd.relay_names,
        "relay_addresses": relay_addresses,
        "relay_latitudes": rd.relay_latitudes,
        "relay_longitudes": rd.relay_longitudes,
        "relay_datacenter_ids": relay_datacenter_ids,
        "relay_id_to_index": relay_id_to_index,
        "dest_relays": dest_relays,
        "dest_relay_names": dest_relay_names,
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string(&json).unwrap(),
    )
        .into_response()
}

async fn cost_matrix_handler(State(state): State<Arc<AppState>>) -> Response {
    let data = state
        .cost_matrix_data
        .read()
        .expect("cost_matrix lock poisoned");
    log::debug!("cost matrix handler ({} bytes)", data.len());
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        data.clone(),
    )
        .into_response()
}

async fn route_matrix_handler(State(state): State<Arc<AppState>>) -> Response {
    let data = state
        .route_matrix_data
        .read()
        .expect("route_matrix lock poisoned");
    log::debug!("route matrix handler ({} bytes)", data.len());
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        data.clone(),
    )
        .into_response()
}

async fn relay_counters_handler(
    State(state): State<Arc<AppState>>,
    Path(relay_name): Path<String>,
) -> Response {
    let rd = &state.relay_data;

    let relay_index = rd.relay_names.iter().position(|n| n == &relay_name);
    let relay_index = match relay_index {
        Some(i) => i,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let relay_id = rd.relay_ids[relay_index];
    let counters = state.relay_manager.get_relay_counters(relay_id);

    let counter_names = get_counter_names();

    let mut rows = String::new();
    for (i, name) in counter_names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let val = if i < counters.len() { counters[i] } else { 0 };
        rows += &format!("<tr><td>{}</td><td>{}</td></tr>\n", name, val);
    }

    // HTML-escape relay_name to prevent XSS
    let safe_name = relay_name
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="1">
  <title>Relay Counters</title>
  <style>
    table, th, td {{ border: 1px solid black; border-collapse: collapse; text-align: center; padding: 10px; }}
    * {{ font-family: Courier; }}
  </style>
</head>
<body>
{}<br><br><table>
{}
</table>
</body></html>"#,
        safe_name, rows
    );

    Html(html).into_response()
}

async fn relay_history_handler(
    State(state): State<Arc<AppState>>,
    Path((src, dest)): Path<(String, String)>,
) -> Response {
    let rm_data = state
        .route_matrix_data
        .read()
        .expect("route_matrix lock poisoned");
    if rm_data.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no route matrix").into_response();
    }

    let route_matrix = match RouteMatrix::read(&rm_data) {
        Ok(rm) => rm,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error: could not read route matrix: {}", e),
            )
                .into_response();
        }
    };

    let src_index = route_matrix.relay_names.iter().position(|n| n == &src);
    let dest_index = route_matrix.relay_names.iter().position(|n| n == &dest);

    let src_index = match src_index {
        Some(i) => i,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let dest_index = match dest_index {
        Some(i) => i,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    if src_index == dest_index {
        return StatusCode::NOT_FOUND.into_response();
    }

    let source_relay_id = route_matrix.relay_ids[src_index];
    let dest_relay_id = route_matrix.relay_ids[dest_index];

    let (rtt, jitter, packet_loss) = state
        .relay_manager
        .get_history(source_relay_id, dest_relay_id);

    let response = format!(
        "history: {} -> {}\n{:?}\n{:?}\n{:?}\n",
        src, dest, rtt, jitter, packet_loss
    );

    (StatusCode::OK, [("content-type", "text/plain")], response).into_response()
}

async fn costs_handler(State(state): State<Arc<AppState>>) -> Response {
    use crate::cost_matrix::CostMatrix;
    use crate::encoding::tri_matrix_index;

    let cm_data = state
        .cost_matrix_data
        .read()
        .expect("cost_matrix lock poisoned");
    if cm_data.is_empty() {
        return (StatusCode::OK, "no cost matrix\n").into_response();
    }

    let cost_matrix = match CostMatrix::read(&cm_data) {
        Ok(cm) => cm,
        Err(e) => {
            return (StatusCode::OK, format!("no cost matrix: {}\n", e)).into_response();
        }
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64;

    let active_relay_map = state.relay_manager.get_active_relay_map(current_time);

    let mut output = String::new();
    for i in 0..cost_matrix.relay_names.len() {
        if !active_relay_map.contains_key(&cost_matrix.relay_ids[i]) {
            continue;
        }
        output += &format!("{}: ", cost_matrix.relay_names[i]);
        for j in 0..cost_matrix.relay_names.len() {
            if !active_relay_map.contains_key(&cost_matrix.relay_ids[j]) {
                continue;
            }
            if i == j {
                continue;
            }
            let index = tri_matrix_index(i, j);
            let cost = cost_matrix.costs[index];
            output += &format!("{},", cost);
        }
        output += "\n";
    }

    (StatusCode::OK, [("content-type", "text/plain")], output).into_response()
}

async fn active_relays_handler(State(state): State<Arc<AppState>>) -> Response {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64;

    let active_relays = state.relay_manager.get_active_relays(current_time);
    let mut output = String::new();
    for r in &active_relays {
        output += &format!("{}, ", r.name);
    }
    output += "\n";

    (StatusCode::OK, [("content-type", "text/plain")], output).into_response()
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn lb_health_handler(State(state): State<Arc<AppState>>) -> Response {
    let has_rm = !state
        .route_matrix_data
        .read()
        .expect("route_matrix lock poisoned")
        .is_empty();
    let elapsed = std::time::SystemTime::now()
        .duration_since(state.start_time)
        .unwrap_or_default()
        .as_secs();
    if has_rm && elapsed > state.config.initial_delay {
        (StatusCode::OK, "OK").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

async fn ready_handler(State(state): State<Arc<AppState>>) -> Response {
    let delay_done = state
        .delay_completed
        .load(std::sync::atomic::Ordering::Relaxed);
    let leader_ready = state.leader_election.is_ready();
    if delay_done && leader_ready {
        (StatusCode::OK, "OK").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

async fn status_handler(State(_state): State<Arc<AppState>>) -> &'static str {
    "relay_backend (rust)"
}

// -------------------------------------------------------
// Prometheus metrics
// -------------------------------------------------------

async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let body = crate::metrics::render_metrics(&state);
    (
        StatusCode::OK,
        [("content-type", crate::metrics::PROMETHEUS_CONTENT_TYPE)],
        body,
    )
        .into_response()
}

// -------------------------------------------------------
// Counter names (HTML display - used by /relay_counters)
// -------------------------------------------------------

fn get_counter_names() -> &'static [&'static str; NUM_RELAY_COUNTERS] {
    &COUNTER_DISPLAY_NAMES
}
