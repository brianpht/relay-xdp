//! HTTP handlers for the relay backend.
//! Port of `cmd/relay_backend/relay_backend.go` handler functions.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::relay_update::{relay_id, RelayUpdateRequest};
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

    let request = match RelayUpdateRequest::read(&body) {
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

    StatusCode::OK.into_response()
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
    let data = state.cost_matrix_data.read().expect("cost_matrix lock poisoned");
    log::debug!("cost matrix handler ({} bytes)", data.len());
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        data.clone(),
    )
        .into_response()
}

async fn route_matrix_handler(State(state): State<Arc<AppState>>) -> Response {
    let data = state.route_matrix_data.read().expect("route_matrix lock poisoned");
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
    let rm_data = state.route_matrix_data.read().expect("route_matrix lock poisoned");
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

    let cm_data = state.cost_matrix_data.read().expect("cost_matrix lock poisoned");
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
    let has_rm = !state.route_matrix_data.read().expect("route_matrix lock poisoned").is_empty();
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
    let delay_done = state.delay_completed.load(std::sync::atomic::Ordering::Relaxed);
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
// Counter names
// -------------------------------------------------------

fn get_counter_names() -> Vec<String> {
    let mut names = vec![String::new(); crate::constants::NUM_RELAY_COUNTERS];
    names[0] = "RELAY_COUNTER_PACKETS_SENT".into();
    names[1] = "RELAY_COUNTER_PACKETS_RECEIVED".into();
    names[2] = "RELAY_COUNTER_BYTES_SENT".into();
    names[3] = "RELAY_COUNTER_BYTES_RECEIVED".into();
    names[4] = "RELAY_COUNTER_BASIC_PACKET_FILTER_DROPPED_PACKET".into();
    names[5] = "RELAY_COUNTER_ADVANCED_PACKET_FILTER_DROPPED_PACKET".into();
    names[6] = "RELAY_COUNTER_SESSION_CREATED".into();
    names[7] = "RELAY_COUNTER_SESSION_CONTINUED".into();
    names[8] = "RELAY_COUNTER_SESSION_DESTROYED".into();
    names[10] = "RELAY_COUNTER_RELAY_PING_PACKET_SENT".into();
    names[11] = "RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED".into();
    names[12] = "RELAY_COUNTER_RELAY_PING_PACKET_DID_NOT_VERIFY".into();
    names[13] = "RELAY_COUNTER_RELAY_PING_PACKET_EXPIRED".into();
    names[14] = "RELAY_COUNTER_RELAY_PING_PACKET_WRONG_SIZE".into();
    names[15] = "RELAY_COUNTER_RELAY_PONG_PACKET_SENT".into();
    names[16] = "RELAY_COUNTER_RELAY_PONG_PACKET_RECEIVED".into();
    names[17] = "RELAY_COUNTER_RELAY_PONG_PACKET_WRONG_SIZE".into();
    names[18] = "RELAY_COUNTER_RELAY_PONG_PACKET_UNKNOWN_RELAY".into();
    names[20] = "RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED".into();
    names[21] = "RELAY_COUNTER_CLIENT_PING_PACKET_WRONG_SIZE".into();
    names[22] = "RELAY_COUNTER_CLIENT_PING_PACKET_RESPONDED_WITH_PONG".into();
    names[23] = "RELAY_COUNTER_CLIENT_PING_PACKET_DID_NOT_VERIFY".into();
    names[24] = "RELAY_COUNTER_CLIENT_PING_PACKET_EXPIRED".into();
    names[30] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_RECEIVED".into();
    names[31] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_WRONG_SIZE".into();
    names[32] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_COULD_NOT_DECRYPT_ROUTE_TOKEN".into();
    names[33] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_TOKEN_EXPIRED".into();
    names[34] = "RELAY_COUNTER_ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP".into();
    names[130] = "RELAY_COUNTER_SESSIONS".into();
    names[131] = "RELAY_COUNTER_ENVELOPE_KBPS_UP".into();
    names[132] = "RELAY_COUNTER_ENVELOPE_KBPS_DOWN".into();
    names
}

