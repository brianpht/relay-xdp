//! Prometheus metrics rendering.
//!
//! Hand-rolled Prometheus text exposition format (no external crate needed).
//! Exposes two categories:
//! - Per-relay counters (150 counters per relay, reported by relay-xdp)
//! - Backend internal metrics (active relays, uptime, optimize time, etc.)

use std::fmt::Write;
use std::sync::Arc;

use crate::constants::COUNTER_NAMES;
use crate::state::AppState;

/// Content-Type for Prometheus text exposition format.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Render all Prometheus metrics for the `/metrics` endpoint.
pub fn render_metrics(state: &Arc<AppState>) -> String {
    // Pre-allocate a generous buffer. With 1000 relays x ~80 active counters,
    // output is roughly 200-500KB.
    let mut out = String::with_capacity(256 * 1024);

    render_relay_counters(state, &mut out);
    render_backend_metrics(state, &mut out);

    out
}

/// Render per-relay counters as Prometheus gauges.
///
/// Each counter is emitted as:
///   # TYPE relay_counter_{name} gauge
///   relay_counter_{name}{relay_name="...",relay_id="..."} value
///
/// We use gauge because counter values are absolute snapshots from relay-xdp,
/// not monotonically increasing from the backend's perspective (they reset on
/// relay restart).
fn render_relay_counters(state: &Arc<AppState>, out: &mut String) {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let relay_data = &state.relay_data;
    let relays = state.relay_manager.get_relays(
        current_time,
        &relay_data.relay_ids,
        &relay_data.relay_names,
        &relay_data.relay_addresses,
    );

    // Emit TYPE headers once per metric name, then all relay values.
    // To keep output clean and Prometheus-compliant, group by metric name.
    for (i, name) in COUNTER_NAMES.iter().enumerate() {
        if name.is_empty() {
            continue;
        }

        // Check if any relay has a non-zero value for this counter (skip empty metrics).
        let has_any_value = relays.iter().any(|relay| {
            let counters = state.relay_manager.get_relay_counters(relay.id);
            i < counters.len() && counters[i] != 0
        });

        if !has_any_value {
            continue;
        }

        let metric_name = format!("relay_counter_{}", name);
        let _ = writeln!(out, "# TYPE {} gauge", metric_name);

        for relay in &relays {
            let counters = state.relay_manager.get_relay_counters(relay.id);
            let value = if i < counters.len() { counters[i] } else { 0 };

            // Escape relay_name for Prometheus label (backslash, double-quote, newline)
            let safe_name = escape_label_value(&relay.name);
            let _ = writeln!(
                out,
                "{}{{relay_name=\"{}\",relay_id=\"{:016x}\"}} {}",
                metric_name, safe_name, relay.id, value
            );
        }
    }
}

/// Render backend-internal metrics.
fn render_backend_metrics(state: &Arc<AppState>, out: &mut String) {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let active_relays = state.relay_manager.get_active_relays(current_time);
    let total_relays = state.relay_data.num_relays;

    let uptime_secs = state.start_time.elapsed().unwrap_or_default().as_secs();

    let is_leader = if state.leader_election.is_leader() {
        1
    } else {
        0
    };

    let is_ready = if state.leader_election.is_ready() {
        1
    } else {
        0
    };

    let delay_completed = if state
        .delay_completed
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        1
    } else {
        0
    };

    let optimize_ms = state
        .last_optimize_ms
        .load(std::sync::atomic::Ordering::Relaxed);

    let _ = writeln!(out, "# TYPE relay_backend_active_relays gauge");
    let _ = writeln!(out, "relay_backend_active_relays {}", active_relays.len());

    let _ = writeln!(out, "# TYPE relay_backend_total_relays gauge");
    let _ = writeln!(out, "relay_backend_total_relays {}", total_relays);

    let _ = writeln!(out, "# TYPE relay_backend_uptime_seconds gauge");
    let _ = writeln!(out, "relay_backend_uptime_seconds {}", uptime_secs);

    let _ = writeln!(out, "# TYPE relay_backend_leader gauge");
    let _ = writeln!(
        out,
        "# HELP relay_backend_leader 1 if this instance is the leader, 0 otherwise."
    );
    let _ = writeln!(out, "relay_backend_leader {}", is_leader);

    let _ = writeln!(out, "# TYPE relay_backend_ready gauge");
    let _ = writeln!(
        out,
        "# HELP relay_backend_ready 1 if delay completed and leader election ready."
    );
    let _ = writeln!(out, "relay_backend_ready {}", is_ready);

    let _ = writeln!(out, "# TYPE relay_backend_delay_completed gauge");
    let _ = writeln!(out, "relay_backend_delay_completed {}", delay_completed);

    let _ = writeln!(out, "# TYPE relay_backend_route_matrix_optimize_ms gauge");
    let _ = writeln!(
        out,
        "# HELP relay_backend_route_matrix_optimize_ms Last route matrix optimization duration in milliseconds."
    );
    let _ = writeln!(
        out,
        "relay_backend_route_matrix_optimize_ms {}",
        optimize_ms
    );
}

/// Escape a label value for Prometheus text format.
/// Per spec: backslash -> \\, double-quote -> \", newline -> \n
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

// -------------------------------------------------------
// Tests
// -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_label_value() {
        assert_eq!(escape_label_value("simple"), "simple");
        assert_eq!(escape_label_value(r#"has"quote"#), r#"has\"quote"#);
        assert_eq!(escape_label_value("has\\slash"), "has\\\\slash");
        assert_eq!(escape_label_value("has\nnewline"), "has\\nnewline");
    }

    #[test]
    fn test_counter_names_populated() {
        // Verify key counter indices are populated
        assert_eq!(COUNTER_NAMES[0], "packets_sent");
        assert_eq!(COUNTER_NAMES[1], "packets_received");
        assert_eq!(COUNTER_NAMES[6], "session_created");
        assert_eq!(COUNTER_NAMES[130], "sessions");
        assert_eq!(COUNTER_NAMES[139], "profile_samples");

        // Verify unused indices are empty
        assert_eq!(COUNTER_NAMES[9], "");
        assert_eq!(COUNTER_NAMES[25], "");
        assert_eq!(COUNTER_NAMES[140], "");
        assert_eq!(COUNTER_NAMES[149], "");
    }

    #[test]
    fn test_counter_names_count() {
        let populated = COUNTER_NAMES.iter().filter(|n| !n.is_empty()).count();
        // We have ~80 named counters out of 150 slots
        assert!(
            populated > 50,
            "expected >50 named counters, got {}",
            populated
        );
        assert!(
            populated < COUNTER_NAMES.len(),
            "some slots should be unused"
        );
    }
}
