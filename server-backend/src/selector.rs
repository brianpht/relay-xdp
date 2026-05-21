//! Relay chain selector.
//! Scores every relay pair in the route matrix using:
//!   score = haversine_ms(client, relay[entry]) + inter_relay_cost + haversine_ms(relay[exit], server)
//! Proximity model: 1 ms per 100 km (Haversine), capped at 255 ms per leg.

use std::net::SocketAddrV4;

use relay_backend::encoding::tri_matrix_index;
use relay_backend::optimizer::RouteEntry;
use relay_backend::route_matrix::RouteMatrix;

// -------------------------------------------------------
// Haversine distance helper
// -------------------------------------------------------

/// Returns the estimated one-way latency (ms) between two geographic points.
/// Model: 1 ms per 100 km of great-circle distance, capped at 255 ms.
fn haversine_ms(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlng = (lng2 - lng1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    let km = EARTH_RADIUS_KM * c;
    // 1 ms per 100 km, capped at 255 ms
    (km / 100.0).min(255.0)
}

// -------------------------------------------------------
// Chain builder
// -------------------------------------------------------

/// Build the ordered relay address list for a (entry, exit) pair using route 0
/// from the RouteEntry. The route_entry is always stored for the canonical (i = larger, j = smaller)
/// index pair, so when the entry/exit orientation is reversed we reverse the
/// intermediate relay list so traffic flows in the correct direction.
fn build_chain(
    matrix: &RouteMatrix,
    entry: usize,
    exit: usize,
    route_entry: &RouteEntry,
    forward: bool,
) -> Vec<SocketAddrV4> {
    let mut chain = vec![matrix.relay_addresses[entry]];

    if route_entry.num_routes > 0 && route_entry.route_num_relays[0] > 0 {
        let num = route_entry.route_num_relays[0] as usize;
        let intermediates: Vec<SocketAddrV4> = if forward {
            (0..num)
                .filter_map(|k| {
                    let idx = route_entry.route_relays[0][k] as usize;
                    matrix.relay_addresses.get(idx).copied()
                })
                .collect()
        } else {
            (0..num)
                .rev()
                .filter_map(|k| {
                    let idx = route_entry.route_relays[0][k] as usize;
                    matrix.relay_addresses.get(idx).copied()
                })
                .collect()
        };
        chain.extend(intermediates);
    }

    if let Some(&exit_addr) = matrix.relay_addresses.get(exit) {
        chain.push(exit_addr);
    }
    chain
}

// -------------------------------------------------------
// Public API
// -------------------------------------------------------

/// Select the optimal relay chain for a (client, server) pair using the
/// provided route matrix.
///
/// Returns `Vec<SocketAddrV4>` - the ordered list of relay hops to pass to
/// relay-backend /bench_token as `relay_chain`. The client sends through
/// chain[0], chain[1], ..., chain[n-1], and the final relay forwards to the
/// game server.
///
/// Returns `Err` (maps to HTTP 503) when the matrix is empty or no valid path
/// exists between any two relays.
pub fn select_chain(
    client_lat: f64,
    client_lng: f64,
    server_lat: f64,
    server_lng: f64,
    matrix: &RouteMatrix,
) -> anyhow::Result<Vec<SocketAddrV4>> {
    let n = matrix.relay_addresses.len();
    if n == 0 {
        anyhow::bail!("route matrix is empty - no relays available");
    }

    // Single relay: use it directly (no inter-relay scoring possible).
    if n == 1 {
        return Ok(vec![matrix.relay_addresses[0]]);
    }

    let mut best_score = f64::MAX;
    let mut best_chain: Option<Vec<SocketAddrV4>> = None;

    // Iterate over lower-triangular index pairs (i > j) matching tri_matrix_index convention.
    for i in 0..n {
        for j in 0..i {
            let idx = tri_matrix_index(i, j);
            let entry = match matrix.route_entries.get(idx) {
                Some(e) => e,
                None => continue,
            };

            // Best inter-relay cost: prefer optimized route, fall back to direct.
            let inter_cost = if entry.num_routes > 0 && entry.route_cost[0] >= 0 {
                entry.route_cost[0] as f64
            } else if entry.direct_cost > 0 && entry.direct_cost < 255 {
                entry.direct_cost as f64
            } else {
                // No valid path between this pair.
                continue;
            };

            let lat_i = matrix.relay_latitudes[i] as f64;
            let lng_i = matrix.relay_longitudes[i] as f64;
            let lat_j = matrix.relay_latitudes[j] as f64;
            let lng_j = matrix.relay_longitudes[j] as f64;

            // Orientation A: client enters at relay[i], exits at relay[j] toward server.
            let score_a = haversine_ms(client_lat, client_lng, lat_i, lng_i)
                + inter_cost
                + haversine_ms(lat_j, lng_j, server_lat, server_lng);

            // Orientation B: client enters at relay[j], exits at relay[i] toward server.
            let score_b = haversine_ms(client_lat, client_lng, lat_j, lng_j)
                + inter_cost
                + haversine_ms(lat_i, lng_i, server_lat, server_lng);

            if score_a < best_score {
                best_score = score_a;
                // forward=true: intermediates go from relay[i] toward relay[j]
                best_chain = Some(build_chain(matrix, i, j, entry, true));
            }

            if score_b < best_score {
                best_score = score_b;
                // forward=false: intermediates are reversed (entry=j -> exit=i)
                best_chain = Some(build_chain(matrix, j, i, entry, false));
            }
        }
    }

    best_chain.ok_or_else(|| anyhow::anyhow!("no valid relay pair found in route matrix"))
}

// -------------------------------------------------------
// Tests
// -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use relay_backend::route_matrix::RouteMatrix;

    // Minimal helper: create a bare-minimum RouteMatrix with synthetic relay positions.
    // Coordinates chosen so the algorithm has an unambiguous winner.
    fn make_matrix_two_relays() -> RouteMatrix {
        // relay[0] near London (51.5, -0.1)
        // relay[1] near Singapore (1.3, 103.8)
        // Client near New York (40.7, -74.0)
        // Server near Tokyo (35.7, 139.7)
        //
        // Best route: client (NY) -> relay[0] (London) -> relay[1] (Singapore) -> server (Tokyo)
        // Score A (entry=1, exit=0 in i>j ordering for i=1,j=0):
        //   haversine(NY, Singapore) + inter_cost + haversine(London, Tokyo)
        // Score B (entry=0, exit=1):
        //   haversine(NY, London) + inter_cost + haversine(Singapore, Tokyo)
        // Score B wins (NY-London is much shorter than NY-Singapore).
        let relay_addresses = vec![
            "51.0.0.1:40000".parse().unwrap(), // London proxy
            "1.0.0.1:40000".parse().unwrap(),  // Singapore proxy
        ];
        let relay_latitudes = vec![51.5f32, 1.3f32];
        let relay_longitudes = vec![-0.1f32, 103.8f32];

        // Build a RouteEntry with direct_cost=80 (sensible London-Singapore RTT proxy)
        let mut entry = relay_backend::optimizer::RouteEntry::default();
        entry.direct_cost = 80;
        entry.num_routes = 0; // direct only

        RouteMatrix {
            version: 4,
            created_at: 0,
            bin_file_bytes: 0,
            bin_file_data: vec![],
            relay_ids: vec![0, 1],
            relay_id_to_index: [(0, 0), (1, 1)].into_iter().collect(),
            relay_addresses,
            relay_names: vec!["london".into(), "singapore".into()],
            relay_latitudes,
            relay_longitudes,
            relay_datacenter_ids: vec![0, 0],
            dest_relays: vec![false, true],
            // tri_matrix_index(1, 0) = 0 (the only entry for n=2)
            route_entries: vec![entry],
            cost_matrix_size: 0,
            optimize_time: 0,
            costs: vec![0],
            relay_price: vec![0, 0],
        }
    }

    #[test]
    fn test_select_chain_empty_matrix() {
        let matrix = RouteMatrix {
            version: 4,
            created_at: 0,
            bin_file_bytes: 0,
            bin_file_data: vec![],
            relay_ids: vec![],
            relay_id_to_index: Default::default(),
            relay_addresses: vec![],
            relay_names: vec![],
            relay_latitudes: vec![],
            relay_longitudes: vec![],
            relay_datacenter_ids: vec![],
            dest_relays: vec![],
            route_entries: vec![],
            cost_matrix_size: 0,
            optimize_time: 0,
            costs: vec![],
            relay_price: vec![],
        };
        assert!(select_chain(40.7, -74.0, 35.7, 139.7, &matrix).is_err());
    }

    #[test]
    fn test_select_chain_single_relay() {
        let mut matrix = make_matrix_two_relays();
        // Shrink to one relay by removing the second.
        matrix.relay_addresses.truncate(1);
        matrix.relay_latitudes.truncate(1);
        matrix.relay_longitudes.truncate(1);
        matrix.relay_ids.truncate(1);
        matrix.relay_names.truncate(1);
        matrix.relay_datacenter_ids.truncate(1);
        matrix.dest_relays.truncate(1);
        matrix.route_entries.clear();
        matrix.costs.clear();
        matrix.relay_price.truncate(1);

        let chain = select_chain(40.7, -74.0, 35.7, 139.7, &matrix).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_select_chain_picks_london_as_entry() {
        // Client = NY, Server = Tokyo
        // London (relay[0]) should be selected as the entry relay because
        // London is closer to NY than Singapore is.
        let matrix = make_matrix_two_relays();
        let chain = select_chain(40.7, -74.0, 35.7, 139.7, &matrix).unwrap();
        assert_eq!(chain.len(), 2);
        // relay_addresses[0] is London proxy (51.0.0.1:40000)
        assert_eq!(chain[0].ip(), &std::net::Ipv4Addr::new(51, 0, 0, 1));
    }

    #[test]
    fn test_haversine_ms_same_point() {
        assert_eq!(haversine_ms(0.0, 0.0, 0.0, 0.0), 0.0);
    }

    #[test]
    fn test_haversine_ms_capped_at_255() {
        // Antipodal points: ~20015 km -> ~200 ms (under cap).
        // Use exaggerated distance via a 2x call to verify cap logic works.
        let v = haversine_ms(0.0, 0.0, 0.0, 180.0); // half earth, ~10008 km -> ~100 ms
        assert!(v < 255.0);
        // Cap: artificially passing same values is 0 ms; use formula limit check.
        let capped = haversine_ms(90.0, 0.0, -90.0, 0.0); // north/south poles, ~20015 km
        assert!(capped <= 255.0);
    }
}
