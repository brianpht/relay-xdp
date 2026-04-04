//! Route optimization (Optimize2).
//! Port of `modules/core/core.go` Optimize2 function.


use crate::constants::*;
use crate::encoding::{tri_matrix_index, tri_matrix_length};

// -------------------------------------------------------
// RouteEntry
// -------------------------------------------------------

#[derive(Clone)]
pub struct RouteEntry {
    pub direct_cost: i32,
    pub num_routes: i32,
    pub route_cost: [i32; MAX_ROUTES_PER_ENTRY],
    pub route_price: [i32; MAX_ROUTES_PER_ENTRY],
    pub route_hash: [u32; MAX_ROUTES_PER_ENTRY],
    pub route_num_relays: [i32; MAX_ROUTES_PER_ENTRY],
    pub route_relays: [[i32; MAX_ROUTE_RELAYS]; MAX_ROUTES_PER_ENTRY],
}

impl Default for RouteEntry {
    fn default() -> Self {
        RouteEntry {
            direct_cost: 0,
            num_routes: 0,
            route_cost: [0; MAX_ROUTES_PER_ENTRY],
            route_price: [0; MAX_ROUTES_PER_ENTRY],
            route_hash: [0; MAX_ROUTES_PER_ENTRY],
            route_num_relays: [0; MAX_ROUTES_PER_ENTRY],
            route_relays: [[0; MAX_ROUTE_RELAYS]; MAX_ROUTES_PER_ENTRY],
        }
    }
}

// -------------------------------------------------------
// RouteHash
// -------------------------------------------------------

pub fn route_hash(relays: &[i32]) -> u32 {
    const PRIME: u32 = 16777619;
    let mut hash: u32 = 0;
    for &r in relays {
        let r = r as u32;
        hash ^= (r >> 24) & 0xFF;
        hash = hash.wrapping_mul(PRIME);
        hash ^= (r >> 16) & 0xFF;
        hash = hash.wrapping_mul(PRIME);
        hash ^= (r >> 8) & 0xFF;
        hash = hash.wrapping_mul(PRIME);
        hash ^= r & 0xFF;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// -------------------------------------------------------
// RouteManager (local helper for route accumulation)
// -------------------------------------------------------

struct RouteManager {
    num_routes: usize,
    route_cost: [i32; MAX_ROUTES_PER_ENTRY],
    route_price: [i32; MAX_ROUTES_PER_ENTRY],
    route_hash: [u32; MAX_ROUTES_PER_ENTRY],
    route_num_relays: [i32; MAX_ROUTES_PER_ENTRY],
    route_relays: [[i32; MAX_ROUTE_RELAYS]; MAX_ROUTES_PER_ENTRY],
}

impl RouteManager {
    fn new() -> Self {
        RouteManager {
            num_routes: 0,
            route_cost: [0; MAX_ROUTES_PER_ENTRY],
            route_price: [0; MAX_ROUTES_PER_ENTRY],
            route_hash: [0; MAX_ROUTES_PER_ENTRY],
            route_num_relays: [0; MAX_ROUTES_PER_ENTRY],
            route_relays: [[0; MAX_ROUTE_RELAYS]; MAX_ROUTES_PER_ENTRY],
        }
    }

    fn add_route(&mut self, cost: i32, price: i32, relays: &[i32]) {
        if cost >= 255 {
            return;
        }

        // Filter out loops
        let mut seen = [false; 1024]; // MAX_RELAYS
        for &r in relays {
            let idx = r as usize;
            if idx < seen.len() {
                if seen[idx] {
                    return;
                }
                seen[idx] = true;
            }
        }

        let hash = route_hash(relays);

        if self.num_routes == 0 {
            self.num_routes = 1;
            self.route_cost[0] = cost;
            self.route_price[0] = price;
            self.route_hash[0] = hash;
            self.route_num_relays[0] = relays.len() as i32;
            for (i, &r) in relays.iter().enumerate() {
                self.route_relays[0][i] = r;
            }
        } else if self.num_routes < MAX_ROUTES_PER_ENTRY {
            // Check for duplicate hash
            for k in 0..self.num_routes {
                if hash == self.route_hash[k] {
                    return;
                }
            }

            if cost >= self.route_cost[self.num_routes - 1] {
                // Append
                let idx = self.num_routes;
                self.route_cost[idx] = cost;
                self.route_price[idx] = price;
                self.route_hash[idx] = hash;
                self.route_num_relays[idx] = relays.len() as i32;
                for (i, &r) in relays.iter().enumerate() {
                    self.route_relays[idx][i] = r;
                }
                self.num_routes += 1;
            } else {
                // Insert in sorted position
                let mut insert_idx = self.num_routes - 1;
                while insert_idx > 0 && cost <= self.route_cost[insert_idx - 1] {
                    insert_idx -= 1;
                }
                self.num_routes += 1;
                for k in (insert_idx + 1..self.num_routes).rev() {
                    self.route_cost[k] = self.route_cost[k - 1];
                    self.route_price[k] = self.route_price[k - 1];
                    self.route_hash[k] = self.route_hash[k - 1];
                    self.route_num_relays[k] = self.route_num_relays[k - 1];
                    self.route_relays[k] = self.route_relays[k - 1];
                }
                self.route_cost[insert_idx] = cost;
                self.route_price[insert_idx] = price;
                self.route_hash[insert_idx] = hash;
                self.route_num_relays[insert_idx] = relays.len() as i32;
                for (i, &r) in relays.iter().enumerate() {
                    self.route_relays[insert_idx][i] = r;
                }
            }
        } else {
            // Full — only insert if better than worst
            if cost >= self.route_cost[self.num_routes - 1] {
                return;
            }

            for k in 0..self.num_routes {
                if hash == self.route_hash[k] {
                    return;
                }
            }

            let mut insert_idx = self.num_routes - 1;
            while insert_idx > 0 && cost <= self.route_cost[insert_idx - 1] {
                insert_idx -= 1;
            }

            for k in (insert_idx + 1..self.num_routes).rev() {
                self.route_cost[k] = self.route_cost[k - 1];
                self.route_price[k] = self.route_price[k - 1];
                self.route_hash[k] = self.route_hash[k - 1];
                self.route_num_relays[k] = self.route_num_relays[k - 1];
                self.route_relays[k] = self.route_relays[k - 1];
            }

            self.route_cost[insert_idx] = cost;
            self.route_price[insert_idx] = price;
            self.route_hash[insert_idx] = hash;
            self.route_num_relays[insert_idx] = relays.len() as i32;
            for (i, &r) in relays.iter().enumerate() {
                self.route_relays[insert_idx][i] = r;
            }
        }
    }
}

// -------------------------------------------------------
// Indirect struct for phase 1
// -------------------------------------------------------

#[derive(Clone, Copy)]
struct Indirect {
    relay: i32,
    cost: u32,
}

// -------------------------------------------------------
// Optimize2
// -------------------------------------------------------

pub fn optimize2(
    num_relays: usize,
    num_segments: usize,
    cost: &[u8],
    relay_price: &[u8],
    _relay_datacenter: &[u64],
    destination_relay: &[bool],
) -> Vec<RouteEntry> {
    if num_relays == 0 {
        return vec![];
    }

    // Phase 1: Build indirect matrix (parallel per segment)
    let mut flat_indirect: Vec<Vec<Vec<Indirect>>> = vec![vec![vec![]; num_relays]; num_relays];

    // Compute segment boundaries
    let mut segment_ranges: Vec<(usize, usize)> = Vec::with_capacity(num_segments);
    for segment in 0..num_segments {
        let start_index = segment * num_relays / num_segments;
        let end_index = if segment == num_segments - 1 {
            num_relays - 1
        } else {
            (segment + 1) * num_relays / num_segments - 1
        };
        segment_ranges.push((start_index, end_index));
    }

    // Split flat_indirect into non-overlapping mutable slices per segment
    {
        let mut remaining = flat_indirect.as_mut_slice();
        let mut slices: Vec<&mut [Vec<Vec<Indirect>>]> = Vec::with_capacity(num_segments);
        for (seg_idx, &(start, end)) in segment_ranges.iter().enumerate() {
            let seg_len = end - start + 1;
            if seg_idx == 0 {
                let (before, rest) = remaining.split_at_mut(start + seg_len);
                slices.push(&mut before[start..]);
                remaining = rest;
            } else {
                let prev_end = segment_ranges[seg_idx - 1].1;
                let gap = start - prev_end - 1;
                let (_skip, rest) = remaining.split_at_mut(gap);
                let (chunk, rest2) = rest.split_at_mut(seg_len);
                slices.push(chunk);
                remaining = rest2;
            }
        }

        std::thread::scope(|s| {
            let mut handles = Vec::new();

            for (seg_idx, slice) in slices.into_iter().enumerate() {
                let (start_index, end_index) = segment_ranges[seg_idx];
                let cost_ref = cost;
                let dest_ref = destination_relay;

                handles.push(s.spawn(move || {
                    let mut working = vec![Indirect { relay: 0, cost: 0 }; num_relays];

                    for i in start_index..=end_index {
                        let row = &mut slice[i - start_index];
                        for j in 0..num_relays {
                            if i == j {
                                continue;
                            }
                            if !dest_ref[i] && !dest_ref[j] {
                                continue;
                            }

                            let ij_index = tri_matrix_index(i, j);
                            let cost_direct = cost_ref[ij_index] as u32;
                            let mut num_routes = 0;

                            for x in 0..num_relays {
                                if x == i || x == j {
                                    continue;
                                }
                                let ix_cost = cost_ref[tri_matrix_index(i, x)] as u32;
                                let xj_cost = cost_ref[tri_matrix_index(x, j)] as u32;
                                let indirect_cost = ix_cost + xj_cost;
                                if indirect_cost >= cost_direct {
                                    continue;
                                }
                                working[num_routes] = Indirect {
                                    relay: x as i32,
                                    cost: indirect_cost,
                                };
                                num_routes += 1;
                            }

                            let result = if num_routes > MAX_INDIRECTS {
                                working[..num_routes].sort_by_key(|a| a.cost);
                                working[..MAX_INDIRECTS].to_vec()
                            } else if num_routes > 0 {
                                working[..num_routes].to_vec()
                            } else {
                                vec![]
                            };

                            row[j] = result;
                        }
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        });
    }

    // Phase 2: Build routes (parallel per segment, each thread returns results)
    let entry_count = tri_matrix_length(num_relays);
    let mut routes = vec![RouteEntry::default(); entry_count];

    std::thread::scope(|s| {
        let mut handles: Vec<std::thread::ScopedJoinHandle<Vec<(usize, RouteEntry)>>> = Vec::new();

        for segment in 0..num_segments {
            let start_index = segment * num_relays / num_segments;
            let end_index = if segment == num_segments - 1 {
                num_relays - 1
            } else {
                (segment + 1) * num_relays / num_segments - 1
            };

            let indirect_ref = &flat_indirect;
            let cost_ref = cost;
            let price_ref = relay_price;

            handles.push(s.spawn(move || {
                let mut results: Vec<(usize, RouteEntry)> = Vec::new();

                for i in start_index..=end_index {
                    for j in 0..i {
                        let mut rm = RouteManager::new();
                        let index = tri_matrix_index(i, j);
                        let direct_cost = cost_ref[index] as i32;

                        if direct_cost < 255 {
                            rm.add_route(
                                direct_cost,
                                price_ref[i] as i32 + price_ref[j] as i32,
                                &[i as i32, j as i32],
                            );
                        }

                        if destination_relay[i] || destination_relay[j] {
                            for k_entry in &indirect_ref[i][j] {
                                let k = k_entry.relay as usize;
                                let ik_cost = cost_ref[tri_matrix_index(i, k)];
                                let kj_cost = cost_ref[tri_matrix_index(k, j)];

                                // i -> (k) -> j
                                {
                                    let c = k_entry.cost as i32;
                                    if c < direct_cost {
                                        rm.add_route(
                                            c,
                                            price_ref[i] as i32
                                                + price_ref[k] as i32
                                                + price_ref[j] as i32,
                                            &[i as i32, k as i32, j as i32],
                                        );
                                    }
                                }

                                // i -> (x) -> k -> j
                                for x_entry in &indirect_ref[i][k] {
                                    let x = x_entry.relay;
                                    let c = x_entry.cost as i32 + kj_cost as i32;
                                    if c < direct_cost {
                                        rm.add_route(
                                            c,
                                            price_ref[i] as i32
                                                + price_ref[x as usize] as i32
                                                + price_ref[k] as i32
                                                + price_ref[j] as i32,
                                            &[i as i32, x, k as i32, j as i32],
                                        );
                                    }
                                }

                                // i -> k -> (y) -> j
                                for y_entry in &indirect_ref[k][j] {
                                    let y = y_entry.relay;
                                    let c = ik_cost as i32 + y_entry.cost as i32;
                                    if c < direct_cost {
                                        rm.add_route(
                                            c,
                                            price_ref[i] as i32
                                                + price_ref[k] as i32
                                                + price_ref[y as usize] as i32
                                                + price_ref[j] as i32,
                                            &[i as i32, k as i32, y, j as i32],
                                        );
                                    }
                                }

                                // i -> (x) -> k -> (y) -> j
                                for x_entry in &indirect_ref[i][k] {
                                    let x = x_entry.relay;
                                    let ixk_cost = x_entry.cost;
                                    for y_entry in &indirect_ref[k][j] {
                                        let y = y_entry.relay;
                                        let kyj_cost = y_entry.cost;
                                        let c = ixk_cost as i32 + kyj_cost as i32;
                                        if c < direct_cost {
                                            rm.add_route(
                                                c,
                                                price_ref[i] as i32
                                                    + price_ref[x as usize] as i32
                                                    + price_ref[k] as i32
                                                    + price_ref[y as usize] as i32
                                                    + price_ref[j] as i32,
                                                &[i as i32, x, k as i32, y, j as i32],
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        // Collect result
                        let mut entry = RouteEntry::default();
                        entry.direct_cost = cost_ref[index] as i32;
                        entry.num_routes = rm.num_routes as i32;
                        for u in 0..rm.num_routes {
                            entry.route_cost[u] = rm.route_cost[u];
                            entry.route_price[u] = rm.route_price[u];
                            entry.route_num_relays[u] = rm.route_num_relays[u];
                            entry.route_hash[u] = rm.route_hash[u];
                            let nr = rm.route_num_relays[u] as usize;
                            for v in 0..nr {
                                entry.route_relays[u][v] = rm.route_relays[u][v];
                            }
                        }
                        results.push((index, entry));
                    }
                }
                results
            }));
        }

        for h in handles {
            let results = h.join().unwrap();
            for (index, entry) in results {
                routes[index] = entry;
            }
        }
    });

    routes
}

