// Linux platform stubs — port of next_platform_linux.cpp
// TODO: Implement socket buffer, connection type detection.

use std::sync::OnceLock;
use std::time::Instant;

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Returns seconds elapsed since first call (monotonic clock).
/// Equivalent to `next_platform_time()` in C++.
pub fn time() -> f64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs_f64()
}
