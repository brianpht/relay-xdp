// Platform abstractions for Linux (time, connection type, UDP socket).
// Port of next_platform_linux.cpp / next_platform.h.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::time;

/// Fallback for non-Linux platforms (tests running on macOS, Windows, etc.)
#[cfg(not(target_os = "linux"))]
pub fn time() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64()
}
