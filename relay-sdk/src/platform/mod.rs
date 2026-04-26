// Platform abstractions for Linux (time, connection type, UDP socket).
// Port of next_platform_linux.cpp / next_platform.h.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    connection_type, get_socket_recv_buffer_size, get_socket_send_buffer_size,
    set_socket_recv_buffer_size, set_socket_send_buffer_size, time, ConnectionType,
};

/// Fallback for non-Linux platforms (tests running on macOS, Windows, etc.)
#[cfg(not(target_os = "linux"))]
pub fn time() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// Connection type - non-Linux stub always returns Unknown.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Unknown,
    Wired,
    Wifi,
    Cellular,
}

#[cfg(not(target_os = "linux"))]
pub fn connection_type() -> ConnectionType {
    ConnectionType::Unknown
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_send_buffer_size(_socket: &std::net::UdpSocket, _size: usize) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_recv_buffer_size(_socket: &std::net::UdpSocket, _size: usize) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_send_buffer_size(_socket: &std::net::UdpSocket) -> usize {
    0
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_recv_buffer_size(_socket: &std::net::UdpSocket) -> usize {
    0
}
