//! Platform helpers: time, sleep, UDP socket, random bytes.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::OnceLock;
use std::time::Instant;

static TIME_START: OnceLock<Instant> = OnceLock::new();

/// Initialize platform (call once at startup).
pub fn init() {
    TIME_START.get_or_init(Instant::now);
}

/// Monotonic time in seconds since init().
pub fn time() -> f64 {
    let start = TIME_START.get().expect("platform not initialized");
    start.elapsed().as_secs_f64()
}

/// Sleep for the given number of seconds.
pub fn sleep(seconds: f64) {
    std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
}

/// Fill buffer with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("getrandom failed");
}

/// Create a blocking UDP socket bound to the given address and port.
/// Sets IP_PMTUDISC_DO and configurable timeout.
pub fn create_udp_socket(
    address: u32, // host byte order
    port: u16,
    timeout_secs: f64,
    send_buf_size: usize,
    recv_buf_size: usize,
) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket")?;

    socket
        .set_send_buffer_size(send_buf_size)
        .context("failed to set send buffer size")?;
    socket
        .set_recv_buffer_size(recv_buf_size)
        .context("failed to set recv buffer size")?;

    let addr = SocketAddrV4::new(Ipv4Addr::from(address), port);
    socket
        .bind(&SockAddr::from(addr))
        .with_context(|| format!("failed to bind socket to {addr}"))?;

    // Set IP_PMTUDISC_DO (don't fragment)
    #[cfg(target_os = "linux")]
    {
        use libc::{IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO};
        unsafe {
            let val: libc::c_int = IP_PMTUDISC_DO;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                IPPROTO_IP,
                IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                log::warn!(
                    "failed to set IP_PMTUDISC_DO: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // Set receive timeout
    if timeout_secs > 0.0 {
        let timeout = std::time::Duration::from_secs_f64(timeout_secs);
        socket
            .set_read_timeout(Some(timeout))
            .context("failed to set read timeout")?;
    }

    Ok(socket.into())
}

/// Parse "1.2.3.4:port" into (host_order_address, port).
pub fn parse_address(s: &str) -> Result<(u32, u16)> {
    let addr: SocketAddrV4 = s.parse().with_context(|| format!("invalid address: {s}"))?;
    let ip_bytes = addr.ip().octets();
    let host_order = u32::from_be_bytes(ip_bytes);
    Ok((host_order, addr.port()))
}

/// Format a host-order IPv4 address as a string.
pub fn format_address(address: u32, port: u16) -> String {
    let ip = Ipv4Addr::from(address.to_be_bytes());
    format!("{ip}:{port}")
}

// Re-export for socket FD access
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
