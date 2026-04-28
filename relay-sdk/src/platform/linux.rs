// Linux platform abstractions - port of next_platform_linux.cpp
//
// Provides:
//   time()                           - monotonic seconds since first call
//   connection_type()                - detect default NIC type (Wired/Wifi/Cellular/Unknown)
//   set_socket_send_buffer_size()    - SO_SNDBUF via setsockopt
//   set_socket_recv_buffer_size()    - SO_RCVBUF via setsockopt
//   get_socket_send_buffer_size()    - SO_SNDBUF via getsockopt
//   get_socket_recv_buffer_size()    - SO_RCVBUF via getsockopt

use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::sync::OnceLock;
use std::time::Instant;

// ── Monotonic time ────────────────────────────────────────────────────────────

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Returns seconds elapsed since first call (monotonic clock).
/// Equivalent to `next_platform_time()` in C++.
pub fn time() -> f64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs_f64()
}

// ── Connection type ───────────────────────────────────────────────────────────

/// Network connection type of the default route interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Could not determine or no default route.
    Unknown,
    /// Wired Ethernet.
    Wired,
    /// Wireless (802.11).
    Wifi,
    /// Mobile broadband / cellular (wwan).
    Cellular,
}

/// Determine the connection type of the interface that carries the default route.
///
/// Algorithm:
///   1. Parse `/proc/net/route` to find the interface with destination 0.0.0.0
///      (hex `00000000`) - that is the default-route interface.
///   2. For that interface:
///      - If `/sys/class/net/{iface}/wireless` exists -> Wifi
///      - If `/sys/class/net/{iface}/uevent` contains `DEVTYPE=wwan` -> Cellular
///      - Otherwise -> Wired
///   3. Returns Unknown on any I/O error or missing entry.
pub fn connection_type() -> ConnectionType {
    let iface = match default_route_iface() {
        Some(i) => i,
        None => return ConnectionType::Unknown,
    };

    // Wifi check: kernel creates the `wireless` sub-directory for 802.11 nics.
    let wireless_path = format!("/sys/class/net/{iface}/wireless");
    if std::path::Path::new(&wireless_path).exists() {
        return ConnectionType::Wifi;
    }

    // Cellular check: mobile broadband interfaces expose DEVTYPE=wwan in uevent.
    let uevent_path = format!("/sys/class/net/{iface}/uevent");
    if let Ok(contents) = std::fs::read_to_string(&uevent_path) {
        if contents.lines().any(|l| l.trim() == "DEVTYPE=wwan") {
            return ConnectionType::Cellular;
        }
    }

    ConnectionType::Wired
}

/// Read `/proc/net/route` and return the interface name for the default route
/// (the entry where the Destination field is `00000000`).
///
/// Format (space-separated columns):
///   Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
fn default_route_iface() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in contents.lines().skip(1) {
        // split_ascii_whitespace handles any run of spaces/tabs.
        let mut cols = line.split_ascii_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        if dest.eq_ignore_ascii_case("00000000") {
            return Some(iface.to_owned());
        }
    }
    None
}

// ── Socket buffer helpers ─────────────────────────────────────────────────────

/// Set `SO_SNDBUF` on `socket` to `size` bytes.
/// The kernel may round up to the nearest page. Returns `true` on success.
pub fn set_socket_send_buffer_size(socket: &UdpSocket, size: usize) -> bool {
    set_sock_opt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, size)
}

/// Set `SO_RCVBUF` on `socket` to `size` bytes.
/// The kernel may round up to the nearest page. Returns `true` on success.
pub fn set_socket_recv_buffer_size(socket: &UdpSocket, size: usize) -> bool {
    set_sock_opt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, size)
}

/// Returns the current `SO_SNDBUF` value for `socket` in bytes.
/// Returns 0 on failure.
pub fn get_socket_send_buffer_size(socket: &UdpSocket) -> usize {
    get_sock_opt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF)
}

/// Returns the current `SO_RCVBUF` value for `socket` in bytes.
/// Returns 0 on failure.
pub fn get_socket_recv_buffer_size(socket: &UdpSocket) -> usize {
    get_sock_opt_int(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF)
}

// ── setsockopt / getsockopt wrappers ─────────────────────────────────────────

fn set_sock_opt_int(fd: libc::c_int, level: libc::c_int, opt: libc::c_int, value: usize) -> bool {
    // Clamp to i32::MAX to satisfy the kernel's expectation of a signed int.
    let v: libc::c_int = value.min(i32::MAX as usize) as libc::c_int;
    // Safety: fd is a valid open socket file descriptor obtained from a
    // UdpSocket. The pointer points to a live stack i32.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    ret == 0
}

fn get_sock_opt_int(fd: libc::c_int, level: libc::c_int, opt: libc::c_int) -> usize {
    let mut v: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // Safety: fd is a valid open socket file descriptor obtained from a
    // UdpSocket. v is a live stack variable and len accurately reflects its size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            opt,
            &mut v as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && v >= 0 {
        v as usize
    } else {
        0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn time_is_non_negative_and_monotonic() {
        let t0 = time();
        let t1 = time();
        assert!(t0 >= 0.0);
        assert!(t1 >= t0);
    }

    #[test]
    fn connection_type_returns_a_variant() {
        // Just verify it doesn't panic; the actual variant depends on the host.
        let ct = connection_type();
        let _ = ct; // all variants are valid in a CI environment
    }

    #[test]
    fn socket_send_buffer_set_and_get() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let target = 256 * 1024; // 256 KiB
        let ok = set_socket_send_buffer_size(&sock, target);
        assert!(ok, "setsockopt SO_SNDBUF failed");
        // The kernel often doubles the requested value (minimum = kmem_max/2).
        // Just verify we get something non-zero back.
        let actual = get_socket_send_buffer_size(&sock);
        assert!(actual > 0, "getsockopt SO_SNDBUF returned 0");
    }

    #[test]
    fn socket_recv_buffer_set_and_get() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let target = 256 * 1024;
        let ok = set_socket_recv_buffer_size(&sock, target);
        assert!(ok, "setsockopt SO_RCVBUF failed");
        let actual = get_socket_recv_buffer_size(&sock);
        assert!(actual > 0, "getsockopt SO_RCVBUF returned 0");
    }

    #[test]
    fn time_advances_over_short_duration() {
        let t0 = time();
        // Busy-loop until clock reports at least 1 ms elapsed.
        let started = std::time::Instant::now();
        while started.elapsed().as_millis() < 5 {}
        let t1 = time();
        assert!(t1 > t0, "time() must advance: t0={}, t1={}", t0, t1);
    }

    #[test]
    fn time_repeated_calls_are_monotonic() {
        // 10 rapid consecutive calls must never go backwards.
        let mut prev = time();
        for _ in 0..10 {
            let t = time();
            assert!(t >= prev, "time() went backwards: {} -> {}", prev, t);
            prev = t;
        }
    }

    #[test]
    fn connection_type_implements_debug_and_eq() {
        let ct = connection_type();
        let dbg = format!("{ct:?}");
        assert!(
            !dbg.is_empty(),
            "ConnectionType Debug must produce non-empty string"
        );
        // All expected variants are representable.
        let _ = ConnectionType::Unknown;
        let _ = ConnectionType::Wired;
        let _ = ConnectionType::Wifi;
        let _ = ConnectionType::Cellular;
        // Equality check (PartialEq derived).
        assert_eq!(ConnectionType::Unknown, ConnectionType::Unknown);
        assert_ne!(ConnectionType::Wired, ConnectionType::Wifi);
    }

    #[test]
    fn socket_send_buffer_get_on_fresh_socket_nonzero() {
        // The kernel always assigns a non-zero SO_SNDBUF default on creation.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let size = get_socket_send_buffer_size(&sock);
        assert!(size > 0, "default SO_SNDBUF must be > 0, got {}", size);
    }

    #[test]
    fn socket_recv_buffer_get_on_fresh_socket_nonzero() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let size = get_socket_recv_buffer_size(&sock);
        assert!(size > 0, "default SO_RCVBUF must be > 0, got {}", size);
    }

    #[test]
    fn socket_set_small_buffer_does_not_panic() {
        // Setting very small values (1 byte) should not panic; kernel clamps to minimum.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        set_socket_send_buffer_size(&sock, 1);
        set_socket_recv_buffer_size(&sock, 1);
        // Any result is acceptable - just must not panic.
    }
}
