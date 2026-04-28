// mod ffi - C ABI exports for relay-sdk.
//
// Exports two opaque handle types:
//   relay_client_t  - game client relay session
//   relay_server_t  - game server as final relay destination
//
// Every entry point wraps its body in std::panic::catch_unwind to prevent
// Rust panics from crossing the FFI boundary (undefined behaviour in C).
//
// Callers are responsible for:
//   - Passing valid non-null pointers to all *mut / *const parameters.
//   - Ensuring buffers are at least as large as the documented sizes.
//   - Calling *_destroy exactly once per *_create.
//
// Thread safety: relay_client_t and relay_server_t internally use
//   Arc<Mutex<VecDeque<T>>> queues. The opaque pointer itself must only be
//   used from one thread at a time (no concurrent calls on the same handle).
//
// Error reporting:
//   - Functions that return a pointer: null indicates failure.
//   - Functions that return c_int: 0 = ok, -1 = error.
//   - Functions that return u32/u64: 0 is the "no error / no data" sentinel.
//   - Void-returning functions (open_session, close_session, register_session,
//     expire_session, clear_last_send_error): panics inside catch_unwind are
//     silently swallowed because there is no return channel. Callers cannot
//     distinguish a panic from normal execution in these paths.

// Safety: all extern "C" entry points perform explicit null checks on every
// raw pointer argument before any dereference. Suppressing the lint here is
// intentional - these are FFI boundary functions with documented contracts.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::address::Address;
use crate::client::{Client, ClientInner};
use crate::constants::SESSION_PRIVATE_KEY_BYTES;
use crate::server::{Server, ServerInner};

// ── relay_client_t ────────────────────────────────────────────────────────────

/// Opaque handle for a relay game-client session.
/// Created by `relay_client_create`, destroyed by `relay_client_destroy`.
pub struct RelayClient {
    inner: ClientInner,
    client: Client,
}

/// Create a new relay client.
/// Returns null on failure (invalid bind_address string).
/// The returned pointer must be freed with `relay_client_destroy`.
#[no_mangle]
pub extern "C" fn relay_client_create(bind_address: *const c_char) -> *mut RelayClient {
    catch_unwind(|| {
        let addr_str = unsafe {
            if bind_address.is_null() {
                return std::ptr::null_mut();
            }
            match CStr::from_ptr(bind_address).to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => return std::ptr::null_mut(),
            }
        };
        let _ = addr_str; // bind_address reserved for future socket binding
        let (inner, client) = ClientInner::create();
        let boxed = Box::new(RelayClient { inner, client });
        Box::into_raw(boxed)
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Destroy a relay client previously created with `relay_client_create`.
/// Passing null is a no-op.
#[no_mangle]
pub extern "C" fn relay_client_destroy(handle: *mut RelayClient) {
    let _ = catch_unwind(|| {
        if !handle.is_null() {
            // Safety: handle was created by relay_client_create via Box::into_raw.
            drop(unsafe { Box::from_raw(handle) });
        }
    });
}

/// Open a relay session to server at `server_address` (e.g. "1.2.3.4:7777").
/// `client_secret_key` must point to exactly SESSION_PRIVATE_KEY_BYTES (32) bytes.
/// No-op if handle is null or server_address is invalid.
#[no_mangle]
pub extern "C" fn relay_client_open_session(
    handle: *mut RelayClient,
    server_address: *const c_char,
    client_secret_key: *const u8,
) {
    let _ = catch_unwind(|| {
        if handle.is_null() || server_address.is_null() || client_secret_key.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        let addr_str = unsafe {
            match CStr::from_ptr(server_address).to_str() {
                Ok(s) => s,
                Err(_) => return,
            }
        };
        let addr: Address = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let mut key = [0u8; SESSION_PRIVATE_KEY_BYTES];
        unsafe {
            key.copy_from_slice(std::slice::from_raw_parts(
                client_secret_key,
                SESSION_PRIVATE_KEY_BYTES,
            ))
        };
        h.client.open_session(addr, key);
        h.inner.pump_commands();
    });
}

/// Close the current relay session.
/// No-op if handle is null.
#[no_mangle]
pub extern "C" fn relay_client_close_session(handle: *mut RelayClient) {
    let _ = catch_unwind(|| {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        h.client.close_session();
        h.inner.pump_commands();
    });
}

/// Queue a game payload for sending via relay (or direct if no route).
/// `data` must point to `bytes` bytes. `bytes` must be > 0 and <= MAX_PACKET_BYTES.
/// No-op if handle is null or byte count is out of range.
#[no_mangle]
pub extern "C" fn relay_client_send_packet(
    handle: *mut RelayClient,
    data: *const u8,
    bytes: c_int,
) {
    let _ = catch_unwind(|| {
        if handle.is_null() || data.is_null() || bytes <= 0 {
            return;
        }
        // Reject oversized payloads before creating the slice to prevent UB
        // from a caller passing an inflated byte count with a short buffer.
        use crate::constants::MAX_PACKET_BYTES;
        if bytes as usize > MAX_PACKET_BYTES {
            return;
        }
        let h = unsafe { &mut *handle };
        let payload = unsafe { std::slice::from_raw_parts(data, bytes as usize) };
        h.client.send_packet(payload);
        h.inner.pump_commands();
    });
}

/// Pop the next received game payload into `out` (caller-provided buffer of `max_bytes`).
/// Returns the number of bytes written, or 0 if no packet is available.
/// No-op and returns 0 if handle is null.
#[no_mangle]
pub extern "C" fn relay_client_recv_packet(
    handle: *mut RelayClient,
    out: *mut u8,
    max_bytes: c_int,
) -> c_int {
    catch_unwind(|| {
        if handle.is_null() || out.is_null() || max_bytes <= 0 {
            return 0;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        match h.client.recv_packet() {
            None => 0,
            Some(payload) => {
                let n = payload.len().min(max_bytes as usize);
                unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), out, n) };
                n as c_int
            }
        }
    })
    .unwrap_or(0)
}

/// Return the current route flags bitmask for this client.
/// Flags encode token validation errors and route state.
/// See FLAGS_BAD_ROUTE_TOKEN, FLAGS_BAD_CONTINUE_TOKEN, etc. in relay_generated.h.
/// Returns 0 if handle is null.
#[no_mangle]
pub extern "C" fn relay_client_flags(handle: *mut RelayClient) -> u32 {
    catch_unwind(|| {
        if handle.is_null() {
            return 0u32;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        h.client.drain_notify();
        h.client.flags
    })
    .unwrap_or(0)
}

// ── relay_server_t ────────────────────────────────────────────────────────────

/// Opaque handle for a relay game-server session.
/// Created by `relay_server_create`, destroyed by `relay_server_destroy`.
pub struct RelayServer {
    inner: ServerInner,
    server: Server,
}

/// Create a new relay server.
/// Returns null on failure (invalid bind_address string).
/// The returned pointer must be freed with `relay_server_destroy`.
#[no_mangle]
pub extern "C" fn relay_server_create(bind_address: *const c_char) -> *mut RelayServer {
    catch_unwind(|| {
        let addr_str = unsafe {
            if bind_address.is_null() {
                return std::ptr::null_mut();
            }
            match CStr::from_ptr(bind_address).to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => return std::ptr::null_mut(),
            }
        };
        let addr: Address = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return std::ptr::null_mut(),
        };
        let (inner, mut server) = ServerInner::create();
        server.open(addr);
        let boxed = Box::new(RelayServer { inner, server });
        Box::into_raw(boxed)
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Destroy a relay server previously created with `relay_server_create`.
/// Passing null is a no-op.
#[no_mangle]
pub extern "C" fn relay_server_destroy(handle: *mut RelayServer) {
    let _ = catch_unwind(|| {
        if !handle.is_null() {
            // Safety: handle was created by relay_server_create via Box::into_raw.
            drop(unsafe { Box::from_raw(handle) });
        }
    });
}

/// Register a session (called when relay-backend pushes session keys via HTTP).
/// `session_private_key` must point to exactly SESSION_PRIVATE_KEY_BYTES (32) bytes.
/// `relay_address` is the last relay hop address string (e.g. "10.0.0.1:4000").
/// No-op if handle is null.
#[no_mangle]
pub extern "C" fn relay_server_register_session(
    handle: *mut RelayServer,
    session_id: u64,
    session_version: u8,
    session_private_key: *const u8,
    relay_address: *const c_char,
) {
    let _ = catch_unwind(|| {
        if handle.is_null() || session_private_key.is_null() || relay_address.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        let addr_str = unsafe {
            match CStr::from_ptr(relay_address).to_str() {
                Ok(s) => s,
                Err(_) => return,
            }
        };
        let addr: Address = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let mut key = [0u8; SESSION_PRIVATE_KEY_BYTES];
        unsafe {
            key.copy_from_slice(std::slice::from_raw_parts(
                session_private_key,
                SESSION_PRIVATE_KEY_BYTES,
            ))
        };
        h.server
            .register_session(session_id, session_version, key, addr);
        h.inner.pump_commands();
    });
}

/// Expire (remove) a session.
/// No-op if handle is null or session not found.
#[no_mangle]
pub extern "C" fn relay_server_expire_session(handle: *mut RelayServer, session_id: u64) {
    let _ = catch_unwind(|| {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        h.server.expire_session(session_id);
        h.inner.pump_commands();
    });
}

/// Send a game payload to `session_id` via the last relay hop.
/// `data` must point to `bytes` bytes.
/// `magic` must point to 8 bytes.
/// `from_address` is the server's own address string (e.g. "10.0.0.2:9000").
/// Returns 0 on success, -1 if handle is null or payload is too large.
#[no_mangle]
pub extern "C" fn relay_server_send_packet(
    handle: *mut RelayServer,
    session_id: u64,
    data: *const u8,
    bytes: c_int,
    magic: *const u8,
    from_address: *const c_char,
) -> c_int {
    catch_unwind(|| {
        if handle.is_null()
            || data.is_null()
            || magic.is_null()
            || from_address.is_null()
            || bytes <= 0
        {
            return -1i32;
        }
        // Pre-flight: reject oversized payloads before queuing.
        use crate::constants::{MAX_PACKET_BYTES, PACKET_BODY_OFFSET};
        use crate::route::HEADER_BYTES as ROUTE_HEADER_BYTES;
        let max_payload = MAX_PACKET_BYTES
            .saturating_sub(PACKET_BODY_OFFSET)
            .saturating_sub(ROUTE_HEADER_BYTES);
        if bytes as usize > max_payload {
            return -1i32;
        }
        let h = unsafe { &mut *handle };
        let payload = unsafe { std::slice::from_raw_parts(data, bytes as usize) };
        let mut magic_buf = [0u8; 8];
        unsafe { magic_buf.copy_from_slice(std::slice::from_raw_parts(magic, 8)) };
        let addr_str = unsafe {
            match CStr::from_ptr(from_address).to_str() {
                Ok(s) => s,
                Err(_) => return -1i32,
            }
        };
        let from: Address = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return -1i32,
        };
        h.server.send_packet(session_id, payload, magic_buf, from);
        h.inner.pump_commands();
        h.server.drain_notify();
        0i32
    })
    .unwrap_or(-1)
}

/// Return the session_id from the last failed send, or 0 if no error is pending.
/// Also drains any pending notifications to refresh the error state.
/// Call `relay_server_clear_last_send_error` after handling the error.
#[no_mangle]
pub extern "C" fn relay_server_last_send_error(handle: *mut RelayServer) -> u64 {
    catch_unwind(|| {
        if handle.is_null() {
            return 0u64;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        h.server.drain_notify();
        match h.server.last_send_error {
            Some((session_id, _)) => session_id,
            None => 0,
        }
    })
    .unwrap_or(0)
}

/// Clear the last send error recorded on the server handle.
#[no_mangle]
pub extern "C" fn relay_server_clear_last_send_error(handle: *mut RelayServer) {
    let _ = catch_unwind(|| {
        if handle.is_null() {
            return;
        }
        let h = unsafe { &mut *handle };
        h.server.clear_last_send_error();
    });
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/// C-visible snapshot of relay client event counters.
/// Populated by `relay_client_get_stats`.
#[repr(C)]
pub struct RelayClientStats {
    /// SendRaw packets enqueued for the UDP socket (relay packets sent outbound).
    pub packets_sent: u64,
    /// PacketReceived payloads delivered to the application.
    pub packets_received: u64,
    /// RouteChanged events observed (any route state transition).
    pub route_changes: u64,
}

/// C-visible snapshot of relay server event counters.
/// Populated by `relay_server_get_stats`.
#[repr(C)]
pub struct RelayServerStats {
    /// PacketReceived events (CLIENT_TO_SERVER payloads extracted from the wire).
    pub packets_received: u64,
    /// SendRaw packets enqueued (SERVER_TO_CLIENT packets sent outbound).
    pub packets_sent: u64,
    /// SendError events (e.g. payload exceeded MAX_PACKET_BYTES).
    pub send_errors: u64,
    /// Sessions registered via RegisterSession commands.
    pub sessions_registered: u64,
    /// Sessions expired via ExpireSession commands.
    pub sessions_expired: u64,
}

/// Copy a snapshot of the current client event counters into `out`.
/// Also drains pending notifications so the counters are up-to-date.
/// Returns 0 on success, -1 if `handle` or `out` is null.
#[no_mangle]
pub extern "C" fn relay_client_get_stats(
    handle: *mut RelayClient,
    out: *mut RelayClientStats,
) -> c_int {
    catch_unwind(|| {
        if handle.is_null() || out.is_null() {
            return -1i32;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        h.client.drain_notify();
        unsafe {
            *out = RelayClientStats {
                packets_sent: h.client.stats.packets_sent,
                packets_received: h.client.stats.packets_received,
                route_changes: h.client.stats.route_changes,
            };
        }
        0i32
    })
    .unwrap_or(-1)
}

/// Copy a snapshot of the current server event counters into `out`.
/// Also drains pending notifications so the counters are up-to-date.
/// Returns 0 on success, -1 if `handle` or `out` is null.
#[no_mangle]
pub extern "C" fn relay_server_get_stats(
    handle: *mut RelayServer,
    out: *mut RelayServerStats,
) -> c_int {
    catch_unwind(|| {
        if handle.is_null() || out.is_null() {
            return -1i32;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        h.server.drain_notify();
        unsafe {
            *out = RelayServerStats {
                packets_received: h.server.stats.packets_received,
                packets_sent: h.server.stats.packets_sent,
                send_errors: h.server.stats.send_errors,
                sessions_registered: h.server.stats.sessions_registered,
                sessions_expired: h.server.stats.sessions_expired,
            };
        }
        0i32
    })
    .unwrap_or(-1)
}

/// Pop the next received game payload into `out` (caller-provided buffer of `max_bytes`).
/// On success, writes the originating session_id into `*out_session_id`.
/// Returns the number of bytes written, or 0 if no packet is available.
/// No-op and returns 0 if handle is null.
#[no_mangle]
pub extern "C" fn relay_server_recv_packet(
    handle: *mut RelayServer,
    out_session_id: *mut u64,
    out: *mut u8,
    max_bytes: c_int,
) -> c_int {
    catch_unwind(|| {
        if handle.is_null() || out_session_id.is_null() || out.is_null() || max_bytes <= 0 {
            return 0;
        }
        let h = unsafe { &mut *handle };
        h.inner.pump_commands();
        match h.server.recv_packet() {
            None => 0,
            Some((session_id, payload)) => {
                unsafe { *out_session_id = session_id };
                let n = payload.len().min(max_bytes as usize);
                unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), out, n) };
                n as c_int
            }
        }
    })
    .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &str) -> CString {
        // Safety: all call-sites pass ASCII string literals without embedded
        // null bytes. CString::new() only fails if the input contains '\0'.
        CString::new(s).expect("test helper cstr: input must not contain null bytes")
    }

    // ── relay_client_t ────────────────────────────────────────────────────────

    #[test]
    fn ffi_client_create_valid_address() {
        let addr = cstr("127.0.0.1:7777");
        let h = relay_client_create(addr.as_ptr());
        assert!(
            !h.is_null(),
            "relay_client_create must return non-null for valid address"
        );
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_client_create_null_address_returns_null() {
        let h = relay_client_create(std::ptr::null());
        assert!(
            h.is_null(),
            "relay_client_create must return null for null address"
        );
    }

    #[test]
    fn ffi_client_destroy_null_is_noop() {
        // Must not panic or segfault.
        relay_client_destroy(std::ptr::null_mut());
    }

    #[test]
    fn ffi_client_open_close_session() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        let server = cstr("10.0.0.1:9000");
        let key = [0xABu8; SESSION_PRIVATE_KEY_BYTES];
        relay_client_open_session(h, server.as_ptr(), key.as_ptr());
        relay_client_close_session(h);
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_client_send_recv_no_route_no_crash() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        let server = cstr("10.0.0.1:9000");
        let key = [0x55u8; SESSION_PRIVATE_KEY_BYTES];
        relay_client_open_session(h, server.as_ptr(), key.as_ptr());
        let payload = b"hello";
        relay_client_send_packet(h, payload.as_ptr(), payload.len() as c_int);
        let mut out = [0u8; 1200];
        let n = relay_client_recv_packet(h, out.as_mut_ptr(), out.len() as c_int);
        // No relay route established -> no packet back.
        assert_eq!(n, 0);
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_client_null_handle_ops_are_noop() {
        let null: *mut RelayClient = std::ptr::null_mut();
        relay_client_open_session(null, std::ptr::null(), std::ptr::null());
        relay_client_close_session(null);
        relay_client_send_packet(null, std::ptr::null(), 0);
        let n = relay_client_recv_packet(null, std::ptr::null_mut(), 0);
        assert_eq!(n, 0);
    }

    // ── relay_server_t ────────────────────────────────────────────────────────

    #[test]
    fn ffi_server_create_valid_address() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(
            !h.is_null(),
            "relay_server_create must return non-null for valid address"
        );
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_create_invalid_address_returns_null() {
        let bad = cstr("not_an_address");
        let h = relay_server_create(bad.as_ptr());
        assert!(
            h.is_null(),
            "relay_server_create must return null for invalid address"
        );
    }

    #[test]
    fn ffi_server_create_null_returns_null() {
        let h = relay_server_create(std::ptr::null());
        assert!(h.is_null());
    }

    #[test]
    fn ffi_server_destroy_null_is_noop() {
        relay_server_destroy(std::ptr::null_mut());
    }

    #[test]
    fn ffi_server_register_expire_session() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let relay = cstr("10.0.0.1:4000");
        let key = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
        relay_server_register_session(h, 0xDEAD_BEEF, 1, key.as_ptr(), relay.as_ptr());
        relay_server_expire_session(h, 0xDEAD_BEEF);
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_recv_no_packet_returns_zero() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let mut sid: u64 = 0;
        let mut out = [0u8; 1200];
        let n = relay_server_recv_packet(h, &mut sid, out.as_mut_ptr(), out.len() as c_int);
        assert_eq!(n, 0);
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_null_handle_ops_are_noop() {
        let null: *mut RelayServer = std::ptr::null_mut();
        relay_server_expire_session(null, 0);
        relay_server_send_packet(
            null,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        );
        let n = relay_server_recv_packet(null, std::ptr::null_mut(), std::ptr::null_mut(), 0);
        assert_eq!(n, 0);
    }

    // ── New functions from error-handling task ────────────────────────────────

    #[test]
    fn ffi_client_flags_null_returns_zero() {
        assert_eq!(relay_client_flags(std::ptr::null_mut()), 0);
    }

    #[test]
    fn ffi_client_flags_no_route_is_zero() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        // No route update issued - flags must be zero.
        assert_eq!(relay_client_flags(h), 0);
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_server_send_packet_null_handle_returns_error() {
        let rc = relay_server_send_packet(
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        );
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_server_send_packet_oversized_payload_returns_error() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let relay_addr = cstr("10.0.0.1:4000");
        let key = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
        relay_server_register_session(h, 0xDEAD_BEEF, 1, key.as_ptr(), relay_addr.as_ptr());
        let from = cstr("10.0.0.2:9000");
        let magic = [0u8; 8];
        // 2000 bytes > MAX_PACKET_BYTES (1384) - must return -1.
        let big_payload = vec![0u8; 2000];
        let rc = relay_server_send_packet(
            h,
            0xDEAD_BEEF,
            big_payload.as_ptr(),
            big_payload.len() as c_int,
            magic.as_ptr(),
            from.as_ptr(),
        );
        assert_eq!(rc, -1, "oversized payload must return -1");
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_last_send_error_null_returns_zero() {
        assert_eq!(relay_server_last_send_error(std::ptr::null_mut()), 0);
    }

    #[test]
    fn ffi_server_last_send_error_no_error_returns_zero() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        assert_eq!(relay_server_last_send_error(h), 0);
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_clear_last_send_error_null_is_noop() {
        // Must not panic.
        relay_server_clear_last_send_error(std::ptr::null_mut());
    }

    #[test]
    fn ffi_client_send_packet_oversized_is_noop() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        let server = cstr("10.0.0.1:9000");
        let key = [0x55u8; SESSION_PRIVATE_KEY_BYTES];
        relay_client_open_session(h, server.as_ptr(), key.as_ptr());
        // 2000 bytes > MAX_PACKET_BYTES (1384) - must be silently ignored.
        let big = vec![0xAAu8; 2000];
        relay_client_send_packet(h, big.as_ptr(), big.len() as c_int);
        // No crash or UB - verify recv finds nothing.
        let mut out = [0u8; 1200];
        let n = relay_client_recv_packet(h, out.as_mut_ptr(), out.len() as c_int);
        assert_eq!(n, 0);
        relay_client_destroy(h);
    }

    // ── Observability (task 9) tests ──────────────────────────────────────────

    #[test]
    fn ffi_client_get_stats_null_handle_returns_error() {
        let null: *mut RelayClient = std::ptr::null_mut();
        let mut stats = RelayClientStats {
            packets_sent: 0,
            packets_received: 0,
            route_changes: 0,
        };
        let rc = relay_client_get_stats(null, &mut stats);
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_client_get_stats_null_out_returns_error() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        let rc = relay_client_get_stats(h, std::ptr::null_mut());
        assert_eq!(rc, -1);
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_client_get_stats_initial_counters_are_zero() {
        let bind = cstr("0.0.0.0:0");
        let h = relay_client_create(bind.as_ptr());
        assert!(!h.is_null());
        let mut stats = RelayClientStats {
            packets_sent: 99,
            packets_received: 99,
            route_changes: 99,
        };
        let rc = relay_client_get_stats(h, &mut stats);
        assert_eq!(rc, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.route_changes, 0);
        relay_client_destroy(h);
    }

    #[test]
    fn ffi_server_get_stats_null_handle_returns_error() {
        let null: *mut RelayServer = std::ptr::null_mut();
        let mut stats = RelayServerStats {
            packets_received: 0,
            packets_sent: 0,
            send_errors: 0,
            sessions_registered: 0,
            sessions_expired: 0,
        };
        let rc = relay_server_get_stats(null, &mut stats);
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_server_get_stats_null_out_returns_error() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let rc = relay_server_get_stats(h, std::ptr::null_mut());
        assert_eq!(rc, -1);
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_get_stats_initial_counters_are_zero() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let mut stats = RelayServerStats {
            packets_received: 99,
            packets_sent: 99,
            send_errors: 99,
            sessions_registered: 99,
            sessions_expired: 99,
        };
        let rc = relay_server_get_stats(h, &mut stats);
        assert_eq!(rc, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.send_errors, 0);
        assert_eq!(stats.sessions_registered, 0);
        assert_eq!(stats.sessions_expired, 0);
        relay_server_destroy(h);
    }

    #[test]
    fn ffi_server_get_stats_session_events_counted() {
        let addr = cstr("0.0.0.0:9000");
        let h = relay_server_create(addr.as_ptr());
        assert!(!h.is_null());
        let relay = cstr("10.0.0.1:4000");
        let key = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
        relay_server_register_session(h, 1, 1, key.as_ptr(), relay.as_ptr());
        relay_server_expire_session(h, 1);
        let mut stats = RelayServerStats {
            packets_received: 0,
            packets_sent: 0,
            send_errors: 0,
            sessions_registered: 0,
            sessions_expired: 0,
        };
        let rc = relay_server_get_stats(h, &mut stats);
        assert_eq!(rc, 0);
        assert_eq!(
            stats.sessions_registered, 1,
            "register_session must increment sessions_registered"
        );
        assert_eq!(
            stats.sessions_expired, 1,
            "expire_session must increment sessions_expired"
        );
        relay_server_destroy(h);
    }
}
