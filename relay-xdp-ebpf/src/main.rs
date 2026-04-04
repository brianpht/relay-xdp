//! Relay XDP eBPF program using aya-ebpf.
//!
//! Runs in the kernel at the NIC
//! driver level, processing UDP packets for relay routing.
//!
//! Build: `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release`

#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::map,
    maps::{Array, LruHashMap, PerCpuArray},
    programs::XdpContext,
};

use relay_xdp_common::*;

// =====================================================================
// Network header definitions
// =====================================================================

const ETH_HLEN: usize = 14;
const IPV4_HLEN: usize = 20;
const UDP_HLEN: usize = 8;
const ETH_ALEN: usize = 6;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;

/// Ethernet header (14 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
struct EthHdr {
    h_dest: [u8; ETH_ALEN],
    h_source: [u8; ETH_ALEN],
    h_proto: u16, // big endian
}

/// IPv4 header (20 bytes, IHL=5 only).
#[repr(C)]
#[derive(Copy, Clone)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16, // big endian
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32, // big endian
    daddr: u32, // big endian
}

/// UDP header (8 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
struct UdpHdr {
    source: u16, // big endian
    dest: u16,   // big endian
    len: u16,    // big endian
    check: u16,
}

// =====================================================================
// BPF Maps - lowercase names to match userspace expectations
// =====================================================================

#[map]
static config_map: Array<RelayConfig> = Array::with_max_entries(1, 0);

#[map]
static state_map: Array<RelayState> = Array::with_max_entries(1, 0);

#[map]
static stats_map: PerCpuArray<RelayStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static relay_map: LruHashMap<u64, u64> = LruHashMap::with_max_entries(MAX_RELAYS as u32 * 2, 0);

#[map]
static session_map: LruHashMap<SessionKey, SessionData> =
    LruHashMap::with_max_entries(MAX_SESSIONS as u32 * 2, 0);

#[map]
static whitelist_map: LruHashMap<WhitelistKey, WhitelistValue> =
    LruHashMap::with_max_entries(MAX_SESSIONS as u32 * 2, 0);

// =====================================================================
// Kfunc declarations - provided by relay_module.ko
// =====================================================================

extern "C" {
    fn bpf_relay_sha256(
        data: *const u8,
        data__sz: i32,
        output: *mut u8,
        output__sz: i32,
    ) -> i32;

    fn bpf_relay_xchacha20poly1305_decrypt(
        data: *mut u8,
        data__sz: i32,
        crypto: *const Chacha20Poly1305Crypto,
    ) -> i32;
}

// =====================================================================
// BPF helper imports
// =====================================================================

extern "C" {
    #[allow(improper_ctypes)]
    fn bpf_xdp_adjust_head(xdp_md: *mut aya_ebpf::bindings::xdp_md, delta: i32) -> i64;
    #[allow(improper_ctypes)]
    fn bpf_xdp_adjust_tail(xdp_md: *mut aya_ebpf::bindings::xdp_md, delta: i32) -> i64;
}

// Map update flags
const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;

// =====================================================================
// Counter helpers
// =====================================================================

#[inline(always)]
fn get_stats() -> Option<*mut RelayStats> {
    stats_map.get_ptr_mut(0)
}

#[inline(always)]
fn get_config() -> Option<*const RelayConfig> {
    config_map.get_ptr(0)
}

#[inline(always)]
fn get_state() -> Option<*const RelayState> {
    state_map.get_ptr(0)
}

#[inline(always)]
unsafe fn increment_counter(stats: *mut RelayStats, index: usize) {
    if index < RELAY_NUM_COUNTERS {
        (*stats).counters[index] += 1;
    }
}

#[inline(always)]
unsafe fn add_counter(stats: *mut RelayStats, index: usize, value: u64) {
    if index < RELAY_NUM_COUNTERS {
        (*stats).counters[index] += value;
    }
}

/// Increment dropped packet/byte counters and return XDP_DROP.
#[inline(always)]
unsafe fn count_drop(stats: *mut RelayStats, pkt_size: usize) -> u32 {
    increment_counter(stats, RELAY_COUNTER_DROPPED_PACKETS);
    add_counter(stats, RELAY_COUNTER_DROPPED_BYTES, pkt_size as u64);
    xdp_action::XDP_DROP
}

// =====================================================================
// Profiling helpers (D2) - compile-time feature flag
// =====================================================================

/// Get monotonic nanosecond timestamp for profiling.
/// Only meaningful when `--features profiling` is enabled.
#[cfg(feature = "profiling")]
#[inline(always)]
unsafe fn profile_now() -> u64 {
    aya_ebpf::bindings::bpf_ktime_get_ns()
}

/// No-op when profiling is disabled.
#[cfg(not(feature = "profiling"))]
#[inline(always)]
fn profile_now() -> u64 {
    0
}

/// Record profiling delta into a stats counter slot.
#[cfg(feature = "profiling")]
#[inline(always)]
unsafe fn profile_record(stats: *mut RelayStats, counter: usize, start: u64, end: u64) {
    add_counter(stats, counter, end.wrapping_sub(start));
}

#[cfg(not(feature = "profiling"))]
#[inline(always)]
fn profile_record(_stats: *mut RelayStats, _counter: usize, _start: u64, _end: u64) {}

// =====================================================================
// Byte-level helpers
// =====================================================================

/// Read a little-endian u64 from a raw byte pointer (matches C byte-by-byte decode).
#[inline(always)]
unsafe fn read_u64_le(p: *const u8) -> u64 {
    (*p.add(0) as u64)
        | ((*p.add(1) as u64) << 8)
        | ((*p.add(2) as u64) << 16)
        | ((*p.add(3) as u64) << 24)
        | ((*p.add(4) as u64) << 32)
        | ((*p.add(5) as u64) << 40)
        | ((*p.add(6) as u64) << 48)
        | ((*p.add(7) as u64) << 56)
}

/// Compare N bytes at two pointers. Returns true if equal.
#[inline(always)]
unsafe fn bytes_equal(a: *const u8, b: *const u8, n: usize) -> bool {
    let mut i = 0usize;
    while i < n {
        if *a.add(i) != *b.add(i) {
            return false;
        }
        i += 1;
    }
    true
}

/// Compare 32 bytes using u64-word comparison (4 iterations instead of 32).
/// Both pointers must be to stack-allocated, naturally aligned buffers.
#[inline(always)]
unsafe fn bytes_equal_32(a: *const u8, b: *const u8) -> bool {
    let a = a as *const u64;
    let b = b as *const u64;
    (*a.add(0) == *b.add(0))
        && (*a.add(1) == *b.add(1))
        && (*a.add(2) == *b.add(2))
        && (*a.add(3) == *b.add(3))
}

/// Copy N bytes from src to dst (non-overlapping).
#[inline(always)]
unsafe fn copy_bytes(src: *const u8, dst: *mut u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

/// Copy exactly 32 bytes using u64-word writes (4 iterations instead of 32).
#[inline(always)]
unsafe fn copy_bytes_32(src: *const u8, dst: *mut u8) {
    let s = src as *const u64;
    let d = dst as *mut u64;
    *d.add(0) = *s.add(0);
    *d.add(1) = *s.add(1);
    *d.add(2) = *s.add(2);
    *d.add(3) = *s.add(3);
}


// =====================================================================
// IP checksum
// =====================================================================

/// Recompute IPv4 header checksum (assumes check field is already 0).
#[inline(always)]
unsafe fn ip_checksum(ip: *mut IpHdr) {
    let p = ip as *const u16;
    let mut sum: u32 = 0;
    sum += *p.add(0) as u32;
    sum += *p.add(1) as u32;
    sum += *p.add(2) as u32;
    sum += *p.add(3) as u32;
    sum += *p.add(4) as u32;
    sum += *p.add(5) as u32;
    sum += *p.add(6) as u32;
    sum += *p.add(7) as u32;
    sum += *p.add(8) as u32;
    sum += *p.add(9) as u32;
    sum = !((sum & 0xFFFF) + (sum >> 16));
    (*ip).check = sum as u16;
}

// =====================================================================
// Pittle / Chonkle (FNV-1a based DDoS packet filter)
// =====================================================================

/// Compute 2-byte pittle from source/dest addresses (big-endian u32) and payload size.
#[inline(always)]
fn compute_pittle(from: u32, to: u32, payload_bytes: i32) -> [u8; 2] {
    let mut sum: u16 = 0;
    sum = sum.wrapping_add((from >> 24) as u16);
    sum = sum.wrapping_add(((from >> 16) & 0xFF) as u16);
    sum = sum.wrapping_add(((from >> 8) & 0xFF) as u16);
    sum = sum.wrapping_add((from & 0xFF) as u16);

    sum = sum.wrapping_add((to >> 24) as u16);
    sum = sum.wrapping_add(((to >> 16) & 0xFF) as u16);
    sum = sum.wrapping_add(((to >> 8) & 0xFF) as u16);
    sum = sum.wrapping_add((to & 0xFF) as u16);

    sum = sum.wrapping_add((payload_bytes >> 8) as u16);
    sum = sum.wrapping_add((payload_bytes & 0xFF) as u16);

    let sum_0 = (sum & 0xFF) as u8;
    let sum_1 = (sum >> 8) as u8;

    let p0 = 1 | (sum_0 ^ sum_1 ^ 193);
    let p1 = 1 | (255u8.wrapping_sub(p0) ^ 113);
    [p0, p1]
}

/// Single FNV-1a step.
#[inline(always)]
fn fnv_step(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(0x00000100000001B3)
}

/// Compute 15-byte chonkle from magic, source/dest addresses, and payload size.
#[inline(always)]
fn compute_chonkle(magic: &[u8; 8], from: u32, to: u32, payload_bytes: i32) -> [u8; 15] {
    let mut h: u64 = 0xCBF29CE484222325;

    h = fnv_step(h, magic[0]);
    h = fnv_step(h, magic[1]);
    h = fnv_step(h, magic[2]);
    h = fnv_step(h, magic[3]);
    h = fnv_step(h, magic[4]);
    h = fnv_step(h, magic[5]);
    h = fnv_step(h, magic[6]);
    h = fnv_step(h, magic[7]);

    h = fnv_step(h, (from & 0xFF) as u8);
    h = fnv_step(h, ((from >> 8) & 0xFF) as u8);
    h = fnv_step(h, ((from >> 16) & 0xFF) as u8);
    h = fnv_step(h, (from >> 24) as u8);

    h = fnv_step(h, (to & 0xFF) as u8);
    h = fnv_step(h, ((to >> 8) & 0xFF) as u8);
    h = fnv_step(h, ((to >> 16) & 0xFF) as u8);
    h = fnv_step(h, (to >> 24) as u8);

    h = fnv_step(h, (payload_bytes & 0xFF) as u8);
    h = fnv_step(h, (payload_bytes >> 8) as u8);

    let d0 = (h & 0xFF) as u8;
    let d1 = ((h >> 8) & 0xFF) as u8;
    let d2 = ((h >> 16) & 0xFF) as u8;
    let d3 = ((h >> 24) & 0xFF) as u8;
    let d4 = ((h >> 32) & 0xFF) as u8;
    let d5 = ((h >> 40) & 0xFF) as u8;
    let d6 = ((h >> 48) & 0xFF) as u8;
    let d7 = (h >> 56) as u8;

    let mut c = [0u8; 15];
    c[0] = ((d6 & 0xC0) >> 6) + 42;
    c[1] = (d3 & 0x1F) + 200;
    c[2] = ((d2 & 0xFC) >> 2) + 5;
    c[3] = d0;
    c[4] = (d2 & 0x03) + 78;
    c[5] = (d4 & 0x7F) + 96;
    c[6] = ((d1 & 0xFC) >> 2) + 100;
    c[7] = if (d7 & 1) == 0 { 79 } else { 7 };
    c[8] = if (d4 & 0x80) == 0 { 37 } else { 83 };
    c[9] = (d5 & 0x07) + 124;
    c[10] = ((d1 & 0xE0) >> 5) + 175;
    c[11] = (d6 & 0x3F) + 33;
    c[12] = match d1 & 0x03 {
        0 => 97,
        1 => 5,
        2 => 43,
        _ => 13,
    };
    c[13] = ((d5 & 0xF8) >> 3) + 210;
    c[14] = ((d7 & 0xFE) >> 1) + 17;
    c
}

/// Write pittle and chonkle into packet_data[1..18].
#[inline(always)]
unsafe fn write_pittle_chonkle(
    packet_data: *mut u8,
    magic: &[u8; 8],
    from: u32,
    to: u32,
    payload_bytes: i32,
) {
    let pittle = compute_pittle(from, to, payload_bytes);
    *packet_data.add(1) = pittle[0];
    *packet_data.add(2) = pittle[1];

    let chonkle = compute_chonkle(magic, from, to, payload_bytes);
    let mut i = 0usize;
    while i < 15 {
        *packet_data.add(3 + i) = chonkle[i];
        i += 1;
    }
}

// =====================================================================
// Packet reflection and redirection
// =====================================================================

/// Reflect packet back to sender: swap src/dst in ETH+IP+UDP,
/// recompute IP checksum, write pittle/chonkle filter bytes.
#[inline(always)]
unsafe fn relay_reflect_packet(
    data: usize,
    payload_bytes: i32,
    magic: &[u8; 8],
    config: *const RelayConfig,
) {
    let eth = data as *mut EthHdr;
    let ip = (data + ETH_HLEN) as *mut IpHdr;
    let udp = (data + ETH_HLEN + IPV4_HLEN) as *mut UdpHdr;

    let tmp_port = (*udp).source;
    (*udp).source = (*udp).dest;
    (*udp).dest = tmp_port;
    (*udp).check = 0;
    (*udp).len = ((UDP_HLEN as i32 + payload_bytes) as u16).to_be();

    let tmp_addr = (*ip).saddr;
    (*ip).saddr = (*ip).daddr;
    (*ip).daddr = tmp_addr;
    (*ip).tot_len = ((IPV4_HLEN as i32 + UDP_HLEN as i32 + payload_bytes) as u16).to_be();
    (*ip).check = 0;

    // Save both MACs in one read, then write back swapped (2 copies instead of 3)
    let mut tmp = [0u8; 12];
    copy_bytes((*eth).h_dest.as_ptr(), tmp.as_mut_ptr(), 12);
    copy_bytes(tmp.as_ptr().add(6), (*eth).h_dest.as_mut_ptr(), 6); // old h_source → h_dest
    copy_bytes(tmp.as_ptr(), (*eth).h_source.as_mut_ptr(), 6);       // old h_dest → h_source

    if (*config).use_gateway_ethernet_address != 0 {
        copy_bytes(
            (*config).gateway_ethernet_address.as_ptr(),
            (*eth).h_dest.as_mut_ptr(),
            ETH_ALEN,
        );
    }

    ip_checksum(ip);

    let from = (*ip).saddr;
    let to = (*ip).daddr;
    let packet_data = (data + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as *mut u8;
    write_pittle_chonkle(packet_data, magic, from, to, payload_bytes);
}

/// Redirect packet to a specific destination. Looks up whitelist for MAC addresses.
/// Returns XDP_TX on success, XDP_DROP if destination not in whitelist.
#[inline(always)]
unsafe fn relay_redirect_packet(
    data: usize,
    payload_bytes: i32,
    source_address: u32,
    dest_address: u32,
    source_port: u16,
    dest_port: u16,
    magic: &[u8; 8],
    config: *const RelayConfig,
) -> u32 {
    let eth = data as *mut EthHdr;
    let ip = (data + ETH_HLEN) as *mut IpHdr;
    let udp = (data + ETH_HLEN + IPV4_HLEN) as *mut UdpHdr;

    (*udp).source = source_port;
    (*udp).dest = dest_port;
    (*udp).check = 0;
    (*udp).len = ((UDP_HLEN as i32 + payload_bytes) as u16).to_be();

    (*ip).saddr = source_address;
    (*ip).daddr = dest_address;
    (*ip).tot_len = ((IPV4_HLEN as i32 + UDP_HLEN as i32 + payload_bytes) as u16).to_be();
    (*ip).check = 0;

    let wl_key = WhitelistKey {
        address: dest_address,
        port: dest_port as u32,
    };

    let wl_value = whitelist_map.get_ptr(&wl_key);
    if wl_value.is_none() {
        return xdp_action::XDP_DROP;
    }
    let wl_value = wl_value.unwrap();

    copy_bytes(
        (*wl_value).dest_address.as_ptr(),
        (*eth).h_source.as_mut_ptr(),
        ETH_ALEN,
    );
    copy_bytes(
        (*wl_value).source_address.as_ptr(),
        (*eth).h_dest.as_mut_ptr(),
        ETH_ALEN,
    );

    if (*config).use_gateway_ethernet_address != 0 {
        copy_bytes(
            (*config).gateway_ethernet_address.as_ptr(),
            (*eth).h_dest.as_mut_ptr(),
            ETH_ALEN,
        );
    }

    ip_checksum(ip);

    let packet_data = (data + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as *mut u8;
    write_pittle_chonkle(packet_data, magic, source_address, dest_address, payload_bytes);

    xdp_action::XDP_TX
}

// =====================================================================
// Token decryption helpers
// =====================================================================

#[inline(always)]
unsafe fn decrypt_route_token(config: *const RelayConfig, route_token: *mut u8) -> bool {
    let nonce = route_token;
    let encrypted = route_token.add(XCHACHA20POLY1305_NONCE_SIZE);
    let mut crypto = Chacha20Poly1305Crypto {
        nonce: [0u8; XCHACHA20POLY1305_NONCE_SIZE],
        key: [0u8; CHACHA20POLY1305_KEY_SIZE],
    };
    copy_bytes(nonce, crypto.nonce.as_mut_ptr(), XCHACHA20POLY1305_NONCE_SIZE);
    copy_bytes_32(
        (*config).relay_secret_key.as_ptr(),
        crypto.key.as_mut_ptr(),
    );
    bpf_relay_xchacha20poly1305_decrypt(
        encrypted,
        (RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES - 24) as i32,
        &crypto,
    ) != 0
}

#[inline(always)]
unsafe fn decrypt_continue_token(config: *const RelayConfig, continue_token: *mut u8) -> bool {
    let nonce = continue_token;
    let encrypted = continue_token.add(XCHACHA20POLY1305_NONCE_SIZE);
    let mut crypto = Chacha20Poly1305Crypto {
        nonce: [0u8; XCHACHA20POLY1305_NONCE_SIZE],
        key: [0u8; CHACHA20POLY1305_KEY_SIZE],
    };
    copy_bytes(nonce, crypto.nonce.as_mut_ptr(), XCHACHA20POLY1305_NONCE_SIZE);
    copy_bytes_32(
        (*config).relay_secret_key.as_ptr(),
        crypto.key.as_mut_ptr(),
    );
    bpf_relay_xchacha20poly1305_decrypt(
        encrypted,
        (RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES - 24) as i32,
        &crypto,
    ) != 0
}

// =====================================================================
// SHA-256 verification helpers
// =====================================================================

/// Verify ping token using SHA-256. Tries the address matching daddr first
/// to avoid a wasted kfunc call (~200-500ns savings on internal packets).
#[inline(always)]
unsafe fn verify_ping_token(
    source_address: u32,
    source_port: u16,
    config: *const RelayConfig,
    state: *const RelayState,
    expire_timestamp: u64,
    ping_token: *const u8,
    daddr: u32,
) -> bool {
    // Pick primary/fallback address based on which address the packet arrived on
    let (primary_addr, fallback_addr) = if daddr == (*config).relay_internal_address {
        ((*config).relay_internal_address, (*config).relay_public_address)
    } else {
        ((*config).relay_public_address, (*config).relay_internal_address)
    };

    let mut verify_data = PingTokenData {
        ping_key: [0u8; RELAY_PING_KEY_BYTES],
        expire_timestamp,
        source_address,
        source_port,
        dest_address: primary_addr,
        dest_port: (*config).relay_port,
    };
    copy_bytes_32(
        (*state).ping_key.as_ptr(),
        verify_data.ping_key.as_mut_ptr(),
    );

    let mut hash = [0u8; RELAY_PING_TOKEN_BYTES];
    bpf_relay_sha256(
        &verify_data as *const PingTokenData as *const u8,
        core::mem::size_of::<PingTokenData>() as i32,
        hash.as_mut_ptr(),
        RELAY_PING_TOKEN_BYTES as i32,
    );

    if bytes_equal_32(hash.as_ptr(), ping_token) {
        return true;
    }

    // Try with fallback address
    verify_data.dest_address = fallback_addr;
    bpf_relay_sha256(
        &verify_data as *const PingTokenData as *const u8,
        core::mem::size_of::<PingTokenData>() as i32,
        hash.as_mut_ptr(),
        RELAY_PING_TOKEN_BYTES as i32,
    );

    bytes_equal_32(hash.as_ptr(), ping_token)
}

/// Verify session header SHA-256. Returns true if first 8 bytes of hash match expected.
#[inline(always)]
unsafe fn verify_session_header(
    session_private_key: *const u8,
    packet_type: u8,
    packet_sequence: u64,
    session_id: u64,
    session_version: u8,
    expected: *const u8,
) -> bool {
    let mut verify_data = HeaderData {
        session_private_key: [0u8; RELAY_SESSION_PRIVATE_KEY_BYTES],
        packet_type,
        packet_sequence,
        session_id,
        session_version,
    };
    copy_bytes_32(
        session_private_key,
        verify_data.session_private_key.as_mut_ptr(),
    );

    let mut hash = [0u8; 32];
    bpf_relay_sha256(
        &verify_data as *const HeaderData as *const u8,
        core::mem::size_of::<HeaderData>() as i32,
        hash.as_mut_ptr(),
        32,
    );

    bytes_equal(hash.as_ptr(), expected, 8)
}

/// Read session_id (u64 LE) and session_version (u8) from header bytes.
#[inline(always)]
unsafe fn read_session_key(header: *const u8) -> (u64, u8) {
    let session_id = read_u64_le(header.add(8));
    let session_version = *header.add(16);
    (session_id, session_version)
}

/// Update whitelist entry for the given address/port with current MAC addresses.
#[inline(always)]
unsafe fn update_whitelist(
    state: *const RelayState,
    eth: *const EthHdr,
    address: u32,
    port: u16,
) {
    let key = WhitelistKey {
        address,
        port: port as u32,
    };
    let mut val = WhitelistValue {
        expire_timestamp: (*state).current_timestamp + WHITELIST_TIMEOUT,
        source_address: [0u8; 6],
        dest_address: [0u8; 6],
    };
    copy_bytes((*eth).h_source.as_ptr(), val.source_address.as_mut_ptr(), 6);
    copy_bytes((*eth).h_dest.as_ptr(), val.dest_address.as_mut_ptr(), 6);
    let _ = whitelist_map.insert(&key, &val, BPF_ANY);
}

// =====================================================================
// Packet handlers
// =====================================================================

/// Handle RELAY_PING_PACKET (type 11): verify ping token, reflect as pong.
#[inline(always)]
unsafe fn handle_relay_ping(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    ip: *const IpHdr,
    udp: *const UdpHdr,
    eth: *const EthHdr,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_RELAY_PING_PACKET_RECEIVED);

    // Exact size: 18 + 8(echo) + 8(expire) + 1(type) + 32(token) = 67
    let expected_end = packet_data as usize + 18 + 8 + 8 + 1 + RELAY_PING_TOKEN_BYTES;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_RELAY_PING_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let payload = packet_data.add(18);
    let expire_timestamp = read_u64_le(payload.add(8));

    if expire_timestamp < (*state).current_timestamp {
        increment_counter(stats, RELAY_COUNTER_RELAY_PING_PACKET_EXPIRED);
        return count_drop(stats, data_end - data);
    }

    // Check relay is known
    let relay_key: u64 = (((*ip).saddr as u64) << 32) | ((*udp).source as u64);
    if relay_map.get_ptr(&relay_key).is_none() {
        increment_counter(stats, RELAY_COUNTER_RELAY_PING_PACKET_UNKNOWN_RELAY);
        return count_drop(stats, data_end - data);
    }

    // Verify ping token
    let ping_token = payload.add(8 + 8 + 1);
    if !verify_ping_token(
        (*ip).saddr,
        (*udp).source,
        config,
        state,
        expire_timestamp,
        ping_token,
        (*ip).daddr,
    ) {
        increment_counter(stats, RELAY_COUNTER_RELAY_PING_PACKET_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    // Update whitelist
    update_whitelist(state, eth, (*ip).saddr, (*udp).source);

    // Reflect as pong
    *packet_data = RELAY_PONG_PACKET;
    let payload_bytes: i32 = 18 + 8;
    relay_reflect_packet(data, payload_bytes, &(*state).current_magic, config);

    // Trim tail
    bpf_xdp_adjust_tail(ctx.ctx, -((8 + 1 + RELAY_PING_TOKEN_BYTES) as i32));

    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    increment_counter(stats, RELAY_COUNTER_RELAY_PONG_PACKET_SENT);
    add_counter(
        stats,
        RELAY_COUNTER_BYTES_SENT,
        (payload_bytes as usize + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as u64,
    );

    xdp_action::XDP_TX
}

/// Handle RELAY_CLIENT_PING_PACKET (type 9): verify token, reflect as client pong.
#[inline(always)]
unsafe fn handle_client_ping(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    ip: *const IpHdr,
    udp: *const UdpHdr,
    eth: *const EthHdr,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_CLIENT_PING_PACKET_RECEIVED);

    // Exact size: 18 + 8(echo) + 8(session_id) + 8(expire) + 32(token) = 74
    let expected_end = packet_data as usize + 18 + 8 + 8 + 8 + RELAY_PING_TOKEN_BYTES;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_CLIENT_PING_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let payload = packet_data.add(18);
    let expire_timestamp = read_u64_le(payload.add(8 + 8));

    if expire_timestamp < (*state).current_timestamp {
        increment_counter(stats, RELAY_COUNTER_CLIENT_PING_PACKET_EXPIRED);
        return count_drop(stats, data_end - data);
    }

    // Client ping: source_port = 0 (NAT may change client port)
    let ping_token = payload.add(8 + 8 + 8);
    let mut verify_data = PingTokenData {
        ping_key: [0u8; RELAY_PING_KEY_BYTES],
        expire_timestamp,
        source_address: (*ip).saddr,
        source_port: 0, // IMPORTANT: NAT workaround
        dest_address: (*config).relay_public_address,
        dest_port: (*udp).dest,
    };
    copy_bytes_32(
        (*state).ping_key.as_ptr(),
        verify_data.ping_key.as_mut_ptr(),
    );

    let mut hash = [0u8; 32];
    bpf_relay_sha256(
        &verify_data as *const PingTokenData as *const u8,
        core::mem::size_of::<PingTokenData>() as i32,
        hash.as_mut_ptr(),
        32,
    );

    if !bytes_equal_32(hash.as_ptr(), ping_token) {
        increment_counter(stats, RELAY_COUNTER_CLIENT_PING_PACKET_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    update_whitelist(state, eth, (*ip).saddr, (*udp).source);

    *packet_data = RELAY_CLIENT_PONG_PACKET;
    let payload_bytes: i32 = 18 + 8 + 8;
    relay_reflect_packet(data, payload_bytes, &(*state).current_magic, config);

    bpf_xdp_adjust_tail(ctx.ctx, -((8 + RELAY_PING_TOKEN_BYTES) as i32));

    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    increment_counter(stats, RELAY_COUNTER_CLIENT_PING_PACKET_RESPONDED_WITH_PONG);
    add_counter(
        stats,
        RELAY_COUNTER_BYTES_SENT,
        (payload_bytes as usize + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as u64,
    );

    xdp_action::XDP_TX
}

/// Handle RELAY_SERVER_PING_PACKET (type 13): verify token, reflect as server pong.
#[inline(always)]
unsafe fn handle_server_ping(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    ip: *mut IpHdr,
    udp: *const UdpHdr,
    eth: *const EthHdr,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_SERVER_PING_PACKET_RECEIVED);

    // Exact size: 18 + 8(echo) + 8(expire) + 32(token) = 66
    let expected_end = packet_data as usize + 18 + 8 + 8 + RELAY_PING_TOKEN_BYTES;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_SERVER_PING_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let payload = packet_data.add(18);
    let expire_timestamp = read_u64_le(payload.add(8));

    if expire_timestamp < (*state).current_timestamp {
        increment_counter(stats, RELAY_COUNTER_SERVER_PING_PACKET_EXPIRED);
        return count_drop(stats, data_end - data);
    }

    let ping_token = payload.add(8 + 8);
    if !verify_ping_token(
        (*ip).saddr,
        (*udp).source,
        config,
        state,
        expire_timestamp,
        ping_token,
        (*ip).daddr,
    ) {
        increment_counter(stats, RELAY_COUNTER_SERVER_PING_PACKET_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    update_whitelist(state, eth, (*ip).saddr, (*udp).source);

    // IMPORTANT: Respond from relay public address
    (*ip).daddr = (*config).relay_public_address;

    *packet_data = RELAY_SERVER_PONG_PACKET;
    let payload_bytes: i32 = 18 + 8;
    relay_reflect_packet(data, payload_bytes, &(*state).current_magic, config);

    bpf_xdp_adjust_tail(ctx.ctx, -((8 + RELAY_PING_TOKEN_BYTES) as i32));

    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    increment_counter(stats, RELAY_COUNTER_SERVER_PING_PACKET_RESPONDED_WITH_PONG);
    add_counter(
        stats,
        RELAY_COUNTER_BYTES_SENT,
        (payload_bytes as usize + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as u64,
    );

    xdp_action::XDP_TX
}

/// Handle RELAY_PONG_PACKET (type 12): whitelist check, pass to userspace.
#[inline(always)]
unsafe fn handle_relay_pong(
    data: usize,
    data_end: usize,
    packet_data: *const u8,
    stats: *mut RelayStats,
    state: *const RelayState,
    ip: *const IpHdr,
    udp: *const UdpHdr,
    whitelist: *mut WhitelistValue,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_RELAY_PONG_PACKET_RECEIVED);

    let expected_end = packet_data as usize + 18 + 8;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_RELAY_PONG_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let relay_key: u64 = (((*ip).saddr as u64) << 32) | ((*udp).source as u64);
    if relay_map.get_ptr(&relay_key).is_none() {
        increment_counter(stats, RELAY_COUNTER_RELAY_PONG_PACKET_UNKNOWN_RELAY);
        return count_drop(stats, data_end - data);
    }

    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;

    xdp_action::XDP_PASS
}

/// Handle RELAY_ROUTE_REQUEST_PACKET (type 1): decrypt token, create session, forward.
#[inline(always)]
unsafe fn handle_route_request(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    udp: *const UdpHdr,
    whitelist: *mut WhitelistValue,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_ROUTE_REQUEST_PACKET_RECEIVED);

    if (packet_data as usize) + 18 + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES > data_end {
        increment_counter(stats, RELAY_COUNTER_ROUTE_REQUEST_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    if !decrypt_route_token(config, packet_data.add(18)) {
        increment_counter(stats, RELAY_COUNTER_ROUTE_REQUEST_PACKET_COULD_NOT_DECRYPT_ROUTE_TOKEN);
        return count_drop(stats, data_end - data);
    }

    let token = packet_data.add(18 + 24) as *const RouteToken;

    if (*token).expire_timestamp < (*state).current_timestamp {
        increment_counter(stats, RELAY_COUNTER_ROUTE_REQUEST_PACKET_TOKEN_EXPIRED);
        return count_drop(stats, data_end - data);
    }

    let mut session = SessionData {
        session_private_key: [0u8; RELAY_SESSION_PRIVATE_KEY_BYTES],
        expire_timestamp: (*token).expire_timestamp,
        session_id: (*token).session_id,
        payload_client_to_server_sequence: 0,
        payload_server_to_client_sequence: 0,
        special_client_to_server_sequence: 0,
        special_server_to_client_sequence: 0,
        envelope_kbps_up: (*token).envelope_kbps_up,
        envelope_kbps_down: (*token).envelope_kbps_down,
        next_address: (*token).next_address,
        prev_address: (*token).prev_address,
        next_port: (*token).next_port,
        prev_port: (*token).prev_port,
        session_version: (*token).session_version,
        next_internal: (*token).next_internal,
        prev_internal: (*token).prev_internal,
        first_hop: 0,
    };
    copy_bytes_32(
        (*token).session_private_key.as_ptr(),
        session.session_private_key.as_mut_ptr(),
    );

    if (*token).prev_port == 0 {
        session.first_hop = 1;
        session.prev_port = (*udp).source;
    }

    let key = SessionKey {
        session_id: (*token).session_id,
        session_version: (*token).session_version as u64,
    };
    let _ = session_map.insert(&key, &session, BPF_NOEXIST);

    // Copy ETH+IP+UDP headers forward past the first route token
    copy_bytes(
        data as *const u8,
        (data + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES) as *mut u8,
        ETH_HLEN + IPV4_HLEN + UDP_HLEN,
    );

    let new_data = data + RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES;
    let new_packet_data = (new_data + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as *mut u8;
    *new_packet_data = RELAY_ROUTE_REQUEST_PACKET;

    let new_payload_bytes = (data_end - new_data - ETH_HLEN - IPV4_HLEN - UDP_HLEN) as i32;
    let result = relay_redirect_packet(
        new_data,
        new_payload_bytes,
        (*config).relay_internal_address,
        session.next_address,
        (*config).relay_port,
        session.next_port,
        &(*state).current_magic,
        config,
    );

    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    bpf_xdp_adjust_head(ctx.ctx, RELAY_ENCRYPTED_ROUTE_TOKEN_BYTES as i32);

    increment_counter(stats, RELAY_COUNTER_ROUTE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - new_data) as u64);

    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;

    xdp_action::XDP_TX
}

/// Handle RELAY_ROUTE_RESPONSE_PACKET (type 2): verify header, forward to prev hop.
#[inline(always)]
unsafe fn handle_route_response(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_RECEIVED);

    let header = packet_data.add(18);
    let expected_end = header as usize + RELAY_HEADER_BYTES;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);
    if packet_sequence <= (*session).special_server_to_client_sequence {
        increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).special_server_to_client_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, (18 + RELAY_HEADER_BYTES) as i32,
        (*config).relay_internal_address, (*session).prev_address,
        (*config).relay_port, (*session).prev_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_ROUTE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_CLIENT_TO_SERVER_PACKET (type 3): verify header, forward to next hop.
#[inline(always)]
unsafe fn handle_client_to_server(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_RECEIVED);

    let header = packet_data.add(18);
    if (header as usize) + RELAY_HEADER_BYTES > data_end {
        increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_SMALL);
        return count_drop(stats, data_end - data);
    }

    let total_payload = (data_end - (packet_data as usize)) as i32;
    let inner_payload = total_payload - 18 - RELAY_HEADER_BYTES as i32;
    if inner_payload > RELAY_MTU as i32 {
        increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_TOO_BIG);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);
    if packet_sequence <= (*session).payload_client_to_server_sequence {
        increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).payload_client_to_server_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, total_payload,
        (*config).relay_internal_address, (*session).next_address,
        (*config).relay_port, (*session).next_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_CLIENT_TO_SERVER_PACKET_FORWARD_TO_NEXT_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_SERVER_TO_CLIENT_PACKET (type 4): verify header, forward to prev hop.
#[inline(always)]
unsafe fn handle_server_to_client(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_RECEIVED);

    let header = packet_data.add(18);
    if (header as usize) + RELAY_HEADER_BYTES > data_end {
        increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_SMALL);
        return count_drop(stats, data_end - data);
    }

    let total_payload = (data_end - (packet_data as usize)) as i32;
    let inner_payload = total_payload - 18 - RELAY_HEADER_BYTES as i32;
    if inner_payload > RELAY_MTU as i32 {
        increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_TOO_BIG);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);
    if packet_sequence <= (*session).payload_server_to_client_sequence {
        increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).payload_server_to_client_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, total_payload,
        (*config).relay_internal_address, (*session).prev_address,
        (*config).relay_port, (*session).prev_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_SERVER_TO_CLIENT_PACKET_FORWARD_TO_PREVIOUS_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_CONTINUE_REQUEST_PACKET (type 7): decrypt token, update session, forward.
#[inline(always)]
unsafe fn handle_continue_request(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_RECEIVED);

    if (packet_data as usize) + 18 + RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES + RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES > data_end {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    if !decrypt_continue_token(config, packet_data.add(18)) {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_DECRYPT_CONTINUE_TOKEN);
        return count_drop(stats, data_end - data);
    }

    let token = packet_data.add(18 + 24) as *const ContinueToken;

    if (*token).expire_timestamp < (*state).current_timestamp {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_TOKEN_EXPIRED);
        return count_drop(stats, data_end - data);
    }

    let key = SessionKey {
        session_id: (*token).session_id,
        session_version: (*token).session_version as u64,
    };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    (*session).expire_timestamp = (*token).expire_timestamp;

    copy_bytes(
        data as *const u8,
        (data + RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES) as *mut u8,
        ETH_HLEN + IPV4_HLEN + UDP_HLEN,
    );

    let new_data = data + RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES;
    let new_packet_data = (new_data + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as *mut u8;
    *new_packet_data = RELAY_CONTINUE_REQUEST_PACKET;

    let new_payload_bytes = (data_end - new_data - ETH_HLEN - IPV4_HLEN - UDP_HLEN) as i32;
    let result = relay_redirect_packet(
        new_data, new_payload_bytes,
        (*config).relay_internal_address, (*session).next_address,
        (*config).relay_port, (*session).next_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    bpf_xdp_adjust_head(ctx.ctx, RELAY_ENCRYPTED_CONTINUE_TOKEN_BYTES as i32);

    increment_counter(stats, RELAY_COUNTER_CONTINUE_REQUEST_PACKET_FORWARD_TO_NEXT_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - new_data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_CONTINUE_RESPONSE_PACKET (type 8): verify header, forward to prev hop.
#[inline(always)]
unsafe fn handle_continue_response(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_RECEIVED);

    let header = packet_data.add(18);
    let expected_end = header as usize + RELAY_HEADER_BYTES;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);

    if packet_sequence <= (*session).special_server_to_client_sequence {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).special_server_to_client_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, (18 + RELAY_HEADER_BYTES) as i32,
        (*config).relay_internal_address, (*session).prev_address,
        (*config).relay_port, (*session).prev_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_CONTINUE_RESPONSE_PACKET_FORWARD_TO_PREVIOUS_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_SESSION_PING_PACKET (type 5): verify header, forward to next hop.
#[inline(always)]
unsafe fn handle_session_ping(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_RECEIVED);

    let header = packet_data.add(18);
    let expected_end = header as usize + RELAY_HEADER_BYTES + 8;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);
    if packet_sequence <= (*session).special_client_to_server_sequence {
        increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).special_client_to_server_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, (18 + RELAY_HEADER_BYTES + 8) as i32,
        (*config).relay_internal_address, (*session).next_address,
        (*config).relay_port, (*session).next_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_SESSION_PING_PACKET_FORWARD_TO_NEXT_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

/// Handle RELAY_SESSION_PONG_PACKET (type 6): verify header, forward to prev hop.
#[inline(always)]
unsafe fn handle_session_pong(
    data: usize,
    data_end: usize,
    packet_data: *mut u8,
    stats: *mut RelayStats,
    config: *const RelayConfig,
    state: *const RelayState,
    whitelist: *mut WhitelistValue,
    packet_type: u8,
) -> u32 {
    increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_RECEIVED);

    let header = packet_data.add(18);
    let expected_end = header as usize + RELAY_HEADER_BYTES + 8;
    if expected_end != data_end {
        increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_WRONG_SIZE);
        return count_drop(stats, data_end - data);
    }

    let (session_id, session_version) = read_session_key(header);
    let key = SessionKey { session_id, session_version: session_version as u64 };
    let session = session_map.get_ptr_mut(&key);
    if session.is_none() {
        increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_COULD_NOT_FIND_SESSION);
        return count_drop(stats, data_end - data);
    }
    let session = session.unwrap();

    let packet_sequence = read_u64_le(header);
    if packet_sequence <= (*session).special_server_to_client_sequence {
        increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_ALREADY_RECEIVED);
        return count_drop(stats, data_end - data);
    }

    let expected = header.add(8 + 8 + 1);
    if !verify_session_header(
        (*session).session_private_key.as_ptr(),
        packet_type, packet_sequence, session_id, session_version, expected,
    ) {
        increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_HEADER_DID_NOT_VERIFY);
        return count_drop(stats, data_end - data);
    }

    (*session).special_server_to_client_sequence = packet_sequence;

    let result = relay_redirect_packet(
        data, (18 + RELAY_HEADER_BYTES + 8) as i32,
        (*config).relay_internal_address, (*session).prev_address,
        (*config).relay_port, (*session).prev_port,
        &(*state).current_magic, config,
    );
    if result == xdp_action::XDP_DROP {
        increment_counter(stats, RELAY_COUNTER_REDIRECT_NOT_IN_WHITELIST);
        return count_drop(stats, data_end - data);
    }

    increment_counter(stats, RELAY_COUNTER_SESSION_PONG_PACKET_FORWARD_TO_PREVIOUS_HOP);
    increment_counter(stats, RELAY_COUNTER_PACKETS_SENT);
    add_counter(stats, RELAY_COUNTER_BYTES_SENT, (data_end - data) as u64);
    (*whitelist).expire_timestamp = (*state).current_timestamp + WHITELIST_TIMEOUT;
    xdp_action::XDP_TX
}

// =====================================================================
// Main XDP entry point
// =====================================================================

#[no_mangle]
#[link_section = "xdp/relay_xdp"]
pub fn relay_xdp_filter(ctx: *mut aya_ebpf::bindings::xdp_md) -> u32 {
    let ctx = XdpContext::new(ctx);
    match unsafe { try_relay_xdp_filter(&ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
unsafe fn try_relay_xdp_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let stats = get_stats().ok_or(())?;
    let config = get_config().ok_or(())?;

    // === Parse Ethernet header ===

    if data + ETH_HLEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth = data as *mut EthHdr;

    if (*eth).h_proto == (ETH_P_IP as u16).to_be() {
        // === Parse IPv4 header ===
        let t0 = profile_now(); // D2: profiling - start of parse

        let ip = (data + ETH_HLEN) as *mut IpHdr;
        if data + ETH_HLEN + IPV4_HLEN > data_end {
            return Ok(count_drop(stats, data_end - data));
        }

        if (*ip).protocol != IPPROTO_UDP {
            return if (*config).dedicated != 0 {
                Ok(count_drop(stats, data_end - data))
            } else {
                Ok(xdp_action::XDP_PASS)
            };
        }

        increment_counter(stats, RELAY_COUNTER_PACKETS_RECEIVED);
        add_counter(stats, RELAY_COUNTER_BYTES_RECEIVED, (data_end - data) as u64);

        // Drop packets with IP header length != 20
        if (*ip).version_ihl & 0x0F != 5 {
            increment_counter(stats, RELAY_COUNTER_DROP_LARGE_IP_HEADER);
            return if (*config).dedicated != 0 {
                Ok(count_drop(stats, data_end - data))
            } else {
                Ok(xdp_action::XDP_PASS)
            };
        }

        // === Parse UDP header ===

        let udp = (data + ETH_HLEN + IPV4_HLEN) as *mut UdpHdr;
        if data + ETH_HLEN + IPV4_HLEN + UDP_HLEN > data_end {
            return Ok(count_drop(stats, data_end - data));
        }

        // Check destination matches relay address and port
        if (*udp).dest != (*config).relay_port
            || ((*ip).daddr != (*config).relay_public_address
                && (*ip).daddr != (*config).relay_internal_address)
        {
            return if (*config).dedicated != 0 {
                Ok(count_drop(stats, data_end - data))
            } else {
                Ok(xdp_action::XDP_PASS)
            };
        }

        // === UDP payload ===

        let packet_data = (data + ETH_HLEN + IPV4_HLEN + UDP_HLEN) as *mut u8;

        if (packet_data as usize) + 18 > data_end {
            increment_counter(stats, RELAY_COUNTER_PACKET_TOO_SMALL);
            return Ok(count_drop(stats, data_end - data));
        }

        let packet_bytes = data_end - (packet_data as usize);
        if packet_bytes > 1400 {
            increment_counter(stats, RELAY_COUNTER_PACKET_TOO_LARGE);
            return Ok(count_drop(stats, data_end - data));
        }

        let t1 = profile_now(); // D2: profiling - after parse
        profile_record(stats, RELAY_COUNTER_PROFILE_PARSE_NS, t0, t1);

        // === Basic packet filter ===

        let pd = packet_data;
        if *pd < 0x01
            || *pd > 0x0E
            || *pd.add(2) != (1 | ((255u8.wrapping_sub(*pd.add(1))) ^ 113))
            || *pd.add(3) < 0x2A || *pd.add(3) > 0x2D
            || *pd.add(4) < 0xC8 || *pd.add(4) > 0xE7
            || *pd.add(5) < 0x05 || *pd.add(5) > 0x44
            || *pd.add(7) < 0x4E || *pd.add(7) > 0x51
            || *pd.add(8) < 0x60 || *pd.add(8) > 0xDF
            || *pd.add(9) < 0x64 || *pd.add(9) > 0xE3
            || (*pd.add(10) != 0x07 && *pd.add(10) != 0x4F)
            || (*pd.add(11) != 0x25 && *pd.add(11) != 0x53)
            || *pd.add(12) < 0x7C || *pd.add(12) > 0x83
            || *pd.add(13) < 0xAF || *pd.add(13) > 0xB6
            || *pd.add(14) < 0x21 || *pd.add(14) > 0x60
            || (*pd.add(15) != 0x61 && *pd.add(15) != 0x05
                && *pd.add(15) != 0x2B && *pd.add(15) != 0x0D)
            || *pd.add(16) < 0xD2 || *pd.add(16) > 0xF1
            || *pd.add(17) < 0x11 || *pd.add(17) > 0x90
        {
            increment_counter(stats, RELAY_COUNTER_BASIC_PACKET_FILTER_DROPPED_PACKET);
            return Ok(count_drop(stats, data_end - data));
        }

        let t2 = profile_now(); // D2: profiling - after DDoS filter
        profile_record(stats, RELAY_COUNTER_PROFILE_FILTER_NS, t1, t2);

        // === Get relay state ===

        let state = get_state().ok_or(())?;
        let packet_type = *pd;

        // === First switch: ping packets (before whitelist check) ===

        match packet_type {
            RELAY_PING_PACKET => {
                return Ok(handle_relay_ping(ctx, data, data_end, packet_data, stats, config, state, ip, udp, eth));
            }
            RELAY_CLIENT_PING_PACKET => {
                return Ok(handle_client_ping(ctx, data, data_end, packet_data, stats, config, state, ip, udp, eth));
            }
            RELAY_SERVER_PING_PACKET => {
                return Ok(handle_server_ping(ctx, data, data_end, packet_data, stats, config, state, ip, udp, eth));
            }
            _ => {}
        }

        // === Whitelist check ===

        let t3 = profile_now(); // D2: profiling - before map lookup

        let wl_key = WhitelistKey {
            address: (*ip).saddr,
            port: (*udp).source as u32,
        };
        let whitelist = whitelist_map.get_ptr_mut(&wl_key);
        if whitelist.is_none() {
            increment_counter(stats, RELAY_COUNTER_NOT_IN_WHITELIST);
            return Ok(count_drop(stats, data_end - data));
        }
        let whitelist = whitelist.unwrap();

        let t4 = profile_now(); // D2: profiling - after map lookup
        profile_record(stats, RELAY_COUNTER_PROFILE_MAP_LOOKUP_NS, t3, t4);

        // === Second switch: remaining packet types ===

        let action = match packet_type {
            RELAY_PONG_PACKET => Ok(handle_relay_pong(data, data_end, packet_data, stats, state, ip, udp, whitelist)),
            RELAY_ROUTE_REQUEST_PACKET => Ok(handle_route_request(ctx, data, data_end, packet_data, stats, config, state, udp, whitelist)),
            RELAY_ROUTE_RESPONSE_PACKET => Ok(handle_route_response(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            RELAY_CLIENT_TO_SERVER_PACKET => Ok(handle_client_to_server(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            RELAY_SERVER_TO_CLIENT_PACKET => Ok(handle_server_to_client(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            RELAY_CONTINUE_REQUEST_PACKET => Ok(handle_continue_request(ctx, data, data_end, packet_data, stats, config, state, whitelist)),
            RELAY_CONTINUE_RESPONSE_PACKET => Ok(handle_continue_response(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            RELAY_SESSION_PING_PACKET => Ok(handle_session_ping(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            RELAY_SESSION_PONG_PACKET => Ok(handle_session_pong(data, data_end, packet_data, stats, config, state, whitelist, packet_type)),
            _ => Ok(count_drop(stats, data_end - data)),
        };

        // D2: profiling - record total time and sample count
        let t_end = profile_now();
        profile_record(stats, RELAY_COUNTER_PROFILE_TOTAL_NS, t0, t_end);
        increment_counter(stats, RELAY_COUNTER_PROFILE_SAMPLES);

        action
    } else if (*eth).h_proto == (ETH_P_IPV6 as u16).to_be() {
        if (*config).dedicated != 0 {
            return Ok(count_drop(stats, data_end - data));
        }
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

// =====================================================================
// Panic handler (required for no_std eBPF)
// =====================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
