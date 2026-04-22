// mod route - RouteManager state machine + wire packet builders.
//
// Wire helpers (generate_pittle, generate_chonkle, fnv1a_64):
//   copied from rust-sdk/src/route/mod.rs - logic identical.
//
// write_header / read_header:
//   HeaderData layout matches relay-xdp-common::HeaderData (50 bytes, packed):
//   [0..32] session_private_key, [32] packet_type, [33..41] packet_sequence (LE),
//   [41..49] session_id (LE), [49] session_version
//   HMAC = SHA-256(HeaderData)[0..8] stored at header[17..25].
pub mod trackers;

pub const HEADER_BYTES: usize = 25;
use crate::address::Address;
use crate::constants::{
    CLIENT_ROUTE_TIMEOUT, CONTINUE_REQUEST_SEND_TIME, CONTINUE_REQUEST_TIMEOUT,
    ENCRYPTED_CONTINUE_TOKEN_BYTES, ENCRYPTED_ROUTE_TOKEN_BYTES, FLAGS_BAD_CONTINUE_TOKEN,
    FLAGS_BAD_ROUTE_TOKEN, FLAGS_CONTINUE_REQUEST_TIMED_OUT, FLAGS_NO_ROUTE_TO_CONTINUE,
    FLAGS_PREVIOUS_UPDATE_STILL_PENDING, FLAGS_ROUTE_EXPIRED, FLAGS_ROUTE_REQUEST_TIMED_OUT,
    FLAGS_ROUTE_TIMED_OUT, MAX_PACKET_BYTES, MAX_TOKENS, MTU, PACKET_BODY_OFFSET,
    PACKET_TYPE_CLIENT_TO_SERVER, PACKET_TYPE_CONTINUE_REQUEST, PACKET_TYPE_ROUTE_REQUEST,
    ROUTE_REQUEST_SEND_TIME, ROUTE_REQUEST_TIMEOUT, SESSION_PRIVATE_KEY_BYTES, SLICE_SECONDS,
    UPDATE_TYPE_CONTINUE, UPDATE_TYPE_DIRECT, UPDATE_TYPE_ROUTE,
};
use crate::crypto::{hash_sha256, XCHACHA_KEY_BYTES};
use crate::platform;
use crate::tokens::{decrypt_continue_token, decrypt_route_token};
// ── FNV-1a (64-bit) - copied from rust-sdk ───────────────────────────────────
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}
// ── Packet filter helpers - copied from rust-sdk ──────────────────────────────
/// Fills the 2-byte "pittle" (bytes 1-2 of every relay packet).
pub fn generate_pittle(
    output: &mut [u8; 2],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
    packet_length: u16,
) {
    let mut sum: u16 = 0;
    for &b in from_address.iter() {
        sum = sum.wrapping_add(b as u16);
    }
    for &b in to_address.iter() {
        sum = sum.wrapping_add(b as u16);
    }
    let len_bytes = packet_length.to_le_bytes();
    sum = sum.wrapping_add(len_bytes[0] as u16);
    sum = sum.wrapping_add(len_bytes[1] as u16);
    let [s0, s1] = sum.to_le_bytes();
    output[0] = 1u8.wrapping_add(s0 ^ s1 ^ 193);
    output[1] = 1u8.wrapping_add((255u8.wrapping_sub(output[0])) ^ 113);
}
/// Fills the 15-byte "chonkle" (bytes 3-17 of every relay packet).
pub fn generate_chonkle(
    output: &mut [u8; 15],
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
    packet_length: u16,
) {
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(magic);
    buf[8..12].copy_from_slice(from_address);
    buf[12..16].copy_from_slice(to_address);
    buf[16..18].copy_from_slice(&packet_length.to_le_bytes());
    let hash = fnv1a_64(&buf);
    let d = hash.to_le_bytes();
    output[0] = ((d[6] & 0xC0) >> 6) + 42;
    output[1] = (d[3] & 0x1F) + 200;
    output[2] = ((d[2] & 0xFC) >> 2) + 5;
    output[3] = d[0];
    output[4] = (d[2] & 0x03) + 78;
    output[5] = (d[4] & 0x7F) + 96;
    output[6] = ((d[1] & 0xFC) >> 2) + 100;
    output[7] = if (d[7] & 1) == 0 { 79 } else { 7 };
    output[8] = if (d[4] & 0x80) == 0 { 37 } else { 83 };
    output[9] = (d[5] & 0x07) + 124;
    output[10] = ((d[1] & 0xE0) >> 5) + 175;
    output[11] = (d[6] & 0x3F) + 33;
    let value = d[1] & 0x03;
    output[12] = match value {
        0 => 97,
        1 => 5,
        2 => 43,
        _ => 13,
    };
    output[13] = ((d[5] & 0xF8) >> 3) + 210;
    output[14] = ((d[7] & 0xFE) >> 1) + 17;
}
/// Public alias for stamp_filter - fills pittle + chonkle bytes [1..18].
pub fn stamp_packet(
    packet: &mut [u8],
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
) {
    stamp_filter(packet, magic, from_address, to_address);
}

fn stamp_filter(packet: &mut [u8], magic: &[u8; 8], from_address: &[u8; 4], to_address: &[u8; 4]) {
    let len = packet.len() as u16;
    let mut pittle = [0u8; 2];
    let mut chonkle = [0u8; 15];
    generate_pittle(&mut pittle, from_address, to_address, len);
    generate_chonkle(&mut chonkle, magic, from_address, to_address, len);
    packet[1..3].copy_from_slice(&pittle);
    packet[3..18].copy_from_slice(&chonkle);
}
// ── Header read / write ───────────────────────────────────────────────────────
//
// Wire layout (HEADER_BYTES = 25):
//   [0..8]   sequence         u64 LE
//   [8..16]  session_id       u64 LE
//   [16]     session_version  u8
//   [17..25] SHA-256(HeaderData)[0..8]
//
// HeaderData (50 bytes, matches relay-xdp-common::HeaderData #[repr(C, packed)]):
//   [0..32]  session_private_key [u8; 32]
//   [32]     packet_type         u8
//   [33..41] packet_sequence     u64 LE
//   [41..49] session_id          u64 LE
//   [49]     session_version     u8
fn make_header_data(
    private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    packet_type: u8,
    sequence: u64,
    session_id: u64,
    session_version: u8,
) -> [u8; 50] {
    let mut buf = [0u8; 50];
    buf[..32].copy_from_slice(private_key);
    buf[32] = packet_type;
    buf[33..41].copy_from_slice(&sequence.to_le_bytes());
    buf[41..49].copy_from_slice(&session_id.to_le_bytes());
    buf[49] = session_version;
    buf
}
pub fn write_header(
    packet_type: u8,
    sequence: u64,
    session_id: u64,
    session_version: u8,
    private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    header: &mut [u8; HEADER_BYTES],
) {
    header[..8].copy_from_slice(&sequence.to_le_bytes());
    header[8..16].copy_from_slice(&session_id.to_le_bytes());
    header[16] = session_version;
    let sha = hash_sha256(&make_header_data(
        private_key,
        packet_type,
        sequence,
        session_id,
        session_version,
    ));
    header[17..25].copy_from_slice(&sha[..8]);
}
pub fn read_header(
    packet_type: u8,
    private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    header: &[u8],
) -> Option<(u64, u64, u8)> {
    if header.len() < HEADER_BYTES {
        return None;
    }
    let sequence = u64::from_le_bytes(header[0..8].try_into().unwrap());
    let session_id = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let session_version = header[16];
    let sha = hash_sha256(&make_header_data(
        private_key,
        packet_type,
        sequence,
        session_id,
        session_version,
    ));
    if sha[..8] != header[17..25] {
        return None;
    }
    Some((sequence, session_id, session_version))
}
// ── Wire packet builders ──────────────────────────────────────────────────────
pub fn write_route_request_packet(
    packet_data: &mut [u8; MAX_PACKET_BYTES],
    token_data: &[u8],
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
) -> usize {
    packet_data[0] = PACKET_TYPE_ROUTE_REQUEST;
    let end = PACKET_BODY_OFFSET + token_data.len();
    packet_data[PACKET_BODY_OFFSET..end].copy_from_slice(token_data);
    stamp_filter(&mut packet_data[..end], magic, from_address, to_address);
    end
}
pub fn write_continue_request_packet(
    packet_data: &mut [u8; MAX_PACKET_BYTES],
    token_data: &[u8],
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
) -> usize {
    packet_data[0] = PACKET_TYPE_CONTINUE_REQUEST;
    let end = PACKET_BODY_OFFSET + token_data.len();
    packet_data[PACKET_BODY_OFFSET..end].copy_from_slice(token_data);
    stamp_filter(&mut packet_data[..end], magic, from_address, to_address);
    end
}
#[allow(clippy::too_many_arguments)]
pub fn write_client_to_server_packet(
    packet_data: &mut [u8; MAX_PACKET_BYTES],
    sequence: u64,
    session_id: u64,
    session_version: u8,
    private_key: &[u8; SESSION_PRIVATE_KEY_BYTES],
    payload: &[u8],
    magic: &[u8; 8],
    from_address: &[u8; 4],
    to_address: &[u8; 4],
) -> usize {
    let end = PACKET_BODY_OFFSET + HEADER_BYTES + payload.len();
    if end > MAX_PACKET_BYTES || payload.len() > MTU {
        return 0;
    }
    packet_data[0] = PACKET_TYPE_CLIENT_TO_SERVER;
    let mut hdr = [0u8; HEADER_BYTES];
    write_header(
        PACKET_TYPE_CLIENT_TO_SERVER,
        sequence,
        session_id,
        session_version,
        private_key,
        &mut hdr,
    );
    packet_data[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES].copy_from_slice(&hdr);
    packet_data[PACKET_BODY_OFFSET + HEADER_BYTES..end].copy_from_slice(payload);
    stamp_filter(&mut packet_data[..end], magic, from_address, to_address);
    end
}
// ── Address helper ────────────────────────────────────────────────────────────
pub fn address_ipv4_bytes(addr: &Address) -> [u8; 4] {
    match addr {
        Address::V4 { octets, .. } => *octets,
        _ => [0u8; 4],
    }
}
// ── RouteData ─────────────────────────────────────────────────────────────────
struct RouteData {
    current_route: bool,
    current_route_expire_time: f64,
    current_route_session_id: u64,
    current_route_session_version: u8,
    current_route_kbps_up: i32,
    current_route_kbps_down: i32,
    current_route_next_address: Address,
    current_route_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    previous_route: bool,
    previous_route_session_id: u64,
    previous_route_session_version: u8,
    previous_route_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    pending_route: bool,
    pending_route_start_time: f64,
    pending_route_last_send_time: f64,
    pending_route_session_id: u64,
    pending_route_session_version: u8,
    pending_route_kbps_up: i32,
    pending_route_kbps_down: i32,
    pending_route_next_address: Address,
    pending_route_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    pending_route_request_packet_data: Box<[u8; MAX_PACKET_BYTES]>,
    pending_route_request_packet_bytes: usize,
    pending_continue: bool,
    pending_continue_start_time: f64,
    pending_continue_last_send_time: f64,
    pending_continue_request_packet_data: Box<[u8; MAX_PACKET_BYTES]>,
    pending_continue_request_packet_bytes: usize,
}
impl RouteData {
    fn new() -> Self {
        Self {
            current_route: false,
            current_route_expire_time: 0.0,
            current_route_session_id: 0,
            current_route_session_version: 0,
            current_route_kbps_up: 0,
            current_route_kbps_down: 0,
            current_route_next_address: Address::None,
            current_route_private_key: [0; SESSION_PRIVATE_KEY_BYTES],
            previous_route: false,
            previous_route_session_id: 0,
            previous_route_session_version: 0,
            previous_route_private_key: [0; SESSION_PRIVATE_KEY_BYTES],
            pending_route: false,
            pending_route_start_time: 0.0,
            pending_route_last_send_time: 0.0,
            pending_route_session_id: 0,
            pending_route_session_version: 0,
            pending_route_kbps_up: 0,
            pending_route_kbps_down: 0,
            pending_route_next_address: Address::None,
            pending_route_private_key: [0; SESSION_PRIVATE_KEY_BYTES],
            pending_route_request_packet_data: Box::new([0; MAX_PACKET_BYTES]),
            pending_route_request_packet_bytes: 0,
            pending_continue: false,
            pending_continue_start_time: 0.0,
            pending_continue_last_send_time: 0.0,
            pending_continue_request_packet_data: Box::new([0; MAX_PACKET_BYTES]),
            pending_continue_request_packet_bytes: 0,
        }
    }
}
// ── RouteManager ──────────────────────────────────────────────────────────────
pub struct RouteManager {
    pub send_sequence: u64,
    pub fallback_to_direct: bool,
    pub flags: u32,
    last_route_update_time: f64,
    route_data: RouteData,
}
impl RouteManager {
    pub fn new() -> Self {
        Self {
            send_sequence: 0,
            fallback_to_direct: false,
            flags: 0,
            last_route_update_time: 0.0,
            route_data: RouteData::new(),
        }
    }
    pub fn reset(&mut self) {
        self.send_sequence = 0;
        self.fallback_to_direct = false;
        self.flags = 0;
        self.last_route_update_time = 0.0;
        self.route_data = RouteData::new();
    }
    pub fn set_fallback_to_direct(&mut self, flags: u32) {
        self.flags |= flags;
        if self.fallback_to_direct {
            return;
        }
        self.fallback_to_direct = true;
        self.save_current_as_previous();
        self.route_data.current_route = false;
    }
    pub fn direct_route(&mut self) {
        if self.fallback_to_direct {
            return;
        }
        self.save_current_as_previous();
        self.route_data.current_route = false;
    }
    fn save_current_as_previous(&mut self) {
        self.route_data.previous_route = self.route_data.current_route;
        self.route_data.previous_route_session_id = self.route_data.current_route_session_id;
        self.route_data.previous_route_session_version =
            self.route_data.current_route_session_version;
        self.route_data.previous_route_private_key = self.route_data.current_route_private_key;
    }
    pub fn begin_next_route(
        &mut self,
        num_tokens: usize,
        tokens: &[u8],
        client_secret_key: &[u8; XCHACHA_KEY_BYTES],
        magic: &[u8; 8],
        client_external_address: &Address,
    ) {
        if self.fallback_to_direct {
            return;
        }
        if !(2..=MAX_TOKENS).contains(&num_tokens)
            || tokens.len() < num_tokens * ENCRYPTED_ROUTE_TOKEN_BYTES
        {
            self.set_fallback_to_direct(FLAGS_BAD_ROUTE_TOKEN);
            return;
        }
        let token_buf: [u8; ENCRYPTED_ROUTE_TOKEN_BYTES] =
            match tokens[..ENCRYPTED_ROUTE_TOKEN_BYTES].try_into() {
                Ok(b) => b,
                Err(_) => {
                    self.set_fallback_to_direct(FLAGS_BAD_ROUTE_TOKEN);
                    return;
                }
            };
        let rt = match decrypt_route_token(&token_buf, client_secret_key) {
            Ok(t) => t,
            Err(_) => {
                self.set_fallback_to_direct(FLAGS_BAD_ROUTE_TOKEN);
                return;
            }
        };
        self.route_data.pending_route = true;
        self.route_data.pending_route_start_time = platform::time();
        self.route_data.pending_route_last_send_time = -1000.0;
        self.route_data.pending_route_session_id = rt.session_id;
        self.route_data.pending_route_session_version = rt.session_version;
        self.route_data.pending_route_kbps_up = rt.envelope_kbps_up as i32;
        self.route_data.pending_route_kbps_down = rt.envelope_kbps_down as i32;
        self.route_data.pending_route_private_key = rt.session_private_key;
        // next_address is stored BE in RouteToken - convert back to native then to bytes
        self.route_data.pending_route_next_address = Address::V4 {
            octets: u32::from_be(rt.next_address).to_be_bytes(),
            port: u16::from_be(rt.next_port),
        };
        let token_data =
            &tokens[ENCRYPTED_ROUTE_TOKEN_BYTES..num_tokens * ENCRYPTED_ROUTE_TOKEN_BYTES];
        let from_address = address_ipv4_bytes(client_external_address);
        let to_address = u32::from_be(rt.next_address).to_be_bytes();
        let bytes = write_route_request_packet(
            &mut self.route_data.pending_route_request_packet_data,
            token_data,
            magic,
            &from_address,
            &to_address,
        );
        self.route_data.pending_route_request_packet_bytes = bytes;
    }
    pub fn continue_next_route(
        &mut self,
        num_tokens: usize,
        tokens: &[u8],
        client_secret_key: &[u8; XCHACHA_KEY_BYTES],
        magic: &[u8; 8],
        client_external_address: &Address,
    ) {
        if self.fallback_to_direct {
            return;
        }
        if !self.route_data.current_route {
            self.set_fallback_to_direct(FLAGS_NO_ROUTE_TO_CONTINUE);
            return;
        }
        if self.route_data.pending_route || self.route_data.pending_continue {
            self.set_fallback_to_direct(FLAGS_PREVIOUS_UPDATE_STILL_PENDING);
            return;
        }
        if !(2..=MAX_TOKENS).contains(&num_tokens)
            || tokens.len() < num_tokens * ENCRYPTED_CONTINUE_TOKEN_BYTES
        {
            self.set_fallback_to_direct(FLAGS_BAD_CONTINUE_TOKEN);
            return;
        }
        let token_buf: [u8; ENCRYPTED_CONTINUE_TOKEN_BYTES] =
            match tokens[..ENCRYPTED_CONTINUE_TOKEN_BYTES].try_into() {
                Ok(b) => b,
                Err(_) => {
                    self.set_fallback_to_direct(FLAGS_BAD_CONTINUE_TOKEN);
                    return;
                }
            };
        if decrypt_continue_token(&token_buf, client_secret_key).is_err() {
            self.set_fallback_to_direct(FLAGS_BAD_CONTINUE_TOKEN);
            return;
        }
        self.route_data.pending_continue = true;
        self.route_data.pending_continue_start_time = platform::time();
        self.route_data.pending_continue_last_send_time = -1000.0;
        let token_data =
            &tokens[ENCRYPTED_CONTINUE_TOKEN_BYTES..num_tokens * ENCRYPTED_CONTINUE_TOKEN_BYTES];
        let from_address = address_ipv4_bytes(client_external_address);
        let to_address = address_ipv4_bytes(&self.route_data.current_route_next_address.clone());
        let bytes = write_continue_request_packet(
            &mut self.route_data.pending_continue_request_packet_data,
            token_data,
            magic,
            &from_address,
            &to_address,
        );
        self.route_data.pending_continue_request_packet_bytes = bytes;
    }
    pub fn update(
        &mut self,
        update_type: u8,
        num_tokens: usize,
        tokens: &[u8],
        client_secret_key: &[u8; XCHACHA_KEY_BYTES],
        magic: &[u8; 8],
        client_external_address: &Address,
    ) {
        self.last_route_update_time = platform::time();
        match update_type {
            t if t == UPDATE_TYPE_DIRECT => self.direct_route(),
            t if t == UPDATE_TYPE_ROUTE => self.begin_next_route(
                num_tokens,
                tokens,
                client_secret_key,
                magic,
                client_external_address,
            ),
            t if t == UPDATE_TYPE_CONTINUE => self.continue_next_route(
                num_tokens,
                tokens,
                client_secret_key,
                magic,
                client_external_address,
            ),
            _ => {}
        }
    }
    pub fn has_network_next_route(&self) -> bool {
        self.route_data.current_route
    }
    pub fn get_flags(&self) -> u32 {
        self.flags
    }
    pub fn get_fallback_to_direct(&self) -> bool {
        self.fallback_to_direct
    }
    pub fn next_send_sequence(&mut self) -> u64 {
        let s = self.send_sequence;
        self.send_sequence += 1;
        s
    }
    pub fn confirm_pending_route(&mut self) -> (i32, i32) {
        if self.route_data.current_route {
            self.save_current_as_previous();
            self.route_data.current_route_expire_time += 2.0 * SLICE_SECONDS;
        } else {
            self.route_data.current_route_expire_time =
                self.route_data.pending_route_start_time + 2.0 * SLICE_SECONDS;
        }
        self.route_data.current_route_session_id = self.route_data.pending_route_session_id;
        self.route_data.current_route_session_version =
            self.route_data.pending_route_session_version;
        self.route_data.current_route_kbps_up = self.route_data.pending_route_kbps_up;
        self.route_data.current_route_kbps_down = self.route_data.pending_route_kbps_down;
        self.route_data.current_route_next_address = self.route_data.pending_route_next_address;
        self.route_data.current_route_private_key = self.route_data.pending_route_private_key;
        self.route_data.current_route = true;
        self.route_data.pending_route = false;
        (
            self.route_data.current_route_kbps_up,
            self.route_data.current_route_kbps_down,
        )
    }
    pub fn confirm_continue_route(&mut self) {
        self.route_data.current_route_expire_time += SLICE_SECONDS;
        self.route_data.pending_continue = false;
    }
    /// Returns the pending route private key if a route request is outstanding.
    /// Used by callers to verify ROUTE_RESPONSE header HMAC before confirming.
    pub fn get_pending_route_private_key(&self) -> Option<[u8; SESSION_PRIVATE_KEY_BYTES]> {
        if self.route_data.pending_route {
            Some(self.route_data.pending_route_private_key)
        } else {
            None
        }
    }
    /// Returns the current route private key if an active route exists.
    /// Used by callers to verify CONTINUE_RESPONSE header HMAC before confirming.
    pub fn get_current_route_private_key(&self) -> Option<[u8; SESSION_PRIVATE_KEY_BYTES]> {
        if self.route_data.current_route {
            Some(self.route_data.current_route_private_key)
        } else {
            None
        }
    }
    pub fn get_current_route_data(&self) -> (bool, bool, u64, u8, [u8; SESSION_PRIVATE_KEY_BYTES]) {
        (
            self.fallback_to_direct,
            self.route_data.current_route,
            self.route_data.current_route_session_id,
            self.route_data.current_route_session_version,
            self.route_data.current_route_private_key,
        )
    }
    pub fn check_for_timeouts(&mut self) {
        if self.fallback_to_direct {
            return;
        }
        let now = platform::time();
        if self.last_route_update_time > 0.0
            && self.last_route_update_time + CLIENT_ROUTE_TIMEOUT < now
        {
            self.set_fallback_to_direct(FLAGS_ROUTE_TIMED_OUT);
            return;
        }
        if self.route_data.current_route && self.route_data.current_route_expire_time <= now {
            self.set_fallback_to_direct(FLAGS_ROUTE_EXPIRED);
            return;
        }
        if self.route_data.pending_route
            && self.route_data.pending_route_start_time + ROUTE_REQUEST_TIMEOUT <= now
        {
            self.set_fallback_to_direct(FLAGS_ROUTE_REQUEST_TIMED_OUT);
            return;
        }
        if self.route_data.pending_continue
            && self.route_data.pending_continue_start_time + CONTINUE_REQUEST_TIMEOUT <= now
        {
            self.set_fallback_to_direct(FLAGS_CONTINUE_REQUEST_TIMED_OUT);
        }
    }
    pub fn send_route_request(
        &mut self,
        packet_data: &mut [u8; MAX_PACKET_BYTES],
    ) -> Option<(Address, usize)> {
        if self.fallback_to_direct || !self.route_data.pending_route {
            return None;
        }
        let now = platform::time();
        if self.route_data.pending_route_last_send_time + ROUTE_REQUEST_SEND_TIME > now {
            return None;
        }
        let to = self.route_data.pending_route_next_address;
        let bytes = self.route_data.pending_route_request_packet_bytes;
        self.route_data.pending_route_last_send_time = now;
        packet_data[..bytes]
            .copy_from_slice(&self.route_data.pending_route_request_packet_data[..bytes]);
        Some((to, bytes))
    }
    pub fn send_continue_request(
        &mut self,
        packet_data: &mut [u8; MAX_PACKET_BYTES],
    ) -> Option<(Address, usize)> {
        if self.fallback_to_direct
            || !self.route_data.current_route
            || !self.route_data.pending_continue
        {
            return None;
        }
        let now = platform::time();
        if self.route_data.pending_continue_last_send_time + CONTINUE_REQUEST_SEND_TIME > now {
            return None;
        }
        let to = self.route_data.current_route_next_address;
        let bytes = self.route_data.pending_continue_request_packet_bytes;
        self.route_data.pending_continue_last_send_time = now;
        packet_data[..bytes]
            .copy_from_slice(&self.route_data.pending_continue_request_packet_data[..bytes]);
        Some((to, bytes))
    }
    pub fn prepare_send_packet(
        &mut self,
        sequence: u64,
        payload: &[u8],
        packet_data: &mut [u8; MAX_PACKET_BYTES],
        magic: &[u8; 8],
        client_external_address: &Address,
    ) -> Option<(Address, usize)> {
        if !self.route_data.current_route {
            return None;
        }
        let to = self.route_data.current_route_next_address;
        let from_address = address_ipv4_bytes(client_external_address);
        let to_address = address_ipv4_bytes(&to);
        let bytes = write_client_to_server_packet(
            packet_data,
            sequence,
            self.route_data.current_route_session_id,
            self.route_data.current_route_session_version,
            &self.route_data.current_route_private_key,
            payload,
            magic,
            &from_address,
            &to_address,
        );
        if bytes == 0 {
            return None;
        }
        Some((to, bytes))
    }
    pub fn process_server_to_client_packet(
        &self,
        packet_type: u8,
        packet_data: &[u8],
    ) -> Option<u64> {
        if packet_data.len() < PACKET_BODY_OFFSET + HEADER_BYTES {
            return None;
        }
        let header = &packet_data[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES];
        if let Some((seq, sid, sver)) = read_header(
            packet_type,
            &self.route_data.current_route_private_key,
            header,
        ) {
            if !self.route_data.current_route {
                return None;
            }
            if sid != self.route_data.current_route_session_id {
                return None;
            }
            if sver != self.route_data.current_route_session_version {
                return None;
            }
            if packet_data.len() - PACKET_BODY_OFFSET - HEADER_BYTES > MTU {
                return None;
            }
            return Some(seq);
        }
        if let Some((seq, sid, sver)) = read_header(
            packet_type,
            &self.route_data.previous_route_private_key,
            header,
        ) {
            if !self.route_data.previous_route {
                return None;
            }
            if sid != self.route_data.previous_route_session_id {
                return None;
            }
            if sver != self.route_data.previous_route_session_version {
                return None;
            }
            if packet_data.len() - PACKET_BODY_OFFSET - HEADER_BYTES > MTU {
                return None;
            }
            return Some(seq);
        }
        None
    }
}
impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}
// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PACKET_TYPE_SERVER_TO_CLIENT;
    use crate::tokens::encrypt_route_token;
    use relay_xdp_common::RouteToken;
    fn dummy_magic() -> [u8; 8] {
        [1, 2, 3, 4, 5, 6, 7, 8]
    }
    fn dummy_from() -> [u8; 4] {
        [10, 0, 0, 1]
    }
    fn dummy_to() -> [u8; 4] {
        [10, 0, 0, 2]
    }
    fn from_addr() -> Address {
        Address::V4 {
            octets: dummy_from(),
            port: 5000,
        }
    }
    #[test]
    fn header_write_read_roundtrip() {
        let pk = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
        let mut hdr = [0u8; HEADER_BYTES];
        write_header(
            PACKET_TYPE_CLIENT_TO_SERVER,
            12345,
            0xDEAD_BEEF,
            7,
            &pk,
            &mut hdr,
        );
        let (seq, sid, sver) = read_header(PACKET_TYPE_CLIENT_TO_SERVER, &pk, &hdr).unwrap();
        assert_eq!(seq, 12345);
        assert_eq!(sid, 0xDEAD_BEEF);
        assert_eq!(sver, 7);
    }
    #[test]
    fn header_wrong_key_fails() {
        let pk = [0x42u8; SESSION_PRIVATE_KEY_BYTES];
        let wrong = [0x99u8; SESSION_PRIVATE_KEY_BYTES];
        let mut hdr = [0u8; HEADER_BYTES];
        write_header(PACKET_TYPE_CLIENT_TO_SERVER, 1, 2, 3, &pk, &mut hdr);
        assert!(read_header(PACKET_TYPE_CLIENT_TO_SERVER, &wrong, &hdr).is_none());
    }
    #[test]
    fn pittle_deterministic() {
        let mut a = [0u8; 2];
        let mut b = [0u8; 2];
        generate_pittle(&mut a, &dummy_from(), &dummy_to(), 100);
        generate_pittle(&mut b, &dummy_from(), &dummy_to(), 100);
        assert_eq!(a, b);
    }
    #[test]
    fn chonkle_deterministic() {
        let mut a = [0u8; 15];
        let mut b = [0u8; 15];
        generate_chonkle(&mut a, &dummy_magic(), &dummy_from(), &dummy_to(), 100);
        generate_chonkle(&mut b, &dummy_magic(), &dummy_from(), &dummy_to(), 100);
        assert_eq!(a, b);
    }
    #[test]
    fn client_to_server_packet_roundtrip() {
        let pk = [0x11u8; SESSION_PRIVATE_KEY_BYTES];
        let payload = [0xAAu8; 64];
        let mut pkt = Box::new([0u8; MAX_PACKET_BYTES]);
        let len = write_client_to_server_packet(
            &mut pkt,
            42,
            0x1234,
            1,
            &pk,
            &payload,
            &dummy_magic(),
            &dummy_from(),
            &dummy_to(),
        );
        assert!(len > 0);
        let hdr = &pkt[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES];
        let (seq, sid, sver) = read_header(PACKET_TYPE_CLIENT_TO_SERVER, &pk, hdr).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(sid, 0x1234);
        assert_eq!(sver, 1);
        let ps = PACKET_BODY_OFFSET + HEADER_BYTES;
        assert_eq!(&pkt[ps..ps + 64], &payload);
    }
    #[test]
    fn route_manager_new_is_direct() {
        let rm = RouteManager::new();
        assert!(!rm.has_network_next_route());
        assert!(!rm.fallback_to_direct);
    }
    #[test]
    fn route_manager_fallback_sets_flags() {
        let mut rm = RouteManager::new();
        rm.set_fallback_to_direct(FLAGS_ROUTE_EXPIRED);
        assert!(rm.fallback_to_direct);
        assert_eq!(rm.flags & FLAGS_ROUTE_EXPIRED, FLAGS_ROUTE_EXPIRED);
    }
    #[test]
    fn route_manager_reset_clears_all() {
        let mut rm = RouteManager::new();
        rm.set_fallback_to_direct(FLAGS_ROUTE_EXPIRED);
        rm.reset();
        assert!(!rm.fallback_to_direct);
        assert_eq!(rm.flags, 0);
    }
    #[test]
    fn send_sequence_increments() {
        let mut rm = RouteManager::new();
        assert_eq!(rm.next_send_sequence(), 0);
        assert_eq!(rm.next_send_sequence(), 1);
        assert_eq!(rm.next_send_sequence(), 2);
    }
    #[test]
    fn begin_next_route_bad_token_causes_fallback() {
        let mut rm = RouteManager::new();
        let bad_tokens = vec![0xFFu8; ENCRYPTED_ROUTE_TOKEN_BYTES * 2];
        rm.begin_next_route(2, &bad_tokens, &[0u8; 32], &dummy_magic(), &from_addr());
        assert!(rm.fallback_to_direct);
        assert_eq!(rm.flags & FLAGS_BAD_ROUTE_TOKEN, FLAGS_BAD_ROUTE_TOKEN);
    }
    #[test]
    fn confirm_pending_route_transitions_to_active() {
        let key = [0xABu8; XCHACHA_KEY_BYTES];
        let route_token = RouteToken {
            session_private_key: [0x55u8; SESSION_PRIVATE_KEY_BYTES],
            expire_timestamp: 9999,
            session_id: 0xCAFE_BABE_DEAD_BEEF,
            envelope_kbps_up: 1000,
            envelope_kbps_down: 2000,
            next_address: 0x0A00_0001u32.to_be(),
            prev_address: 0,
            next_port: 12345u16.to_be(),
            prev_port: 0,
            session_version: 3,
            next_internal: 0,
            prev_internal: 0,
        };
        let enc = encrypt_route_token(&route_token, &key);
        let mut tokens = Vec::new();
        tokens.extend_from_slice(&enc);
        tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);
        let mut rm = RouteManager::new();
        rm.begin_next_route(2, &tokens, &key, &dummy_magic(), &from_addr());
        assert!(rm.route_data.pending_route);
        assert!(!rm.fallback_to_direct);
        assert!(!rm.has_network_next_route());
        let (up, down) = rm.confirm_pending_route();
        assert!(rm.has_network_next_route());
        assert!(!rm.route_data.pending_route);
        assert_eq!(up, 1000);
        assert_eq!(down, 2000);
        // Regression: next_address BE u32 -> correct IPv4 octets
        assert_eq!(
            rm.route_data.current_route_next_address,
            Address::V4 {
                octets: [10, 0, 0, 1],
                port: 12345,
            }
        );
    }
    #[test]
    fn prepare_send_packet_no_route_returns_none() {
        let mut rm = RouteManager::new();
        let mut pkt = Box::new([0u8; MAX_PACKET_BYTES]);
        assert!(rm
            .prepare_send_packet(0, &[0xAAu8; 10], &mut pkt, &dummy_magic(), &Address::None)
            .is_none());
    }
    #[test]
    fn process_s2c_no_route_rejects() {
        let rm = RouteManager::new();
        let pkt = vec![0u8; PACKET_BODY_OFFSET + HEADER_BYTES + 10];
        assert!(rm
            .process_server_to_client_packet(PACKET_TYPE_SERVER_TO_CLIENT, &pkt)
            .is_none());
    }
}
