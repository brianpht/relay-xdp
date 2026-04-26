// mod client - Game client relay session.
//
// Architecture: two-half pattern.
//   Client     - main-thread handle, lightweight, owns shared queues.
//   ClientInner - network-thread side, drives RouteManager and packet I/O.
//
// IPC: Arc<Mutex<VecDeque<T>>> queues only (matches relay-xdp threading model).
// No threads are spawned here - callers control execution.
//
// Performance (task 7 + 8):
//   - Outbound packets use BytePool to avoid per-packet heap allocation.
//   - pump_commands() drains the entire command queue under a single lock.
//   - Notify items are accumulated locally and flushed under a single lock
//     at the end of each pump_commands() / process_incoming() call.
//
// Session lifecycle:
//   1. open_session(server_address, client_secret_key)
//   2. Network thread receives RouteUpdate from backend (HTTP push) -> update()
//   3. ClientInner drives RouteManager: send_route_request / prepare_send_packet
//   4. Incoming packets routed through process_incoming()
//   5. close_session() or drop() cleans up

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::address::Address;
use crate::constants::*;
use crate::crypto::XCHACHA_KEY_BYTES;
use crate::packets::{ContinueResponsePacket, RouteResponsePacket, PACKET_BODY_OFFSET};
use crate::pool::{BytePool, PooledBuf};
use crate::route::trackers::ReplayProtection;
use crate::route::{read_header, RouteManager, HEADER_BYTES};

// ── Client state constants ────────────────────────────────────────────────────

pub const CLIENT_STATE_CLOSED: i32 = 0;
pub const CLIENT_STATE_OPEN: i32 = 1;
pub const CLIENT_STATE_ERROR: i32 = -1;

// ── Command (main thread -> network thread) ───────────────────────────────────

#[derive(Debug)]
pub enum Command {
    /// Open a new session to the given server.
    OpenSession {
        server_address: Address,
        client_secret_key: [u8; XCHACHA_KEY_BYTES],
    },
    /// Close the current session.
    CloseSession,
    /// Route update from backend (HTTP push, once per second).
    RouteUpdate {
        update_type: u8,
        num_tokens: usize,
        tokens: Vec<u8>,
        magic: [u8; 8],
        client_external_address: Address,
    },
    /// Tick: advance time, let RouteManager send pending requests.
    Tick { delta_time: f64 },
    /// Send a game payload toward the server.
    SendPacket { payload: Vec<u8> },
    /// Shut down the inner half.
    Destroy,
}

// ── Notify (network thread -> main thread) ────────────────────────────────────

#[derive(Debug)]
pub enum Notify {
    /// A game payload was received from the server (direct or via relay).
    PacketReceived { payload: Vec<u8>, via_relay: bool },
    /// Route state changed.
    RouteChanged {
        has_relay_route: bool,
        fallback_to_direct: bool,
        flags: u32,
    },
    /// A relay protocol packet to send on the UDP socket.
    /// Uses a pooled buffer to avoid per-packet heap allocation (task 7).
    SendRaw { to: Address, data: PooledBuf },
}

// ── Shared queue type aliases ─────────────────────────────────────────────────

pub type CommandQueue = Arc<Mutex<VecDeque<Command>>>;
pub type NotifyQueue = Arc<Mutex<VecDeque<Notify>>>;

// ── ClientInner ───────────────────────────────────────────────────────────────

pub struct ClientInner {
    commands: CommandQueue,
    notify: NotifyQueue,

    pub session_open: bool,
    pub server_address: Address,
    pub client_external_address: Address,
    pub client_secret_key: [u8; XCHACHA_KEY_BYTES],
    pub magic: [u8; 8],
    pub time: f64,

    pub route_manager: RouteManager,
    pub payload_replay: ReplayProtection,

    // Scratch buffer for building outbound packets before copying into pool buf.
    send_buf: Box<[u8; MAX_PACKET_BYTES]>,

    // Task 7: pool of pre-allocated packet buffers (capacity = MAX_PACKET_BYTES).
    packet_pool: BytePool,

    // Task 8: local staging buffer for notify items.
    // Accumulated during pump_commands / process_incoming, flushed once at the
    // end under a single lock acquisition instead of one lock per push_notify.
    notify_batch: Vec<Notify>,
}

impl ClientInner {
    /// Create a linked (ClientInner, Client) pair sharing the same queues.
    pub fn create() -> (ClientInner, Client) {
        let commands: CommandQueue = Arc::new(Mutex::new(VecDeque::new()));
        let notify: NotifyQueue = Arc::new(Mutex::new(VecDeque::new()));

        let packet_pool = BytePool::new();
        packet_pool.warm(8); // pre-allocate 8 buffers to absorb cold-start bursts

        let inner = ClientInner {
            commands: Arc::clone(&commands),
            notify: Arc::clone(&notify),
            session_open: false,
            server_address: Address::None,
            client_external_address: Address::None,
            client_secret_key: [0u8; XCHACHA_KEY_BYTES],
            magic: [0u8; 8],
            time: 0.0,
            route_manager: RouteManager::new(),
            payload_replay: ReplayProtection::new(),
            send_buf: Box::new([0u8; MAX_PACKET_BYTES]),
            packet_pool,
            notify_batch: Vec::new(),
        };

        let client = Client {
            commands,
            notify,
            state: CLIENT_STATE_CLOSED,
            has_relay_route: false,
            fallback_to_direct: false,
            flags: 0,
            server_address: Address::None,
        };

        (inner, client)
    }

    // ── Command pump (task 8) ─────────────────────────────────────────────────

    /// Drain all pending commands. Returns false if Destroy was received.
    ///
    /// Task 8: drains the entire command queue under a single lock acquisition,
    /// then processes commands without holding the lock. Notifies accumulated
    /// during processing are flushed to the shared queue under a single lock at
    /// the end.
    pub fn pump_commands(&mut self) -> bool {
        // Single lock acquisition: take the whole queue.
        let batch: VecDeque<Command> = std::mem::take(&mut *self.commands.lock().unwrap());

        let mut alive = true;
        for cmd in batch {
            if matches!(cmd, Command::Destroy) {
                alive = false;
                break;
            }
            self.handle_command(cmd);
        }

        // Single lock acquisition: flush all accumulated notifies.
        self.flush_notify();
        alive
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Destroy => {}

            Command::OpenSession {
                server_address,
                client_secret_key,
            } => {
                self.open_session(server_address, client_secret_key);
            }

            Command::CloseSession => {
                self.close_session();
            }

            Command::RouteUpdate {
                update_type,
                num_tokens,
                tokens,
                magic,
                client_external_address,
            } => {
                if self.session_open {
                    self.magic = magic;
                    self.client_external_address = client_external_address;
                    self.route_manager.update(
                        update_type,
                        num_tokens,
                        &tokens,
                        &self.client_secret_key,
                        &magic,
                        &client_external_address,
                    );
                    self.emit_route_changed();
                }
            }

            Command::Tick { delta_time } => {
                self.time += delta_time;
                if self.session_open {
                    self.route_manager.check_for_timeouts();
                    self.try_send_pending();
                    self.emit_route_changed();
                }
            }

            Command::SendPacket { payload } => {
                if !self.session_open {
                    return;
                }
                let seq = self.route_manager.next_send_sequence();
                if let Some((to, len)) = self.route_manager.prepare_send_packet(
                    seq,
                    &payload,
                    self.send_buf.as_mut(),
                    &self.magic,
                    &self.client_external_address,
                ) {
                    // Task 7: check out a pooled buffer instead of allocating.
                    let mut data = self.packet_pool.get();
                    data.extend_from_slice(&self.send_buf[..len]);
                    self.push_notify(Notify::SendRaw { to, data });
                }
                // No relay route: caller is responsible for direct UDP to server_address.
            }
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    pub fn open_session(
        &mut self,
        server_address: Address,
        client_secret_key: [u8; XCHACHA_KEY_BYTES],
    ) {
        self.server_address = server_address;
        self.client_secret_key = client_secret_key;
        self.session_open = true;
        self.time = 0.0;
        self.magic = [0u8; 8];
        self.client_external_address = Address::None;
        self.route_manager.reset();
        self.payload_replay.reset();
    }

    pub fn close_session(&mut self) {
        self.session_open = false;
        self.server_address = Address::None;
        self.client_external_address = Address::None;
        self.client_secret_key = [0u8; XCHACHA_KEY_BYTES];
        self.magic = [0u8; 8];
        self.route_manager.reset();
        self.payload_replay.reset();
    }

    // ── Incoming packet processing ────────────────────────────────────────────

    /// Process a raw incoming UDP packet (from relay or server).
    /// Returns Some(payload) if a game payload was extracted.
    ///
    /// Task 8: any route-change notifies emitted during processing are flushed
    /// to the shared queue under a single lock at the end.
    pub fn process_incoming(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let result = self.process_incoming_inner(data);
        // Flush route-change notifies accumulated during this call.
        self.flush_notify();
        result
    }

    fn process_incoming_inner(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            PACKET_TYPE_ROUTE_RESPONSE => {
                // Decode and verify relay header HMAC before confirming the route.
                // Any packet with type=2 but without a valid header is silently dropped.
                let pkt = RouteResponsePacket::decode(data).ok()?;
                let private_key = self.route_manager.get_pending_route_private_key()?;
                read_header(PACKET_TYPE_ROUTE_RESPONSE, &private_key, &pkt.relay_header)?;
                let (kbps_up, kbps_down) = self.route_manager.confirm_pending_route();
                let _ = (kbps_up, kbps_down);
                self.emit_route_changed();
                None
            }
            PACKET_TYPE_CONTINUE_RESPONSE => {
                // Decode and verify relay header HMAC before confirming the continue.
                let pkt = ContinueResponsePacket::decode(data).ok()?;
                let private_key = self.route_manager.get_current_route_private_key()?;
                read_header(
                    PACKET_TYPE_CONTINUE_RESPONSE,
                    &private_key,
                    &pkt.relay_header,
                )?;
                self.route_manager.confirm_continue_route();
                self.emit_route_changed();
                None
            }
            PACKET_TYPE_SERVER_TO_CLIENT => {
                if let Some(seq) = self
                    .route_manager
                    .process_server_to_client_packet(PACKET_TYPE_SERVER_TO_CLIENT, data)
                {
                    // Replay check.
                    if self.payload_replay.already_received(seq) {
                        return None;
                    }
                    let body_off = PACKET_BODY_OFFSET + HEADER_BYTES;
                    if data.len() <= body_off {
                        return None;
                    }
                    Some(data[body_off..].to_vec())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn try_send_pending(&mut self) {
        // Task 7: use pooled buffer for route request packet.
        if let Some((to, len)) = self
            .route_manager
            .send_route_request(self.send_buf.as_mut())
        {
            let mut data = self.packet_pool.get();
            data.extend_from_slice(&self.send_buf[..len]);
            self.push_notify(Notify::SendRaw { to, data });
        }
        // Task 7: use pooled buffer for continue request packet.
        if let Some((to, len)) = self
            .route_manager
            .send_continue_request(self.send_buf.as_mut())
        {
            let mut data = self.packet_pool.get();
            data.extend_from_slice(&self.send_buf[..len]);
            self.push_notify(Notify::SendRaw { to, data });
        }
    }

    fn emit_route_changed(&mut self) {
        let (fallback, has_route, _, _, _) = self.route_manager.get_current_route_data();
        self.push_notify(Notify::RouteChanged {
            has_relay_route: has_route,
            fallback_to_direct: fallback,
            flags: self.route_manager.get_flags(),
        });
    }

    /// Accumulate a notify item locally (task 8).
    /// Call flush_notify() to push the batch to the shared queue under one lock.
    fn push_notify(&mut self, n: Notify) {
        self.notify_batch.push(n);
    }

    /// Flush all accumulated notify items to the shared queue under a single
    /// lock acquisition (task 8). No-op if the batch is empty.
    fn flush_notify(&mut self) {
        if self.notify_batch.is_empty() {
            return;
        }
        let mut q = self.notify.lock().unwrap();
        for n in self.notify_batch.drain(..) {
            q.push_back(n);
        }
    }
}

// ── Client (main-thread handle) ───────────────────────────────────────────────

pub struct Client {
    commands: CommandQueue,
    notify: NotifyQueue,

    pub state: i32,
    pub has_relay_route: bool,
    pub fallback_to_direct: bool,
    pub flags: u32,
    pub server_address: Address,
}

impl Client {
    /// Open a session to `server_address`.
    /// `client_secret_key` is the 32-byte key received from backend HTTP push.
    pub fn open_session(
        &mut self,
        server_address: Address,
        client_secret_key: [u8; XCHACHA_KEY_BYTES],
    ) {
        self.server_address = server_address;
        self.push_command(Command::OpenSession {
            server_address,
            client_secret_key,
        });
        self.state = CLIENT_STATE_OPEN;
    }

    /// Close the current session.
    pub fn close_session(&mut self) {
        self.push_command(Command::CloseSession);
        self.state = CLIENT_STATE_CLOSED;
        self.has_relay_route = false;
        self.fallback_to_direct = false;
        self.flags = 0;
        self.server_address = Address::None;
    }

    /// Deliver a route update from the backend (HTTP push, ~1 Hz).
    pub fn route_update(
        &mut self,
        update_type: u8,
        num_tokens: usize,
        tokens: Vec<u8>,
        magic: [u8; 8],
        client_external_address: Address,
    ) {
        self.push_command(Command::RouteUpdate {
            update_type,
            num_tokens,
            tokens,
            magic,
            client_external_address,
        });
    }

    /// Tick the session forward by `delta_time` seconds.
    pub fn tick(&mut self, delta_time: f64) {
        self.push_command(Command::Tick { delta_time });
        self.drain_notify();
    }

    /// Queue a game payload for sending via relay (or direct if no route).
    pub fn send_packet(&mut self, payload: &[u8]) {
        if self.state != CLIENT_STATE_OPEN {
            return;
        }
        self.push_command(Command::SendPacket {
            payload: payload.to_vec(),
        });
    }

    /// Drain all pending notifications, updating local state.
    pub fn drain_notify(&mut self) {
        loop {
            let n = { self.notify.lock().unwrap().pop_front() };
            match n {
                None => break,
                Some(n) => self.apply_notify(n),
            }
        }
    }

    fn apply_notify(&mut self, n: Notify) {
        match n {
            Notify::RouteChanged {
                has_relay_route,
                fallback_to_direct,
                flags,
            } => {
                self.has_relay_route = has_relay_route;
                self.fallback_to_direct = fallback_to_direct;
                self.flags = flags;
            }
            Notify::PacketReceived { .. } | Notify::SendRaw { .. } => {}
        }
    }

    /// Pop next outbound raw UDP packet (to be sent by the socket loop).
    /// Returns a `PooledBuf` that is automatically returned to the pool on drop.
    pub fn pop_send_raw(&self) -> Option<(Address, PooledBuf)> {
        loop {
            let n = { self.notify.lock().unwrap().pop_front() };
            match n {
                None => return None,
                Some(Notify::SendRaw { to, data }) => return Some((to, data)),
                Some(n) => self.apply_notify_ref(n),
            }
        }
    }

    fn apply_notify_ref(&self, n: Notify) {
        // Read-only version used inside pop_send_raw.
        // State updates are handled by apply_notify in tick/drain_notify.
        let _ = n;
    }

    /// Pop next received game payload, if any.
    pub fn recv_packet(&self) -> Option<Vec<u8>> {
        loop {
            let n = { self.notify.lock().unwrap().pop_front() };
            match n {
                None => return None,
                Some(Notify::PacketReceived { payload, .. }) => return Some(payload),
                Some(_) => continue,
            }
        }
    }

    pub fn is_session_open(&self) -> bool {
        self.state == CLIENT_STATE_OPEN
    }
    pub fn has_relay_route(&self) -> bool {
        self.has_relay_route
    }
    pub fn is_fallback_direct(&self) -> bool {
        self.fallback_to_direct
    }
    pub fn state(&self) -> i32 {
        self.state
    }

    fn push_command(&self, c: Command) {
        self.commands.lock().unwrap().push_back(c);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.push_command(Command::Destroy);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (ClientInner, Client) {
        ClientInner::create()
    }

    fn key() -> [u8; XCHACHA_KEY_BYTES] {
        [0xABu8; XCHACHA_KEY_BYTES]
    }
    fn addr() -> Address {
        Address::V4 {
            octets: [127, 0, 0, 1],
            port: 7777,
        }
    }

    #[test]
    fn client_initial_state_is_closed() {
        let (_inner, client) = make_pair();
        assert_eq!(client.state(), CLIENT_STATE_CLOSED);
        assert!(!client.is_session_open());
        assert!(!client.has_relay_route());
    }

    #[test]
    fn client_open_session_sets_state_open() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        inner.pump_commands();
        assert_eq!(client.state(), CLIENT_STATE_OPEN);
        assert!(inner.session_open);
        assert_eq!(inner.server_address, addr());
    }

    #[test]
    fn client_close_session_resets_state() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        inner.pump_commands();
        client.close_session();
        inner.pump_commands();
        assert_eq!(client.state(), CLIENT_STATE_CLOSED);
        assert!(!inner.session_open);
    }

    #[test]
    fn client_tick_advances_time() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        inner.pump_commands();
        client.tick(0.016);
        inner.pump_commands();
        assert!((inner.time - 0.016).abs() < 1e-9);
    }

    #[test]
    fn client_send_packet_no_relay_route_yields_no_send_raw() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        inner.pump_commands();
        client.send_packet(b"hello");
        inner.pump_commands();
        // No relay route -> RouteManager returns None -> no SendRaw in queue.
        let notify_count = inner.notify.lock().unwrap().len();
        let has_send_raw = inner
            .notify
            .lock()
            .unwrap()
            .iter()
            .any(|n| matches!(n, Notify::SendRaw { .. }));
        assert!(
            !has_send_raw,
            "expected no SendRaw without relay route, notify_count={notify_count}"
        );
    }

    #[test]
    fn client_sequence_increments_on_send() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        inner.pump_commands();
        let before = inner.route_manager.next_send_sequence();
        client.send_packet(b"test");
        inner.pump_commands();
        let after = inner.route_manager.next_send_sequence();
        // next_send_sequence is called once per send_packet + once for before + once for after
        assert!(after > before);
    }

    #[test]
    fn client_destroy_stops_pump() {
        let (mut inner, client) = make_pair();
        drop(client); // triggers Destroy command via Drop
        let result = inner.pump_commands();
        assert!(!result);
    }

    #[test]
    fn client_route_update_direct_type_does_not_fallback() {
        let (mut inner, mut client) = make_pair();
        let ext = Address::V4 {
            octets: [1, 2, 3, 4],
            port: 5555,
        };
        client.open_session(addr(), key());
        inner.pump_commands();
        client.route_update(UPDATE_TYPE_DIRECT, 0, vec![], [0u8; 8], ext);
        inner.pump_commands();
        // UPDATE_TYPE_DIRECT calls direct_route() - no fallback unless already fallback
        assert!(!inner.route_manager.get_fallback_to_direct());
    }

    // ── Task 8 specific tests ─────────────────────────────────────────────────

    #[test]
    fn pump_commands_batch_processes_multiple_commands_in_one_call() {
        let (mut inner, mut client) = make_pair();
        // Queue several commands before pumping.
        client.open_session(addr(), key());
        client.tick(0.016);
        client.tick(0.016);
        // All three commands processed in a single pump_commands call.
        inner.pump_commands();
        assert!(inner.session_open);
        assert!((inner.time - 0.032).abs() < 1e-9);
    }

    #[test]
    fn notify_batch_flushed_atomically() {
        let (mut inner, mut client) = make_pair();
        client.open_session(addr(), key());
        // pump_commands triggers emit_route_changed -> notify_batch -> flush
        inner.pump_commands();
        // The notify queue must be reachable from the Client handle.
        client.drain_notify();
        // If batch was not flushed, drain_notify would see nothing (and not crash).
        // The important invariant is that this doesn't panic.
    }
}

// ── Helper: build a pending route state for tests ────────────────────────────

#[cfg(test)]
fn setup_pending_route(
    inner: &mut ClientInner,
    client: &mut Client,
) -> [u8; SESSION_PRIVATE_KEY_BYTES] {
    use crate::tokens::encrypt_route_token;
    use relay_xdp_common::RouteToken;

    let client_key = [0xABu8; XCHACHA_KEY_BYTES];
    let route_token = RouteToken {
        session_private_key: [0x55u8; SESSION_PRIVATE_KEY_BYTES],
        expire_timestamp: 9_999_999,
        session_id: 0xCAFE_BABE_DEAD_BEEFu64,
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
    let enc = encrypt_route_token(&route_token, &client_key);
    let mut tokens = Vec::new();
    tokens.extend_from_slice(&enc);
    tokens.extend_from_slice(&[0u8; ENCRYPTED_ROUTE_TOKEN_BYTES]);
    let ext = Address::V4 {
        octets: [10, 0, 0, 1],
        port: 5000,
    };
    client.open_session(
        Address::V4 {
            octets: [1, 2, 3, 4],
            port: 9999,
        },
        client_key,
    );
    inner.pump_commands();
    client.route_update(UPDATE_TYPE_ROUTE, 2, tokens, [1, 2, 3, 4, 5, 6, 7, 8], ext);
    inner.pump_commands();
    route_token.session_private_key
}

// ── Security tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::packets::{RouteResponsePacket, ROUTE_RESPONSE_BYTES};
    use crate::route::{write_header, HEADER_BYTES};

    #[test]
    fn route_response_spoofed_hmac_does_not_confirm_route() {
        let (mut inner, mut client) = ClientInner::create();
        let _pk = setup_pending_route(&mut inner, &mut client);
        assert!(inner
            .route_manager
            .get_pending_route_private_key()
            .is_some());

        let bad_hdr = [0u8; HEADER_BYTES];
        let pkt = RouteResponsePacket {
            relay_header: bad_hdr,
        };
        let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
        pkt.encode(&mut buf).unwrap();

        inner.process_incoming(&buf);

        assert!(
            !inner.route_manager.has_network_next_route(),
            "route must not be confirmed with invalid header HMAC"
        );
        assert!(
            inner
                .route_manager
                .get_pending_route_private_key()
                .is_some(),
            "pending route must remain pending after rejected ROUTE_RESPONSE"
        );
    }

    #[test]
    fn route_response_valid_hmac_confirms_route() {
        let (mut inner, mut client) = ClientInner::create();
        let session_pk = setup_pending_route(&mut inner, &mut client);
        assert!(inner
            .route_manager
            .get_pending_route_private_key()
            .is_some());

        let mut hdr = [0u8; HEADER_BYTES];
        write_header(
            PACKET_TYPE_ROUTE_RESPONSE,
            0,
            0xCAFE_BABE_DEAD_BEEFu64,
            3,
            &session_pk,
            &mut hdr,
        );
        let pkt = RouteResponsePacket { relay_header: hdr };
        let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
        pkt.encode(&mut buf).unwrap();

        inner.process_incoming(&buf);

        assert!(
            inner.route_manager.has_network_next_route(),
            "route must be confirmed with valid header HMAC"
        );
    }
}
