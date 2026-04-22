// mod client - Game client relay session.
//
// Architecture: two-half pattern.
//   Client     - main-thread handle, lightweight, owns shared queues.
//   ClientInner - network-thread side, drives RouteManager and packet I/O.
//
// IPC: Arc<Mutex<VecDeque<T>>> queues only (matches relay-xdp threading model).
// No threads are spawned here - callers control execution.
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
use crate::route::trackers::ReplayProtection;
use crate::route::RouteManager;

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
    /// A pending route request packet to send on the UDP socket.
    SendRaw { to: Address, data: Vec<u8> },
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

    // Scratch buffer for route request / data packets.
    send_buf: Box<[u8; MAX_PACKET_BYTES]>,
}

impl ClientInner {
    /// Create a linked (ClientInner, Client) pair sharing the same queues.
    pub fn create() -> (ClientInner, Client) {
        let commands: CommandQueue = Arc::new(Mutex::new(VecDeque::new()));
        let notify: NotifyQueue = Arc::new(Mutex::new(VecDeque::new()));

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

    // ── Command pump ─────────────────────────────────────────────────────────

    /// Drain all pending commands. Returns false if Destroy was received.
    pub fn pump_commands(&mut self) -> bool {
        loop {
            let cmd = {
                let mut q = self.commands.lock().unwrap();
                q.pop_front()
            };
            match cmd {
                None => break,
                Some(Command::Destroy) => return false,
                Some(c) => self.handle_command(c),
            }
        }
        true
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
                    let data = self.send_buf[..len].to_vec();
                    self.push_notify(Notify::SendRaw { to, data });
                }
                // If no relay route: caller is responsible for direct UDP to server_address.
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
    pub fn process_incoming(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            PACKET_TYPE_ROUTE_RESPONSE => {
                // Relay confirms pending route -> transition to active.
                let (kbps_up, kbps_down) = self.route_manager.confirm_pending_route();
                let _ = (kbps_up, kbps_down);
                self.emit_route_changed();
                None
            }
            PACKET_TYPE_CONTINUE_RESPONSE => {
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
        // Try to send a pending route request.
        if let Some((to, len)) = self
            .route_manager
            .send_route_request(self.send_buf.as_mut())
        {
            let data = self.send_buf[..len].to_vec();
            self.push_notify(Notify::SendRaw { to, data });
        }
        // Try to send a pending continue request.
        if let Some((to, len)) = self
            .route_manager
            .send_continue_request(self.send_buf.as_mut())
        {
            let data = self.send_buf[..len].to_vec();
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

    fn push_notify(&self, n: Notify) {
        self.notify.lock().unwrap().push_back(n);
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
    pub fn pop_send_raw(&self) -> Option<(Address, Vec<u8>)> {
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
        // Only RouteChanged notifications expected, no SendRaw.
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
}
