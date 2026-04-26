// mod server - Game server as final relay destination.
//
// Architecture: two-half pattern (mirrors mod client).
//   Server      - main-thread handle.
//   ServerInner - network-thread side.
//
// IPC: Arc<Mutex<VecDeque<T>>> queues only.
//
// Role: receives CLIENT_TO_SERVER_PACKET from the last relay hop,
//       verifies the header using per-session session_private_key,
//       and extracts the game payload.
//
// Per-session keys are pushed by the backend via HTTP
// (not derived from a KX handshake like rust-sdk).
//
// Session lifecycle:
//   1. Backend HTTP push -> register_session(session_id, private_key, version)
//   2. Incoming CLIENT_TO_SERVER packet -> process_incoming(data) -> payload
//   3. send_packet(session_id, payload) -> SERVER_TO_CLIENT packet via SendRaw
//   4. expire_session(session_id) / drop()

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::address::Address;
use crate::constants::*;
use crate::route::trackers::ReplayProtection;
use crate::route::{address_ipv4_bytes, write_header, HEADER_BYTES as ROUTE_HEADER_BYTES};

// ── Server state constants ────────────────────────────────────────────────────

pub const SERVER_STATE_CLOSED: i32 = 0;
pub const SERVER_STATE_OPEN: i32 = 1;

// ── Per-session state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: u64,
    pub session_version: u8,
    pub session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
    /// Address of the last relay hop (where SERVER_TO_CLIENT goes).
    pub relay_address: Address,
    /// Running send sequence for SERVER_TO_CLIENT packets.
    pub send_sequence: u64,
    pub replay_protection: ReplayProtection,
}

impl SessionInfo {
    pub fn new(
        session_id: u64,
        session_version: u8,
        session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
        relay_address: Address,
    ) -> Self {
        SessionInfo {
            session_id,
            session_version,
            session_private_key,
            relay_address,
            send_sequence: 0,
            replay_protection: ReplayProtection::new(),
        }
    }
}

// ── Command (main thread -> network thread) ───────────────────────────────────

#[derive(Debug)]
pub enum Command {
    /// Open the server.
    Open { bind_address: Address },
    /// Close the server.
    Close,
    /// Register or refresh a session (key pushed by backend HTTP).
    RegisterSession {
        session_id: u64,
        session_version: u8,
        session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
        relay_address: Address,
    },
    /// Expire / remove a session.
    ExpireSession { session_id: u64 },
    /// Send a game payload to a specific session (via relay).
    SendPacket {
        session_id: u64,
        payload: Vec<u8>,
        magic: [u8; 8],
        from_address: Address,
    },
    /// Shut down the inner half.
    Destroy,
}

// ── Notify (network thread -> main thread) ────────────────────────────────────

#[derive(Debug)]
pub enum Notify {
    /// A game payload was received from a client session.
    PacketReceived { session_id: u64, payload: Vec<u8> },
    /// A raw UDP packet to send on the socket.
    SendRaw { to: Address, data: Vec<u8> },
    /// Session was registered successfully.
    SessionRegistered { session_id: u64 },
    /// Session was expired.
    SessionExpired { session_id: u64 },
    /// A send_packet call failed (e.g. payload exceeded MAX_PACKET_BYTES).
    SendError {
        session_id: u64,
        reason: &'static str,
    },
}

// ── Shared queue type aliases ─────────────────────────────────────────────────

pub type CommandQueue = Arc<Mutex<VecDeque<Command>>>;
pub type NotifyQueue = Arc<Mutex<VecDeque<Notify>>>;

// ── ServerInner ───────────────────────────────────────────────────────────────

pub struct ServerInner {
    commands: CommandQueue,
    notify: NotifyQueue,

    pub state: i32,
    pub bind_address: Address,

    // Sessions indexed by session_id.
    pub sessions: HashMap<u64, SessionInfo>,

    // Scratch buffer for SERVER_TO_CLIENT packets.
    send_buf: Box<[u8; MAX_PACKET_BYTES]>,
}

impl ServerInner {
    /// Create a linked (ServerInner, Server) pair sharing the same queues.
    pub fn create() -> (ServerInner, Server) {
        let commands: CommandQueue = Arc::new(Mutex::new(VecDeque::new()));
        let notify: NotifyQueue = Arc::new(Mutex::new(VecDeque::new()));

        let inner = ServerInner {
            commands: Arc::clone(&commands),
            notify: Arc::clone(&notify),
            state: SERVER_STATE_CLOSED,
            bind_address: Address::None,
            sessions: HashMap::new(),
            send_buf: Box::new([0u8; MAX_PACKET_BYTES]),
        };

        let server = Server {
            commands,
            notify,
            state: SERVER_STATE_CLOSED,
            num_sessions: 0,
            bind_address: Address::None,
            last_send_error: None,
        };

        (inner, server)
    }

    // ── Command pump ─────────────────────────────────────────────────────────

    /// Drain all pending commands. Returns false if Destroy was received.
    pub fn pump_commands(&mut self) -> bool {
        loop {
            let cmd = { self.commands.lock().unwrap().pop_front() };
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

            Command::Open { bind_address } => {
                self.bind_address = bind_address;
                self.state = SERVER_STATE_OPEN;
                self.sessions.clear();
            }

            Command::Close => {
                self.state = SERVER_STATE_CLOSED;
                self.sessions.clear();
            }

            Command::RegisterSession {
                session_id,
                session_version,
                session_private_key,
                relay_address,
            } => {
                self.sessions.insert(
                    session_id,
                    SessionInfo::new(
                        session_id,
                        session_version,
                        session_private_key,
                        relay_address,
                    ),
                );
                self.push_notify(Notify::SessionRegistered { session_id });
            }

            Command::ExpireSession { session_id } => {
                self.sessions.remove(&session_id);
                self.push_notify(Notify::SessionExpired { session_id });
            }

            Command::SendPacket {
                session_id,
                payload,
                magic,
                from_address,
            } => {
                self.send_packet_inner(session_id, &payload, &magic, &from_address);
            }
        }
    }

    // ── Incoming packet processing ────────────────────────────────────────────

    /// Process a raw incoming UDP packet.
    /// Returns Some((session_id, payload)) if a verified game payload was extracted.
    pub fn process_incoming(&mut self, data: &[u8]) -> Option<(u64, Vec<u8>)> {
        if data.is_empty() {
            return None;
        }
        if data[0] != PACKET_TYPE_CLIENT_TO_SERVER {
            return None;
        }

        let body_off = PACKET_BODY_OFFSET;
        if data.len() < body_off + ROUTE_HEADER_BYTES {
            return None;
        }

        let header = &data[body_off..body_off + ROUTE_HEADER_BYTES];

        // Try each known session to find which key verifies this header.
        let mut verified: Option<(u64, u64)> = None; // (session_id, seq)
        for sess in self.sessions.values() {
            if let Some((seq, sid, sver)) = crate::route::read_header(
                PACKET_TYPE_CLIENT_TO_SERVER,
                &sess.session_private_key,
                header,
            ) {
                if sid != sess.session_id || sver != sess.session_version {
                    continue;
                }
                if sess.replay_protection.already_received(seq) {
                    return None;
                }
                verified = Some((sess.session_id, seq));
                break;
            }
        }

        if let Some((session_id, seq)) = verified {
            // Mark sequence as received.
            if let Some(sess) = self.sessions.get_mut(&session_id) {
                sess.replay_protection.advance_sequence(seq);
            }
            let payload_off = body_off + ROUTE_HEADER_BYTES;
            if data.len() <= payload_off {
                return None;
            }
            let payload = data[payload_off..].to_vec();
            self.push_notify(Notify::PacketReceived {
                session_id,
                payload: payload.clone(),
            });
            return Some((session_id, payload));
        }
        None
    }

    // ── Send SERVER_TO_CLIENT ─────────────────────────────────────────────────

    fn send_packet_inner(
        &mut self,
        session_id: u64,
        payload: &[u8],
        magic: &[u8; 8],
        from_address: &Address,
    ) {
        let sess = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return,
        };
        let seq = sess.send_sequence;
        sess.send_sequence += 1;
        let to_address = match &sess.relay_address {
            Address::V4 { octets, .. } => *octets,
            _ => return,
        };
        let from_bytes = address_ipv4_bytes(from_address);

        // Build SERVER_TO_CLIENT packet:
        //   [0]       packet_type
        //   [1..3]    pittle   (stamp_filter fills these via write_header/stamp)
        //   [3..18]   chonkle
        //   [18..43]  header (ROUTE_HEADER_BYTES = 25)
        //   [43..]    payload
        let total = PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES + payload.len();
        if total > MAX_PACKET_BYTES {
            self.push_notify(Notify::SendError {
                session_id,
                reason: "payload too large for MAX_PACKET_BYTES",
            });
            return;
        }

        let buf = self.send_buf.as_mut();
        buf[0] = PACKET_TYPE_SERVER_TO_CLIENT;
        // Write header into buf[18..43].
        let header_slice: &mut [u8; ROUTE_HEADER_BYTES] = (&mut buf
            [PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES])
            .try_into()
            .expect("infallible: slice is exactly ROUTE_HEADER_BYTES wide");
        write_header(
            PACKET_TYPE_SERVER_TO_CLIENT,
            seq,
            sess.session_id,
            sess.session_version,
            &sess.session_private_key,
            header_slice,
        );
        buf[PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES..total].copy_from_slice(payload);

        // stamp pittle + chonkle.
        crate::route::stamp_packet(&mut buf[..total], magic, &from_bytes, &to_address);

        let to = sess.relay_address;
        let data = buf[..total].to_vec();
        self.push_notify(Notify::SendRaw { to, data });
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn session(&self, session_id: u64) -> Option<&SessionInfo> {
        self.sessions.get(&session_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn push_notify(&self, n: Notify) {
        self.notify.lock().unwrap().push_back(n);
    }
}

// ── Server (main-thread handle) ───────────────────────────────────────────────

pub struct Server {
    commands: CommandQueue,
    notify: NotifyQueue,

    pub state: i32,
    pub num_sessions: usize,
    pub bind_address: Address,
    /// Last send error from the network thread, if any.
    /// Set when send_packet_inner fails (e.g. oversized payload).
    /// Cleared by `clear_last_send_error()`.
    pub last_send_error: Option<(u64, &'static str)>,
}

impl Server {
    /// Open the server.
    pub fn open(&mut self, bind_address: Address) {
        self.bind_address = bind_address;
        self.push_command(Command::Open { bind_address });
        self.state = SERVER_STATE_OPEN;
    }

    /// Close the server.
    pub fn close(&mut self) {
        self.push_command(Command::Close);
        self.state = SERVER_STATE_CLOSED;
        self.num_sessions = 0;
    }

    /// Register a session (called when backend pushes session keys via HTTP).
    pub fn register_session(
        &mut self,
        session_id: u64,
        session_version: u8,
        session_private_key: [u8; SESSION_PRIVATE_KEY_BYTES],
        relay_address: Address,
    ) {
        self.push_command(Command::RegisterSession {
            session_id,
            session_version,
            session_private_key,
            relay_address,
        });
    }

    /// Expire / remove a session.
    pub fn expire_session(&mut self, session_id: u64) {
        self.push_command(Command::ExpireSession { session_id });
    }

    /// Send a game payload to `session_id` via the relay hop.
    pub fn send_packet(
        &mut self,
        session_id: u64,
        payload: &[u8],
        magic: [u8; 8],
        from_address: Address,
    ) {
        self.push_command(Command::SendPacket {
            session_id,
            payload: payload.to_vec(),
            magic,
            from_address,
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
            Notify::SessionRegistered { .. } => {
                self.num_sessions += 1;
            }
            Notify::SessionExpired { .. } => {
                if self.num_sessions > 0 {
                    self.num_sessions -= 1;
                }
            }
            Notify::SendError { session_id, reason } => {
                self.last_send_error = Some((session_id, reason));
            }
            Notify::PacketReceived { .. } => {}
            Notify::SendRaw { .. } => {}
        }
    }

    /// Pop next received game payload (session_id, payload), if any.
    pub fn recv_packet(&mut self) -> Option<(u64, Vec<u8>)> {
        loop {
            let n = { self.notify.lock().unwrap().pop_front() };
            match n {
                None => return None,
                Some(Notify::PacketReceived {
                    session_id,
                    payload,
                }) => return Some((session_id, payload)),
                Some(n) => self.apply_notify(n),
            }
        }
    }

    /// Pop next outbound raw UDP packet, if any.
    pub fn pop_send_raw(&mut self) -> Option<(Address, Vec<u8>)> {
        loop {
            let n = { self.notify.lock().unwrap().pop_front() };
            match n {
                None => return None,
                Some(Notify::SendRaw { to, data }) => return Some((to, data)),
                Some(n) => self.apply_notify(n),
            }
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == SERVER_STATE_OPEN
    }
    pub fn state(&self) -> i32 {
        self.state
    }
    /// Clear the last recorded send error.
    pub fn clear_last_send_error(&mut self) {
        self.last_send_error = None;
    }

    fn push_command(&self, c: Command) {
        self.commands.lock().unwrap().push_back(c);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.push_command(Command::Destroy);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (ServerInner, Server) {
        ServerInner::create()
    }

    fn addr() -> Address {
        Address::V4 {
            octets: [127, 0, 0, 1],
            port: 7777,
        }
    }
    fn relay_addr() -> Address {
        Address::V4 {
            octets: [10, 0, 0, 1],
            port: 4000,
        }
    }
    fn priv_key() -> [u8; SESSION_PRIVATE_KEY_BYTES] {
        [0x42u8; SESSION_PRIVATE_KEY_BYTES]
    }

    #[test]
    fn server_initial_state_is_closed() {
        let (_inner, server) = make_pair();
        assert_eq!(server.state(), SERVER_STATE_CLOSED);
        assert!(!server.is_open());
        assert_eq!(server.num_sessions, 0);
    }

    #[test]
    fn server_open_sets_state_open() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        assert_eq!(inner.state, SERVER_STATE_OPEN);
        assert_eq!(inner.bind_address, addr());
    }

    #[test]
    fn server_close_resets_state() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        server.close();
        inner.pump_commands();
        assert_eq!(inner.state, SERVER_STATE_CLOSED);
    }

    #[test]
    fn server_register_session_stores_info() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        server.register_session(0xDEAD_BEEF, 1, priv_key(), relay_addr());
        inner.pump_commands();
        assert_eq!(inner.session_count(), 1);
        let sess = inner.session(0xDEAD_BEEF).unwrap();
        assert_eq!(sess.session_id, 0xDEAD_BEEF);
        assert_eq!(sess.session_version, 1);
        assert_eq!(sess.session_private_key, priv_key());
    }

    #[test]
    fn server_expire_session_removes_info() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        server.register_session(42, 1, priv_key(), relay_addr());
        inner.pump_commands();
        assert_eq!(inner.session_count(), 1);
        server.expire_session(42);
        inner.pump_commands();
        assert_eq!(inner.session_count(), 0);
        assert!(inner.session(42).is_none());
    }

    #[test]
    fn server_destroy_stops_pump() {
        let (mut inner, server) = make_pair();
        drop(server); // triggers Destroy via Drop
        let result = inner.pump_commands();
        assert!(!result);
    }

    #[test]
    fn server_drain_notify_updates_session_count() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        server.register_session(1, 1, priv_key(), relay_addr());
        inner.pump_commands();
        // Before drain, num_sessions is still 0 on the client handle.
        server.drain_notify();
        assert_eq!(server.num_sessions, 1);
        server.expire_session(1);
        inner.pump_commands();
        server.drain_notify();
        assert_eq!(server.num_sessions, 0);
    }

    #[test]
    fn server_incoming_unknown_type_is_ignored() {
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();
        // packet type 0xFF is unknown
        let data = vec![0xFFu8; 64];
        let result = inner.process_incoming(&data);
        assert!(result.is_none());
    }

    #[test]
    fn server_client_to_server_with_valid_header_extracts_payload() {
        use crate::route::{address_ipv4_bytes, stamp_packet, write_header};
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();

        let session_id = 0xCAFE_BABEu64;
        let session_ver = 2u8;
        let key = priv_key();
        server.register_session(session_id, session_ver, key, relay_addr());
        inner.pump_commands();

        // Build a CLIENT_TO_SERVER packet with a valid header.
        let payload = b"game data";
        let seq = 1u64;
        let total = PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES + payload.len();
        let mut buf = vec![0u8; total];
        buf[0] = PACKET_TYPE_CLIENT_TO_SERVER;
        let header_slice: &mut [u8; ROUTE_HEADER_BYTES] = (&mut buf
            [PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES])
            .try_into()
            .unwrap();
        write_header(
            PACKET_TYPE_CLIENT_TO_SERVER,
            seq,
            session_id,
            session_ver,
            &key,
            header_slice,
        );
        buf[PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES..].copy_from_slice(payload);
        let from_bytes = address_ipv4_bytes(&addr());
        let to_bytes = address_ipv4_bytes(&relay_addr());
        stamp_packet(&mut buf, &[0u8; 8], &from_bytes, &to_bytes);

        let result = inner.process_incoming(&buf);
        assert!(result.is_some(), "expected payload to be extracted");
        let (sid, extracted) = result.unwrap();
        assert_eq!(sid, session_id);
        assert_eq!(extracted.as_slice(), payload.as_slice());
    }

    #[test]
    fn server_client_to_server_replay_is_rejected() {
        use crate::route::{address_ipv4_bytes, stamp_packet, write_header};
        let (mut inner, mut server) = make_pair();
        server.open(addr());
        inner.pump_commands();

        let session_id = 0xAABBCCDD_u64;
        let session_ver = 1u8;
        let key = priv_key();
        server.register_session(session_id, session_ver, key, relay_addr());
        inner.pump_commands();

        let payload = b"hello";
        let seq = 5u64;
        let total = PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES + payload.len();
        let mut buf = vec![0u8; total];
        buf[0] = PACKET_TYPE_CLIENT_TO_SERVER;
        let header_slice: &mut [u8; ROUTE_HEADER_BYTES] = (&mut buf
            [PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES])
            .try_into()
            .unwrap();
        write_header(
            PACKET_TYPE_CLIENT_TO_SERVER,
            seq,
            session_id,
            session_ver,
            &key,
            header_slice,
        );
        buf[PACKET_BODY_OFFSET + ROUTE_HEADER_BYTES..].copy_from_slice(payload);
        let from_bytes = address_ipv4_bytes(&addr());
        let to_bytes = address_ipv4_bytes(&relay_addr());
        stamp_packet(&mut buf, &[0u8; 8], &from_bytes, &to_bytes);

        // First receive OK.
        assert!(inner.process_incoming(&buf).is_some());
        // Second receive (replay) should be rejected.
        assert!(inner.process_incoming(&buf).is_none());
    }
}
