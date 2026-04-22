// mod packets - Encode/decode for all 14 relay packet types (IDs 1-14).
//
// Wire layout common to all packets:
//   [0]      packet_type   u8
//   [1..3]   pittle        2 bytes  (filled by stamp_filter in route/mod.rs)
//   [3..18]  chonkle       15 bytes (filled by stamp_filter)
//   [18..]   packet body   (type-specific)
//
// Packet bodies (offset from byte 0):
//   1 ROUTE_REQUEST    18 + token_data (variable, (N-1)*111 bytes)
//   2 ROUTE_RESPONSE   18 + HEADER(25)                        = 43
//   3 CLIENT_TO_SERVER 18 + HEADER(25) + game_payload         = variable
//   4 SERVER_TO_CLIENT 18 + HEADER(25) + game_payload         = variable
//   5 SESSION_PING     18 + HEADER(25) + seq(8)               = 51
//   6 SESSION_PONG     18 + HEADER(25) + seq(8)               = 51
//   7 CONTINUE_REQUEST 18 + token_data (variable)
//   8 CONTINUE_RESPONSE 18 + HEADER(25)                       = 43
//   9 CLIENT_PING      18 + echo(8)+session_id(8)+expire(8)+token(32) = 74
//  10 CLIENT_PONG      18 + echo(8)+session_id(8)             = 34
//  11 RELAY_PING       18 + seq(8)+expire(8)+internal(1)+token(32)   = 67
//  12 RELAY_PONG       18 + seq(8)                            = 26
//  13 SERVER_PING      18 + echo(8)+expire(8)+token(32)       = 66
//  14 SERVER_PONG      18 + echo(8)                           = 26
use crate::constants::*;
use crate::route::HEADER_BYTES;
use thiserror::Error;
pub const PACKET_BODY_OFFSET: usize = 18;
pub const ROUTE_RESPONSE_BYTES:    usize = PACKET_BODY_OFFSET + HEADER_BYTES;               // 43
pub const SESSION_PING_BYTES:      usize = PACKET_BODY_OFFSET + HEADER_BYTES + 8;           // 51
pub const SESSION_PONG_BYTES:      usize = PACKET_BODY_OFFSET + HEADER_BYTES + 8;           // 51
pub const CONTINUE_RESPONSE_BYTES: usize = PACKET_BODY_OFFSET + HEADER_BYTES;               // 43
pub const CLIENT_PING_BYTES:       usize = PACKET_BODY_OFFSET + 8 + 8 + 8 + RELAY_PING_TOKEN_BYTES; // 74
pub const CLIENT_PONG_BYTES:       usize = PACKET_BODY_OFFSET + 8 + 8;                       // 34
pub const RELAY_PING_BYTES:        usize = PACKET_BODY_OFFSET + 8 + 8 + 1 + RELAY_PING_TOKEN_BYTES; // 67
pub const RELAY_PONG_BYTES:        usize = PACKET_BODY_OFFSET + 8;                           // 26
pub const SERVER_PING_BYTES:       usize = PACKET_BODY_OFFSET + 8 + 8 + RELAY_PING_TOKEN_BYTES;     // 66
pub const SERVER_PONG_BYTES:       usize = PACKET_BODY_OFFSET + 8;                           // 26
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("buffer too small: need {need}, got {got}")]
    TooSmall { need: usize, got: usize },
    #[error("wrong packet type: expected {expected}, got {got}")]
    WrongType { expected: u8, got: u8 },
    #[error("invalid packet size: expected {expected}, got {got}")]
    WrongSize { expected: usize, got: usize },
}
// ── Read helpers ──────────────────────────────────────────────────────────────
#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}
// ── Packet structs ────────────────────────────────────────────────────────────
/// ROUTE_RESPONSE (type 2): relay confirms route established.
/// Body at offset 18: relay_header[HEADER_BYTES]
#[derive(Debug, Clone)]
pub struct RouteResponsePacket {
    pub relay_header: [u8; HEADER_BYTES],
}
impl RouteResponsePacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_ROUTE_RESPONSE, ROUTE_RESPONSE_BYTES)?;
        let mut hdr = [0u8; HEADER_BYTES];
        hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
        Ok(Self { relay_header: hdr })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, ROUTE_RESPONSE_BYTES)?;
        buf[0] = PACKET_TYPE_ROUTE_RESPONSE;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES].copy_from_slice(&self.relay_header);
        Ok(ROUTE_RESPONSE_BYTES)
    }
}
/// SESSION_PING (type 5): session-level ping forwarded hop-by-hop.
/// Body: relay_header[25] + ping_sequence[8]
#[derive(Debug, Clone)]
pub struct SessionPingPacket {
    pub relay_header:  [u8; HEADER_BYTES],
    pub ping_sequence: u64,
}
impl SessionPingPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_SESSION_PING, SESSION_PING_BYTES)?;
        let mut hdr = [0u8; HEADER_BYTES];
        hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
        let seq = read_u64(buf, PACKET_BODY_OFFSET + HEADER_BYTES);
        Ok(Self { relay_header: hdr, ping_sequence: seq })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, SESSION_PING_BYTES)?;
        buf[0] = PACKET_TYPE_SESSION_PING;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES].copy_from_slice(&self.relay_header);
        buf[PACKET_BODY_OFFSET + HEADER_BYTES..PACKET_BODY_OFFSET + HEADER_BYTES + 8]
            .copy_from_slice(&self.ping_sequence.to_le_bytes());
        Ok(SESSION_PING_BYTES)
    }
}
/// SESSION_PONG (type 6): session-level pong forwarded hop-by-hop.
/// Same layout as SESSION_PING.
#[derive(Debug, Clone)]
pub struct SessionPongPacket {
    pub relay_header:   [u8; HEADER_BYTES],
    pub pong_sequence:  u64,
}
impl SessionPongPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_SESSION_PONG, SESSION_PONG_BYTES)?;
        let mut hdr = [0u8; HEADER_BYTES];
        hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
        let seq = read_u64(buf, PACKET_BODY_OFFSET + HEADER_BYTES);
        Ok(Self { relay_header: hdr, pong_sequence: seq })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, SESSION_PONG_BYTES)?;
        buf[0] = PACKET_TYPE_SESSION_PONG;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES].copy_from_slice(&self.relay_header);
        buf[PACKET_BODY_OFFSET + HEADER_BYTES..PACKET_BODY_OFFSET + HEADER_BYTES + 8]
            .copy_from_slice(&self.pong_sequence.to_le_bytes());
        Ok(SESSION_PONG_BYTES)
    }
}
/// CONTINUE_RESPONSE (type 8): relay confirms continue-route established.
/// Same layout as ROUTE_RESPONSE.
#[derive(Debug, Clone)]
pub struct ContinueResponsePacket {
    pub relay_header: [u8; HEADER_BYTES],
}
impl ContinueResponsePacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_CONTINUE_RESPONSE, CONTINUE_RESPONSE_BYTES)?;
        let mut hdr = [0u8; HEADER_BYTES];
        hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
        Ok(Self { relay_header: hdr })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, CONTINUE_RESPONSE_BYTES)?;
        buf[0] = PACKET_TYPE_CONTINUE_RESPONSE;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES].copy_from_slice(&self.relay_header);
        Ok(CONTINUE_RESPONSE_BYTES)
    }
}
/// CLIENT_PING (type 9): client pings relay to probe RTT.
/// Body: echo(8) + session_id(8) + expire_timestamp(8) + ping_token(32)
#[derive(Debug, Clone)]
pub struct ClientPingPacket {
    pub echo:            u64,
    pub session_id:      u64,
    pub expire_timestamp: u64,
    pub ping_token:      [u8; RELAY_PING_TOKEN_BYTES],
}
impl ClientPingPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_CLIENT_PING, CLIENT_PING_BYTES)?;
        let o = PACKET_BODY_OFFSET;
        let mut tok = [0u8; RELAY_PING_TOKEN_BYTES];
        tok.copy_from_slice(&buf[o + 24..o + 24 + RELAY_PING_TOKEN_BYTES]);
        Ok(Self {
            echo:             read_u64(buf, o),
            session_id:       read_u64(buf, o + 8),
            expire_timestamp: read_u64(buf, o + 16),
            ping_token:       tok,
        })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, CLIENT_PING_BYTES)?;
        buf[0] = PACKET_TYPE_CLIENT_PING;
        let o = PACKET_BODY_OFFSET;
        buf[o..o + 8].copy_from_slice(&self.echo.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&self.session_id.to_le_bytes());
        buf[o + 16..o + 24].copy_from_slice(&self.expire_timestamp.to_le_bytes());
        buf[o + 24..o + 24 + RELAY_PING_TOKEN_BYTES].copy_from_slice(&self.ping_token);
        Ok(CLIENT_PING_BYTES)
    }
}
/// CLIENT_PONG (type 10): relay echo response to client_ping.
/// Body: echo(8) + session_id(8)
#[derive(Debug, Clone)]
pub struct ClientPongPacket {
    pub echo:       u64,
    pub session_id: u64,
}
impl ClientPongPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_CLIENT_PONG, CLIENT_PONG_BYTES)?;
        let o = PACKET_BODY_OFFSET;
        Ok(Self { echo: read_u64(buf, o), session_id: read_u64(buf, o + 8) })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, CLIENT_PONG_BYTES)?;
        buf[0] = PACKET_TYPE_CLIENT_PONG;
        let o = PACKET_BODY_OFFSET;
        buf[o..o + 8].copy_from_slice(&self.echo.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&self.session_id.to_le_bytes());
        Ok(CLIENT_PONG_BYTES)
    }
}
/// RELAY_PING (type 11): relay-to-relay ping for RTT measurement.
/// Body: sequence(8) + expire_timestamp(8) + is_internal(1) + ping_token(32)
#[derive(Debug, Clone)]
pub struct RelayPingPacket {
    pub sequence:        u64,
    pub expire_timestamp: u64,
    pub is_internal:     bool,
    pub ping_token:      [u8; RELAY_PING_TOKEN_BYTES],
}
impl RelayPingPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_RELAY_PING, RELAY_PING_BYTES)?;
        let o = PACKET_BODY_OFFSET;
        let mut tok = [0u8; RELAY_PING_TOKEN_BYTES];
        tok.copy_from_slice(&buf[o + 17..o + 17 + RELAY_PING_TOKEN_BYTES]);
        Ok(Self {
            sequence:         read_u64(buf, o),
            expire_timestamp: read_u64(buf, o + 8),
            is_internal:      buf[o + 16] != 0,
            ping_token:       tok,
        })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, RELAY_PING_BYTES)?;
        buf[0] = PACKET_TYPE_RELAY_PING;
        let o = PACKET_BODY_OFFSET;
        buf[o..o + 8].copy_from_slice(&self.sequence.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&self.expire_timestamp.to_le_bytes());
        buf[o + 16] = self.is_internal as u8;
        buf[o + 17..o + 17 + RELAY_PING_TOKEN_BYTES].copy_from_slice(&self.ping_token);
        Ok(RELAY_PING_BYTES)
    }
}
/// RELAY_PONG (type 12): relay-to-relay pong echo.
/// Body: sequence(8)
#[derive(Debug, Clone)]
pub struct RelayPongPacket {
    pub sequence: u64,
}
impl RelayPongPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_RELAY_PONG, RELAY_PONG_BYTES)?;
        Ok(Self { sequence: read_u64(buf, PACKET_BODY_OFFSET) })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, RELAY_PONG_BYTES)?;
        buf[0] = PACKET_TYPE_RELAY_PONG;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + 8].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(RELAY_PONG_BYTES)
    }
}
/// SERVER_PING (type 13): game server pings relay to probe RTT.
/// Body: echo(8) + expire_timestamp(8) + ping_token(32)
#[derive(Debug, Clone)]
pub struct ServerPingPacket {
    pub echo:            u64,
    pub expire_timestamp: u64,
    pub ping_token:      [u8; RELAY_PING_TOKEN_BYTES],
}
impl ServerPingPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_SERVER_PING, SERVER_PING_BYTES)?;
        let o = PACKET_BODY_OFFSET;
        let mut tok = [0u8; RELAY_PING_TOKEN_BYTES];
        tok.copy_from_slice(&buf[o + 16..o + 16 + RELAY_PING_TOKEN_BYTES]);
        Ok(Self {
            echo:             read_u64(buf, o),
            expire_timestamp: read_u64(buf, o + 8),
            ping_token:       tok,
        })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, SERVER_PING_BYTES)?;
        buf[0] = PACKET_TYPE_SERVER_PING;
        let o = PACKET_BODY_OFFSET;
        buf[o..o + 8].copy_from_slice(&self.echo.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&self.expire_timestamp.to_le_bytes());
        buf[o + 16..o + 16 + RELAY_PING_TOKEN_BYTES].copy_from_slice(&self.ping_token);
        Ok(SERVER_PING_BYTES)
    }
}
/// SERVER_PONG (type 14): relay echo response to server_ping.
/// Body: echo(8)
#[derive(Debug, Clone)]
pub struct ServerPongPacket {
    pub echo: u64,
}
impl ServerPongPacket {
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        check_type_size(buf, PACKET_TYPE_SERVER_PONG, SERVER_PONG_BYTES)?;
        Ok(Self { echo: read_u64(buf, PACKET_BODY_OFFSET) })
    }
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        require_size(buf, SERVER_PONG_BYTES)?;
        buf[0] = PACKET_TYPE_SERVER_PONG;
        buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + 8].copy_from_slice(&self.echo.to_le_bytes());
        Ok(SERVER_PONG_BYTES)
    }
}
// ── Dispatch ──────────────────────────────────────────────────────────────────
/// All decoded packet variants.
#[derive(Debug, Clone)]
pub enum Packet {
    RouteResponse(RouteResponsePacket),
    SessionPing(SessionPingPacket),
    SessionPong(SessionPongPacket),
    ContinueResponse(ContinueResponsePacket),
    ClientPing(ClientPingPacket),
    ClientPong(ClientPongPacket),
    RelayPing(RelayPingPacket),
    RelayPong(RelayPongPacket),
    ServerPing(ServerPingPacket),
    ServerPong(ServerPongPacket),
    // CLIENT_TO_SERVER and SERVER_TO_CLIENT carry variable payloads;
    // they are decoded by RouteManager (header verification needed first).
    ClientToServer { relay_header: [u8; HEADER_BYTES], payload_offset: usize },
    ServerToClient { relay_header: [u8; HEADER_BYTES], payload_offset: usize },
}
pub fn decode(buf: &[u8]) -> Result<Packet, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::TooSmall { need: 1, got: 0 });
    }
    match buf[0] {
        t if t == PACKET_TYPE_ROUTE_RESPONSE    => Ok(Packet::RouteResponse(RouteResponsePacket::decode(buf)?)),
        t if t == PACKET_TYPE_SESSION_PING      => Ok(Packet::SessionPing(SessionPingPacket::decode(buf)?)),
        t if t == PACKET_TYPE_SESSION_PONG      => Ok(Packet::SessionPong(SessionPongPacket::decode(buf)?)),
        t if t == PACKET_TYPE_CONTINUE_RESPONSE => Ok(Packet::ContinueResponse(ContinueResponsePacket::decode(buf)?)),
        t if t == PACKET_TYPE_CLIENT_PING       => Ok(Packet::ClientPing(ClientPingPacket::decode(buf)?)),
        t if t == PACKET_TYPE_CLIENT_PONG       => Ok(Packet::ClientPong(ClientPongPacket::decode(buf)?)),
        t if t == PACKET_TYPE_RELAY_PING        => Ok(Packet::RelayPing(RelayPingPacket::decode(buf)?)),
        t if t == PACKET_TYPE_RELAY_PONG        => Ok(Packet::RelayPong(RelayPongPacket::decode(buf)?)),
        t if t == PACKET_TYPE_SERVER_PING       => Ok(Packet::ServerPing(ServerPingPacket::decode(buf)?)),
        t if t == PACKET_TYPE_SERVER_PONG       => Ok(Packet::ServerPong(ServerPongPacket::decode(buf)?)),
        t if t == PACKET_TYPE_CLIENT_TO_SERVER  => {
            if buf.len() < PACKET_BODY_OFFSET + HEADER_BYTES {
                return Err(PacketError::TooSmall { need: PACKET_BODY_OFFSET + HEADER_BYTES, got: buf.len() });
            }
            let mut hdr = [0u8; HEADER_BYTES];
            hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
            Ok(Packet::ClientToServer { relay_header: hdr, payload_offset: PACKET_BODY_OFFSET + HEADER_BYTES })
        }
        t if t == PACKET_TYPE_SERVER_TO_CLIENT  => {
            if buf.len() < PACKET_BODY_OFFSET + HEADER_BYTES {
                return Err(PacketError::TooSmall { need: PACKET_BODY_OFFSET + HEADER_BYTES, got: buf.len() });
            }
            let mut hdr = [0u8; HEADER_BYTES];
            hdr.copy_from_slice(&buf[PACKET_BODY_OFFSET..PACKET_BODY_OFFSET + HEADER_BYTES]);
            Ok(Packet::ServerToClient { relay_header: hdr, payload_offset: PACKET_BODY_OFFSET + HEADER_BYTES })
        }
        t => Err(PacketError::WrongType { expected: 0, got: t }),
    }
}
// ── Validation helpers ────────────────────────────────────────────────────────
fn check_type_size(buf: &[u8], expected_type: u8, expected_size: usize) -> Result<(), PacketError> {
    if buf.len() < 1 {
        return Err(PacketError::TooSmall { need: 1, got: 0 });
    }
    if buf[0] != expected_type {
        return Err(PacketError::WrongType { expected: expected_type, got: buf[0] });
    }
    if buf.len() != expected_size {
        return Err(PacketError::WrongSize { expected: expected_size, got: buf.len() });
    }
    Ok(())
}
fn require_size(buf: &[u8], need: usize) -> Result<(), PacketError> {
    if buf.len() < need {
        Err(PacketError::TooSmall { need, got: buf.len() })
    } else {
        Ok(())
    }
}
// ── Packet type constants (re-exported from constants for convenience) ─────────
pub use crate::constants::{
    PACKET_TYPE_ROUTE_REQUEST    as PACKET_TYPE_ROUTE_REQUEST,
    PACKET_TYPE_ROUTE_RESPONSE   as PACKET_TYPE_ROUTE_RESPONSE,
    PACKET_TYPE_CLIENT_TO_SERVER as PACKET_TYPE_CLIENT_TO_SERVER,
    PACKET_TYPE_SERVER_TO_CLIENT as PACKET_TYPE_SERVER_TO_CLIENT,
    PACKET_TYPE_SESSION_PING     as PACKET_TYPE_SESSION_PING,
    PACKET_TYPE_SESSION_PONG     as PACKET_TYPE_SESSION_PONG,
    PACKET_TYPE_CONTINUE_REQUEST as PACKET_TYPE_CONTINUE_REQUEST,
    PACKET_TYPE_CONTINUE_RESPONSE as PACKET_TYPE_CONTINUE_RESPONSE,
    PACKET_TYPE_CLIENT_PING      as PACKET_TYPE_CLIENT_PING,
    PACKET_TYPE_CLIENT_PONG      as PACKET_TYPE_CLIENT_PONG,
    PACKET_TYPE_RELAY_PING       as PACKET_TYPE_RELAY_PING,
    PACKET_TYPE_RELAY_PONG       as PACKET_TYPE_RELAY_PONG,
    PACKET_TYPE_SERVER_PING      as PACKET_TYPE_SERVER_PING,
    PACKET_TYPE_SERVER_PONG      as PACKET_TYPE_SERVER_PONG,
};
// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    // ── Fixed-size packet size assertions ─────────────────────────────────────
    #[test]
    fn packet_size_constants() {
        assert_eq!(ROUTE_RESPONSE_BYTES,    43);
        assert_eq!(SESSION_PING_BYTES,      51);
        assert_eq!(SESSION_PONG_BYTES,      51);
        assert_eq!(CONTINUE_RESPONSE_BYTES, 43);
        assert_eq!(CLIENT_PING_BYTES,       74);
        assert_eq!(CLIENT_PONG_BYTES,       34);
        assert_eq!(RELAY_PING_BYTES,        67);
        assert_eq!(RELAY_PONG_BYTES,        26);
        assert_eq!(SERVER_PING_BYTES,       66);
        assert_eq!(SERVER_PONG_BYTES,       26);
    }
    // ── RouteResponse roundtrip ───────────────────────────────────────────────
    #[test]
    fn route_response_roundtrip() {
        let hdr = [0xAAu8; HEADER_BYTES];
        let pkt = RouteResponsePacket { relay_header: hdr };
        let mut buf = [0u8; ROUTE_RESPONSE_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, ROUTE_RESPONSE_BYTES);
        assert_eq!(buf[0], PACKET_TYPE_ROUTE_RESPONSE);
        let dec = RouteResponsePacket::decode(&buf).unwrap();
        assert_eq!(dec.relay_header, hdr);
    }
    // ── ContinueResponse roundtrip ────────────────────────────────────────────
    #[test]
    fn continue_response_roundtrip() {
        let hdr = [0xBBu8; HEADER_BYTES];
        let pkt = ContinueResponsePacket { relay_header: hdr };
        let mut buf = [0u8; CONTINUE_RESPONSE_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, CONTINUE_RESPONSE_BYTES);
        let dec = ContinueResponsePacket::decode(&buf).unwrap();
        assert_eq!(dec.relay_header, hdr);
    }
    // ── SessionPing roundtrip ─────────────────────────────────────────────────
    #[test]
    fn session_ping_roundtrip() {
        let hdr = [0x11u8; HEADER_BYTES];
        let pkt = SessionPingPacket { relay_header: hdr, ping_sequence: 0xDEAD_BEEF_1234_5678 };
        let mut buf = [0u8; SESSION_PING_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, SESSION_PING_BYTES);
        assert_eq!(buf[0], PACKET_TYPE_SESSION_PING);
        let dec = SessionPingPacket::decode(&buf).unwrap();
        assert_eq!(dec.relay_header, hdr);
        assert_eq!(dec.ping_sequence, 0xDEAD_BEEF_1234_5678);
    }
    // ── RelayPing roundtrip ───────────────────────────────────────────────────
    #[test]
    fn relay_ping_roundtrip() {
        let tok = [0x55u8; RELAY_PING_TOKEN_BYTES];
        let pkt = RelayPingPacket {
            sequence: 42,
            expire_timestamp: 99999,
            is_internal: true,
            ping_token: tok,
        };
        let mut buf = [0u8; RELAY_PING_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, RELAY_PING_BYTES);
        assert_eq!(buf[0], PACKET_TYPE_RELAY_PING);
        let dec = RelayPingPacket::decode(&buf).unwrap();
        assert_eq!(dec.sequence, 42);
        assert_eq!(dec.expire_timestamp, 99999);
        assert!(dec.is_internal);
        assert_eq!(dec.ping_token, tok);
    }
    // ── RelayPong roundtrip ───────────────────────────────────────────────────
    #[test]
    fn relay_pong_roundtrip() {
        let pkt = RelayPongPacket { sequence: 12345 };
        let mut buf = [0u8; RELAY_PONG_BYTES];
        pkt.encode(&mut buf).unwrap();
        assert_eq!(buf[0], PACKET_TYPE_RELAY_PONG);
        let dec = RelayPongPacket::decode(&buf).unwrap();
        assert_eq!(dec.sequence, 12345);
    }
    // ── ClientPing roundtrip ──────────────────────────────────────────────────
    #[test]
    fn client_ping_roundtrip() {
        let tok = [0x77u8; RELAY_PING_TOKEN_BYTES];
        let pkt = ClientPingPacket {
            echo: 0xCAFE, session_id: 0xBEEF, expire_timestamp: 1234567, ping_token: tok,
        };
        let mut buf = [0u8; CLIENT_PING_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, CLIENT_PING_BYTES);
        assert_eq!(buf[0], PACKET_TYPE_CLIENT_PING);
        let dec = ClientPingPacket::decode(&buf).unwrap();
        assert_eq!(dec.echo, 0xCAFE);
        assert_eq!(dec.session_id, 0xBEEF);
        assert_eq!(dec.expire_timestamp, 1234567);
        assert_eq!(dec.ping_token, tok);
    }
    // ── ClientPong roundtrip ──────────────────────────────────────────────────
    #[test]
    fn client_pong_roundtrip() {
        let pkt = ClientPongPacket { echo: 0xCAFE, session_id: 0xBEEF };
        let mut buf = [0u8; CLIENT_PONG_BYTES];
        pkt.encode(&mut buf).unwrap();
        assert_eq!(buf[0], PACKET_TYPE_CLIENT_PONG);
        let dec = ClientPongPacket::decode(&buf).unwrap();
        assert_eq!(dec.echo, 0xCAFE);
        assert_eq!(dec.session_id, 0xBEEF);
    }
    // ── ServerPing roundtrip ──────────────────────────────────────────────────
    #[test]
    fn server_ping_roundtrip() {
        let tok = [0x33u8; RELAY_PING_TOKEN_BYTES];
        let pkt = ServerPingPacket { echo: 7777, expire_timestamp: 8888, ping_token: tok };
        let mut buf = [0u8; SERVER_PING_BYTES];
        let len = pkt.encode(&mut buf).unwrap();
        assert_eq!(len, SERVER_PING_BYTES);
        assert_eq!(buf[0], PACKET_TYPE_SERVER_PING);
        let dec = ServerPingPacket::decode(&buf).unwrap();
        assert_eq!(dec.echo, 7777);
        assert_eq!(dec.expire_timestamp, 8888);
        assert_eq!(dec.ping_token, tok);
    }
    // ── ServerPong roundtrip ──────────────────────────────────────────────────
    #[test]
    fn server_pong_roundtrip() {
        let pkt = ServerPongPacket { echo: 999 };
        let mut buf = [0u8; SERVER_PONG_BYTES];
        pkt.encode(&mut buf).unwrap();
        assert_eq!(buf[0], PACKET_TYPE_SERVER_PONG);
        let dec = ServerPongPacket::decode(&buf).unwrap();
        assert_eq!(dec.echo, 999);
    }
    // ── Dispatch decode ───────────────────────────────────────────────────────
    #[test]
    fn dispatch_decode_relay_pong() {
        let pkt = RelayPongPacket { sequence: 55 };
        let mut buf = [0u8; RELAY_PONG_BYTES];
        pkt.encode(&mut buf).unwrap();
        match decode(&buf).unwrap() {
            Packet::RelayPong(p) => assert_eq!(p.sequence, 55),
            _ => panic!("wrong variant"),
        }
    }
    #[test]
    fn dispatch_decode_unknown_type_fails() {
        let buf = [0xFFu8; 10];
        assert!(decode(&buf).is_err());
    }
    // ── Wrong-size decode fails ───────────────────────────────────────────────
    #[test]
    fn route_response_wrong_size_fails() {
        let mut buf = [0u8; ROUTE_RESPONSE_BYTES + 1];
        buf[0] = PACKET_TYPE_ROUTE_RESPONSE;
        assert!(RouteResponsePacket::decode(&buf).is_err());
    }
    #[test]
    fn relay_pong_too_small_fails() {
        let buf = [PACKET_TYPE_RELAY_PONG, 0, 0, 0, 0];
        assert!(RelayPongPacket::decode(&buf).is_err());
    }
}
