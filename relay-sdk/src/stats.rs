// mod stats - Event counters for Client and Server.
//
// ClientStats and ServerStats are plain counter structs accumulated on the
// main-thread handle (Client / Server) as Notify events are drained.
// Counters are u64 and only ever increment; reset by replacing with Default::default().
//
// Update points:
//   Client: apply_notify (drain_notify path), pop_send_raw (SendRaw path),
//           recv_packet (PacketReceived path)
//   Server: apply_notify (drain_notify / recv_packet / pop_send_raw paths)

/// Accumulated event counters for a relay client session.
///
/// Updated by `Client::drain_notify()`, `Client::recv_packet()`, and
/// `Client::pop_send_raw()`. Reset the struct with `Default::default()` to
/// start a new measurement window.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ClientStats {
    /// SendRaw packets enqueued for the UDP socket (relay packets sent outbound).
    pub packets_sent: u64,
    /// PacketReceived payloads delivered to the application.
    pub packets_received: u64,
    /// RouteChanged events observed (any route state transition).
    pub route_changes: u64,
}

/// Accumulated event counters for a relay server.
///
/// Updated by `Server::drain_notify()`, `Server::recv_packet()`, and
/// `Server::pop_send_raw()`. Reset the struct with `Default::default()` to
/// start a new measurement window.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServerStats {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_stats_default_is_all_zero() {
        let s = ClientStats::default();
        assert_eq!(s.packets_sent, 0);
        assert_eq!(s.packets_received, 0);
        assert_eq!(s.route_changes, 0);
    }

    #[test]
    fn server_stats_default_is_all_zero() {
        let s = ServerStats::default();
        assert_eq!(s.packets_received, 0);
        assert_eq!(s.packets_sent, 0);
        assert_eq!(s.send_errors, 0);
        assert_eq!(s.sessions_registered, 0);
        assert_eq!(s.sessions_expired, 0);
    }

    #[test]
    fn client_stats_replace_resets_counters() {
        let s = ClientStats {
            packets_sent: 100,
            packets_received: 50,
            route_changes: 3,
        };
        // Verify non-zero before reset.
        assert_eq!(s.packets_sent, 100);
        let s = ClientStats::default();
        assert_eq!(s.packets_sent, 0);
        assert_eq!(s.route_changes, 0);
    }

    #[test]
    fn server_stats_replace_resets_counters() {
        let s = ServerStats {
            packets_received: 10,
            packets_sent: 20,
            send_errors: 2,
            sessions_registered: 5,
            sessions_expired: 3,
        };
        // Verify non-zero before reset.
        assert_eq!(s.sessions_registered, 5);
        let s = ServerStats::default();
        assert_eq!(s.sessions_registered, 0);
        assert_eq!(s.send_errors, 0);
    }

    #[test]
    fn client_stats_copy_is_independent() {
        let a = ClientStats {
            packets_sent: 1,
            packets_received: 2,
            route_changes: 3,
        };
        let b = a;
        // Construct a modified copy without mutating a (avoid unused_assignments).
        let a2 = ClientStats {
            packets_sent: 99,
            ..a
        };
        assert_eq!(b.packets_sent, 1, "copy must be independent");
        assert_eq!(a2.packets_sent, 99);
    }
}
