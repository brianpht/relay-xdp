//! Ping history - circular buffer tracking RTT, jitter, packet loss.
//! Port of `relay_ping_history.c`.

use relay_xdp_common::RELAY_PING_HISTORY_SIZE;

#[derive(Clone)]
struct Entry {
    sequence: u64,
    time_ping_sent: f64,
    time_pong_received: f64,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            sequence: u64::MAX,
            time_ping_sent: -1.0,
            time_pong_received: -1.0,
        }
    }
}

pub struct PingHistory {
    sequence: u64,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Default)]
pub struct PingHistoryStats {
    pub rtt: f32,
    pub jitter: f32,
    pub packet_loss: f32,
}

impl PingHistory {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            entries: vec![Entry::default(); RELAY_PING_HISTORY_SIZE],
        }
    }

    /// Record a ping sent. Returns the sequence number used.
    pub fn ping_sent(&mut self, time: f64) -> u64 {
        let index = (self.sequence as usize) % RELAY_PING_HISTORY_SIZE;
        self.entries[index] = Entry {
            sequence: self.sequence,
            time_ping_sent: time,
            time_pong_received: -1.0,
        };
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    /// Record a pong received for the given sequence.
    pub fn pong_received(&mut self, sequence: u64, time: f64) {
        let index = (sequence as usize) % RELAY_PING_HISTORY_SIZE;
        if self.entries[index].sequence == sequence {
            self.entries[index].time_pong_received = time;
        }
    }

    /// Compute RTT, jitter, packet loss over a time window (single pass).
    pub fn get_stats(&self, start: f64, end: f64, ping_safety: f64) -> PingHistoryStats {
        let mut num_pings_sent = 0u32;
        let mut num_pongs_received = 0u32;
        let mut min_rtt = f64::MAX;
        let mut rtt_sum = 0.0f64;
        let mut rtt_count = 0u32;

        for entry in &self.entries {
            if entry.time_ping_sent < start || entry.time_ping_sent > end {
                continue;
            }
            let has_pong = entry.time_pong_received > entry.time_ping_sent;

            // Packet loss: only count entries within the safety window
            if entry.time_ping_sent <= end - ping_safety {
                num_pings_sent += 1;
                if has_pong {
                    num_pongs_received += 1;
                }
            }

            // RTT + jitter accumulation
            if has_pong {
                let rtt = entry.time_pong_received - entry.time_ping_sent;
                if rtt < min_rtt {
                    min_rtt = rtt;
                }
                rtt_sum += rtt;
                rtt_count += 1;
            }
        }

        let packet_loss = if num_pings_sent > 0 {
            (100.0 * (1.0 - num_pongs_received as f64 / num_pings_sent as f64)) as f32
        } else {
            100.0
        };

        let rtt = if min_rtt < f64::MAX {
            (1000.0 * min_rtt) as f32
        } else {
            0.0
        };

        // Jitter = avg(rtt) - min_rtt
        let jitter = if rtt_count > 0 && min_rtt < f64::MAX {
            (1000.0 * (rtt_sum / rtt_count as f64 - min_rtt)) as f32
        } else {
            0.0
        };

        PingHistoryStats {
            rtt,
            jitter,
            packet_loss,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_history_100_percent_loss() {
        let h = PingHistory::new();
        let stats = h.get_stats(0.0, 10.0, 1.0);
        assert_eq!(stats.packet_loss, 100.0);
        assert_eq!(stats.rtt, 0.0);
        assert_eq!(stats.jitter, 0.0);
    }

    #[test]
    fn test_single_ping_pong() {
        let mut h = PingHistory::new();
        let seq = h.ping_sent(1.0);
        assert_eq!(seq, 0);
        h.pong_received(0, 1.005); // 5ms RTT

        let stats = h.get_stats(0.0, 10.0, 1.0);
        // 1 ping sent in [0.0, 9.0] window (end - safety), 1 pong received
        assert_eq!(stats.packet_loss, 0.0);
        assert!((stats.rtt - 5.0).abs() < 0.1); // ~5ms
        assert_eq!(stats.jitter, 0.0); // Only 1 sample, jitter is 0
    }

    #[test]
    fn test_multiple_pings_with_loss() {
        let mut h = PingHistory::new();
        // Send 4 pings, receive pongs for only 2
        h.ping_sent(1.0); // seq 0
        h.ping_sent(2.0); // seq 1
        h.ping_sent(3.0); // seq 2
        h.ping_sent(4.0); // seq 3

        h.pong_received(0, 1.010); // 10ms
        h.pong_received(2, 3.020); // 20ms

        let stats = h.get_stats(0.0, 10.0, 1.0);
        // 4 pings in [0.0, 9.0], 2 pongs → 50% loss
        assert!((stats.packet_loss - 50.0).abs() < 0.1);
        // Min RTT = 10ms
        assert!((stats.rtt - 10.0).abs() < 0.5);
    }

    #[test]
    fn test_jitter_computation() {
        let mut h = PingHistory::new();
        h.ping_sent(1.0); // seq 0
        h.ping_sent(2.0); // seq 1
        h.pong_received(0, 1.010); // 10ms RTT
        h.pong_received(1, 2.030); // 30ms RTT

        let stats = h.get_stats(0.0, 10.0, 1.0);
        // Min RTT = 10ms, jitter = avg(|rtt - min_rtt|) = avg(0, 20ms) = 10ms
        assert!((stats.rtt - 10.0).abs() < 0.5);
        assert!((stats.jitter - 10.0).abs() < 0.5);
    }

    #[test]
    fn test_circular_buffer_wraparound() {
        let mut h = PingHistory::new();
        // Send more than RELAY_PING_HISTORY_SIZE (64) pings
        for i in 0..100u64 {
            let seq = h.ping_sent(i as f64);
            assert_eq!(seq, i);
            h.pong_received(i, i as f64 + 0.005);
        }

        // Stats should only see entries within the window
        let stats = h.get_stats(90.0, 100.0, 1.0);
        assert!(stats.packet_loss < 50.0); // Most pongs received
        assert!((stats.rtt - 5.0).abs() < 0.5); // ~5ms RTT
    }

    #[test]
    fn test_sequence_numbers_increment() {
        let mut h = PingHistory::new();
        assert_eq!(h.ping_sent(0.0), 0);
        assert_eq!(h.ping_sent(0.1), 1);
        assert_eq!(h.ping_sent(0.2), 2);
    }
}
