use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct PacketMetadata {
    pub timestamp: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_count: u64,
    #[serde(skip)]
    pub last_seen: Instant,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_count: 0,
            last_seen: Instant::now(),
        }
    }
}

/// Holds accumulated stats for a single connection within an aggregation time window.
/// Used by the storage writer when aggregation is enabled.
#[derive(Debug, Clone)]
pub struct AggregatedBucket {
    pub first_timestamp: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub total_bytes: u64,
}

impl AggregatedBucket {
    pub fn from_packet(packet: &PacketMetadata) -> Self {
        Self {
            first_timestamp: packet.timestamp,
            src_ip: packet.src_ip.clone(),
            dst_ip: packet.dst_ip.clone(),
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol.clone(),
            packet_count: 1,
            total_bytes: packet.length as u64,
        }
    }

    pub fn merge(&mut self, packet: &PacketMetadata) {
        self.packet_count += 1;
        self.total_bytes += packet.length as u64;
    }
}

pub struct TrafficState {
    pub connections: DashMap<String, ConnectionStats>, // Key: "src_ip:port -> dst_ip:port"
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    pub active_connections: AtomicUsize,
}

impl TrafficState {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }

    pub fn update(&self, packet: &PacketMetadata) {
        let key = format!(
            "{}:{} -> {}:{}",
            packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
        );

        self.connections
            .entry(key)
            .and_modify(|stats| {
                stats.packets_count += 1;
                stats.bytes_sent += packet.length as u64; 
                stats.last_seen = Instant::now();
            })
            .or_insert_with(|| {
                self.active_connections.fetch_add(1, Ordering::Relaxed);
                ConnectionStats {
                    bytes_sent: packet.length as u64,
                    packets_count: 1,
                    ..Default::default()
                }
            });

        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes
            .fetch_add(packet.length as u64, Ordering::Relaxed);
    }

    /// Remove connections that haven't been seen for the given duration
    pub fn cleanup_stale_connections(&self, timeout: tokio::time::Duration) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for entry in self.connections.iter() {
            if now.duration_since(entry.value().last_seen) > timeout {
                to_remove.push(entry.key().clone());
            }
        }

        let removed_count = to_remove.len();
        for key in to_remove {
            self.connections.remove(&key);
        }

        if removed_count > 0 {
            self.active_connections
                .fetch_sub(removed_count, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_state_update() {
        let state = TrafficState::new();
        let packet = PacketMetadata {
            timestamp: 0,
            src_ip: "127.0.0.1".into(),
            dst_ip: "127.0.0.1".into(),
            src_port: 80,
            dst_port: 1234,
            protocol: "TCP".into(),
            length: 100,
        };

        state.update(&packet);

        assert_eq!(state.total_packets.load(Ordering::Relaxed), 1);
        assert_eq!(state.total_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        
        // Update again
        state.update(&packet);
        assert_eq!(state.total_packets.load(Ordering::Relaxed), 2);
        assert_eq!(state.total_bytes.load(Ordering::Relaxed), 200);
        // Connection count should stay 1
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
    }
}
