use dashmap::DashMap;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::time::Instant;

use ayaflow_common::PacketEvent;

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

impl PacketMetadata {
    /// Convert a kernel-side PacketEvent into a userspace PacketMetadata.
    ///
    /// IP addresses are converted from u32 (network byte order, already
    /// converted to host order in the eBPF program) to dotted-quad strings.
    /// The timestamp is assigned here in userspace.
    pub fn from_ebpf(event: &PacketEvent) -> Self {
        let src_ip = Ipv4Addr::from(event.src_addr).to_string();
        let dst_ip = Ipv4Addr::from(event.dst_addr).to_string();
        let protocol = match event.protocol {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            other => format!("IP({})", other),
        };
        Self {
            timestamp: chrono::Utc::now().timestamp_millis(),
            src_ip,
            dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol,
            length: event.pkt_len as usize,
        }
    }
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
    pub connections: DashMap<String, ConnectionStats>,
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
    fn test_from_ebpf_tcp() {
        let event = PacketEvent {
            src_addr: u32::from_be_bytes([10, 0, 0, 1]),
            dst_addr: u32::from_be_bytes([192, 168, 1, 100]),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            _pad: [0; 3],
            pkt_len: 1500,
        };
        let meta = PacketMetadata::from_ebpf(&event);

        assert_eq!(meta.src_ip, "10.0.0.1");
        assert_eq!(meta.dst_ip, "192.168.1.100");
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.protocol, "TCP");
        assert_eq!(meta.length, 1500);
    }

    #[test]
    fn test_from_ebpf_udp() {
        let event = PacketEvent {
            src_addr: u32::from_be_bytes([172, 16, 0, 1]),
            dst_addr: u32::from_be_bytes([8, 8, 8, 8]),
            src_port: 53000,
            dst_port: 53,
            protocol: 17,
            _pad: [0; 3],
            pkt_len: 64,
        };
        let meta = PacketMetadata::from_ebpf(&event);

        assert_eq!(meta.src_ip, "172.16.0.1");
        assert_eq!(meta.dst_ip, "8.8.8.8");
        assert_eq!(meta.protocol, "UDP");
        assert_eq!(meta.length, 64);
    }

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

        state.update(&packet);
        assert_eq!(state.total_packets.load(Ordering::Relaxed), 2);
        assert_eq!(state.total_bytes.load(Ordering::Relaxed), 200);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
    }
}
