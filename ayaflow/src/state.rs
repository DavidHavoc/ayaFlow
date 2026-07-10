use dashmap::DashMap;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    /// Packet direction: "ingress" or "egress".
    pub direction: String,
    /// Reverse-DNS hostname for source IP (None when DNS resolution is disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    /// Reverse-DNS hostname for destination IP (None when DNS resolution is disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_hostname: Option<String>,
    /// Domain name from DNS query or TLS SNI (None when deep_inspect is disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Convert a 16-byte address + addr_type into a human-readable IP string.
fn addr_to_string(raw: &[u8; 16], addr_type: u8) -> String {
    if addr_type == 4 {
        // IPv4-mapped-IPv6: last 4 bytes hold the IPv4 octets.
        Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string()
    } else {
        Ipv6Addr::from(*raw).to_string()
    }
}

impl PacketMetadata {
    /// Convert a kernel-side PacketEvent into a userspace PacketMetadata.
    ///
    /// IP addresses are converted from the 16-byte wire format (IPv4-mapped
    /// or raw IPv6) to canonical string representations.
    /// The timestamp is assigned here in userspace.
    pub fn from_ebpf(event: &PacketEvent) -> Self {
        let src_ip = addr_to_string(&event.src_addr, event.addr_type);
        let dst_ip = addr_to_string(&event.dst_addr, event.addr_type);
        let protocol = match event.protocol {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            other => format!("IP({})", other),
        };
        let direction = if event.direction == 0 {
            "ingress".to_string()
        } else {
            "egress".to_string()
        };
        Self {
            timestamp: chrono::Utc::now().timestamp_millis(),
            src_ip,
            dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol,
            length: event.pkt_len as usize,
            direction,
            src_hostname: None,
            dst_hostname: None,
            domain: None,
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
    pub direction: String,
    pub src_hostname: Option<String>,
    pub dst_hostname: Option<String>,
    pub domain: Option<String>,
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
            direction: packet.direction.clone(),
            src_hostname: packet.src_hostname.clone(),
            dst_hostname: packet.dst_hostname.clone(),
            domain: packet.domain.clone(),
        }
    }

    pub fn merge(&mut self, packet: &PacketMetadata) {
        self.packet_count += 1;
        self.total_bytes += packet.length as u64;
        if self.domain.is_none() {
            self.domain = packet.domain.clone();
        }
    }
}

pub struct TrafficState {
    pub connections: DashMap<String, ConnectionStats>,
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    pub active_connections: AtomicUsize,
    /// Total L7 payload events received from eBPF (only when deep_inspect is on).
    pub deep_inspect_packets: AtomicU64,
    /// Total domains successfully resolved from DNS/TLS SNI.
    pub domains_resolved: AtomicU64,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficState {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            deep_inspect_packets: AtomicU64::new(0),
            domains_resolved: AtomicU64::new(0),
        }
    }

    pub fn update(&self, packet: &PacketMetadata) {
        let key = format!(
            "{}:{} -> {}:{}",
            packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
        );

        let is_egress = packet.direction == "egress";

        self.connections
            .entry(key)
            .and_modify(|stats| {
                stats.packets_count += 1;
                if is_egress {
                    stats.bytes_sent += packet.length as u64;
                } else {
                    stats.bytes_received += packet.length as u64;
                }
                stats.last_seen = Instant::now();
            })
            .or_insert_with(|| {
                self.active_connections.fetch_add(1, Ordering::Relaxed);
                let mut cs = ConnectionStats {
                    packets_count: 1,
                    ..Default::default()
                };
                if is_egress {
                    cs.bytes_sent = packet.length as u64;
                } else {
                    cs.bytes_received = packet.length as u64;
                }
                cs
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
    use ayaflow_common::ipv4_mapped;

    #[test]
    fn test_from_ebpf_tcp() {
        let event = PacketEvent {
            src_addr: ipv4_mapped(u32::from_be_bytes([10, 0, 0, 1])),
            dst_addr: ipv4_mapped(u32::from_be_bytes([192, 168, 1, 100])),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            direction: 0,
            addr_type: 4,
            _pad: [0; 1],
            pkt_len: 1500,
        };
        let meta = PacketMetadata::from_ebpf(&event);

        assert_eq!(meta.src_ip, "10.0.0.1");
        assert_eq!(meta.dst_ip, "192.168.1.100");
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.protocol, "TCP");
        assert_eq!(meta.length, 1500);
        assert_eq!(meta.direction, "ingress");
    }

    #[test]
    fn test_from_ebpf_udp() {
        let event = PacketEvent {
            src_addr: ipv4_mapped(u32::from_be_bytes([172, 16, 0, 1])),
            dst_addr: ipv4_mapped(u32::from_be_bytes([8, 8, 8, 8])),
            src_port: 53000,
            dst_port: 53,
            protocol: 17,
            direction: 1,
            addr_type: 4,
            _pad: [0; 1],
            pkt_len: 64,
        };
        let meta = PacketMetadata::from_ebpf(&event);

        assert_eq!(meta.src_ip, "172.16.0.1");
        assert_eq!(meta.dst_ip, "8.8.8.8");
        assert_eq!(meta.protocol, "UDP");
        assert_eq!(meta.length, 64);
        assert_eq!(meta.direction, "egress");
    }

    #[test]
    fn test_from_ebpf_ipv6() {
        // 2001:db8::1 and 2001:db8::2
        let src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let event = PacketEvent {
            src_addr: src,
            dst_addr: dst,
            src_port: 8080,
            dst_port: 80,
            protocol: 6,
            direction: 0,
            addr_type: 6,
            _pad: [0; 1],
            pkt_len: 500,
        };
        let meta = PacketMetadata::from_ebpf(&event);

        assert_eq!(meta.src_ip, "2001:db8::1");
        assert_eq!(meta.dst_ip, "2001:db8::2");
        assert_eq!(meta.protocol, "TCP");
        assert_eq!(meta.length, 500);
        assert_eq!(meta.direction, "ingress");
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
            direction: "ingress".into(),
            src_hostname: None,
            dst_hostname: None,
            domain: None,
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

    #[test]
    fn aggregated_bucket_accumulates_bytes_and_late_domain() {
        let mut first = PacketMetadata {
            timestamp: 100,
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 50_000,
            dst_port: 443,
            protocol: "TCP".into(),
            length: 100,
            direction: "egress".into(),
            src_hostname: Some("client.local".into()),
            dst_hostname: None,
            domain: None,
        };
        let mut bucket = AggregatedBucket::from_packet(&first);
        first.timestamp = 200;
        first.length = 250;
        first.domain = Some("example.com".into());

        bucket.merge(&first);

        assert_eq!(bucket.first_timestamp, 100);
        assert_eq!(bucket.packet_count, 2);
        assert_eq!(bucket.total_bytes, 350);
        assert_eq!(bucket.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn traffic_state_tracks_sent_and_received_bytes_separately() {
        let state = TrafficState::new();
        let mut packet = PacketMetadata {
            timestamp: 0,
            src_ip: "127.0.0.1".into(),
            dst_ip: "127.0.0.1".into(),
            src_port: 80,
            dst_port: 1234,
            protocol: "TCP".into(),
            length: 100,
            direction: "egress".into(),
            src_hostname: None,
            dst_hostname: None,
            domain: None,
        };

        state.update(&packet);
        packet.direction = "ingress".into();
        packet.length = 40;
        state.update(&packet);

        let stats = state.connections.iter().next().unwrap();
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 40);
        assert_eq!(stats.packets_count, 2);
    }

    #[test]
    fn cleanup_removes_only_stale_connections() {
        let state = TrafficState::new();
        let mut packet = PacketMetadata {
            timestamp: 0,
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 1000,
            dst_port: 443,
            protocol: "TCP".into(),
            length: 100,
            direction: "egress".into(),
            src_hostname: None,
            dst_hostname: None,
            domain: None,
        };
        state.update(&packet);
        let stale_key = "10.0.0.1:1000 -> 1.1.1.1:443";
        state.connections.get_mut(stale_key).unwrap().last_seen =
            Instant::now() - tokio::time::Duration::from_secs(6);

        packet.src_port = 2000;
        state.update(&packet);
        state.cleanup_stale_connections(tokio::time::Duration::from_secs(5));

        assert_eq!(state.connections.len(), 1);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        assert!(state
            .connections
            .iter()
            .any(|entry| entry.key().contains(":2000")));
    }
}
