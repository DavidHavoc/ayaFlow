use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, Instant};

use aya::maps::RingBuf;
use ayaflow_common::{PayloadEvent, MAX_PAYLOAD_LEN};

use crate::state::TrafficState;

// ── DNS Parser ────────────────────────────────────────────────────────────────

/// Parse a DNS query from raw UDP payload bytes.
///
/// DNS wire format (RFC 1035):
///   Header:  12 bytes (ID, flags, counts)
///   Question: QNAME (sequence of length-prefixed labels) + QTYPE(2) + QCLASS(2)
///
/// Returns the queried domain name or None on any parse failure.
pub fn parse_dns_query(payload: &[u8]) -> Option<String> {
    // Minimum DNS header is 12 bytes.
    if payload.len() < 12 {
        return None;
    }

    // Check QR bit (byte 2, bit 7): 0 = query, 1 = response.
    // We want queries, but we also accept responses to capture what was asked.
    let _flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

    // We only parse the first question.
    if qdcount == 0 {
        return None;
    }

    // Parse QNAME starting at byte 12.
    let mut pos = 12;
    let mut labels: Vec<&str> = Vec::new();

    loop {
        if pos >= payload.len() {
            return None;
        }
        let label_len = payload[pos] as usize;
        if label_len == 0 {
            break; // Root label -- end of QNAME.
        }
        // Reject compression pointers (top 2 bits set) in the question section.
        if label_len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + label_len > payload.len() {
            return None;
        }
        let label = core::str::from_utf8(&payload[pos..pos + label_len]).ok()?;
        labels.push(label);
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

// ── TLS SNI Parser ────────────────────────────────────────────────────────────

/// Parse a TLS ClientHello to extract the Server Name Indication (SNI).
///
/// TLS record format:
///   ContentType(1) | ProtocolVersion(2) | Length(2) | Handshake...
///
/// Handshake (ClientHello):
///   HandshakeType(1) | Length(3) | ClientVersion(2) | Random(32) |
///   SessionID(var) | CipherSuites(var) | CompressionMethods(var) |
///   ExtensionsLength(2) | Extensions...
///
/// SNI Extension (type 0x0000):
///   ExtType(2) | ExtLen(2) | SNIListLen(2) | NameType(1) | NameLen(2) | Name...
///
/// Returns the server name or None.
pub fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes.
    if payload.len() < 5 {
        return None;
    }

    // Content type 0x16 = Handshake.
    if payload[0] != 0x16 {
        return None;
    }

    // TLS record length.
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5 + record_len;
    if record_end > payload.len() {
        // Truncated, but we may still have enough for SNI.
        // We will bounds-check as we go.
    }

    // Handshake header starts at byte 5.
    let mut pos: usize = 5;

    // HandshakeType: 0x01 = ClientHello.
    if pos >= payload.len() || payload[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // Handshake length (3 bytes) -- skip.
    if pos + 3 > payload.len() {
        return None;
    }
    pos += 3;

    // Client version (2 bytes) -- skip.
    if pos + 2 > payload.len() {
        return None;
    }
    pos += 2;

    // Random (32 bytes) -- skip.
    if pos + 32 > payload.len() {
        return None;
    }
    pos += 32;

    // Session ID (variable).
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites (variable, 2-byte length prefix).
    if pos + 2 > payload.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods (variable, 1-byte length prefix).
    if pos >= payload.len() {
        return None;
    }
    let compression_len = payload[pos] as usize;
    pos += 1 + compression_len;

    // Extensions length (2 bytes).
    if pos + 2 > payload.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;

    // Walk extensions looking for SNI (type 0x0000).
    while pos + 4 <= payload.len() && pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension found.
            // SNI list length (2 bytes).
            if pos + 2 > payload.len() {
                return None;
            }
            let _sni_list_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;

            // Name type (1 byte): 0x00 = host_name.
            if pos >= payload.len() || payload[pos] != 0x00 {
                return None;
            }
            pos += 1;

            // Name length (2 bytes).
            if pos + 2 > payload.len() {
                return None;
            }
            let name_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;

            if pos + name_len > payload.len() {
                return None;
            }
            return core::str::from_utf8(&payload[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
        }

        // Skip this extension's data.
        pos += ext_len;
    }

    None
}

// ── Domain Cache ──────────────────────────────────────────────────────────────

/// A resolved domain name with an expiration time.
struct DomainEntry {
    domain: String,
    expires_at: Instant,
}

/// Cache mapping connection tuples to their resolved domain names.
///
/// Keyed by a string like "192.168.1.10:443" (the destination side),
/// since a DNS query for is followed by a TLS connection to the resolved IP on port 443.
pub struct DomainCache {
    /// For DNS: maps destination IP to domain (from the query).
    /// For TLS SNI: maps "dst_ip:dst_port" to domain.
    cache: DashMap<String, DomainEntry>,
    ttl: Duration,
}

impl DomainCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
        }
    }

    /// Store a domain association.
    pub fn insert(&self, key: &str, domain: String) {
        self.cache.insert(
            key.to_string(),
            DomainEntry {
                domain,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Look up a domain by connection key.
    pub fn get(&self, key: &str) -> Option<String> {
        if let Some(entry) = self.cache.get(key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.domain.clone());
            }
        }
        None
    }

    /// Look up domain for a given destination IP (used to match DNS answers
    /// to subsequent TCP connections).
    pub fn get_by_dst_ip(&self, dst_ip: &str) -> Option<String> {
        self.get(dst_ip)
    }

    /// Periodic cleanup of expired entries.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| now < entry.expires_at);
    }
}

// ── Payload Ring Buffer Poller ────────────────────────────────────────────────

/// Continuously poll the PAYLOAD_EVENTS eBPF RingBuf, parse DNS/TLS payloads,
/// and populate the domain cache.
pub async fn poll_payload_ring_buf(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    domain_cache: Arc<DomainCache>,
    traffic_state: Arc<TrafficState>,
) {
    loop {
        while let Some(item) = ring_buf.next() {
            if item.len() < core::mem::size_of::<PayloadEvent>() {
                continue;
            }
            let event =
                unsafe { core::ptr::read_unaligned(item.as_ptr() as *const PayloadEvent) };

            traffic_state.deep_inspect_packets.fetch_add(1, Ordering::Relaxed);

            let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_LEN);
            let payload = &event.payload[..payload_len];

            let src_ip = std::net::Ipv4Addr::from(event.src_addr).to_string();
            let dst_ip = std::net::Ipv4Addr::from(event.dst_addr).to_string();

            // DNS (UDP port 53).
            if event.protocol == 17 && (event.dst_port == 53 || event.src_port == 53) {
                if let Some(domain) = parse_dns_query(payload) {
                    tracing::debug!("DNS query: {} -> {}", src_ip, domain);
                    domain_cache.insert(&format!("dns:{}", domain), domain.clone());
                    traffic_state.domains_resolved.fetch_add(1, Ordering::Relaxed);
                }
            }

            // TLS (TCP port 443).
            if event.protocol == 6 && event.dst_port == 443 {
                if let Some(sni) = parse_tls_sni(payload) {
                    let key = format!("{}:{}", dst_ip, event.dst_port);
                    tracing::debug!("TLS SNI: {} -> {} ({})", src_ip, dst_ip, sni);
                    domain_cache.insert(&key, sni);
                    traffic_state.domains_resolved.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Yield briefly to avoid busy-spinning.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_valid() {
        // Manually constructed DNS query for "example.com"
        // Header: 12 bytes (transaction ID, flags, qdcount=1, ancount=0, nscount=0, arcount=0)
        let mut packet: Vec<u8> = vec![
            0xAB, 0xCD, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        // QNAME: "example.com" = [7]example[3]com[0]
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0, // root label
        ]);
        // QTYPE (A = 1) and QCLASS (IN = 1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let result = parse_dns_query(&packet);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_query_subdomain() {
        let mut packet: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        // "www.example.com"
        packet.extend_from_slice(&[
            3, b'w', b'w', b'w',
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,
        ]);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        assert_eq!(parse_dns_query(&packet), Some("www.example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_query_invalid_too_short() {
        assert_eq!(parse_dns_query(&[0; 5]), None);
    }

    #[test]
    fn test_parse_dns_query_no_questions() {
        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, // QDCOUNT: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(parse_dns_query(&packet), None);
    }

    #[test]
    fn test_parse_tls_sni_valid() {
        // Minimal TLS ClientHello with SNI for "example.com"
        let sni_name = b"example.com";
        let sni_name_len = sni_name.len();

        // Build SNI extension
        let mut sni_ext: Vec<u8> = Vec::new();
        // SNI list length
        sni_ext.extend_from_slice(&((sni_name_len as u16 + 3).to_be_bytes())); // list len
        sni_ext.push(0x00); // name type = host_name
        sni_ext.extend_from_slice(&(sni_name_len as u16).to_be_bytes()); // name len
        sni_ext.extend_from_slice(sni_name);

        // Build extensions block
        let mut extensions: Vec<u8> = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // ext len
        extensions.extend_from_slice(&sni_ext);

        // Build ClientHello body (after handshake header)
        let mut client_hello_body: Vec<u8> = Vec::new();
        client_hello_body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        client_hello_body.extend_from_slice(&[0x00; 32]); // random
        client_hello_body.push(0x00); // session ID length = 0
        client_hello_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x01]); // cipher suites: len=2, one suite
        client_hello_body.extend_from_slice(&[0x01, 0x00]); // compression: len=1, null
        client_hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello_body.extend_from_slice(&extensions);

        // Build handshake header
        let mut handshake: Vec<u8> = Vec::new();
        handshake.push(0x01); // HandshakeType = ClientHello
        let hs_len = client_hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&client_hello_body);

        // Build TLS record
        let mut record: Vec<u8> = Vec::new();
        record.push(0x16); // ContentType = Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let result = parse_tls_sni(&record);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_tls_sni_no_sni_extension() {
        // ClientHello with no extensions at all
        let mut client_hello_body: Vec<u8> = Vec::new();
        client_hello_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        client_hello_body.extend_from_slice(&[0x00; 32]); // random
        client_hello_body.push(0x00); // session ID len = 0
        client_hello_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x01]); // cipher suites
        client_hello_body.extend_from_slice(&[0x01, 0x00]); // compression
        client_hello_body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

        let mut handshake: Vec<u8> = Vec::new();
        handshake.push(0x01);
        let hs_len = client_hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&client_hello_body);

        let mut record: Vec<u8> = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(parse_tls_sni(&record), None);
    }

    #[test]
    fn test_parse_tls_sni_not_handshake() {
        // Not a handshake record (content type 0x17 = Application Data)
        let record = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_tls_sni(&record), None);
    }

    #[test]
    fn test_parse_tls_sni_too_short() {
        assert_eq!(parse_tls_sni(&[0x16, 0x03]), None);
    }

    #[test]
    fn test_domain_cache_insert_and_get() {
        let cache = DomainCache::new(Duration::from_secs(300));
        cache.insert("192.168.1.1:443", "example.com".to_string());
        assert_eq!(cache.get("192.168.1.1:443"), Some("example.com".to_string()));
    }

    #[test]
    fn test_domain_cache_miss() {
        let cache = DomainCache::new(Duration::from_secs(300));
        assert_eq!(cache.get("10.0.0.1:443"), None);
    }

    #[test]
    fn test_domain_cache_expired() {
        let cache = DomainCache::new(Duration::from_millis(1));
        cache.insert("key", "domain.com".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(cache.get("key"), None);
    }
}
