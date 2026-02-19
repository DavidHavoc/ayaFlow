use dashmap::DashMap;
use std::net::IpAddr;
use tokio::time::{Duration, Instant};

/// Cached DNS entry with expiration.
struct CacheEntry {
    hostname: Option<String>,
    expires_at: Instant,
}

/// Async reverse-DNS resolver with a TTL-based cache.
///
/// Lookups that fail (no PTR record, timeout, etc.) are cached as `None` to
/// prevent repeated queries for non-resolvable addresses.
pub struct DnsCache {
    cache: DashMap<IpAddr, CacheEntry>,
    ttl: Duration,
    timeout: Duration,
}

impl DnsCache {
    /// Create a new cache.
    ///
    /// * `ttl` -- how long a successful (or failed) lookup is kept.
    /// * `timeout` -- max wall-clock time for a single DNS query.
    pub fn new(ttl: Duration, timeout: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
            timeout,
        }
    }

    /// Resolve an IPv4 dotted-quad string to a hostname.
    ///
    /// Returns `None` when the address cannot be parsed, cannot be resolved,
    /// or the lookup times out. Results (including failures) are cached.
    pub async fn resolve(&self, ip_str: &str) -> Option<String> {
        let ip: IpAddr = match ip_str.parse() {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        // Fast path: cache hit & still fresh.
        if let Some(entry) = self.cache.get(&ip) {
            if Instant::now() < entry.expires_at {
                return entry.hostname.clone();
            }
        }

        // Slow path: perform the reverse lookup (blocking, via spawn_blocking)
        // with a timeout to prevent stalls.
        let ip_copy = ip;
        let result = tokio::time::timeout(self.timeout, async move {
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_copy).ok())
                .await
                .unwrap_or(None)
        })
        .await
        .unwrap_or(None);

        // If the resolved hostname is just the IP address echoed back, treat
        // it as a failed lookup.
        let hostname = result.filter(|h| h != ip_str);

        self.cache.insert(
            ip,
            CacheEntry {
                hostname: hostname.clone(),
                expires_at: Instant::now() + self.ttl,
            },
        );

        hostname
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_stores_result() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(2));

        // Resolve the loopback -- most systems have a PTR for 127.0.0.1.
        let first = cache.resolve("127.0.0.1").await;
        // Whether it resolves or not, a second call must return the cached value.
        let second = cache.resolve("127.0.0.1").await;
        assert_eq!(first, second);

        // The cache should now contain exactly one entry.
        assert_eq!(cache.cache.len(), 1);
    }

    #[tokio::test]
    async fn test_unparseable_ip_returns_none() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(2));
        assert_eq!(cache.resolve("not-an-ip").await, None);
        // Unparseable IPs are not cached (no IpAddr key).
        assert_eq!(cache.cache.len(), 0);
    }

    #[tokio::test]
    async fn test_failed_lookup_is_cached() {
        let cache = DnsCache::new(Duration::from_secs(300), Duration::from_secs(2));

        // RFC 5737 TEST-NET: 192.0.2.1 has no PTR record on any real resolver.
        let result = cache.resolve("192.0.2.1").await;
        assert_eq!(result, None);

        // The failed lookup should still be cached.
        assert!(cache.cache.contains_key(&"192.0.2.1".parse::<IpAddr>().unwrap()));
    }
}
