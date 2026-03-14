use clap::Parser;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use aya::maps::{Array, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;

use ayaflow_common::PacketEvent;

mod api;
mod config;
mod dns;
mod l7;
mod state;
mod storage;

use config::{CliArgs, Config};
use state::PacketMetadata;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = CliArgs::parse();

    // Load config from file if provided, otherwise use defaults.
    let mut config = if let Some(ref config_path) = cli.config {
        Config::from_file(Path::new(config_path))?
    } else {
        Config::default()
    };
    config.merge_cli(&cli);

    // Logging.
    if config.quiet {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("error"))
            .with(tracing_subscriber::fmt::layer())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // -- eBPF setup --------------------------------------------------------
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ayaflow-ebpf/target/bpfel-unknown-none/debug/ayaflow"
    )))?;


    // Attach TC classifier to the target interface.
    let iface = config
        .interface
        .as_deref()
        .unwrap_or("eth0");

    // If the clsact qdisc already exists (EEXIST), that is fine.
    if let Err(e) = tc::qdisc_add_clsact(iface) {
        if e.raw_os_error() != Some(17) {
            return Err(e.into());
        }
        tracing::debug!("clsact qdisc already exists on {}, reusing", iface);
    }
    let program: &mut SchedClassifier =
        bpf.program_mut("ayaflow").unwrap().try_into()?;

    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;
    tracing::info!("eBPF TC classifier attached to {} (ingress)", iface);

    // -- Write deep_inspect flag to eBPF CONFIG map ------------------------
    if config.deep_inspect {
        let mut config_map: Array<_, u32> =
            Array::try_from(bpf.map_mut("CONFIG").unwrap())?;
        config_map.set(0, 1u32, 0)?;
        tracing::info!("Deep L7 inspection enabled (DNS + TLS SNI)");
    } else {
        tracing::debug!("Deep L7 inspection disabled");
    }

    // -- Channels ----------------------------------------------------------
    let (tx, rx) = mpsc::channel::<PacketMetadata>(10000);

    // -- State & Storage ---------------------------------------------------
    let traffic_state = Arc::new(state::TrafficState::new());
    let storage = Arc::new(storage::Storage::new(&config.db_path)?);

    // -- Storage Writer Task -----------------------------------------------
    let storage_clone = storage.clone();
    let aggregation_window = config.aggregation_window_seconds;
    tokio::spawn(async move {
        storage_clone.run_writer(rx, aggregation_window).await;
    });

    // -- Connection Cleanup Task -------------------------------------------
    let traffic_state_cleanup = traffic_state.clone();
    let connection_timeout = config.connection_timeout;
    tokio::spawn(async move {
        let mut cleanup_interval = interval(Duration::from_secs(10));
        loop {
            cleanup_interval.tick().await;
            traffic_state_cleanup
                .cleanup_stale_connections(Duration::from_secs(connection_timeout));
        }
    });

    // -- Data Retention Task -----------------------------------------------
    if let Some(retention_seconds) = config.data_retention_seconds {
        let storage_retention = storage.clone();
        tokio::spawn(async move {
            let mut retention_interval = interval(Duration::from_secs(60));
            loop {
                retention_interval.tick().await;
                match storage_retention.delete_old_data(retention_seconds) {
                    Ok(deleted) if deleted > 0 => {
                        tracing::info!("Data retention: deleted {} old packets", deleted);
                    }
                    Err(e) => {
                        tracing::error!("Data retention cleanup failed: {}", e);
                    }
                    _ => {}
                }
            }
        });
    }

    // -- DNS Cache (optional reverse lookup) --------------------------------
    let dns_cache = if config.resolve_dns {
        tracing::info!("Reverse DNS resolution enabled");
        Some(Arc::new(dns::DnsCache::new(
            Duration::from_secs(300),
            Duration::from_secs(2),
        )))
    } else {
        None
    };

    // -- Domain Cache for L7 deep inspection (optional) ---------------------
    let domain_cache = if config.deep_inspect {
        let cache = Arc::new(l7::DomainCache::new(Duration::from_secs(300)));

        // Spawn the payload ring buffer poller.
        let payload_map = bpf.take_map("PAYLOAD_EVENTS").unwrap();
        let payload_ring_buf = RingBuf::try_from(payload_map)?;
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            l7::poll_payload_ring_buf(payload_ring_buf, cache_clone).await;
        });

        // Spawn periodic cleanup of expired domain cache entries.
        let cache_cleanup = cache.clone();
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));
            loop {
                cleanup_interval.tick().await;
                cache_cleanup.cleanup_expired();
            }
        });

        Some(cache)
    } else {
        None
    };

    // -- RingBuf Poller (L3/L4 events) --------------------------------------
    let events_map = bpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(events_map)?;
    let tx_ring = tx.clone();
    let traffic_state_ring = traffic_state.clone();

    tokio::spawn(async move {
        poll_ring_buf(ring_buf, tx_ring, traffic_state_ring, dns_cache, domain_cache).await;
    });

    // -- HTTP API -----------------------------------------------------------
    let app_state = Arc::new(api::AppState {
        traffic: traffic_state.clone(),
        storage: storage.clone(),
        start_time: std::time::Instant::now(),
    });

    let allowed_ips = config.allowed_ips.clone();
    let app = api::router(app_state, &allowed_ips);

    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    tracing::info!("Server running on http://0.0.0.0:{}", config.port);
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}

/// Continuously poll the eBPF RingBuf for PacketEvent entries, convert them
/// to PacketMetadata, update the live TrafficState, and forward to the storage
/// writer channel.
async fn poll_ring_buf(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<PacketMetadata>,
    traffic_state: Arc<state::TrafficState>,
    dns_cache: Option<Arc<dns::DnsCache>>,
    domain_cache: Option<Arc<l7::DomainCache>>,
) {
    loop {
        while let Some(item) = ring_buf.next() {
            if item.len() < core::mem::size_of::<PacketEvent>() {
                continue;
            }
            let event =
                unsafe { core::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) };
            let mut meta = PacketMetadata::from_ebpf(&event);

            // Enrich with reverse DNS if enabled.
            if let Some(ref cache) = dns_cache {
                meta.src_hostname = cache.resolve(&meta.src_ip).await;
                meta.dst_hostname = cache.resolve(&meta.dst_ip).await;
            }

            // Enrich with domain from L7 deep inspection if enabled.
            if let Some(ref cache) = domain_cache {
                // Try TLS SNI match first (most specific: dst_ip:dst_port).
                let sni_key = format!("{}:{}", meta.dst_ip, meta.dst_port);
                if let Some(domain) = cache.get(&sni_key) {
                    meta.domain = Some(domain);
                } else {
                    // Try DNS-based match (by domain name is less direct, so
                    // we try the dst_ip match for any cached DNS resolution).
                    if let domain @ Some(_) = cache.get_by_dst_ip(&meta.dst_ip) {
                        meta.domain = domain;
                    }
                }
            }

            traffic_state.update(&meta);
            let _ = tx.send(meta).await;
        }

        // Yield briefly to avoid busy-spinning when the ring buffer is empty.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
