use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use aya::maps::{Array, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use ayaflow_common::PacketEvent;

use crate::api::{self, AppState};
use crate::config::{CliArgs, Config};
use crate::dns;
use crate::l7;
use crate::state::{self, PacketMetadata};
use crate::storage;

pub async fn run() -> anyhow::Result<()> {
    let cli = CliArgs::parse();

    let mut config = if let Some(ref config_path) = cli.config {
        Config::from_file(Path::new(config_path))?
    } else {
        Config::default()
    };
    config.merge_cli(&cli);

    init_logging(config.quiet);

    let interface = resolve_interface(&config);
    let runtime_settings = config.runtime_settings(interface.clone());

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ayaflow-ebpf/target/bpfel-unknown-none/debug/ayaflow"
    )))?;

    if let Err(e) = tc::qdisc_add_clsact(&interface) {
        if e.raw_os_error() != Some(17) {
            tracing::error!(
                interface = %interface,
                error = %e,
                "failed to add clsact qdisc; confirm CAP_NET_ADMIN and that the interface exists"
            );
            return Err(e.into());
        }
        tracing::debug!("clsact qdisc already exists on {}, reusing", interface);
    }

    let program: &mut SchedClassifier = bpf.program_mut("ayaflow").unwrap().try_into()?;
    program.load().context(
        "failed to load eBPF program; verify kernel >= 5.8 with BTF support and CAP_BPF/CAP_PERFMON",
    )?;
    program.attach(&interface, TcAttachType::Ingress)?;
    program.attach(&interface, TcAttachType::Egress)?;
    tracing::info!(
        "eBPF TC classifier attached to {} (ingress + egress)",
        interface
    );

    {
        let mut config_map: Array<_, u32> = Array::try_from(bpf.map_mut("CONFIG").unwrap())?;

        config_map.set(0, u32::from(config.deep_inspect), 0)?;
        config_map.set(1, u32::from(config.enable_ipv6), 0)?;
    }

    let (tx, rx) = mpsc::channel::<PacketMetadata>(10000);

    let traffic_state = Arc::new(state::TrafficState::new());
    let storage = Arc::new(storage::Storage::new(&config.db_path)?);

    let storage_clone = storage.clone();
    let aggregation_window = config.aggregation_window_seconds;
    tokio::spawn(async move {
        storage_clone.run_writer(rx, aggregation_window).await;
    });

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
                    Err(e) => tracing::error!("Data retention cleanup failed: {}", e),
                    _ => {}
                }
            }
        });
    }

    let dns_cache = if config.resolve_dns {
        tracing::info!("Reverse DNS resolution enabled");
        Some(Arc::new(dns::DnsCache::new(
            Duration::from_secs(300),
            Duration::from_secs(2),
        )))
    } else {
        None
    };

    let domain_cache = if config.deep_inspect {
        let cache = Arc::new(l7::DomainCache::new(Duration::from_secs(300)));

        let payload_map = bpf.take_map("PAYLOAD_EVENTS").unwrap();
        let payload_ring_buf = RingBuf::try_from(payload_map)?;
        let cache_clone = cache.clone();
        let traffic_state_l7 = traffic_state.clone();
        tokio::spawn(async move {
            l7::poll_payload_ring_buf(payload_ring_buf, cache_clone, traffic_state_l7).await;
        });

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

    let events_map = bpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(events_map)?;
    let tx_ring = tx.clone();
    let traffic_state_ring = traffic_state.clone();

    tokio::spawn(async move {
        poll_ring_buf(
            ring_buf,
            tx_ring,
            traffic_state_ring,
            dns_cache,
            domain_cache,
        )
        .await;
    });
    drop(tx);

    let allowed_ips = runtime_settings.allowed_ips.clone();
    let app_state = Arc::new(AppState {
        traffic: traffic_state.clone(),
        storage: storage.clone(),
        start_time: std::time::Instant::now(),
        runtime: runtime_settings,
    });

    let app = api::router(app_state, &allowed_ips);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    tracing::info!(
        "Server running on http://0.0.0.0:{} (interface: {})",
        config.port,
        interface
    );
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received, cleaning up...");
        }
    }

    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(bpf);
    tracing::info!("TC filters detached from {}, shutdown complete", interface);

    Ok(())
}

fn init_logging(quiet: bool) {
    if quiet {
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
}

fn resolve_interface(config: &Config) -> String {
    if let Some(interface) = config.interface.clone() {
        return interface;
    }

    match detect_default_interface() {
        Some(interface) => {
            tracing::info!("Auto-detected default interface: {}", interface);
            interface
        }
        None => {
            tracing::warn!(
                "Could not auto-detect a default interface from /proc/net/route, falling back to eth0"
            );
            "eth0".to_string()
        }
    }
}

fn detect_default_interface() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;

    for line in routes.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let destination = fields.next()?;
        let _gateway = fields.next()?;
        let flags = fields.next()?;

        if destination == "00000000" {
            let flags = u16::from_str_radix(flags, 16).ok()?;
            if flags & 0x2 != 0 {
                return Some(iface.to_string());
            }
        }
    }

    None
}

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
            let event = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) };
            let mut meta = PacketMetadata::from_ebpf(&event);

            if let Some(ref cache) = dns_cache {
                meta.src_hostname = cache.resolve(&meta.src_ip).await;
                meta.dst_hostname = cache.resolve(&meta.dst_ip).await;
            }

            if let Some(ref cache) = domain_cache {
                meta.domain = lookup_domain_with_retry(cache, &meta).await;
            }

            traffic_state.update(&meta);
            let _ = tx.send(meta).await;
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn lookup_domain_with_retry(
    cache: &l7::DomainCache,
    packet: &PacketMetadata,
) -> Option<String> {
    const MAX_ATTEMPTS: usize = 6;

    for attempt in 0..MAX_ATTEMPTS {
        if let Some(domain) = lookup_domain(cache, packet) {
            return Some(domain);
        }

        if !is_deep_inspect_candidate(packet) {
            return None;
        }

        if attempt + 1 < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    None
}

fn lookup_domain(cache: &l7::DomainCache, packet: &PacketMetadata) -> Option<String> {
    let packet_key = l7::DomainPacketKey {
        protocol: &packet.protocol,
        src_ip: &packet.src_ip,
        dst_ip: &packet.dst_ip,
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        direction: &packet.direction,
    };

    cache
        .get_packet_domain(&packet_key)
        .or_else(|| cache.get(&format!("{}:{}", packet.dst_ip, packet.dst_port)))
        .or_else(|| cache.get_by_dst_ip(&packet.dst_ip))
}

fn is_deep_inspect_candidate(packet: &PacketMetadata) -> bool {
    (packet.protocol == "UDP" && (packet.src_port == 53 || packet.dst_port == 53))
        || (packet.protocol == "TCP" && packet.dst_port == 443)
}
