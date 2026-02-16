use clap::Parser;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod sniffer;
mod state;
mod storage;

use config::{CliArgs, Config};
use sniffer::FilterConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();

    // Load config from file if provided, otherwise use defaults
    let mut config = if let Some(ref config_path) = cli.config {
        Config::from_file(Path::new(config_path))?
    } else {
        Config::default()
    };

    // CLI args override config file
    config.merge_cli(&cli);

    // Setup logging based on quiet mode
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

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Channels
    let (tx, rx) = mpsc::channel(10000);

    // State & Storage
    let traffic_state = Arc::new(state::TrafficState::new());
    let storage = Arc::new(storage::Storage::new(&config.db_path)?);

    // Spawn Writer Task
    let storage_clone = storage.clone();
    let aggregation_window = config.aggregation_window_seconds;
    tokio::spawn(async move {
        storage_clone.run_writer(rx, aggregation_window).await;
    });

    // Spawn Connection Cleanup Task
    let traffic_state_cleanup = traffic_state.clone();
    let connection_timeout = config.connection_timeout;
    tokio::spawn(async move {
        let mut cleanup_interval = interval(Duration::from_secs(10));
        loop {
            cleanup_interval.tick().await;
            traffic_state_cleanup.cleanup_stale_connections(Duration::from_secs(connection_timeout));
        }
    });

    // Spawn Data Retention Cleanup Task (if enabled)
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

    // Signal handler for graceful shutdown
    let _storage_for_shutdown = storage.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Shutdown signal received, flushing...");
        // Note: In a more complete implementation, we'd flush the buffer here
        r.store(false, std::sync::atomic::Ordering::Relaxed);
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Start Sniffer Thread
    let tx_clone = tx.clone();
    let interface = config.interface.clone();
    let running_sniffer = running.clone();
    let traffic_state_clone = traffic_state.clone();
    let filter = FilterConfig::from(&config);
    let quiet = config.quiet;
    let sample_rate = config.sample_rate;

    std::thread::spawn(move || {
        sniffer::start_sniffer(interface, tx_clone, running_sniffer, traffic_state_clone, filter, quiet, sample_rate);
    });

    // API
    let app_state = Arc::new(api::AppState {
        traffic: traffic_state.clone(),
        storage: storage.clone(),
        start_time: std::time::Instant::now(),
    });

    let app = api::router(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    tracing::info!("Server running on http://0.0.0.0:{}", config.port);
    axum::serve(listener, app).await?;

    Ok(())
}
