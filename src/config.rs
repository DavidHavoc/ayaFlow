use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Application configuration, loadable from CLI or YAML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Network interface to capture on
    #[serde(default)]
    pub interface: Option<String>,

    /// API server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Database path
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Filter by port (only capture traffic on this port)
    #[serde(default)]
    pub filter_port: Option<u16>,

    /// Filter by IP (only capture traffic to/from this IP)
    #[serde(default)]
    pub filter_ip: Option<String>,

    /// Filter by protocol (TCP, UDP)
    #[serde(default)]
    pub filter_protocol: Option<String>,

    /// Connection timeout in seconds (for stale connection cleanup)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,

    /// Enable DNS resolution for IPs
    #[serde(default)]
    pub resolve_dns: bool,

    /// Quiet mode (suppress non-error logs)
    #[serde(default)]
    pub quiet: bool,

    /// Data retention in seconds (None = keep forever, Some(seconds) = delete older data)
    #[serde(default)]
    pub data_retention_seconds: Option<u64>,

    /// Packet sampling rate: keep 1 out of every N packets for storage.
    /// 1 = keep all (default), 10 = keep every 10th packet, etc.
    /// Live in-memory stats always reflect all packets regardless of this setting.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,

    /// Aggregation window in seconds. When > 0, packets are collapsed into
    /// per-connection summary rows covering this time window before writing to the DB.
    /// 0 = disabled (default), store every sampled packet individually.
    #[serde(default = "default_aggregation_window")]
    pub aggregation_window_seconds: u64,
}

fn default_port() -> u16 {
    3000
}

fn default_db_path() -> String {
    "traffic.db".to_string()
}

fn default_connection_timeout() -> u64 {
    60
}

fn default_data_retention() -> Option<u64> {
    None
}

fn default_sample_rate() -> u32 {
    1
}

fn default_aggregation_window() -> u64 {
    0
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            port: default_port(),
            db_path: default_db_path(),
            filter_port: None,
            filter_ip: None,
            filter_protocol: None,
            connection_timeout: default_connection_timeout(),
            resolve_dns: false,
            quiet: false,
            data_retention_seconds: default_data_retention(),
            sample_rate: default_sample_rate(),
            aggregation_window_seconds: default_aggregation_window(),
        }
    }
}

impl Config {
    /// Load config from a YAML file
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Merge CLI args into config (CLI takes precedence)
    pub fn merge_cli(&mut self, cli: &CliArgs) {
        if cli.interface.is_some() {
            self.interface = cli.interface.clone();
        }
        if cli.port != 3000 {
            self.port = cli.port;
        }
        if cli.db_path != "traffic.db" {
            self.db_path = cli.db_path.clone();
        }
        if cli.filter_port.is_some() {
            self.filter_port = cli.filter_port;
        }
        if cli.filter_ip.is_some() {
            self.filter_ip = cli.filter_ip.clone();
        }
        if cli.filter_protocol.is_some() {
            self.filter_protocol = cli.filter_protocol.clone();
        }
        if cli.connection_timeout != 60 {
            self.connection_timeout = cli.connection_timeout;
        }
        if cli.resolve_dns {
            self.resolve_dns = true;
        }
        if cli.quiet {
            self.quiet = true;
        }
        if cli.data_retention.is_some() {
            self.data_retention_seconds = cli.data_retention;
        }
        if cli.sample_rate != 1 {
            self.sample_rate = cli.sample_rate;
        }
        if cli.aggregation_window != 0 {
            self.aggregation_window_seconds = cli.aggregation_window;
        }
    }
}

use clap::Parser;

/// LightShark-mini: Lightweight network traffic analyzer
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// Network interface to capture on (e.g., eth0). Auto-detects if not provided.
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Port to serve the API on
    #[arg(short, long, default_value_t = 3000)]
    pub port: u16,

    /// Database path
    #[arg(long, default_value = "traffic.db")]
    pub db_path: String,

    /// Path to YAML config file
    #[arg(short, long)]
    pub config: Option<String>,

    /// Filter: only capture traffic on this port
    #[arg(long)]
    pub filter_port: Option<u16>,

    /// Filter: only capture traffic to/from this IP
    #[arg(long)]
    pub filter_ip: Option<String>,

    /// Filter: only capture this protocol (TCP, UDP)
    #[arg(long)]
    pub filter_protocol: Option<String>,

    /// Connection timeout in seconds for stale cleanup
    #[arg(long, default_value_t = 60)]
    pub connection_timeout: u64,

    /// Enable DNS resolution for IPs
    #[arg(long)]
    pub resolve_dns: bool,

    /// Quiet mode (suppress non-error logs)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Data retention in seconds (delete packets older than this, disabled if not set)
    #[arg(long)]
    pub data_retention: Option<u64>,

    /// Sampling rate: keep 1 out of every N packets for storage (1 = keep all)
    #[arg(long, default_value_t = 1)]
    pub sample_rate: u32,

    /// Aggregation window in seconds (0 = disabled, store raw packets)
    #[arg(long, default_value_t = 0)]
    pub aggregation_window: u64,
}
