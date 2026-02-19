use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Application configuration, loadable from CLI or YAML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Network interface to attach the eBPF TC classifier on.
    #[serde(default)]
    pub interface: Option<String>,

    /// API server port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// SQLite database path.
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Connection timeout in seconds (for stale connection cleanup).
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,

    /// Quiet mode (suppress non-error logs).
    #[serde(default)]
    pub quiet: bool,

    /// Data retention in seconds (None = keep forever).
    #[serde(default)]
    pub data_retention_seconds: Option<u64>,

    /// Aggregation window in seconds. 0 = disabled.
    #[serde(default)]
    pub aggregation_window_seconds: u64,

    /// Enable reverse DNS resolution for IP addresses.
    #[serde(default)]
    pub resolve_dns: bool,

    /// List of CIDRs allowed to access the API (empty = allow all).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            port: default_port(),
            db_path: default_db_path(),
            connection_timeout: default_connection_timeout(),
            quiet: false,
            data_retention_seconds: None,
            aggregation_window_seconds: 0,
            resolve_dns: false,
            allowed_ips: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Merge CLI args into config (CLI takes precedence).
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
        if cli.connection_timeout != 60 {
            self.connection_timeout = cli.connection_timeout;
        }
        if cli.quiet {
            self.quiet = true;
        }
        if cli.data_retention.is_some() {
            self.data_retention_seconds = cli.data_retention;
        }
        if cli.aggregation_window != 0 {
            self.aggregation_window_seconds = cli.aggregation_window;
        }
        if cli.resolve_dns {
            self.resolve_dns = true;
        }
        if !cli.allowed_ips.is_empty() {
            self.allowed_ips = cli.allowed_ips.clone();
        }
    }
}

use clap::Parser;

/// ayaFlow: eBPF-based network traffic analyzer
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
    /// Network interface to attach the eBPF program to (e.g., eth0).
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Port to serve the API on.
    #[arg(short, long, default_value_t = 3000)]
    pub port: u16,

    /// SQLite database path.
    #[arg(long, default_value = "traffic.db")]
    pub db_path: String,

    /// Path to YAML config file.
    #[arg(short, long)]
    pub config: Option<String>,

    /// Connection timeout in seconds for stale cleanup.
    #[arg(long, default_value_t = 60)]
    pub connection_timeout: u64,

    /// Quiet mode (suppress non-error logs).
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Data retention in seconds (delete packets older than this).
    #[arg(long)]
    pub data_retention: Option<u64>,

    /// Aggregation window in seconds (0 = disabled, store raw events).
    #[arg(long, default_value_t = 0)]
    pub aggregation_window: u64,

    /// Enable reverse DNS resolution for IP addresses.
    #[arg(long)]
    pub resolve_dns: bool,

    /// IP CIDRs allowed to access the API (e.g., 10.0.0.0/8). Repeat for multiple.
    #[arg(long)]
    pub allowed_ips: Vec<String>,
}
