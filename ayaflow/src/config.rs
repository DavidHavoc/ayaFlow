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

    /// Enable deep L7 inspection (DNS query + TLS SNI extraction).
    #[serde(default)]
    pub deep_inspect: bool,

    /// Enable IPv6 packet capture (default: off, IPv4 only).
    #[serde(default)]
    pub enable_ipv6: bool,

    /// List of CIDRs allowed to access the API (empty = allow all).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeSettings {
    pub interface: String,
    pub port: u16,
    pub db_path: String,
    pub connection_timeout: u64,
    pub data_retention_seconds: Option<u64>,
    pub aggregation_window_seconds: u64,
    pub resolve_dns: bool,
    pub deep_inspect: bool,
    pub enable_ipv6: bool,
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
            deep_inspect: false,
            enable_ipv6: false,
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
        if cli.deep_inspect {
            self.deep_inspect = true;
        }
        if cli.enable_ipv6 {
            self.enable_ipv6 = true;
        }
        if !cli.allowed_ips.is_empty() {
            self.allowed_ips = cli.allowed_ips.clone();
        }
    }

    pub fn runtime_settings(&self, interface: String) -> RuntimeSettings {
        RuntimeSettings {
            interface,
            port: self.port,
            db_path: self.db_path.clone(),
            connection_timeout: self.connection_timeout,
            data_retention_seconds: self.data_retention_seconds,
            aggregation_window_seconds: self.aggregation_window_seconds,
            resolve_dns: self.resolve_dns,
            deep_inspect: self.deep_inspect,
            enable_ipv6: self.enable_ipv6,
            allowed_ips: self.allowed_ips.clone(),
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

    /// Enable deep packet inspection (extract DNS queries and TLS SNI).
    #[arg(long)]
    pub deep_inspect: bool,

    /// Enable IPv6 packet capture (default: IPv4 only).
    #[arg(long)]
    pub enable_ipv6: bool,

    /// IP CIDRs allowed to access the API (e.g., 10.0.0.0/8). Repeat for multiple.
    #[arg(long)]
    pub allowed_ips: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::default();

        assert!(config.interface.is_none());
        assert_eq!(config.port, 3000);
        assert_eq!(config.db_path, "traffic.db");
        assert_eq!(config.connection_timeout, 60);
        assert!(!config.quiet);
        assert_eq!(config.data_retention_seconds, None);
        assert_eq!(config.aggregation_window_seconds, 0);
        assert!(!config.resolve_dns);
        assert!(!config.deep_inspect);
        assert!(!config.enable_ipv6);
        assert!(config.allowed_ips.is_empty());
    }

    #[test]
    fn merge_cli_overrides_file_values() {
        let mut config = Config {
            interface: Some("ens5".to_string()),
            port: 8080,
            db_path: "/tmp/from-config.db".to_string(),
            connection_timeout: 120,
            quiet: false,
            data_retention_seconds: Some(600),
            aggregation_window_seconds: 30,
            resolve_dns: false,
            deep_inspect: false,
            enable_ipv6: false,
            allowed_ips: vec!["10.0.0.0/8".to_string()],
        };

        let cli = CliArgs::parse_from([
            "ayaflow",
            "--interface",
            "eth1",
            "--port",
            "9090",
            "--db-path",
            "/tmp/from-cli.db",
            "--connection-timeout",
            "15",
            "--data-retention",
            "42",
            "--aggregation-window",
            "5",
            "--resolve-dns",
            "--deep-inspect",
            "--enable-ipv6",
            "--allowed-ips",
            "127.0.0.1/32",
            "--quiet",
        ]);

        config.merge_cli(&cli);

        assert_eq!(config.interface.as_deref(), Some("eth1"));
        assert_eq!(config.port, 9090);
        assert_eq!(config.db_path, "/tmp/from-cli.db");
        assert_eq!(config.connection_timeout, 15);
        assert!(config.quiet);
        assert_eq!(config.data_retention_seconds, Some(42));
        assert_eq!(config.aggregation_window_seconds, 5);
        assert!(config.resolve_dns);
        assert!(config.deep_inspect);
        assert!(config.enable_ipv6);
        assert_eq!(config.allowed_ips, vec!["127.0.0.1/32".to_string()]);
    }
}
