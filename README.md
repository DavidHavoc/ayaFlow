# ayaFlow

ayaFlow is a Rust + eBPF network traffic analyzer built with [Aya](https://aya-rs.dev/). It runs one agent per Linux node, attaches a TC classifier at ingress and egress, and exposes live traffic data, historical SQLite-backed history, and Prometheus metrics.

## What It Does

- Captures IPv4, IPv6, TCP, and UDP traffic with an eBPF TC classifier.
- Maintains live connection stats in memory and historical records in SQLite.
- Optionally enriches traffic with reverse DNS, DNS query domains, and TLS SNI.
- Exposes a REST API, WebSocket stream, and Prometheus `/metrics` endpoint.
- Ships with Docker, Kubernetes, Prometheus, and Grafana examples.

## Supported Development Flow

ayaFlow's packet-capture runtime is Linux-only. Contributor workflows are split on purpose:

- Host-safe checks on macOS or Linux:
  - `cargo test -p ayaflow-common`
  - `cargo test -p ayaflow`
  - `cargo xtask build-user`
  - `cargo xtask check-host`
- Linux-only build and runtime:
  - `cargo xtask build-ebpf`
  - `cargo xtask build`
  - `cargo xtask run -- --deep-inspect`

If you are on macOS, use Docker or a Linux VM for the full eBPF workflow. See [HOW_TO_USE_LOCAL.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_LOCAL.md) for both paths.

## Quick Start

### 1. Check host support

```bash
cargo xtask check-host
```

### 2. Build on Linux

```bash
cargo xtask build
```

### 3. Run on Linux

```bash
sudo ./target/debug/ayaflow --db-path /tmp/traffic.db
```

If `--interface` is omitted, ayaFlow auto-detects the default route interface from `/proc/net/route` and falls back to `eth0` only if detection fails.

### 4. Verify

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/stats
curl "http://localhost:3000/api/history?limit=5&row_type=raw"
curl http://localhost:3000/metrics
```

## CLI Options

| Flag | Description | Default |
|---|---|---|
| `-i, --interface` | Interface to monitor. Omit to auto-detect the default route interface on Linux. | auto-detect, fallback `eth0` |
| `-p, --port` | API server port | `3000` |
| `--db-path` | SQLite database path | `traffic.db` |
| `--connection-timeout` | Stale connection cleanup in seconds | `60` |
| `--data-retention` | Auto-delete history older than N seconds | disabled |
| `--aggregation-window` | Store aggregated history windows instead of raw packet rows | `0` (raw mode) |
| `--allowed-ips` | CIDRs allowed to access the API | unrestricted |
| `-c, --config` | YAML config file path | none |
| `-q, --quiet` | Suppress non-error logs | `false` |
| `--deep-inspect` | Enable DNS query + TLS SNI extraction | `false` |
| `--enable-ipv6` | Enable IPv6 packet capture | `false` |
| `--resolve-dns` | Enable reverse DNS lookups | `false` |

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health status, packet counters, and active runtime configuration |
| `/api/stats` | GET | Uptime, throughput, counts, and active runtime configuration |
| `/api/live` | GET | Top 50 active connections by packet count |
| `/api/history` | GET | Filterable historical traffic with pagination metadata |
| `/api/stream` | WS | Live stats every second |
| `/metrics` | GET | Prometheus text format |

`/api/history` supports:

- `limit`, `offset`
- `start_time`, `end_time`
- `protocol`
- `ip`, `src_ip`, `dst_ip`
- `port`, `src_port`, `dst_port`
- `direction`
- `domain`
- `row_type=raw|aggregated`

Example:

```bash
curl "http://localhost:3000/api/history?limit=20&protocol=TCP&dst_port=443&row_type=raw"
```

## Project Structure

```text
ayaflow/           Userspace runtime, API, storage, and host-safe tests
ayaflow-common/    Shared packet/event types used by userspace and eBPF
ayaflow-ebpf/      TC classifier and payload capture program
xtask/             Build and workflow helpers
k8s/               Kubernetes manifests
monitoring/        Prometheus and Grafana assets
```

The duplicate root-level `src/` tree is legacy and not part of the supported build path. Use the `ayaflow/` crate and `cargo xtask` commands above.

## Deployment Guides

- Local Linux and macOS+VM workflows: [HOW_TO_USE_LOCAL.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_LOCAL.md)
- Docker: [HOW_TO_USE_DOCKER.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_DOCKER.md)
- Kubernetes: [HOW_TO_USE_K8S.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_K8S.md)

## Technical Docs

- Architecture: [ARCHITECTURE.md](/Users/David/Documents/GitHub/ayaFlow/ARCHITECTURE.md)
- Footprint and performance notes: [PERFORMANCE.md](/Users/David/Documents/GitHub/ayaFlow/PERFORMANCE.md)

## Tested Here

The host-safe workflow now passes on this macOS development machine with:

- `cargo test -p ayaflow-common`
- `cargo test -p ayaflow`
- `cargo xtask check-host`

Linux-only runtime validation still needs to happen on a Linux host or CI runner with the eBPF toolchain installed.
