# ayaFlow

A high-performance, eBPF-based network traffic analyzer written in Rust. Designed to run as a sidecarless DaemonSet in Kubernetes, providing kernel-native visibility into node-wide network traffic with minimal overhead.

Built on the [Aya](https://aya-rs.dev/) eBPF framework.

## Architecture

```
Kernel:  NIC --> TC Hook (eBPF) --> RingBuf
                                      |
Userspace:              Tokio Event Loop
                       /       |       \
                DashMap    SQLite     Axum HTTP
              (live stats) (history)  (API + /metrics)
```

- **Kernel-side**: A TC (Traffic Control) classifier attached at ingress parses Ethernet/IPv4/TCP/UDP headers and pushes lightweight `PacketEvent` structs to a shared ring buffer.
- **Userspace**: An async Tokio agent polls the ring buffer, maintains live connection state in a DashMap, persists events to SQLite, and exposes a REST API with Prometheus metrics.

## Features

- **eBPF-native capture** -- No libpcap, no privileged sidecar. Hooks directly into the kernel's traffic control subsystem.
- **Sidecarless DaemonSet** -- One pod per node instead of one per application pod.
- **Real-time monitoring** -- Live dashboard via REST API + WebSocket streaming.
- **Persistent history** -- SQLite storage with configurable data retention and aggregation.
- **Prometheus /metrics** -- Native exporter for `ayaflow_packets_total`, `ayaflow_bytes_total`, `ayaflow_active_connections`.
- **IP allowlist** -- Restrict API/dashboard access by source CIDR.

## Prerequisites

- **Rust**: Stable + nightly toolchain
- **bpf-linker**: `cargo +nightly install bpf-linker`
- **Linux kernel**: >= 5.8 with BTF support (for eBPF)
- **Capabilities**: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`

## Quick Start

### Build

```bash
# Install bpf-linker (one-time)
cargo +nightly install bpf-linker

# Build everything (eBPF + userspace)
cargo xtask build
```

### Run

```bash
# Requires root for eBPF attachment
sudo ./target/debug/ayaflow --interface eth0
```

### Verify

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/metrics
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Network interface to attach eBPF on | `eth0` |
| `-p, --port` | API server port | `3000` |
| `--db-path` | SQLite database path | `traffic.db` |
| `--connection-timeout` | Stale connection cleanup (seconds) | `60` |
| `--data-retention` | Auto-delete packets older than (seconds) | disabled |
| `--aggregation-window` | Aggregate events per window (seconds) | `0` (off) |
| `--allowed-ips` | CIDR(s) allowed to access the API | unrestricted |
| `-c, --config` | Path to YAML config file | - |
| `-q, --quiet` | Suppress non-error logs | `false` |

## Kubernetes Deployment

Deploy as a DaemonSet (see `k8s/daemonset.yaml`):

```bash
kubectl apply -f k8s/daemonset.yaml
```

The DaemonSet uses `hostNetwork: true` and mounts `/sys/fs/bpf`. Prometheus scrape annotations are included by default.

### Resource Recommendations

```yaml
resources:
  requests:
    memory: "32Mi"
    cpu: "50m"
  limits:
    memory: "128Mi"
    cpu: "500m"
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check with basic counters |
| `/api/stats` | GET | Uptime, throughput, connection counts |
| `/api/live` | GET | Top 50 active connections by packet count |
| `/api/history?limit=N` | GET | Recent packets from SQLite (max 1000) |
| `/api/stream` | WS | WebSocket push of stats every 1s |
| `/metrics` | GET | Prometheus text-format metrics |

## Project Structure

```
ayaflow-common/    # Shared types (no_std, used by both kernel and userspace)
ayaflow-ebpf/      # eBPF kernel program (TC classifier)
ayaflow/            # Userspace agent (Aya loader + Tokio + Axum)
xtask/              # Build orchestration (cargo xtask)
k8s/                # Kubernetes DaemonSet manifest
```

## Performance & Footprint

Measured on a minimal VM (Ubuntu 24.04, 2 vCPU, 2 GB RAM):

| Metric | Value |
|--------|-------|
| Userspace RSS (steady-state) | ~33 MB |
| eBPF program (xlated) | 784 B |
| eBPF program (JIT-compiled) | 576 B |
| eBPF program memlock | 4 KB |
| EVENTS ring buffer | 256 KB |
| Ring buffer memlock | ~270 KB |
| Memory growth over time | None observed (stable RSS) |

The eBPF classifier is verified loaded via `bpftool`:

```
$ sudo bpftool prog show name ayaflow
430: sched_cls  name ayaflow  tag 0dabf78b3d068075  gpl
     loaded_at 2026-02-16T16:38:12+0100  uid 0
     xlated 784B  jited 576B  memlock 4096B  map_ids 76
```

## Tested On

- **OS**: Ubuntu 24.04 LTS (aarch64)
- **Kernel**: 6.x with BTF support
- **Hardware**: 2 vCPU, 2 GB RAM (Lima VM)
- **Rust**: nightly toolchain + `bpf-linker`

## License

This project is licensed under either of:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

The eBPF kernel components (`ayaflow-ebpf`) are licensed under GPL to ensure compatibility with the Linux kernel verifier.


