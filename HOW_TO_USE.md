# How to Use ayaFlow

This guide covers building, configuring, deploying, and using **ayaFlow**, the high-performance eBPF network traffic analyzer.

## Prerequisites

- **Host OS**: Linux kernel >= 5.8 with BTF support enabled (`CONFIG_DEBUG_INFO_BTF=y`).
- **Rust Toolchain**: Stable and Nightly (for eBPF compilation).
- **Dependencies**: `bpf-linker` must be installed.
  ```bash
  cargo +nightly install bpf-linker
  ```
- **Capabilities**: Running the agent requires `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON` (or simply root/privileged mode).

## Building from Source

The project uses a Cargo Workspace managed by `xtask`.

1.  **Build Everything (eBPF + Userspace)**:
    ```bash
    cargo xtask build
    ```
    This command compiles the kernel-side eBPF program (`ayaflow-ebpf`) using the nightly toolchain and embeds it into the userspace binary (`ayaflow`).

2.  **Run Locally (requires sudo)**:
    ```bash
    sudo ./target/debug/ayaflow --interface eth0
    ```
    If no interface is specified, check logs to see if it auto-detected one or failed.

## Configuration Reference

You can configure ayaFlow via CLI arguments or a YAML config file. CLI arguments take precedence.

| Argument | YAML Key | Env Var | Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| `-i, --interface` | `interface` | `AYAFLOW_INTERFACE` | Network interface to attach the TC classifier to. | `eth0` (or first available) |
| `-p, --port` | `port` | `AYAFLOW_PORT` | HTTP port for the API server. | `3000` |
| `--db-path` | `db_path` | `AYAFLOW_DB_PATH` | Path to SQLite database file. | `traffic.db` |
| `--connection-timeout` | `connection_timeout` | `AYAFLOW_CONNECTION_TIMEOUT` | Seconds of inactivity before a connection is marked closed. | `60` |
| `--data-retention` | `data_retention_seconds` | `AYAFLOW_DATA_RETENTION` | Delete packets older than N seconds (optional). | Disabled |
| `--aggregation-window` | `aggregation_window_seconds` | `AYAFLOW_AGGREGATION_WINDOW` | Aggregate packets into N-second windows to save space. | `0` (Disabled, raw storage) |
| `--allowed-ips` | `allowed_ips` | `AYAFLOW_ALLOWED_IPS` | List of CIDRs allowed to access the API (e.g. `10.0.0.0/8`). | All allowed |
| `-q, --quiet` | `quiet` | `AYAFLOW_QUIET` | Suppress non-error logs. | `false` |
| `-c, --config` | N/A | `AYAFLOW_CONFIG` | Path to YAML config file. | None |

### Example Config (`config.yaml`)

```yaml
interface: eth0
port: 8080
db_path: /data/traffic.db
connection_timeout: 300
data_retention_seconds: 86400  # 1 day
aggregation_window_seconds: 60 # 1 minute buckets
allowed_ips:
  - "127.0.0.1/32"
  - "192.168.1.0/24"
```

## Deployment

### Kubernetes (DaemonSet)

ayaFlow is designed to run as a **DaemonSet** on each node to provide cluster-wide visibility without sidecars.

Key Manifest Requirements:
- `hostNetwork: true`: To see the actual node traffic.
- `capabilities`:
  - `BPF`: Create maps and load programs.
  - `NET_ADMIN`: Attach TC (Traffic Control) programs.
  - `PERFMON`: Access perf ring buffers.
- `volumeMounts`:
  - `/sys/fs/bpf`: For BPF object pinning (optional but recommended).

See [k8s/daemonset.yaml](k8s/daemonset.yaml) for the reference configuration.

### Docker

Build the image using the provided multi-stage Dockerfile:

```bash
docker build -t ayaflow:latest .
```

Run with required privileges:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ayaflow:latest --interface eth0
```

> **Note**: `--privileged` is the easiest way to granted necessary capabilities. For production, granular capabilities (`--cap-add=BPF --cap-add=NET_ADMIN --cap-add=PERFMON`) are safer but require a kernel/Docker version that supports them fully.

## Observability & API

The API server runs on port `3000` by default.

### Prometheus Metrics [`GET /metrics`]
Standard Prometheus endpoint scraping:
- `ayaflow_packets_total`: Counter of total observed packets.
- `ayaflow_bytes_total`: Counter of total observed bytes.
- `ayaflow_active_connections`: Gauge of currently tracked connections in the state map.

### Live Dashboard Data [`GET /api/live`]
Returns JSON with the top 50 active connections sorted by packet count.
```json
{
  "connections": [
    {
      "connection": {
        "src": "192.168.1.5:443",
        "dst": "10.0.0.2:34560",
        "proto": "TCP"
      },
      "stats": {
        "packets_count": 150,
        "bytes_count": 120450,
        "first_seen": 1678886000,
        "last_seen": 1678886005
      }
    }
  ],
  "total_packets": 12050,
  "total_bytes": 8504320
}
```

### WebSocket Stream [`WS /api/stream`]
Connect to this endpoint to receive the same live stats pushed every second.

### Historical Query [`GET /api/history?limit=100`]
Retrieve raw or aggregated packet events from the SQLite database.

## Architecture Notes for Operators

- **Traffic Control (TC) Hook**: ayaFlow attaches to the **ingress** qdisc of the specified interface. It does **not** attach to egress by default to avoid double-counting packets on certain virtual interfaces, but this behavior is defined in `ayaflow-ebpf/src/main.rs`.
- **Performance**: The eBPF program is minimal and uses per-CPU arrays and RingBuffers. Userspace is async and offloads disk I/O to a separate blocking thread pool (via `rusqlite`).
- **IPv6**: Currently, only IPv4 traffic is fully parsed and reported. IPv6 packets may be ignored or reported with empty addresses.

## Troubleshooting

**Error: `failed to load bpf program`**
- Ensure your kernel supports BTF (`ls /sys/kernel/btf/vmlinux`).
- Ensure you have root privileges (`sudo`).

**Error: `operation not permitted`**
- Check capabilities. In containers, you likely need `--privileged` or explicit `--cap-add`.
- Check if another eBPF program is attached to the same interface with `tc qdisc show dev eth0`.

**No Packets Visible?**
- Verify the correct interface is selected (`--interface`).
- Check if traffic is actually hitting that interface (use `tcpdump` to verify).
- Check `ayaflow_packets_total` metric to see if the kernel probe is seeing *anything*.

## Grafana Dashboard

A recommended Grafana dashboard is available in `grafana/dashboard.json`.

**To Import:**
1.  Open Grafana.
2.  Go to **Dashboards** -> **New** -> **Import**.
3.  Upload the JSON file or paste its contents.
4.  Select your Prometheus data source.

**Panels included:**
- Active Connections (Gauge)
- Packets/sec (Live Rate)
- Throughput/sec (Live Rate)
- Historical trends for packet rate and throughput.

