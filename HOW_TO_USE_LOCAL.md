# How to Use ayaFlow -- Local

Step-by-step guide for building and running ayaFlow directly on a Linux host.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Linux kernel >= 5.8 with BTF support (`CONFIG_DEBUG_INFO_BTF=y`) |
| **Rust** | Stable **and** Nightly toolchains installed |
| **bpf-linker** | `cargo +nightly install bpf-linker` |
| **Capabilities** | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (or root) |

Verify BTF support before anything else:
```bash
ls /sys/kernel/btf/vmlinux
```
If the file does not exist, your kernel was not compiled with BTF. You will need a different kernel or a distribution that ships BTF-enabled kernels (Ubuntu 22.04+, Fedora 36+, etc.).

---

## 1 -- Install Toolchains

```bash
# Install Rust via rustup (if not already present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the nightly toolchain
rustup install nightly

# Install bpf-linker on nightly
cargo +nightly install bpf-linker
```

---

## 2 -- Build

The project uses a Cargo Workspace orchestrated by `xtask`.

```bash
# Clone the repo
git clone https://github.com/DavidHavoc/ayaFlow.git
cd ayaFlow

# Build everything (eBPF kernel program + userspace agent)
cargo xtask build
```

This single command:
1. Compiles the eBPF program (`ayaflow-ebpf`) with the nightly toolchain targeting `bpfel-unknown-none`.
2. Embeds the resulting object into the userspace binary (`ayaflow`).

---

## 3 -- Run

ayaFlow must run with elevated privileges to load eBPF programs and attach to the network interface.

```bash
sudo ./target/debug/ayaflow --interface eth0
```

Replace `eth0` with the interface you want to monitor. To list available interfaces:
```bash
ip link show
```

---

## 4 -- Verify

Once running, confirm the agent is healthy:
```bash
# Health check
curl http://localhost:3000/api/health

# Prometheus metrics
curl http://localhost:3000/metrics

# Live connections (top 50 by packet count)
curl http://localhost:3000/api/live
```

You can also verify the eBPF program is loaded in the kernel:
```bash
sudo bpftool prog show name ayaflow
```

---

## Configuration

ayaFlow accepts configuration through **CLI flags**, **environment variables**, or a **YAML config file**. CLI flags take the highest precedence.

| CLI Flag | Env Var | Description | Default |
|---|---|---|---|
| `-i, --interface` | `AYAFLOW_INTERFACE` | Network interface to attach to | `eth0` |
| `-p, --port` | `AYAFLOW_PORT` | HTTP API port | `3000` |
| `--db-path` | `AYAFLOW_DB_PATH` | SQLite database file path | `traffic.db` |
| `--connection-timeout` | `AYAFLOW_CONNECTION_TIMEOUT` | Seconds before a connection is marked stale | `60` |
| `--data-retention` | `AYAFLOW_DATA_RETENTION` | Auto-delete packets older than N seconds | Disabled |
| `--aggregation-window` | `AYAFLOW_AGGREGATION_WINDOW` | Aggregate events into N-second windows | `0` (off) |
| `--allowed-ips` | `AYAFLOW_ALLOWED_IPS` | CIDRs allowed to hit the API | All |
| `-q, --quiet` | `AYAFLOW_QUIET` | Suppress non-error logs | `false` |
| `-c, --config` | `AYAFLOW_CONFIG` | Path to YAML config file | None |

### Example YAML config

```yaml
interface: eth0
port: 8080
db_path: /data/traffic.db
connection_timeout: 300
data_retention_seconds: 86400   # 1 day
aggregation_window_seconds: 60  # 1-minute buckets
allowed_ips:
  - "127.0.0.1/32"
  - "192.168.1.0/24"
```

Run with the config file:
```bash
sudo ./target/debug/ayaflow -c config.yaml
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check with basic counters |
| `/api/stats` | GET | Uptime, throughput, connection counts |
| `/api/live` | GET | Top 50 active connections by packet count |
| `/api/history?limit=N` | GET | Recent packets from SQLite (max 1000) |
| `/api/stream` | WS | WebSocket push every 1 second |
| `/metrics` | GET | Prometheus text-format metrics |

---

## Grafana Dashboard

A pre-built dashboard is provided in `grafana/dashboard.json`.

1. Open Grafana.
2. Navigate to **Dashboards** > **New** > **Import**.
3. Upload the JSON file or paste its contents.
4. Select your Prometheus data source.

Panels included: Active Connections (gauge), Packets/sec, Throughput/sec, and historical trends.

---

## Troubleshooting

**`failed to load bpf program`**
- Confirm BTF support: `ls /sys/kernel/btf/vmlinux`
- Confirm you are running as root or with `sudo`.

**`operation not permitted`**
- Check capabilities. You need `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`.
- Check if another eBPF program is already attached: `tc qdisc show dev eth0`

**No packets visible**
- Verify you selected the correct interface (`--interface`).
- Confirm traffic is actually hitting that interface with `tcpdump -i eth0`.
- Check the `ayaflow_packets_total` metric to see if the kernel probe is seeing anything at all.
