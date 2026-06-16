# How to Use ayaFlow Locally

This guide covers the two supported contributor paths:

- Host-safe development on macOS or Linux
- Full eBPF build and runtime on Linux

## 1. Host-Safe Workflow

Use this on macOS or any machine where you want to work on the API, storage, config, and parser logic without loading eBPF programs.

```bash
git clone https://github.com/DavidHavoc/ayaFlow.git
cd ayaFlow

cargo xtask check-host
cargo test -p ayaflow-common
cargo test -p ayaflow
cargo xtask build-user
```

`cargo test -p ayaflow` is expected to work on non-Linux hosts now because the eBPF loader is compiled only on Linux.

## 2. Full Linux Workflow

### Requirements

| Requirement | Details |
|---|---|
| OS | Linux kernel >= 5.8 with BTF support |
| Toolchains | Stable Rust plus nightly |
| eBPF linker | `cargo +nightly install bpf-linker` |
| Privileges | root, or `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON` |

Verify BTF support:

```bash
ls /sys/kernel/btf/vmlinux
```

### Build

```bash
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly install bpf-linker

cargo xtask build
```

### Run

```bash
sudo ./target/debug/ayaflow --db-path /tmp/traffic.db
```

If you omit `--interface`, ayaFlow auto-detects the default route interface from `/proc/net/route`. Override it explicitly only when you want a different device:

```bash
sudo ./target/debug/ayaflow --interface ens5 --deep-inspect --db-path /tmp/traffic.db
```

### Verify

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/stats
curl "http://localhost:3000/api/history?limit=10&row_type=raw"
curl http://localhost:3000/metrics
```

## Configuration

ayaFlow supports CLI flags and YAML config files. CLI flags override file values.

### Example config

```yaml
interface: ens5
port: 3000
db_path: /data/traffic.db
connection_timeout: 60
data_retention_seconds: 86400
aggregation_window_seconds: 0
resolve_dns: true
deep_inspect: true
enable_ipv6: true
allowed_ips:
  - "127.0.0.1/32"
  - "10.0.0.0/8"
```

Run with a config file:

```bash
sudo ./target/debug/ayaflow -c config.yaml
```

## History API

The history endpoint now returns pagination metadata and supports filtering:

```bash
curl "http://localhost:3000/api/history?limit=20&offset=0&protocol=TCP&dst_port=443&row_type=raw"
```

Available filters:

- `limit`, `offset`
- `start_time`, `end_time`
- `protocol`
- `ip`, `src_ip`, `dst_ip`
- `port`, `src_port`, `dst_port`
- `direction`
- `domain`
- `row_type=raw|aggregated`

Aggregated rows include `packet_count` and `row_type=aggregated` so consumers can distinguish them from raw packet rows.

## Troubleshooting

**`cargo xtask build` fails on macOS**

That command is Linux-only by design. Use `cargo xtask check-host` and the host-safe workflow above, then switch to a Linux VM or container host for the eBPF build.

**`failed to load eBPF program`**

- Confirm kernel BTF support: `ls /sys/kernel/btf/vmlinux`
- Confirm Linux capabilities or run with `sudo`
- Confirm the eBPF artifact exists by re-running `cargo xtask build`

**No packets visible**

- Let ayaFlow auto-detect the interface first, or inspect the default route with `ip route`
- Override `--interface` only when you know the correct device name
- Confirm traffic is present with `curl`, `ping`, or `nslookup`, then re-check `/api/stats`
