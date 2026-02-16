# Why ayaFlow?

ayaFlow is a lightweight, eBPF-based network traffic analyzer built in Rust.
It is designed for teams that need per-node packet visibility without the
overhead of a full-blown service mesh or CNI replacement.

## At a Glance

| | ayaFlow | Cilium Hubble | Pixie | Retina | tcpdump |
|---|---|---|---|---|---|
| Memory | **~33 MB** | 300-500 MB | 500 MB - 1 GB | 150-200 MB | Varies |
| eBPF program size | **576 B** (JIT) | 10-50 KB | Multi-KB | Multi-KB | N/A (kernel module) |
| Language | Rust (no GC) | Go | C++/Go | Go | C |
| Kubernetes-native | DaemonSet | Full CNI | Operator | DaemonSet | Manual |
| Prometheus metrics | Built-in | Built-in | Via adapter | Built-in | No |
| L7 protocol parsing | No | Yes | Yes | Partial | Yes (with dissectors) |
| Network policy | No | Yes | No | No | No |
| Requires CNI swap | **No** | Yes | No | No | No |

## When to use ayaFlow

- **You need lightweight packet-level visibility** on bare-metal or VM nodes
  without replacing your CNI or installing a service mesh.
- **Resource-constrained environments** where 33 MB RSS matters (edge nodes,
  IoT gateways, small VMs).
- **Simple Prometheus integration** -- scrape `/metrics` and build Grafana
  dashboards. No extra adapters or operators required.
- **Kubernetes clusters** -- deploy as a DaemonSet and every node reports its
  own traffic. Each pod exposes the same REST API and Prometheus endpoint, so
  you get cluster-wide visibility by scraping all nodes.
- **Quick audits** -- spin it up, look at `/api/live` or `/api/history`, and
  see exactly what traffic is hitting a node right now.

## When to use something else

- **You need L7 protocol parsing** (HTTP path, gRPC method, DNS query).
  Use Hubble or Pixie.
- **You need network policy enforcement** (allow/deny traffic between pods).
  Use Cilium.
- **You need distributed request tracing** across services.
  Use Pixie or OpenTelemetry.
- **You need egress monitoring** in addition to ingress.
  ayaFlow currently attaches to ingress only (egress support is planned).

## Kubernetes Deployment

ayaFlow runs as a sidecarless DaemonSet -- one pod per node, no injection:

```
Node 1                  Node 2                  Node 3
+-----------------+     +-----------------+     +-----------------+
| ayaFlow pod     |     | ayaFlow pod     |     | ayaFlow pod     |
|  TC hook (eBPF) |     |  TC hook (eBPF) |     |  TC hook (eBPF) |
|  :3000/metrics  |     |  :3000/metrics  |     |  :3000/metrics  |
+-----------------+     +-----------------+     +-----------------+
         \                      |                      /
          \_____________________|_____________________/
                                |
                     Prometheus scrapes all nodes
                                |
                          Grafana dashboard
```

```bash
kubectl apply -f k8s/daemonset.yaml
```

Each ayaFlow pod monitors the traffic on its own node. Prometheus discovers
all pods via the scrape annotations in the DaemonSet spec and aggregates the
metrics cluster-wide.

## Measured Performance

Tested on Ubuntu 24.04 (2 vCPU, 2 GB RAM):

| Metric | Value |
|--------|-------|
| Userspace RSS (steady-state) | ~33 MB |
| eBPF program (JIT-compiled) | 576 B |
| Ring buffer allocation | 256 KB |
| Memory growth over time | None observed |
| GC pauses | None (Rust, no garbage collector) |

The eBPF classifier verified via `bpftool`:

```
$ sudo bpftool prog show name ayaflow
430: sched_cls  name ayaflow  tag 0dabf78b3d068075  gpl
     loaded_at 2026-02-16T16:38:12+0100  uid 0
     xlated 784B  jited 576B  memlock 4096B  map_ids 76
```

## Summary

ayaFlow is not a replacement for Cilium or Pixie. It fills a different niche:
**minimal resource cost, zero-config network visibility, flat Prometheus
integration, no CNI dependency.** If all you need is to know what packets are
hitting your nodes and expose that as metrics, ayaFlow does it in 33 MB of RAM
and 576 bytes of kernel code.
