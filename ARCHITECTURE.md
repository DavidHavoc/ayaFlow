# ayaFlow Architecture

This document describes how ayaFlow is structured today and how packet data moves from the Linux kernel into the API and storage layers.

## Overview

ayaFlow is split into four main parts:

- `ayaflow-ebpf/`: the eBPF program attached to Linux TC ingress and egress hooks
- `ayaflow-common/`: shared packet and payload event types used by both kernel and userspace
- `ayaflow/`: the userspace runtime, API server, in-memory state, L7 enrichment, and SQLite storage
- `xtask/`: build helpers for the Linux eBPF pipeline and host-safe userspace workflow

At runtime, the eBPF side emits lightweight events into ring buffers, and the userspace runtime consumes them asynchronously to build live and historical traffic views.

## Data Flow

```text
                                KERNEL SPACE
          +-------------------------------------------------------+
          |                                                       |
          |   NIC                                                 |
          |    |                                                  |
          |    +-- TC Hook (Ingress + Egress)                     |
          |           |                                           |
          |       eBPF Classifier                                 |
          |           |                                           |
          |       PacketEvent --> EVENTS Ring Buffer              |
          |           |                                           |
          |       PayloadEvent --> PAYLOAD_EVENTS Ring Buffer     |
          |                         (only for deep inspection)    |
          +-------------------------------------------------------+
                                    |
                                USER SPACE
          +-------------------------------------------------------+
          |                                                       |
          |                  Tokio Runtime                        |
          |                     /      |      \                   |
          |                    /       |       \                  |
          |             TrafficState  Storage   Axum API          |
          |              (DashMap +   (SQLite)  + metrics/ws      |
          |               counters)                                |
          |                      \                                  |
          |                 DNS + TLS SNI enrichment               |
          |                                                       |
          +-------------------------------------------------------+
```

## Kernel-Side Responsibilities

The eBPF program in `ayaflow-ebpf/`:

- attaches to TC ingress and egress on the selected interface
- parses Ethernet, IPv4, IPv6, TCP, and UDP headers
- emits `PacketEvent` records for normal traffic accounting
- emits `PayloadEvent` records for DNS and TLS payload inspection when `--deep-inspect` is enabled
- reads runtime flags from the `CONFIG` map for features like deep inspection and IPv6 capture

The kernel side stays intentionally small. It does not persist data or perform expensive parsing beyond what is needed to classify traffic and forward compact metadata to userspace.

## Userspace Responsibilities

The `ayaflow/` crate owns the main runtime:

- loads and attaches the eBPF program on Linux
- polls the `EVENTS` ring buffer for L3/L4 packet metadata
- optionally polls `PAYLOAD_EVENTS` for DNS query and TLS SNI extraction
- maintains live connection state in `TrafficState`
- persists raw or aggregated rows into SQLite through `Storage`
- serves REST, WebSocket, and Prometheus endpoints through Axum

Key modules:

- [ayaflow/src/runtime_linux.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/runtime_linux.rs): Linux-only loader and runtime orchestration
- [ayaflow/src/state.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/state.rs): live counters, connection tracking, and aggregation buckets
- [ayaflow/src/storage.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/storage.rs): SQLite schema, writes, history queries, and retention cleanup
- [ayaflow/src/api.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/api.rs): REST, WebSocket, metrics, and filter handling
- [ayaflow/src/l7.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/l7.rs): DNS and TLS parsing plus domain cache logic
- [ayaflow/src/dns.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/dns.rs): reverse DNS cache for optional hostname enrichment

## Runtime Features

The runtime supports:

- live connection counters from in-memory state
- raw packet history or aggregated history windows in SQLite
- reverse DNS hostname enrichment with `--resolve-dns`
- DNS query and TLS SNI domain enrichment with `--deep-inspect`
- IPv6 capture with `--enable-ipv6`
- API source filtering with `--allowed-ips`
- Prometheus export through `/metrics`

## Supported Build Model

ayaFlow has a deliberately split workflow:

- host-safe development on macOS or Linux for API, storage, config, and parser work
- Linux-only build and runtime for eBPF loading and packet capture

That split is implemented in:

- [ayaflow/src/main.rs](/Users/David/Documents/GitHub/ayaFlow/ayaflow/src/main.rs): Linux runtime entrypoint plus non-Linux guard
- [xtask/src/main.rs](/Users/David/Documents/GitHub/ayaFlow/xtask/src/main.rs): `check-host`, `build-user`, `build-ebpf`, `build`, and `run`

## Operational Model

In Kubernetes, ayaFlow is intended to run as a DaemonSet with one pod per node. Each instance monitors the node interface selected by the runtime, usually the default route interface when `--interface` is omitted.

For deployment details, see:

- [HOW_TO_USE_K8S.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_K8S.md)
- [HOW_TO_USE_DOCKER.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_DOCKER.md)
- [HOW_TO_USE_LOCAL.md](/Users/David/Documents/GitHub/ayaFlow/HOW_TO_USE_LOCAL.md)
