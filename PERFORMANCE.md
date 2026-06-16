# ayaFlow Footprint and Performance

This document is the home for ayaFlow footprint notes, benchmark snapshots, and low-level runtime measurements.

## Measurement Status

The numbers below come from earlier Linux test runs and older validation notes, not from the recent macOS host-safe workflow. They are useful historical reference points, but they should be re-measured on a current Linux environment before being treated as release-grade benchmarks.

## Performance & Footprint

Measured on a minimal VM (Ubuntu 24.04, 2 vCPU, 2 GB RAM):

| Metric | Value |
|--------|-------|
| Userspace RSS (steady-state) | ~33 MB |
| eBPF program (xlated) | 784 B |
| eBPF program (JIT-compiled) | 576 B |
| eBPF program memlock | 4 KB |
| EVENTS ring buffer | 256 KB |
| PAYLOAD_EVENTS ring buffer | 256 KB (only used when `--deep-inspect` is on) |
| Ring buffer memlock | ~270 KB (540 KB with deep inspect) |
| Memory growth over time | None observed (stable RSS) |

The eBPF classifier was verified loaded via `bpftool`:

```bash
$ sudo bpftool prog show name ayaflow
430: sched_cls  name ayaflow  tag 0dabf78b3d068075  gpl
     loaded_at 2026-02-16T16:38:12+0100  uid 0
     xlated 784B  jited 576B  memlock 4096B  map_ids 76
```

## Notes on Interpretation

- The userspace RSS number reflects the full runtime with API server, in-memory state, and SQLite writer active.
- The second ring buffer is only part of the footprint when `--deep-inspect` is enabled.
- The JIT and translated byte counts are kernel-reported eBPF program sizes, not userspace binary sizes.
- These values describe one measured setup, not a hard upper bound across all interfaces, kernels, traffic mixes, or deployment modes.

## Re-Measurement Checklist

When refreshing these numbers on Linux, collect at least:

- steady-state userspace RSS
- eBPF translated and JIT sizes from `bpftool`
- ring buffer map sizes and memlock usage
- raw mode versus `--deep-inspect` mode
- any meaningful difference between raw history and aggregated history

Useful commands from prior test notes:

```bash
ps -p $(pgrep ayaflow) -o pid,rss,vsz,%mem,cmd
sudo bpftool prog show name ayaflow
sudo bpftool map show name EVENTS
sudo bpftool map show name PAYLOAD_EVENTS
```

## Related Docs

- [ARCHITECTURE.md](/Users/David/Documents/GitHub/ayaFlow/ARCHITECTURE.md)
- [WHY_AYAFLOW.md](/Users/David/Documents/GitHub/ayaFlow/WHY_AYAFLOW.md)
- [Testing_CONF.md](/Users/David/Documents/GitHub/ayaFlow/Testing_CONF.md)
