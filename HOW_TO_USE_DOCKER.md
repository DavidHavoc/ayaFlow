# How to Use ayaFlow with Docker

ayaFlow can run in a container, but the eBPF programs still execute in the host kernel. The host therefore needs the same Linux prerequisites as a local install.

## Prerequisites

| Requirement | Details |
|---|---|
| Docker | Engine 20.10+ |
| Host OS | Linux kernel >= 5.8 with BTF support |
| Privileges | `--privileged` or explicit `BPF`, `NET_ADMIN`, and `PERFMON` capabilities |

## Pull or Build

```bash
docker pull ghcr.io/davidhavoc/ayaflow:latest
```

Or:

```bash
docker build -t ayaflow:latest .
```

## Run

The recommended container workflow is to let ayaFlow auto-detect the default route interface and persist data explicitly:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v ayaflow-data:/data \
  ghcr.io/davidhavoc/ayaflow:latest \
  --db-path /data/traffic.db
```

If you want more explicit security controls, replace `--privileged` with:

```bash
--cap-add=BPF --cap-add=NET_ADMIN --cap-add=PERFMON
```

## Override the Interface

Only override `--interface` when the default route is not the device you want:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/davidhavoc/ayaflow:latest \
  --interface ens5 \
  --db-path /data/traffic.db
```

## Verify

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/stats
curl http://localhost:3000/metrics
```

## Compose Example

The included `docker-compose.example.yml` shows a sidecar-style namespace-sharing setup. Start it with:

```bash
docker compose -f docker-compose.example.yml up -d
```

## Notes

- ayaFlow currently supports CLI flags and YAML config files. It does not read `AYAFLOW_*` environment variables.
- Persist SQLite data with `--db-path` mounted into a durable volume.
- The history API supports filtered queries and pagination metadata, which is handy when debugging through a containerized deployment.
