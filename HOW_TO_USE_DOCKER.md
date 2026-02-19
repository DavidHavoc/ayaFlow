# How to Use ayaFlow -- Docker

Step-by-step guide for building and running ayaFlow as a Docker container.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Docker** | Docker Engine 20.10+ (or Docker Desktop) |
| **Host kernel** | Linux >= 5.8 with BTF support (`CONFIG_DEBUG_INFO_BTF=y`) |

> eBPF programs execute inside the host kernel, not inside the container's userspace. The host must satisfy the same kernel requirements as a local installation.

---

## 1 -- Build the Image

The repository includes a multi-stage `Dockerfile` that handles the entire build pipeline:

```bash
docker build -t ayaflow:latest .
```

**What the build does:**

| Stage | Purpose |
|---|---|
| `ebpf-builder` | Installs the nightly Rust toolchain and `bpf-linker`, compiles the eBPF kernel program targeting `bpfel-unknown-none`. |
| `builder` | Copies the compiled eBPF object from the previous stage and builds the userspace agent in release mode. |
| `runtime` | Produces a minimal `debian:bookworm-slim` image containing only the final binary (`/usr/local/bin/ayaflow`). |

---

## 2 -- Run (Standalone)

ayaFlow needs host-level network access and eBPF capabilities to function.

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ayaflow:latest --interface eth0
```

Replace `eth0` with the host interface you want to monitor.

### Flag Breakdown

| Flag | Why |
|---|---|
| `--net=host` | Shares the host network namespace so ayaFlow sees real node traffic. |
| `--privileged` | Grants all capabilities needed for eBPF (`BPF`, `NET_ADMIN`, `PERFMON`). |
| `-v /sys/fs/bpf:/sys/fs/bpf` | Mounts the BPF filesystem for optional object pinning. |

### Using Granular Capabilities (Production)

For tighter security, replace `--privileged` with explicit capability grants:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=PERFMON \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ayaflow:latest --interface eth0
```

This requires a Docker version and host kernel that fully support these individual capabilities.

---

## 3 -- Run with Docker Compose (Sidecar Pattern)

The repository ships a `docker-compose.example.yml` demonstrating how to attach ayaFlow as a **sidecar** to an existing service.

```yaml
version: '3.8'

services:
  my-web-app:
    image: nginx:alpine
    container_name: my-web-app
    ports:
      - "8080:80"

  ayaflow:
    build: .
    network_mode: "service:my-web-app"
    depends_on:
      - my-web-app
```

Key detail: `network_mode: "service:my-web-app"` merges the two containers into the same network namespace, so ayaFlow sees all traffic hitting `my-web-app` on its interfaces.

Start both:
```bash
docker compose -f docker-compose.example.yml up -d
```

---

## 4 -- Verify

```bash
# Health check
curl http://localhost:3000/api/health

# Prometheus metrics
curl http://localhost:3000/metrics

# Live connections
curl http://localhost:3000/api/live
```

View container logs:
```bash
docker logs -f ayaflow
```

---

## Configuration

Pass any CLI flag after the image name. For example, to change the port and enable quiet mode:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ayaflow:latest \
    --interface eth0 \
    --port 8080 \
    --quiet
```

You can also use environment variables:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e AYAFLOW_INTERFACE=eth0 \
  -e AYAFLOW_PORT=8080 \
  -e AYAFLOW_QUIET=true \
  ayaflow:latest
```

Or mount a YAML config file:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/config.yaml:/etc/ayaflow/config.yaml:ro \
  ayaflow:latest -c /etc/ayaflow/config.yaml
```

See [HOW_TO_USE_LOCAL.md](HOW_TO_USE_LOCAL.md) for the full configuration reference table.

---

## Persistent Storage

To persist the SQLite database across container restarts, mount a volume for the database path:

```bash
docker run -d \
  --name ayaflow \
  --net=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v ayaflow-data:/data \
  ayaflow:latest --interface eth0 --db-path /data/traffic.db
```

---

## Troubleshooting

**`operation not permitted` or `failed to load bpf program`**
- Confirm `--privileged` or the explicit `--cap-add` flags are set.
- Confirm the **host** kernel has BTF support: `ls /sys/kernel/btf/vmlinux`

**No packets visible**
- Confirm `--net=host` is set. Without it, the container has its own isolated network namespace and will not see host traffic.
- Verify the correct interface name. Inside `--net=host`, interface names match the host. Run `ip link show` on the host to check.

**Port conflict**
- If another service uses port 3000 on the host, pass `--port <other>` to change ayaFlow's API port.
