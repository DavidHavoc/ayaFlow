# How to Use ayaFlow on Kubernetes

ayaFlow is designed to run as a DaemonSet: one pod per node, watching node-level traffic without application sidecars.

## Prerequisites

| Requirement | Details |
|---|---|
| Kubernetes | v1.24+ |
| Node OS | Linux kernel >= 5.8 with BTF support on every node |
| Image | `ghcr.io/davidhavoc/ayaflow:latest` or your own registry mirror |
| Privileges | `BPF`, `NET_ADMIN`, and `PERFMON` capabilities available in the container runtime |

Before rollout, confirm at least one node satisfies:

```bash
kubectl debug node/<node-name> -it --image=ubuntu
ls /sys/kernel/btf/vmlinux
```

## Deploy

```bash
kubectl apply -f k8s/daemonset.yaml
```

The reference manifest now:

- uses `ghcr.io/davidhavoc/ayaflow:latest`
- persists SQLite data under `/data/traffic.db`
- omits `--interface` so ayaFlow auto-detects the node's default route interface
- includes readiness and liveness probes

## Interface Strategy

By default, ayaFlow reads `/proc/net/route` and selects the interface for the default route. That is the recommended Kubernetes path because node interface names vary across environments such as:

- `eth0`
- `ens5`
- `ens4`
- cloud and CNI-specific names

Only set `--interface` explicitly when your cluster needs a non-default device.

## Verify the Rollout

```bash
kubectl get daemonset ayaflow
kubectl get pods -l app=ayaflow -o wide
kubectl logs -l app=ayaflow --tail=50
kubectl port-forward daemonset/ayaflow 3000:3000
```

Then:

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/stats
curl http://localhost:3000/metrics
```

## Configuration

CLI flags can be added directly in the DaemonSet `args` list. Example:

```yaml
args:
  - "--db-path"
  - "/data/traffic.db"
  - "--data-retention"
  - "86400"
  - "--deep-inspect"
```

For larger configs, mount a YAML file and pass `-c /etc/ayaflow/config.yaml`.

## Operational Notes

- SQLite persistence is host-backed by default through `/var/lib/ayaflow`.
- `/api/health` and `/api/stats` now expose the active runtime config, which helps confirm whether IPv6, deep inspection, DNS resolution, retention, and the selected interface are actually enabled.
- `/api/history` supports filters and pagination, which is useful for targeted debugging through a port-forwarded pod.

Example:

```bash
curl "http://localhost:3000/api/history?limit=25&protocol=TCP&dst_port=443&row_type=raw"
```

## Troubleshooting

**Pod starts but eBPF attach fails**

- Confirm node kernel BTF support
- Confirm container runtime allows `BPF`, `NET_ADMIN`, and `PERFMON`
- Check pod logs for qdisc attach or program load failures

**No traffic appears**

- Verify the node's default route points at the interface you expect
- If your cluster requires a non-default interface, set `--interface` explicitly
- Generate traffic on the node, then re-check `/api/stats`

**Metrics are not scraped**

- Confirm your Prometheus setup honors pod scrape annotations
- Verify `/metrics` is reachable through the pod IP or a port-forward
