# How to Use ayaFlow -- Kubernetes

Step-by-step guide for deploying ayaFlow as a DaemonSet on a Kubernetes cluster for cluster-wide network visibility.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Kubernetes** | v1.24+ cluster |
| **kubectl** | Configured and pointed at the target cluster |
| **Node kernels** | Linux >= 5.8 with BTF support (`CONFIG_DEBUG_INFO_BTF=y`) on every node |
| **Container image** | `ayaflow:latest` available in a registry the cluster can pull from |

Build and push the image first (or load it into your local cluster tool):
```bash
docker build -t ayaflow:latest .

# For a remote registry
docker tag ayaflow:latest your-registry.io/ayaflow:latest
docker push your-registry.io/ayaflow:latest

# For local clusters (kind / minikube)
kind load docker-image ayaflow:latest
# or
minikube image load ayaflow:latest
```

---

## Why a DaemonSet?

ayaFlow is designed to run **one pod per node** rather than one sidecar per application pod. A DaemonSet ensures every node in the cluster gets an instance that monitors all traffic on that node's network interface. Benefits:

- No per-pod sidecar overhead.
- Full visibility into node-level traffic regardless of which pods are scheduled.
- `hostNetwork: true` gives the pod access to the real node interfaces.

---

## 1 -- Deploy the DaemonSet

The reference manifest is located at `k8s/daemonset.yaml`:

```bash
kubectl apply -f k8s/daemonset.yaml
```

This creates a DaemonSet in the default namespace. To deploy into a specific namespace:

```bash
kubectl create namespace monitoring
kubectl apply -f k8s/daemonset.yaml -n monitoring
```

---

## 2 -- Manifest Walkthrough

The key sections of `k8s/daemonset.yaml` and why they exist:

### Host Networking

```yaml
spec:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
```

`hostNetwork: true` places the pod directly in the node's network namespace. Without it, the pod would only see its own virtual network interface. `ClusterFirstWithHostNet` ensures internal DNS still works.

### Security Capabilities

```yaml
securityContext:
  privileged: false
  capabilities:
    add:
      - BPF
      - NET_ADMIN
      - PERFMON
```

These are the minimum capabilities for eBPF operation:

| Capability | Purpose |
|---|---|
| `BPF` | Create BPF maps and load programs into the kernel |
| `NET_ADMIN` | Attach the TC (Traffic Control) classifier to a network interface |
| `PERFMON` | Access perf ring buffers for event streaming |

The container does **not** need full `privileged: true`.

### Volume Mounts

```yaml
volumeMounts:
  - name: bpffs
    mountPath: /sys/fs/bpf
  - name: data
    mountPath: /data
```

| Volume | Host Path | Purpose |
|---|---|---|
| `bpffs` | `/sys/fs/bpf` | BPF filesystem for optional object pinning |
| `data` | `/var/lib/ayaflow` | Persistent SQLite database storage on the node |

### Resource Limits

```yaml
resources:
  requests:
    memory: "32Mi"
    cpu: "50m"
  limits:
    memory: "128Mi"
    cpu: "500m"
```

These are conservative defaults. Adjust based on node traffic volume.

### Prometheus Annotations

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "3000"
  prometheus.io/path: "/metrics"
```

If your cluster has a Prometheus Operator or kube-prometheus-stack, these annotations enable automatic scraping of ayaFlow's `/metrics` endpoint on every node.

---

## 3 -- Verify the Deployment

```bash
# Check DaemonSet status
kubectl get daemonset ayaflow

# Confirm one pod per node
kubectl get pods -l app=ayaflow -o wide

# View logs from a specific pod
kubectl logs -l app=ayaflow --tail=50 

# Port-forward to test the API locally
kubectl port-forward daemonset/ayaflow 3000:3000

# Then in another terminal
curl http://localhost:3000/api/health
curl http://localhost:3000/metrics
curl http://localhost:3000/api/live
```

---

## 4 -- Configuration

Pass CLI arguments through the `args` field in the DaemonSet spec:

```yaml
args:
  - "--interface"
  - "eth0"
  - "--port"
  - "3000"
  - "--data-retention"
  - "86400"
  - "--quiet"
```

Or use environment variables:

```yaml
env:
  - name: AYAFLOW_INTERFACE
    value: "eth0"
  - name: AYAFLOW_DATA_RETENTION
    value: "86400"
  - name: RUST_LOG
    value: "info"
```

For a YAML config file, mount it via a ConfigMap:

```bash
kubectl create configmap ayaflow-config --from-file=config.yaml
```

Then reference it in the DaemonSet:

```yaml
volumeMounts:
  - name: config
    mountPath: /etc/ayaflow
    readOnly: true

volumes:
  - name: config
    configMap:
      name: ayaflow-config
```

And pass the path:

```yaml
args:
  - "-c"
  - "/etc/ayaflow/config.yaml"
```

See [HOW_TO_USE_LOCAL.md](HOW_TO_USE_LOCAL.md) for the full configuration reference table.

---

## Sidecar Pattern (Alternative)

If you prefer per-pod monitoring instead of per-node, an example sidecar deployment is provided in `k8s/example.yaml`. In this mode, ayaFlow runs as a second container in the same pod as your application. Containers in the same pod share a network namespace automatically, so no `hostNetwork` is needed.

```bash
kubectl apply -f k8s/example.yaml
```

Use the DaemonSet approach for cluster-wide visibility. Use the sidecar approach when you only need to monitor a specific workload.

---

## Prometheus and Grafana Setup

The DaemonSet already includes Prometheus scrape annotations. This section covers setting up the full observability stack.

### Install via Helm (Recommended)

The **kube-prometheus-stack** chart installs Prometheus and Grafana together:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace
```

Prometheus will auto-discover and scrape any pod with `prometheus.io/scrape: "true"` annotations, which the ayaFlow DaemonSet already has.

### Verify Prometheus is Scraping ayaFlow

```bash
kubectl port-forward -n monitoring svc/monitoring-kube-prometheus-prometheus 9090:9090
```

Open `http://localhost:9090/targets` in a browser. ayaFlow pods should appear with status **UP**. Run a quick query to confirm data:

```
ayaflow_packets_total
```

### Access Grafana

```bash
kubectl port-forward -n monitoring svc/monitoring-grafana 3001:80
```

Open `http://localhost:3001`. Default credentials for the Helm chart:

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `prom-operator` |

The Helm chart pre-configures Prometheus as a data source automatically. Verify under **Connections** > **Data sources**.

### Import the ayaFlow Dashboard

A pre-built dashboard is available in `grafana/dashboard.json`.

1. In Grafana, go to **Dashboards** > **New** > **Import**.
2. Upload `grafana/dashboard.json` or paste its contents.
3. Select the Prometheus data source from the dropdown.

Panels included: Active Connections (gauge), Packets/sec, Throughput/sec, and historical trends.

### Accessing Metrics Without Grafana

You do not need Grafana or Prometheus at all. Since the DaemonSet uses `hostNetwork: true`, ayaFlow listens on the node's real IP on port 3000:

```bash
# Find node IPs
kubectl get nodes -o wide

# Hit ayaFlow directly from any machine that can reach the node
curl http://<NODE_IP>:3000/metrics
curl http://<NODE_IP>:3000/api/live
curl http://<NODE_IP>:3000/api/stats
```

Or via port-forward:

```bash
kubectl port-forward daemonset/ayaflow 3000:3000
curl http://localhost:3000/metrics
```

If Prometheus is deployed, query its API directly:

```bash
kubectl port-forward -n monitoring svc/monitoring-kube-prometheus-prometheus 9090:9090

# Instant query
curl 'http://localhost:9090/api/v1/query?query=ayaflow_packets_total'

# Rate over 5 minutes
curl 'http://localhost:9090/api/v1/query?query=rate(ayaflow_packets_total[5m])'

# Active connections across all nodes
curl 'http://localhost:9090/api/v1/query?query=sum(ayaflow_active_connections)'
```

You can also open `http://localhost:9090` in a browser -- Prometheus has its own built-in query UI.

### Security Note

If ayaFlow metrics are reachable externally via node IPs, use `--allowed-ips` to restrict access:

```yaml
args:
  - "--allowed-ips"
  - "10.0.0.0/8,192.168.0.0/16"
```

---

## Troubleshooting

**Pods stuck in `CrashLoopBackOff`**
- Check logs: `kubectl logs -l app=ayaflow`
- Confirm the node kernel has BTF support. SSH into the node and check: `ls /sys/kernel/btf/vmlinux`
- Confirm the capabilities are granted. Some cluster policies (PodSecurityPolicies, OPA Gatekeeper) may block `BPF` or `NET_ADMIN`.

**No packets visible**
- Confirm `hostNetwork: true` is set in the spec.
- Verify the `--interface` argument matches an actual interface on the node. Interface names vary by cloud provider and CNI plugin (e.g., `eth0`, `ens5`, `cali*`).
- Check the `ayaflow_packets_total` Prometheus metric.

**Prometheus not scraping**
- Verify the annotations are present on the pod template (not on the DaemonSet metadata).
- Confirm your Prometheus instance is configured to discover pod annotations.

**Port conflict with hostPort**
- The default manifest maps `hostPort: 3000`. If another service on the node uses that port, change it in the DaemonSet spec and update the `--port` argument to match.
