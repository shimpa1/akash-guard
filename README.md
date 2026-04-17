# akash-guard

A standalone provider add-on for [Akash Network](https://akash.network) that detects and alerts on abusive tenant workloads — DDoS tools, spam bots, port scanners, and connections to known malicious infrastructure.

Akash is a permissionless marketplace. Providers bear the consequences of abusive deployments: IP reputation damage, ISP blacklisting, uplink saturation, and potential legal exposure. `akash-guard` gives providers visibility and alerting without interfering with the decentralized, permissionless nature of the network. It never automatically kills a lease.

**Image**: `shimpa/akash-guard:latest` (Docker Hub)

---

## Component Status

| Component | Status |
|---|---|
| Threat Intel Blocker | Working — tested on live provider |
| eBPF Anomaly Detector | Working — tested on live provider |

---

## How It Works

`akash-guard` runs as a Kubernetes DaemonSet on every provider node and operates two independent detection engines:

### Component 1 — Threat Intel Blocker

Periodically fetches IP blocklists from public threat intelligence feeds, then creates a Calico `GlobalNetworkPolicy` that **logs and denies** egress to those IPs. Any policy hit produces an alert with full context: namespace, destination IP, and the feed that flagged it.

Feeds used by default:
- [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) — botnet C2 servers
- [Spamhaus DROP](https://www.spamhaus.org/drop/) — hijacked/rogue netblocks
- [Spamhaus EDROP](https://www.spamhaus.org/drop/) — extended DROP list

### Component 2 — Anomaly Detector

Attaches an eBPF TC (traffic control) egress hook to every pod veth interface on the host. Over each configurable time window it tracks per-namespace:

| Signal | What it detects |
|---|---|
| Packets per second (PPS) | Volumetric flood / DDoS |
| Unique destination IP count | Scatter-shot DDoS, scanning |
| Outbound connections to port 25 | Spam bots |
| SYN packet rate | SYN flood, port scanning |

When any threshold is breached the event is logged and all configured alert channels are notified. No traffic is blocked and no leases are terminated.

### Alerting Channels

All channels fire simultaneously on every detection event:

| Channel | Details |
|---|---|
| Structured JSON log | Always on — written to stdout, compatible with any log aggregator |
| Prometheus metrics | `akash_guard_alerts_total` counter, labelled by type and namespace |
| Webhook | HTTP POST of a JSON event payload to a configurable URL |
| Email | SMTP delivery with JSON body |

---

## Architecture

```
Cluster
│
├── Leader Pod (one per cluster — elected via coordination.k8s.io Lease)
│   └── Threat Intel Engine
│       ├── Feed fetcher — HTTP, runs on refresh_interval
│       ├── IP deduplicator
│       └── Calico GlobalNetworkPolicy writer (Log + Deny + catch-all Allow)
│
└── Every Node (DaemonSet — one pod per node, regardless of leader status)
    ├── eBPF Monitor
    │   ├── TC ingress hook on host-side cali interfaces (captures pod-originated traffic)
    │   ├── Per-CPU hash map — packet/SYN/port25 counters per ifindex
    │   ├── Ring buffer — per-packet dst IP events
    │   └── Veth watcher — polls /sys/class/net every 5s, auto-attaches/detaches
    │
    ├── Anomaly Detector
    │   └── Window evaluator — reads snapshots, fires alerts, resets counters
    │
    └── Alerting Layer
        ├── Prometheus /metrics endpoint
        ├── Structured JSON logger (slog)
        ├── Webhook sender
        └── SMTP email sender
```

---

## Prerequisites

### Provider nodes
- Kubernetes with **Calico** as the CNI
- Linux kernel ≥ 6.6 (TCX attachment); ring buffer requires ≥ 5.8
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` available to the DaemonSet pod

### Development machine (any OS)
- Go ≥ 1.26
- SSH access to a Linux build VM
- `rsync`

### Linux build VM (for eBPF code generation and Docker builds)
- `clang` and `llvm`
- `libbpf-dev`
- `gcc-multilib` (provides `asm/types.h` required by the eBPF C compiler)
- `linux-headers-amd64`
- Go ≥ 1.26
- Docker

Install on Debian/Ubuntu:
```bash
apt-get install -y clang llvm libbpf-dev gcc-multilib linux-headers-amd64
# Install Go from https://go.dev/dl/ — do not use the distro package, it is too old
```

---

## Quick Deploy

### Helm (recommended)

```bash
git clone https://github.com/shimpa1/akash-guard.git
cd akash-guard
helm install akash-guard charts/akash-guard -n kube-system --create-namespace
```

Override values inline or with a file:

```bash
helm install akash-guard charts/akash-guard -n kube-system --create-namespace \
  --set config.anomaly.thresholds.pps=5000 \
  --set config.alerting.webhook.enabled=true \
  --set config.alerting.webhook.url=https://hooks.example.com/akash-guard
```

### Raw manifests (alternative)

```bash
kubectl apply -f https://raw.githubusercontent.com/shimpa1/akash-guard/main/deploy/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/shimpa1/akash-guard/main/deploy/configmap.yaml
kubectl apply -f https://raw.githubusercontent.com/shimpa1/akash-guard/main/deploy/daemonset.yaml
```

### Verify

```bash
kubectl -n kube-system get pods -l app=akash-guard
kubectl -n kube-system logs -l app=akash-guard
```

On a healthy deployment you should see within ~10 seconds:
```json
{"level":"INFO","msg":"became leader, starting threat intel engine","identity":"akash-guard-xxxxx"}
{"level":"INFO","msg":"threat intel feeds fetched","total_entries":1595}
{"level":"INFO","msg":"updated Calico GlobalNetworkPolicy","name":"akash-guard-threatintel-egress-deny","entries":1595}
{"level":"INFO","msg":"attached TC egress hook","iface":"caliXXXX","namespace":"tenant-abc123","pod":"web-6d4f8b-xk2pz"}
```

---

## Getting Started (building from source)

### 1. Clone the repository

```bash
git clone https://github.com/shimpa1/akash-guard.git
cd akash-guard
```

### 2. Configure your local build VM

```bash
cp local.mk.example local.mk
```

Edit `local.mk` and set `DEV_VM` to the IP or hostname of your Linux build VM:

```makefile
DEV_VM = 192.168.1.100
# DEV_USER = myuser   # optional, defaults to $USER
```

`local.mk` is gitignored — it is never committed.

### 3. Generate eBPF Go bindings

Compiles `bpf/tc_egress.c` into BPF bytecode and generates the Go bindings on the build VM over SSH, then pulls the results back. Run once, and again whenever `tc_egress.c` changes.

```bash
make generate
```

### 4. Build the binary

Cross-compiles a `linux/amd64` binary locally using Go's native cross-compilation. No VM needed after `generate`.

```bash
make build
# output: bin/akash-guard
```

### 5. Build and push the container image

The Docker build runs on the build VM (requires Docker installed there). The Dockerfile runs `go generate` internally, so the VM needs `clang`, `llvm`, `libbpf-dev`, and `gcc-multilib`.

```bash
make docker IMAGE=youruser/akash-guard TAG=v0.1.0
make push  IMAGE=youruser/akash-guard TAG=v0.1.0
```

---

## Configuration

`akash-guard` reads its configuration from a YAML file. The default path is `/etc/akash-guard/config.yaml`, overridable via the `AKASH_GUARD_CONFIG` environment variable.

Edit `deploy/configmap.yaml` for in-cluster deployments, or copy `config.yaml.example` for standalone use.

### Full reference

```yaml
threatintel:
  # How often to re-fetch all feeds and sync the Calico policy.
  refresh_interval: 1h

  # List of line-delimited IP/CIDR blocklist URLs.
  # Lines starting with # or ; are treated as comments.
  # Bare IPs are normalised to /32 (IPv4) or /128 (IPv6).
  feeds:
    - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    - https://www.spamhaus.org/drop/drop.txt
    - https://www.spamhaus.org/drop/edrop.txt

anomaly:
  # Length of each evaluation window. Counters reset after each window.
  window: 10s

  thresholds:
    # Packets per second from a single namespace before alerting.
    pps: 10000

    # Number of unique destination IPs seen in one window before alerting.
    # High values indicate scatter-shot DDoS or scanning.
    unique_dst_ips: 500

    # Number of new outbound TCP connections to port 25 in one window.
    port25_connections: 20

    # SYN packets per second from a single namespace before alerting.
    syn_rate: 1000

    # high_pps only fires when the average packet size is below this threshold (bytes).
    # Legitimate bulk transfers (downloads, AI model pulls) send large packets near MTU
    # (~1400 bytes) and would otherwise generate false positives at gigabit speeds.
    # Flood/amplification attacks use small packets (40–100 bytes).
    # Set to 0 to disable the size guard and fire on pps alone.
    min_packet_bytes: 300

alerting:
  prometheus:
    enabled: true
    # Port to expose /metrics and /healthz on.
    port: 9090

  webhook:
    enabled: false
    # Endpoint that receives a POST with a JSON-encoded event body.
    url: https://hooks.example.com/akash-guard

  email:
    enabled: false
    smtp_host: smtp.example.com
    smtp_port: 587
    username: alerts@example.com
    password: changeme
    from: akash-guard@example.com
    to:
      - provider-admin@example.com

namespaces:
  # If set, the anomaly detector only alerts on namespaces matching this regex.
  # Everything else is silently skipped — no need to whitelist system namespaces.
  # On Akash providers, tenant workload namespaces are 45-char lowercase alphanumeric
  # lease IDs. This pattern scopes alerts to those namespaces only.
  # Leave empty to monitor all namespaces.
  monitor_pattern: "^[a-z0-9]{45}$"

  # Explicit per-namespace exclusions within the matched set.
  whitelist: []
```

---

## Deployment

### Helm (recommended)

```bash
# First install
helm install akash-guard charts/akash-guard -n kube-system --create-namespace

# Update configuration — pods restart automatically when config changes
helm upgrade akash-guard charts/akash-guard -n kube-system -f my-values.yaml

# Remove
helm uninstall akash-guard -n kube-system
```

Makefile shortcuts:

```bash
make helm-install                          # install with default values
make helm-install HELM_VALUES=prod.yaml    # install with custom values
make helm-upgrade HELM_VALUES=prod.yaml    # upgrade
make helm-uninstall                        # remove
```

### Raw manifests (alternative)

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/daemonset.yaml
```

Edit `deploy/configmap.yaml` before applying to set thresholds and alert destinations.

### Check logs

```bash
kubectl -n kube-system logs -l app=akash-guard -f
```

Logs are structured JSON. Example threat intel policy creation:

```json
{"level":"INFO","msg":"threat intel feeds fetched","total_entries":1596}
{"level":"INFO","msg":"created Calico GlobalNetworkPolicy","name":"akash-guard-threatintel-egress-deny","entries":1596}
```

---

## Prometheus Metrics

`akash-guard` exposes metrics at `http://<node-ip>:9090/metrics`.

| Metric | Labels | Description |
|---|---|---|
| `akash_guard_alerts_total` | `type`, `namespace` | Counter incremented on every alert event |

Alert type values: `threat_intel_hit`, `high_pps`, `high_unique_dst_ips`, `port25_egress`, `high_syn_rate`.

A minimal Prometheus scrape config:

```yaml
- job_name: akash-guard
  kubernetes_sd_configs:
    - role: pod
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: akash-guard
```

---

## Alert Event Schema

All channels (webhook, email, log) use the same JSON structure:

```json
{
  "time": "2026-04-12T10:23:45.123Z",
  "type": "high_pps",
  "namespace": "tenant-abc123-web",
  "pod_name": "web-deployment-6d4f8b-xk2pz",
  "dst_ip": "",
  "feed_source": "",
  "value": 14500,
  "threshold": 10000
}
```

| Field | Description |
|---|---|
| `type` | One of the alert type values listed above |
| `namespace` | Kubernetes namespace (maps to an Akash tenant deployment) |
| `pod_name` | Pod that triggered the alert, if resolved |
| `dst_ip` | Destination IP (threat intel hits only) |
| `feed_source` | Feed URL that matched (threat intel hits only) |
| `value` | Observed metric value that exceeded the threshold |
| `threshold` | Configured threshold that was breached |

---

## Verification

### Automated: trigger-tester deployment

The easiest way to verify all 4 detection signals at once is to deploy the
trigger-tester SDL to the provider under test:

```yaml
# deploy/test/trigger-tester.yaml
version: "2.0"

services:
  guard-tester:
    image: shimpa/akash-guard-tester:latest
    expose:
      - port: 8080
        as: 80
        to:
          - global: true

profiles:
  compute:
    guard-tester:
      resources:
        cpu:
          units: 0.5
        memory:
          size: 256Mi
        storage:
          - size: 512Mi
  placement:
    akash:
      pricing:
        guard-tester:
          denom: uact
          amount: 10000

deployment:
  guard-tester:
    akash:
      profile: guard-tester
      count: 1
```

The container runs four tests sequentially (15-second gaps between each to land in separate 10-second anomaly windows):

| Step | Signal | Method |
|------|--------|--------|
| 1 | `port25_egress` | 30 TCP connections to port 25 on RFC 5737 IPs |
| 2 | `high_unique_dst_ips` | `nmap` ping sweep of 768 RFC 5737 IPs |
| 3 | `high_syn_rate` | `hping3 --syn --flood` to 8.8.8.8:80 for 5s |
| 4 | `high_pps` | `hping3 --udp --flood -d 40` to 8.8.8.8:53 for 5s |

Watch for all four alert lines within ~90 seconds of deployment:

```bash
kubectl -n kube-system logs -l app=akash-guard -f | grep "anomaly:"
```

### Manual checks

After deploying to a test provider, run through these checks:

**Threat Intel — policy creation**
```bash
kubectl get globalnetworkpolicy akash-guard-threatintel-egress-deny
kubectl get globalnetworkpolicy akash-guard-threatintel-egress-deny \
  -o jsonpath='{.metadata.annotations}'
```
Expected: policy exists, `akash-guard/entry-count` annotation shows ~1596 entries.

**Threat Intel — egress block**
```bash
# From inside a test pod, attempt to reach an IP on the Spamhaus DROP list.
# The connection should be dropped and a log line should appear:
kubectl -n kube-system logs -l app=akash-guard | grep threat_intel_hit
```

**High PPS / DDoS signal**
```bash
# From inside a test pod:
nmap -Pn --min-rate 3000 -p 1-3000 1.2.3.4
# Confirm high_pps alert fires in logs within one window period.
```

**Spam signal**
```bash
# From inside a test pod:
for i in $(seq 1 30); do nc -z -w1 1.2.3.4 25 & done
# Confirm port25_egress alert fires.
```

**Scan signal**
```bash
# From inside a test pod:
nmap -Pn -sS --min-rate 1000 1.2.3.0/24
# Confirm high_syn_rate and high_unique_dst_ips alerts fire.
```

**Whitelist**
```bash
# Add the namespace to the whitelist in deploy/configmap.yaml and redeploy.
# Generate the same traffic — confirm no alerts fire.
```

---

## Project Layout

```
akash-guard/
├── charts/
│   └── akash-guard/
│       ├── Chart.yaml           # Chart metadata
│       ├── values.yaml          # All config options with defaults
│       └── templates/           # ServiceAccount, ClusterRole, ClusterRoleBinding, ConfigMap, DaemonSet
├── bpf/
│   ├── tc_egress.c          # eBPF TC egress hook (C source)
│   └── gen.go               # go:generate directive for bpf2go
├── cmd/
│   └── akash-guard/
│       └── main.go          # Entry point: wires all components together
├── deploy/
│   ├── configmap.yaml            # Default configuration
│   ├── daemonset.yaml            # DaemonSet with required capabilities
│   ├── rbac.yaml                 # ServiceAccount, ClusterRole, ClusterRoleBinding
│   ├── cert-manager/
│   │   ├── install.sh            # Idempotent cert-manager installer
│   │   └── cluster-issuer.yaml   # Let's Encrypt staging + prod ClusterIssuers
│   ├── logging/
│   │   ├── install.sh            # Installs Loki + Fluent Bit + Grafana via Helm
│   │   ├── loki-values.yaml      # Loki single-binary, filesystem storage
│   │   ├── fluent-bit-values.yaml # Fluent Bit with k8s metadata enrichment
│   │   ├── grafana-values.yaml   # Grafana with pre-provisioned dashboard
│   │   └── grafana-integration/  # For clusters with existing kube-prometheus-stack Grafana
│   │       ├── install.sh        # Applies loki-datasource.yaml + dashboard.yaml
│   │       ├── loki-datasource.yaml  # ConfigMap labeled grafana_datasource=1
│   │       └── dashboard.yaml    # ConfigMap labeled grafana_dashboard=1
│   └── test/
│       ├── Dockerfile            # Builds shimpa/akash-guard-tester:latest
│       ├── entrypoint.sh         # Test script: triggers all 4 detection signals
│       └── trigger-tester.yaml   # Akash SDL for the tester deployment
├── internal/
│   ├── alerting/
│   │   └── alerting.go      # Unified alerter: log, Prometheus, webhook, email
│   ├── config/
│   │   └── config.go        # YAML config loader with defaults
│   ├── ebpf/
│   │   ├── loader.go        # eBPF object loader, veth watcher, ring buffer consumer
│   │   └── anomaly.go       # Per-window threshold evaluator
│   └── threatintel/
│       ├── feed.go          # Concurrent feed fetcher and IP/CIDR parser
│       ├── calico.go        # Calico GlobalNetworkPolicy writer
│       └── engine.go        # Periodic refresh loop
├── config.yaml.example      # Fully commented configuration reference
├── local.mk.example         # Developer-local build VM config (copy to local.mk)
├── Dockerfile               # Multi-stage build: go generate + go build
├── Makefile                 # Build targets: generate, build, docker, push, clean
└── .gitignore
```

---

## Makefile Targets

| Target | Description |
|---|---|
| `make helm-install` | Install akash-guard via Helm with default values. |
| `make helm-install HELM_VALUES=f.yaml` | Install with a custom values file. |
| `make helm-upgrade HELM_VALUES=f.yaml` | Upgrade an existing release. |
| `make helm-uninstall` | Remove the Helm release. |
| `make generate` | Compile `tc_egress.c` → Go bindings on `DEV_VM` via SSH. Requires `DEV_VM` set in `local.mk`. |
| `make build` | Cross-compile `linux/amd64` binary to `bin/akash-guard`. No VM needed. |
| `make docker` | Build container image on `DEV_VM`. |
| `make push` | Push image from `DEV_VM` to registry. |
| `make cert-manager-deploy` | Install cert-manager v1.14.5 and Let's Encrypt ClusterIssuers. Run once before `logging-deploy`. |
| `make logging-deploy` | Deploy Loki + Fluent Bit + Grafana to the current kubectl context. Requires cert-manager. |
| `make grafana-integration-deploy` | Inject Loki datasource + akash-guard dashboard into an existing kube-prometheus-stack Grafana. |
| `make clean` | Remove local build artefacts and remote temp directory. |
| `make all` | `generate` + `build`. |

Override variables on the command line:

```bash
make docker IMAGE=myregistry.io/akash-guard TAG=v0.2.0
make generate DEV_USER=ubuntu
```

---

## Releasing

Releases are published manually via GitHub Actions. To cut a release:

1. Merge all intended changes to `main`.
2. Go to **Actions → Release → Run workflow** on GitHub.
3. Enter the version in `vX.Y.Z` format (e.g. `v0.2.0`) and click **Run workflow**.

The workflow will:
- Build and push the Docker image to `ghcr.io/shimpa1/akash-guard` tagged with the version and `latest`.
- Package the Helm chart and push it as an OCI artifact to `ghcr.io/shimpa1/charts/akash-guard`.
- Create a GitHub release with auto-generated notes from merged PRs and the chart `.tgz` attached.

To install a specific released version via Helm OCI:

```bash
helm install akash-guard oci://ghcr.io/shimpa1/charts/akash-guard --version 0.2.0 -n kube-system
```

---

## Multi-Node Clusters

`akash-guard` is designed for multi-node providers:

- **eBPF anomaly detection** is inherently per-node. Each DaemonSet pod attaches TC hooks only to its own node's pod interfaces and fires alerts for local traffic. No coordination needed.
- **Threat intel policy** is cluster-scoped (a single Calico `GlobalNetworkPolicy`). To avoid N nodes racing to write the same policy, leader election ensures only one pod writes it at a time. On leadership change, the policy stays in place; the new leader wins within 15 seconds and immediately refreshes it.
- **Prometheus metrics** are per-node. Configure your scraper to collect from all DaemonSet pods (the `prometheus.io/scrape` annotation is already set).

Verify leader election on a running cluster:
```bash
kubectl -n kube-system get lease akash-guard-leader
kubectl -n kube-system logs -l app=akash-guard | grep "became leader\|new threat intel leader"
```

---

## Logging Stack

An optional but recommended observability stack is included in `deploy/logging/` and `deploy/cert-manager/`:

| Component | Chart | Version | Purpose |
|---|---|---|---|
| Loki | grafana/loki | 6.6.3 | Log aggregation, 30-day retention |
| Fluent Bit | fluent/fluent-bit | 0.47.10 | Log collection from all nodes |
| Grafana | grafana/grafana | 8.4.1 | Dashboard, pre-provisioned datasource |
| cert-manager | jetstack/cert-manager | 1.14.5 | TLS certificates via Let's Encrypt |

The Grafana dashboard shows:
- Live abuse alert log stream
- Alert rate by type and by namespace
- Per-signal stat counters (high PPS, high SYN rate, high unique DST IPs, port 25, threat intel hits)

**Option A — standalone Grafana** (provider has no existing Grafana):
```bash
make cert-manager-deploy   # one-time: installs cert-manager + ClusterIssuers
make logging-deploy        # installs Loki + Fluent Bit + Grafana
```

**Option B — existing kube-prometheus-stack Grafana** (provider already has Grafana):
```bash
make logging-deploy        # installs Loki + Fluent Bit only
make grafana-integration-deploy  # injects Loki datasource + dashboard into existing Grafana
```

`grafana-integration-deploy` applies two labeled ConfigMaps to the `monitoring` namespace. The `grafana-sc-datasources` and `grafana-sc-dashboard` sidecars included in kube-prometheus-stack pick these up and hot-reload them into Grafana without a pod restart.

---

## Limitations and Known Issues

- **`kernel.unprivileged_bpf_disabled=2`**: Akash provider nodes restrict BPF to root. The DaemonSet must run as uid 0 with `privileged: true`. The published image uses the distroless root variant.
- **`AttachTCX` requires kernel ≥ 6.6**: If the provider node runs an older kernel, TC hook attachment will fail. Legacy `tc filter` attachment can be substituted in `loader.go`.
- **IPv4 only**: The eBPF hook currently tracks IPv4 egress only. IPv6 support is planned.
- **veth resolution**: If a pod's IP has not yet appeared in the k8s API when its cali interface is first seen, the interface is recorded as `unknown`. It is automatically re-resolved on the next 5-second watcher tick once the pod IP becomes available.
- **Threat intel feeds**: Spamhaus feeds may require a paid subscription for high-volume or commercial use. See their [terms of service](https://www.spamhaus.org/organization/dnsblusage/).
- **No automatic enforcement**: By design. Providers must act on alerts manually or integrate with their own automation.
