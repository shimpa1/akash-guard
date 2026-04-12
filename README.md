# akash-guard

A standalone provider add-on for [Akash Network](https://akash.network) that detects and alerts on abusive tenant workloads — DDoS tools, spam bots, port scanners, and connections to known malicious infrastructure.

Akash is a permissionless marketplace. Providers bear the consequences of abusive deployments: IP reputation damage, ISP blacklisting, uplink saturation, and potential legal exposure. `akash-guard` gives providers visibility and alerting without interfering with the decentralized, permissionless nature of the network. It never automatically kills a lease.

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
Provider Node (DaemonSet — one pod per node)
│
├── Threat Intel Engine
│   ├── Feed fetcher — HTTP, runs on refresh_interval
│   ├── IP deduplicator
│   └── Calico GlobalNetworkPolicy writer (Log + Deny rules)
│
├── eBPF Monitor
│   ├── TC egress hook (C, attached to each pod veth)
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
- Linux kernel ≥ 5.8 (ring buffer support)
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` available to the DaemonSet pod

### Development machine (any OS)
- Go ≥ 1.24
- SSH access to a Linux build VM
- `rsync`

### Linux build VM (for eBPF code generation only)
- `clang` and `llvm`
- `libbpf-dev`
- `linux-headers` matching the kernel (or the amd64 headers package)
- Go ≥ 1.24

Install on Debian/Ubuntu:
```bash
apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go
```

---

## Getting Started

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

This step compiles `bpf/tc_egress.c` into BPF bytecode and generates the Go bindings. It runs on the Linux build VM over SSH and pulls the results back. Only needed once, and again whenever `tc_egress.c` changes.

```bash
make generate
```

### 4. Build the binary

Cross-compiles a `linux/amd64` binary locally. No VM needed after `generate`.

```bash
make build
# output: bin/akash-guard
```

### 5. Build the container image

Builds the full Docker image on the Linux VM (requires Docker installed there):

```bash
make docker IMAGE=ghcr.io/yourorg/akash-guard TAG=v0.1.0
```

### 6. Push the image

```bash
make push IMAGE=ghcr.io/yourorg/akash-guard TAG=v0.1.0
```

---

## Configuration

`akash-guard` reads its configuration from a YAML file. The default path is `/etc/akash-guard/config.yaml`, overridable via the `AKASH_GUARD_CONFIG` environment variable.

Copy `config.yaml.example` as a starting point:

```bash
cp config.yaml.example config.yaml
```

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
  # Namespaces listed here are never alerted on.
  # Add system namespaces that legitimately generate high traffic.
  whitelist:
    - kube-system
    - calico-system
```

---

## Deployment

### 1. Update the ConfigMap

Edit `deploy/configmap.yaml` with your desired thresholds and alert destinations, then apply:

```bash
kubectl apply -f deploy/configmap.yaml
```

### 2. Apply RBAC

Creates a `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding` in `kube-system`:

```bash
kubectl apply -f deploy/rbac.yaml
```

The ClusterRole grants:
- `get/list/watch` on `nodes` and `pods` (for veth → namespace/pod resolution)
- `get/list/watch/create/update/patch/delete` on Calico `GlobalNetworkPolicy` CRDs

### 3. Deploy the DaemonSet

Update the image reference in `deploy/daemonset.yaml` if you pushed to a custom registry, then:

```bash
kubectl apply -f deploy/daemonset.yaml
```

Verify pods are running on all nodes:

```bash
kubectl -n kube-system get pods -l app=akash-guard
```

### 4. Check logs

```bash
kubectl -n kube-system logs -l app=akash-guard -f
```

Logs are structured JSON. Example threat intel hit:

```json
{
  "time": "2026-04-12T10:23:45Z",
  "level": "WARN",
  "msg": "abuse detected",
  "type": "threat_intel_hit",
  "namespace": "t8k3m2-deployment-web",
  "dst_ip": "185.220.101.5",
  "feed_source": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
}
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

After deploying to a test provider, run through these checks:

**Threat Intel**
```bash
# Pick any IP from the Spamhaus DROP list and attempt to reach it from a test pod.
# Confirm the Calico policy was created:
kubectl get globalnetworkpolicy akash-guard-threatintel-egress-deny
# Confirm a log line appears in akash-guard pod logs for the hit.
```

**High PPS / DDoS signal**
```bash
# From inside a test pod:
hping3 --flood 1.2.3.4
# Within one window period, confirm high_pps alert fires in logs.
```

**Spam signal**
```bash
# From inside a test pod, open 25+ TCP connections to port 25:
for i in $(seq 1 30); do nc -z -w1 1.2.3.4 25 & done
# Confirm port25_egress alert fires.
```

**Scan signal**
```bash
# From inside a test pod:
nmap -sS 1.2.3.0/24
# Confirm high_syn_rate alert fires.
```

**Whitelist**
```bash
# Add kube-system to the whitelist in config.yaml and redeploy.
# Generate the same traffic from a kube-system pod.
# Confirm no alerts fire.
```

---

## Project Layout

```
akash-guard/
├── bpf/
│   ├── tc_egress.c          # eBPF TC egress hook (C source)
│   └── gen.go               # go:generate directive for bpf2go
├── cmd/
│   └── akash-guard/
│       └── main.go          # Entry point: wires all components together
├── deploy/
│   ├── configmap.yaml       # Default configuration
│   ├── daemonset.yaml       # DaemonSet with required capabilities
│   └── rbac.yaml            # ServiceAccount, ClusterRole, ClusterRoleBinding
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
├── Dockerfile               # Multi-stage build (eBPF generation + Go binary)
├── Makefile                 # Build targets: generate, build, docker, push, clean
└── .gitignore
```

---

## Makefile Targets

| Target | Description |
|---|---|
| `make generate` | Compile `tc_egress.c` → Go bindings on `DEV_VM` via SSH. Requires `DEV_VM` set in `local.mk`. |
| `make build` | Cross-compile `linux/amd64` binary to `bin/akash-guard`. No VM needed. |
| `make docker` | Build container image on `DEV_VM`. |
| `make push` | Push image from `DEV_VM` to registry. |
| `make clean` | Remove local build artefacts and remote temp directory. |
| `make all` | `generate` + `build`. |

Override variables on the command line:

```bash
make docker IMAGE=myregistry.io/akash-guard TAG=v0.2.0
make generate DEV_USER=ubuntu
```

---

## Limitations and Known Issues

- **IPv4 only**: The eBPF hook currently tracks IPv4 egress only. IPv6 support is planned.
- **veth resolution**: Namespace/pod name resolution from veth interfaces is best-effort. In some CNI configurations the mapping may fall back to `unknown`.
- **Threat intel feeds**: Spamhaus feeds may require a paid subscription for high-volume or commercial use. See their [terms of service](https://www.spamhaus.org/organization/dnsblusage/).
- **No automatic enforcement**: By design. Providers must act on alerts manually or integrate with their own automation.
