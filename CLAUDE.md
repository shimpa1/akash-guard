# akash-guard — Claude Code Instructions

## Branching and PRs

- Always create a new branch before making changes that will become a PR.
- Never commit directly to `main`.

## Build

The project has two build steps with different requirements:

```bash
# Step 1 — eBPF Go bindings (requires a Linux VM, run once or when tc_egress.c changes)
make generate          # uses DEV_VM from local.mk

# Step 2 — Go binary (cross-compiles locally, no VM needed)
make build             # output: bin/akash-guard (linux/amd64)
```

`local.mk` must exist with `DEV_VM` set before running `make generate`. Copy `local.mk.example` to get started. `local.mk` is gitignored — never commit it.

## Project-Specific Constraints

- **Calico is the CNI** on Akash providers. Never use Cilium APIs, Cilium CRDs, or Hubble. Network policy enforcement goes through Calico `GlobalNetworkPolicy` objects.
- **No automatic lease termination**. akash-guard is detection and alerting only. Do not add any code that closes, modifies, or terminates Akash leases.
- **eBPF C source lives in `bpf/tc_egress.c`**. The Go bindings in `bpf/` are generated — do not edit generated files by hand.

## Code Structure

| Path | Responsibility |
|---|---|
| `cmd/akash-guard/main.go` | Entry point — wires components, starts goroutines |
| `internal/config/` | YAML config loading and defaults |
| `internal/alerting/` | Unified alerter: log, Prometheus, webhook, email |
| `internal/threatintel/` | Feed fetching, IP parsing, Calico policy management |
| `internal/ebpf/` | eBPF loader, veth watcher, ring buffer, anomaly detection |
| `bpf/` | eBPF C source and bpf2go generate directive |
| `deploy/` | Kubernetes manifests (DaemonSet, RBAC, ConfigMap) |

## Kubernetes Manifests

All manifests deploy into the `kube-system` namespace. RBAC grants the minimum permissions needed: node/pod read for veth resolution, and full CRUD on Calico `GlobalNetworkPolicy` CRDs.

## Alert Events

All alert paths (`log`, `Prometheus`, `webhook`, `email`) use the `alerting.Event` struct in `internal/alerting/alerting.go`. Add new detection types there first, then reference them from detection code.

## Akash Blockchain

To inspect Akash blockchain state during development or debugging, use the `provider-services` binary.
