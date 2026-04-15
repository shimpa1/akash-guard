#!/usr/bin/env bash
# Inject akash-guard Loki datasource and dashboard into an existing Grafana
# deployed by kube-prometheus-stack.
#
# How it works
# ------------
# kube-prometheus-stack ships two sidecar containers alongside Grafana:
#   - grafana-sc-datasources: watches ConfigMaps labeled grafana_datasource=1
#   - grafana-sc-dashboard:   watches ConfigMaps labeled grafana_dashboard=1
#
# Both sidecars run in the Grafana pod and react to label changes in real time
# — no Grafana pod restart is needed after applying these ConfigMaps.
#
# Prerequisites
# -------------
# - Loki must be running at loki.logging.svc.cluster.local:3100
#   (deployed via deploy/logging/install.sh or equivalent)
# - kube-prometheus-stack Grafana must be in the `monitoring` namespace
#   If your Grafana lives in a different namespace, edit the namespace fields
#   in loki-datasource.yaml and dashboard.yaml before applying.
#
# Usage
# -----
#   ./install.sh
#   ./install.sh --dry-run   # preview without applying

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run=client"
fi

echo "Applying Loki datasource ConfigMap..."
kubectl apply $DRY_RUN -f "${SCRIPT_DIR}/loki-datasource.yaml"

echo "Applying akash-guard dashboard ConfigMap..."
kubectl apply $DRY_RUN -f "${SCRIPT_DIR}/dashboard.yaml"

if [[ -z "$DRY_RUN" ]]; then
    echo
    echo "Done. The Grafana sidecar will pick up the changes within ~30 seconds."
    echo "Dashboard: akash-guard — Abuse Detection"
    echo "Datasource: Loki (http://loki.logging.svc.cluster.local:3100)"
fi
