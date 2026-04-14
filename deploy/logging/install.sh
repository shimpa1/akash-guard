#!/usr/bin/env bash
# deploy/logging/install.sh
#
# Deploy the akash-guard logging stack: Loki + Fluent Bit + Grafana.
# Idempotent — safe to re-run; uses `helm upgrade --install`.
#
# Requirements: helm >= 3.0, kubectl with cluster access.
#
# Usage:
#   ./deploy/logging/install.sh
#
# To upgrade to newer chart versions, update the version variables below
# and re-run the script.

set -euo pipefail

NAMESPACE="monitoring"

# Pinned chart versions — update here when upgrading.
LOKI_CHART_VERSION="6.6.3"
FLUENT_BIT_CHART_VERSION="0.47.10"
GRAFANA_CHART_VERSION="8.4.1"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Adding Helm repositories"
helm repo add grafana  https://grafana.github.io/helm-charts  2>/dev/null || true
helm repo add fluent   https://fluent.github.io/helm-charts   2>/dev/null || true
helm repo update

echo "==> Creating namespace '${NAMESPACE}'"
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Installing Loki ${LOKI_CHART_VERSION}"
helm upgrade --install loki grafana/loki \
  --namespace "${NAMESPACE}" \
  --version "${LOKI_CHART_VERSION}" \
  --values "${DIR}/loki-values.yaml" \
  --wait \
  --timeout 5m

echo "==> Installing Fluent Bit ${FLUENT_BIT_CHART_VERSION}"
helm upgrade --install fluent-bit fluent/fluent-bit \
  --namespace "${NAMESPACE}" \
  --version "${FLUENT_BIT_CHART_VERSION}" \
  --values "${DIR}/fluent-bit-values.yaml" \
  --wait \
  --timeout 3m

echo "==> Installing Grafana ${GRAFANA_CHART_VERSION}"
helm upgrade --install grafana grafana/grafana \
  --namespace "${NAMESPACE}" \
  --version "${GRAFANA_CHART_VERSION}" \
  --values "${DIR}/grafana-values.yaml" \
  --wait \
  --timeout 3m

echo ""
echo "==> Logging stack deployed."
echo ""
echo "    Grafana:  http://<node-ip>:32000  (admin / akash-guard)"
echo "    Loki:     http://<node-ip>:$(kubectl -n "${NAMESPACE}" get svc loki -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo '3100 (ClusterIP)')"
echo ""
echo "    Dashboard: akash-guard — Abuse Detection (pre-provisioned)"
echo ""
echo "    To uninstall:"
echo "      helm -n ${NAMESPACE} uninstall loki fluent-bit grafana"
echo "      kubectl delete namespace ${NAMESPACE}"
