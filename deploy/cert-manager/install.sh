#!/usr/bin/env bash
# deploy/cert-manager/install.sh
#
# Install cert-manager and create Let's Encrypt ClusterIssuers.
# Idempotent — safe to re-run.
#
# Requirements: helm >= 3.0, kubectl with cluster access.
#
# Usage:
#   ./deploy/cert-manager/install.sh

set -euo pipefail

CERT_MANAGER_VERSION="1.14.5"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Adding jetstack Helm repository"
helm repo add jetstack https://charts.jetstack.io 2>/dev/null || true
helm repo update jetstack

echo "==> Installing cert-manager CRDs (v${CERT_MANAGER_VERSION})"
# Install CRDs separately — the --set crds.enabled=true Helm flag is unreliable
# across cert-manager 1.x minor versions; direct apply is always safe.
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/v${CERT_MANAGER_VERSION}/cert-manager.crds.yaml"

echo "==> Installing cert-manager ${CERT_MANAGER_VERSION}"
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version "v${CERT_MANAGER_VERSION}" \
  --set startupapicheck.enabled=false \
  --wait \
  --timeout 5m

echo "==> Waiting for cert-manager webhook to be ready"
kubectl -n cert-manager wait --for=condition=Available deployment/cert-manager-webhook --timeout=60s

echo "==> Creating Let's Encrypt ClusterIssuers"
kubectl apply -f "${DIR}/cluster-issuer.yaml"

echo ""
echo "==> cert-manager deployed."
echo ""
echo "    Verify issuers are ready:"
echo "      kubectl get clusterissuer"
echo ""
echo "    To uninstall:"
echo "      helm -n cert-manager uninstall cert-manager"
echo "      kubectl delete namespace cert-manager"
echo "      kubectl delete clusterissuer letsencrypt-staging letsencrypt-prod"
