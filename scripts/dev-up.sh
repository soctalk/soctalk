#!/usr/bin/env bash
#
# dev-up.sh: bring up a local k3d cluster with Cilium CNI for SocTalk V1 dev.
#
# Creates a k3d cluster that matches the prerequisites in docs/v1/P0-3:
#   - K3s with flannel disabled and kube-proxy disabled
#   - Cilium installed with NetworkPolicy enforcement and FQDN egress
#   - cert-manager for per-tenant TLS issuance (P0-6)
#   - default StorageClass from k3d local-path
#
# Usage:
#   scripts/dev-up.sh           # create cluster "soctalk-dev"
#   scripts/dev-up.sh --clean   # delete and recreate
#
# Requires: docker, k3d (>= 5.6), helm (>= 3.14), kubectl
#
# For CI, this script is reused as-is. CI sets HELM_CACHE_HOME to a persistent
# path to avoid re-downloading chart deps.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-soctalk-dev}"
K3S_VERSION="${K3S_VERSION:-v1.29.4-k3s1}"
CILIUM_VERSION="${CILIUM_VERSION:-1.15.4}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.14.4}"

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not on PATH"
}

require docker
require k3d
require helm
require kubectl

if [[ "${1:-}" == "--clean" ]]; then
    log "Deleting existing k3d cluster '${CLUSTER_NAME}' (if present)"
    k3d cluster delete "${CLUSTER_NAME}" 2>/dev/null || true
fi

if k3d cluster list | grep -q "^${CLUSTER_NAME}"; then
    log "Cluster '${CLUSTER_NAME}' already exists: skipping create"
else
    log "Creating k3d cluster '${CLUSTER_NAME}' (K3s ${K3S_VERSION})"
    # Flags explained:
    #   --k3s-arg '--flannel-backend=none@server:*'   Disable default Flannel; Cilium will provide CNI
    #   --k3s-arg '--disable-network-policy@server:*' Disable kube-router NP; Cilium enforces
    #   --k3s-arg '--disable=traefik@server:*'         Skip bundled Traefik; install ingress explicitly if needed
    #   --k3s-arg '--disable-kube-proxy@server:*'      Let Cilium replace kube-proxy (optional but recommended)
    k3d cluster create "${CLUSTER_NAME}" \
        --image "rancher/k3s:${K3S_VERSION}" \
        --k3s-arg '--flannel-backend=none@server:*' \
        --k3s-arg '--disable-network-policy@server:*' \
        --k3s-arg '--disable=traefik@server:*' \
        --k3s-arg '--disable-kube-proxy@server:*' \
        --port '8443:443@loadbalancer' \
        --port '8080:80@loadbalancer' \
        --wait
fi

log "Waiting for k8s API to become responsive"
until kubectl --context "k3d-${CLUSTER_NAME}" get nodes >/dev/null 2>&1; do
    sleep 2
done

log "Installing Cilium ${CILIUM_VERSION}"
helm repo add cilium https://helm.cilium.io/ >/dev/null
helm repo update cilium >/dev/null

# Determine k3s API server IP for kubeProxyReplacement
API_IP="$(docker inspect "k3d-${CLUSTER_NAME}-server-0" \
    -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' 2>/dev/null || \
    docker inspect "k3d-${CLUSTER_NAME}-server-0" \
    -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
API_IP="${API_IP:-127.0.0.1}"

helm upgrade --install cilium cilium/cilium --version "${CILIUM_VERSION}" \
    --namespace kube-system \
    --set operator.replicas=1 \
    --set ipam.mode=kubernetes \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="${API_IP}" \
    --set k8sServicePort=6443 \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --wait

log "Waiting for Cilium pods ready"
kubectl --context "k3d-${CLUSTER_NAME}" -n kube-system \
    wait --for=condition=Ready pod -l k8s-app=cilium --timeout=5m

log "Installing cert-manager ${CERT_MANAGER_VERSION}"
helm repo add jetstack https://charts.jetstack.io >/dev/null
helm repo update jetstack >/dev/null
helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace \
    --version "${CERT_MANAGER_VERSION}" \
    --set installCRDs=true \
    --wait

log "Cluster '${CLUSTER_NAME}' is ready"
cat <<EOF

  Cluster:       k3d-${CLUSTER_NAME}
  Kubeconfig:    ~/.kube/config  (context: k3d-${CLUSTER_NAME})
  CNI:           Cilium ${CILIUM_VERSION}
  cert-manager:  ${CERT_MANAGER_VERSION}

  Quick checks:
    kubectl --context k3d-${CLUSTER_NAME} get nodes
    cilium status --context k3d-${CLUSTER_NAME}
    kubectl --context k3d-${CLUSTER_NAME} -n cert-manager get pods

  Next steps:
    helm install soctalk-system ./charts/soctalk-system \\
        --namespace soctalk-system --create-namespace \\
        --kube-context k3d-${CLUSTER_NAME} \\
        -f scripts/dev-values.yaml        # create this from values.schema.json

  Tear down:
    scripts/dev-up.sh --clean

EOF
