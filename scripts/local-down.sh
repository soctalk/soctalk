#!/usr/bin/env bash
#
# local-down.sh — destroy the local SocTalk k3d profile + drop the
# local kubeconfig. The lab profile (~/.kube/config / k3d-lab
# context) is untouched.
#
# To merely pause without destroying state:
#   k3d cluster stop soctalk-local
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CLUSTER_NAME="${CLUSTER_NAME:-soctalk-local}"
KCFG="${PWD}/.kube/config"

if k3d cluster list -o json 2>/dev/null | grep -q "\"name\": \"${CLUSTER_NAME}\""; then
  k3d cluster delete "${CLUSTER_NAME}"
else
  echo "cluster ${CLUSTER_NAME} not present"
fi

# k3d auto-removes the registry container when ``create.name`` is
# embedded in the cluster config; the explicit cleanup below covers
# the case where the registry was created out-of-band and survives.
if docker ps -a --format '{{.Names}}' | grep -q '^k3d-soctalk-local-registry$'; then
  docker rm -f k3d-soctalk-local-registry >/dev/null
fi

rm -f "${KCFG}"
echo "local profile destroyed"
