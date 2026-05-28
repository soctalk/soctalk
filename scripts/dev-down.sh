#!/usr/bin/env bash
#
# dev-down.sh — destroy the local SocTalk V1 k3d cluster (the one
# scripts/dev-up.sh creates) + drop the project-local kubeconfig.
# ~/.kube/config is untouched.
#
# To merely pause without destroying state:
#   k3d cluster stop soctalk-dev
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CLUSTER_NAME="${CLUSTER_NAME:-soctalk-dev}"
KCFG="${PWD}/.kube/config"

if k3d cluster list -o json 2>/dev/null | grep -q "\"name\": \"${CLUSTER_NAME}\""; then
    k3d cluster delete "${CLUSTER_NAME}"
else
    echo "cluster ${CLUSTER_NAME} not present"
fi

rm -f "${KCFG}"
echo "dev profile destroyed"
