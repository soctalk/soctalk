#!/usr/bin/env bash
# Keep kubectl port-forwards alive for the k3d-deployed Wazuh.
#
# Run this in its own terminal (or via tmux / screen). The script
# respawns each forward if it drops (k3d sometimes closes idle
# forwards or the kubectl tools pod gets restarted).
#
# Ports:
#   9200  → wazuh-wazuh-indexer   (admin:admin)                    REST + TLS
#   55000 → wazuh-wazuh-manager   (wazuh-wui:MyS3cr37P450r.*-)      management API
#   1515  → wazuh-wazuh-manager   (enrollment)                      agent-auth
#   1514  → wazuh-wazuh-manager   (events)                          agent ossec protocol

set -euo pipefail

NAMESPACE="${NAMESPACE:-wazuh}"
INDEXER_SVC="${INDEXER_SVC:-wazuh-wazuh-indexer}"
MANAGER_SVC="${MANAGER_SVC:-wazuh-wazuh-manager}"

forward() {
  local svc="$1" port="$2"
  while true; do
    echo "[forward] starting ${svc} on :${port}"
    kubectl -n "$NAMESPACE" port-forward "svc/${svc}" "${port}:${port}" || true
    echo "[forward] ${svc}:${port} exited; restarting in 2s"
    sleep 2
  done
}

cleanup() {
  echo
  echo "[forward] shutting down"
  kill $(jobs -p) 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

forward "$INDEXER_SVC" 9200 &
forward "$MANAGER_SVC" 55000 &
forward "$MANAGER_SVC" 1515 &
forward "$MANAGER_SVC" 1514 &

wait
