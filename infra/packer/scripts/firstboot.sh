#!/bin/bash
# Runs once on the customer's first boot. Two paths:
#
#   A. cloud-init supplied /etc/soctalk/values.yaml + /etc/soctalk/llm.key:
#      go straight to helm install.
#
#   B. neither file is present: the soctalk-setup-wizard.service unit
#      runs first (started by systemd via After=cloud-final.service),
#      collects config via the browser, writes both files + a wizard
#      sentinel /var/lib/soctalk-wizard.done, then exits. This script
#      then continues from there.
#
# In both cases the END state is the same: SocTalk installed via helm
# on k3s, sentinel /var/lib/soctalk-firstboot.done written.
set -euo pipefail

LOG=/var/log/soctalk-firstboot.log
exec > >(tee -a "$LOG") 2>&1
echo "==> soctalk-firstboot at $(date -u +%FT%TZ)"

VALUES=/etc/soctalk/values.yaml
LLM_KEY=/etc/soctalk/llm.key
WIZARD_SENTINEL=/var/lib/soctalk-wizard.done
INSTALL_SENTINEL=/var/lib/soctalk-firstboot.done

# Wait up to 30 min for the wizard to finish, polled at 5s. The wizard
# unit has Before this unit (set via firstboot.service [Unit] section),
# so this loop is normally a no-op for the cloud-init path; it only
# matters when the wizard is the source of values.
#
# Count elapsed time by summing the sleeps, NOT by reading the wall
# clock: an appliance VM frequently boots with a stale RTC (frozen at
# image-build time) and corrects forward by hours once systemd-timesyncd
# syncs. A wall-clock deadline ($(date +%s)+1800) trips instantly on
# that jump, failing first boot before the operator can finish the
# wizard. A sleep-counted budget is immune to clock steps.
WAIT_BUDGET_SECONDS=1800
WAIT_POLL_SECONDS=5
waited=0
while [[ ! -s "$VALUES" || ! -s "$LLM_KEY" ]]; do
  if [[ -f "$INSTALL_SENTINEL" ]]; then
    echo "install sentinel present; nothing to do"
    exit 0
  fi
  if (( waited >= WAIT_BUDGET_SECONDS )); then
    echo "ERROR: timed out waiting for /etc/soctalk/values.yaml and /etc/soctalk/llm.key"
    echo "  (expected from cloud-init user-data OR from the setup wizard)"
    exit 1
  fi
  sleep "$WAIT_POLL_SECONDS"
  waited=$(( waited + WAIT_POLL_SECONDS ))
done

echo "==> values + llm key ready, proceeding to install"

# Start k3s now (it was installed but not started by Packer install.sh,
# so the wizard could collect config first without competing for ports).
systemctl start k3s
until [[ -f /etc/rancher/k3s/k3s.yaml ]]; do sleep 1; done
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
chmod 600 "$KUBECONFIG"

for _ in $(seq 1 60); do
  kubectl get nodes >/dev/null 2>&1 && break
  sleep 2
done

# Create the LLM key Secret that the chart consumes.
kubectl create namespace soctalk-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n soctalk-system create secret generic soctalk-system-llm-api-key \
  --from-file=anthropic-api-key="$LLM_KEY" \
  --from-file=openai-api-key="$LLM_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install soctalk-system /opt/soctalk/charts/soctalk-system \
  --namespace soctalk-system \
  --create-namespace \
  --values "$VALUES" \
  --wait \
  --timeout 15m

# Patch the kube-system NetworkPolicy to allow k3s's bundled Traefik
# (which lives in kube-system, not ingress-system) to reach the
# soctalk-system services. Same patch poc-funnel applies.
for np in soctalk-system-ui-ingress-allow soctalk-system-api-ingress-allow; do
  kubectl -n soctalk-system patch networkpolicy "$np" --type=json \
    -p='[{"op":"add","path":"/spec/ingress/0/from/-","value":{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}}]' \
    2>/dev/null || true
done

echo "==> helm install + NetworkPolicy patches complete"

# ---------------------------------------------------------------------
# Demo tenant onboarding. Mirrors poc-funnel's cloud-init pattern:
#   1. wait for the API to answer through Traefik (Host header trick)
#   2. log in as the bootstrap admin from /etc/soctalk/onboard.env
#   3. POST /api/mssp/tenants/onboard with profile=poc
# The provisioning worker brings up Wazuh + soctalk-tenant + adapter +
# runs-worker in the new tenant- namespace asynchronously. We don't
# wait for ACTIVE here — the install sentinel marks soctalk-system
# done; the tenant rolls out in the background.
# ---------------------------------------------------------------------
ONBOARD_ENV=/etc/soctalk/onboard.env
if [[ -f "$ONBOARD_ENV" ]]; then
  # shellcheck disable=SC1090
  . "$ONBOARD_ENV"
  if [[ -n "${TENANT_SLUG:-}" && -n "${ADMIN_EMAIL:-}" && -n "${ADMIN_PW:-}" ]]; then
    HOST="${INGRESS_HOST:-soctalk.local}"
    echo "==> waiting for API to answer through Traefik (Host: $HOST)"
    api_ok=0
    # 120 × 5s = 10 min cap. Traefik registers the Ingress fairly fast
    # but the api Service endpoint can take 30-60s to be picked up.
    # Probe without -f so we accept 401 ("API is up, just not authed yet")
    # as success. -f would reject the 401 and we'd loop until timeout even
    # though Traefik is fully wired up.
    for _ in $(seq 1 120); do
      code=$(curl -sk -m 5 -o /dev/null -w "%{http_code}" \
               -H "Host: $HOST" "https://127.0.0.1/api/auth/me" || echo 000)
      case "$code" in
        200|401)
          api_ok=1
          break
          ;;
      esac
      sleep 5
    done
    if [[ "$api_ok" = "1" ]]; then
      echo "==> logging in as bootstrap admin"
      JAR=/tmp/soctalk-onboard.cookies
      rm -f "$JAR"
      LOGIN_BODY=$(printf '{"email":"%s","password":"%s"}' \
        "$ADMIN_EMAIL" "$ADMIN_PW")
      if curl -sfk -m 10 -c "$JAR" \
           -H "Content-Type: application/json" \
           -H "Host: $HOST" -H "Origin: https://$HOST" \
           -d "$LOGIN_BODY" "https://127.0.0.1/api/auth/login" >/dev/null; then
        echo "==> onboarding demo tenant ${TENANT_SLUG}"
        ONBOARD_BODY=$(printf '{"slug":"%s","display_name":"%s","profile":"poc"}' \
          "$TENANT_SLUG" "$TENANT_NAME")
        if curl -sfk -m 30 -b "$JAR" \
             -H "Content-Type: application/json" \
             -H "Host: $HOST" -H "Origin: https://$HOST" \
             -X POST -d "$ONBOARD_BODY" \
             "https://127.0.0.1/api/mssp/tenants/onboard" >/dev/null; then
          echo "==> tenant onboard accepted; provisioning runs async"
        else
          echo "WARNING: tenant onboard POST failed (continuing)"
        fi
      else
        echo "WARNING: bootstrap admin login failed (continuing without tenant)"
      fi
      rm -f "$JAR"
    else
      echo "WARNING: API never answered through Traefik (continuing without tenant)"
    fi
  fi
fi

echo "==> soctalk-firstboot complete at $(date -u +%FT%TZ)"

# Mark install done. Both soctalk-firstboot.service and
# soctalk-setup-wizard.service have ConditionPathExists=!/var/lib/soctalk-firstboot.done
# so neither re-fires on subsequent boots.
touch "$INSTALL_SENTINEL"
