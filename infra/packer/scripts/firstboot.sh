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

# Wait up to 60 min for the wizard to finish, polled at 5s. The wizard
# unit has Before this unit (set via firstboot.service [Unit] section),
# so this loop is normally a no-op for the cloud-init path; it only
# matters when the wizard is the source of values.
#
# 60 min (not 30): on slow / nested hardware the wizard itself is sluggish
# to come up and the operator needs headroom to fill the form. This budget
# is the real wait gate — the systemd unit is TimeoutStartSec=infinity so
# it never kills us mid-wait (a 20m unit timeout used to fire before this
# budget even elapsed).
#
# Count elapsed time by summing the sleeps, NOT by reading the wall
# clock: an appliance VM frequently boots with a stale RTC (frozen at
# image-build time) and corrects forward by hours once systemd-timesyncd
# syncs. A wall-clock deadline ($(date +%s)+3600) trips instantly on
# that jump, failing first boot before the operator can finish the
# wizard. A sleep-counted budget is immune to clock steps.
WAIT_BUDGET_SECONDS=3600
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

# Shared install core. The same script that powers the Linux
# `curl … | bash` installer; sourcing it (rather than re-running) gives
# us its functions without executing its main(). Only the chart source
# differs: the appliance installs from the pre-pulled chart directory,
# the curl path from the OCI chart. See install.sh.
# shellcheck source=/dev/null
source /usr/local/bin/soctalk-install

# Appliance inputs for the shared functions:
#   - k3s is installed-but-not-started (ensure_k3s starts it)
#   - config comes from the wizard / cloud-init files, not prompts
#   - chart is the directory Packer pre-pulled at build time
CHART_DIR=/opt/soctalk/charts/soctalk-system
VALUES_FILE="$VALUES"
LLM_KEY_FILE="$LLM_KEY"
ONBOARD_ENV=/etc/soctalk/onboard.env

ensure_k3s
ensure_helm
create_llm_secret
install_chart
patch_networkpolicy
echo "==> helm install + NetworkPolicy patches complete"

# Demo tenant onboarding (no-op if /etc/soctalk/onboard.env is absent).
# The provisioning worker brings up Wazuh + soctalk-tenant + adapter +
# runs-worker asynchronously; we don't wait for ACTIVE here.
maybe_onboard

echo "==> soctalk-firstboot complete at $(date -u +%FT%TZ)"

# Mark install done. Both soctalk-firstboot.service and
# soctalk-setup-wizard.service have ConditionPathExists=!/var/lib/soctalk-firstboot.done
# so neither re-fires on subsequent boots.
touch "$INSTALL_SENTINEL"
