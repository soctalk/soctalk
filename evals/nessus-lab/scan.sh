#!/usr/bin/env bash
# Drive the Nessus API to run one real Basic Network Scan against the lab
# target, and wait for it to finish. The scan's web/service probes hit the
# target's nginx + sshd, which the Wazuh agent turns into real alerts on the
# manager. Run this once Nessus reports status "ready".
#
#   ./scan.sh
#
# Prints the scanner's source IP + the scan start epoch so capture.sh can
# window the alerts.
set -euo pipefail
cd "$(dirname "$0")"
source .env

B="https://localhost:8834"
jqpy() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

# Nessus Essentials disables the external scan API (scan_api:false); the web UI
# works because it also sends X-API-Token, a UUID baked into nessus6.js. Send
# both that and the session cookie to drive scans headlessly.
echo ">> api token + login"
APITOKEN=$(curl -sk "$B/nessus6.js" | grep -oE '[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}' | head -1)
TOKEN=$(curl -sk -X POST "$B/session" \
  --data-urlencode "username=$NESSUS_USER" --data-urlencode "password=$NESSUS_PASSWORD" \
  | jqpy 'd["token"]')
H=(-H "X-Cookie: token=$TOKEN" -H "X-API-Token: $APITOKEN")

echo ">> resolve 'Basic Network Scan' template"
UUID=$(curl -sk "${H[@]}" "$B/editor/scan/templates" \
  | jqpy 'next(t["uuid"] for t in d["templates"] if t.get("name")=="basic")')

# Campaign: scan all three target hosts in one run, so the alerts span hosts
# but share this scanner's source IP.
TARGETS="${TARGETS:-target-1, target-2, target-3}"
echo ">> create campaign scan (targets: $TARGETS)"
SID=$(curl -sk "${H[@]}" -X POST "$B/scans" -H 'Content-Type: application/json' \
  -d '{"uuid":"'"$UUID"'","settings":{"name":"nessus-lab-campaign","text_targets":"'"$TARGETS"'","enabled":true,"launch_now":false}}' \
  | jqpy 'd["scan"]["id"]')

# The scanner's own IP on the lab network — the srcip the target's nginx logs.
SCANNER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nessus-lab-nessus-1)
START_EPOCH=$(date +%s)
echo ">> launch scan id=$SID  scanner_ip=$SCANNER_IP  start_epoch=$START_EPOCH"
curl -sk "${H[@]}" -X POST "$B/scans/$SID/launch" >/dev/null

echo ">> waiting for completion..."
while :; do
  S=$(curl -sk "${H[@]}" "$B/scans/$SID" | jqpy 'd["info"]["status"]')
  echo "   status=$S  ($(date -u +%H:%M:%S))"
  case "$S" in
    completed) break ;;
    canceled|aborted) echo "scan ended: $S"; break ;;
  esac
  sleep 20
done

echo "SCAN_DONE id=$SID scanner_ip=$SCANNER_IP start_epoch=$START_EPOCH"
