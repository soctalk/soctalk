#!/usr/bin/env bash
# Export the real Wazuh alerts the Nessus scan produced, as NDJSON — one raw
# Wazuh alert per line. This IS the replay corpus (real data, not fabricated).
#
# Filters to the scan target agent and (when SCANNER_IP is set) to the
# scanner's source IP, which cleanly isolates the scan from any bench traffic.
#
#   SCANNER_IP=<ip from scan.sh> ./capture.sh > ../nessus_scan_alerts.ndjson
set -euo pipefail
MGR=nessus-lab-wazuh-manager-1

docker exec "$MGR" cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
SCANNER_IP="${SCANNER_IP:-}" python3 -c '
import sys, json, os
scanner = os.environ.get("SCANNER_IP", "").strip()
kept = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        a = json.loads(line)
    except Exception:
        continue
    # campaign hosts are nessus-target-1/2/3 (the trailing dash excludes any
    # earlier single-host "nessus-target" orphan)
    if not a.get("agent", {}).get("name", "").startswith("nessus-target-"):
        continue
    src = (a.get("data", {}) or {}).get("srcip") or ""
    if scanner and src != scanner:
        continue
    print(json.dumps(a, separators=(",", ":")))
    kept += 1
sys.stderr.write(f"captured {kept} scan alerts\n")
'
