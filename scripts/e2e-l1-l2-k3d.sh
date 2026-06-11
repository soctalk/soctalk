#!/usr/bin/env bash
# End-to-end L1→L2 harness for the agent dispatch protocol.
#
# Proves the full cross-cluster chain against two real k3d clusters:
#
#   1. L1 = soctalk docker-compose (postgres + api at :8000)
#   2. L2 = k3d cluster ``l2-demo`` (where the tenant agent lands)
#
# Flow:
#
#   a. Seed an MSSP admin + a tenant on L1.
#   b. MSSP admin calls POST /api/mssp/tenants/{id}:issue-agent → gets
#      bootstrap token + helm install hint.
#   c. Script helm-installs the soctalk-cloud-agent chart into L2,
#      overriding the image repository to ``soctalk-cloud-agent:e2e``
#      and control-plane URL to ``host.docker.internal:8000``.
#   d. Agent self-registers with L1, runs preflight against L2's API
#      server, claims install_helm_release → Helm-installs the
#      ``/charts/e2e-tenant-stub`` chart (bundled in the agent image)
#      into L2. Stub exposes a Service at ``<release>-wazuh-manager``
#      on port 55000 matching what L1's wait_for_ready probe targets.
#   e. Installation state walks agent_connected → provisioning →
#      (helm_apply_succeeded) → active.
#
# What this proves: the new L1 control-plane surface + the agent's
# preflight/install/wait_for_ready executors end-to-end against a real
# separate Kubernetes cluster. It does NOT exercise the soctalk-tenant
# chart's full Wazuh/TheHive/Cortex stack — that's a separate slice.
#
# Prereqs:
#   - k3d cluster ``l2-demo`` already up with ``soctalk-cloud-agent:e2e``
#     imported (scripts/e2e-l1-l2-k3d-up.sh does this in one call, or
#     run ``k3d cluster create l2-demo`` + ``k3d image import ... -c
#     l2-demo`` manually).
#   - docker-compose.yml + docker-compose.k3d.yml from this repo
#     bringing up ``soctalk-api`` with the L1→L2 env knobs
#     (SOCTALK_TENANT_CHART_REF, SOCTALK_TENANT_PROBE_SCHEME=http).
#   - Alembic head applied to the soctalk postgres.

set -euo pipefail

log()  { printf '\033[1;34m[e2e-l2]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m    %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31m[fail]\033[0m  %s\n' "$*" >&2; exit 1; }

L1_URL="${L1_URL:-http://localhost:8000}"
L2_CTX="${L2_CTX:-k3d-l2-demo}"
AGENT_IMAGE="${AGENT_IMAGE:-soctalk-cloud-agent:e2e}"
AGENT_CHART="${AGENT_CHART:-$(cd "$(dirname "$0")/../.." && pwd)/soctalk-cloud-agent/charts/soctalk-cloud-agent}"
AGENT_NS="soctalk-cloud-agent"
AGENT_RELEASE="soctalk-agent-e2e"
COOKIES="/tmp/e2e-l1-l2.cookies"
DEADLINE_ACTIVE="${DEADLINE_ACTIVE:-180}"   # install → active (stub: ~30s; real Wazuh: ~10+ min)
DEADLINE_CASE="${DEADLINE_CASE:-600}"       # time to wait for the first L1 Case after active

trap _teardown EXIT

_teardown() {
  rc=$?
  log "teardown (rc=$rc)"
  helm --kube-context "$L2_CTX" uninstall "$AGENT_RELEASE" \
    --namespace "$AGENT_NS" >/dev/null 2>&1 || true
  kubectl --context "$L2_CTX" delete namespace "$AGENT_NS" \
    --wait=false --ignore-not-found >/dev/null 2>&1 || true
  # Drop the tenant-* namespace the stub created on L2.
  if [[ -n "${TENANT_NS:-}" ]]; then
    kubectl --context "$L2_CTX" delete namespace "$TENANT_NS" \
      --wait=false --ignore-not-found >/dev/null 2>&1 || true
  fi
  rm -f "$COOKIES"
  exit $rc
}

# --- Prereqs ---------------------------------------------------------

log "prereq check"
command -v helm >/dev/null || fail "helm not on PATH"
command -v kubectl >/dev/null || fail "kubectl not on PATH"
command -v curl >/dev/null || fail "curl not on PATH"
command -v jq >/dev/null || fail "jq not on PATH"
kubectl --context "$L2_CTX" get nodes >/dev/null 2>&1 \
  || fail "L2 cluster context $L2_CTX not reachable — create it: k3d cluster create l2-demo"
curl -sf "$L1_URL/openapi.json" >/dev/null \
  || fail "L1 not responding at $L1_URL — bring up soctalk compose first"
[[ -d "$AGENT_CHART" ]] \
  || fail "agent chart not found at $AGENT_CHART"
ok  "prereqs ok"

# --- Seed L1 ---------------------------------------------------------
# Idempotent: skip create when already present (script re-run friendly).

log "seed MSSP admin + tenant on L1"
SQL_ENV=${DATABASE_URL_MSSP:-postgresql+psycopg2://soctalk:soctalk@localhost:5432/soctalk}
# Use the soctalk venv explicitly — the seed step imports soctalk.*
# which needs structlog/sqlmodel/argon2-cffi + friends.
PY_BIN="$(dirname "$0")/../.venv/bin/python"
[[ -x "$PY_BIN" ]] || fail "soctalk venv not found at $PY_BIN (run uv sync in soctalk/)"
"$PY_BIN" - <<PY
import os, sys
sys.path.insert(0, "$(dirname "$0")/../src")
import soctalk.persistence.models  # noqa
import soctalk.core.ir.models  # noqa
import soctalk.core.tenancy.models as tm
import soctalk.core.auth.models as am
from soctalk.core.auth.passwords import hash_password
from sqlmodel import Session, create_engine, select
from uuid import uuid4

engine = create_engine("${SQL_ENV/postgresql+asyncpg/postgresql+psycopg2}")
with Session(engine) as s:
    org = s.exec(select(tm.Organization)).first()
    if org is None:
        org = tm.Organization(
            mssp_id=uuid4(), mssp_name="E2E MSSP",
            install_id=uuid4(), install_label="e2e-l1-l2",
        )
        s.add(org); s.commit(); s.refresh(org)

    u = s.exec(select(tm.User).where(tm.User.email == "e2e-admin@acme.example")).first()
    if u is None:
        u = tm.User(
            email="e2e-admin@acme.example",
            display_name="E2E MSSP Admin",
            user_type="mssp", role="mssp_admin",
        )
        s.add(u); s.commit(); s.refresh(u)
        s.add(am.PasswordCredential(
            user_id=u.id, password_hash=hash_password("e2e-admin-pw-12345")))
        s.commit()
PY
ok  "L1 seeded"

log "login as MSSP admin"
curl -sf -c "$COOKIES" -X POST "$L1_URL/api/auth/login" \
  -H 'Content-Type: application/json' -H "Origin: $L1_URL" \
  -d '{"email":"e2e-admin@acme.example","password":"e2e-admin-pw-12345"}' \
  >/dev/null || fail "login failed"
ok  "logged in"

log "create tenant"
# Idempotent: if slug already exists, keep going with its id.
TENANT_BODY=$(cat <<'JSON'
{
  "slug": "e2e-l2",
  "display_name": "E2E L2 Tenant",
  "llm_base_url": "https://api.example.com/v1",
  "llm_model": "gpt-4"
}
JSON
)
CREATE_RESP=$(curl -s -b "$COOKIES" -X POST "$L1_URL/api/mssp/tenants" \
  -H 'Content-Type: application/json' -H "Origin: $L1_URL" \
  -d "$TENANT_BODY")
if echo "$CREATE_RESP" | jq -e '.id' >/dev/null 2>&1; then
  TENANT_ID=$(echo "$CREATE_RESP" | jq -r '.id')
  ok "tenant created ($TENANT_ID)"
else
  # Slug exists → fetch via list.
  TENANT_ID=$(curl -s -b "$COOKIES" "$L1_URL/api/mssp/tenants" \
    | jq -r '.[] | select(.slug=="e2e-l2") | .id')
  [[ -n "$TENANT_ID" ]] || fail "create_tenant failed: $CREATE_RESP"
  ok "tenant reused ($TENANT_ID)"
fi
TENANT_NS="tenant-e2e-l2"

log "issue agent credentials"
ISSUE=$(curl -sf -b "$COOKIES" -X POST \
  "$L1_URL/api/mssp/tenants/$TENANT_ID:issue-agent" -H "Origin: $L1_URL")
BOOTSTRAP=$(echo "$ISSUE" | jq -r '.bootstrap_token')
CP_URL=$(echo "$ISSUE" | jq -r '.control_plane_url')
INSTALL_ID=$(echo "$ISSUE" | jq -r '.installation_id')
[[ -n "$BOOTSTRAP" && "$BOOTSTRAP" != "null" ]] \
  || fail "issue-agent didn't return a bootstrap token: $ISSUE"
ok  "bootstrap minted ($INSTALL_ID)"

# --- Helm-install the agent into L2 ---------------------------------

log "helm install soctalk-cloud-agent into L2 cluster"
# Ensure any previous run's release is gone before reinstall.
helm --kube-context "$L2_CTX" uninstall "$AGENT_RELEASE" \
  --namespace "$AGENT_NS" >/dev/null 2>&1 || true
helm --kube-context "$L2_CTX" install "$AGENT_RELEASE" "$AGENT_CHART" \
  --namespace "$AGENT_NS" --create-namespace \
  --set-string controlPlaneUrl="$CP_URL" \
  --set-string bootstrapToken="$BOOTSTRAP" \
  --set-string clusterLabel="l2-demo" \
  --set-string image.repository="${AGENT_IMAGE%:*}" \
  --set-string image.tag="${AGENT_IMAGE##*:}" \
  --set-string image.pullPolicy=IfNotPresent \
  --wait --timeout 60s >/dev/null || {
    warn "helm install failed — dumping diagnostics"
    kubectl --context "$L2_CTX" -n "$AGENT_NS" get pods -o wide 2>&1 || true
    kubectl --context "$L2_CTX" -n "$AGENT_NS" describe pods 2>&1 | tail -40 || true
    fail "helm install agent failed"
  }
ok  "agent pod up"

# --- Poll installation → active -------------------------------------

log "wait for installation state → active (deadline ${DEADLINE_ACTIVE}s)"
# The L1 agent-dispatch audit table ``tenant_installation_events`` is
# the authoritative transition log for this slice. There is no MSSP
# HTTP endpoint exposing it yet (follow-up), so poll the DB directly
# for the current state. Tenant id → installation (unique by tenant_id).
PG_URL="${DATABASE_URL_MSSP_SYNC:-postgresql://soctalk:soctalk@localhost:5432/soctalk}"
psql_q() { "$PY_BIN" -c "import psycopg2,sys;c=psycopg2.connect('${PG_URL}');cur=c.cursor();cur.execute(sys.argv[1]);r=cur.fetchone();print(r[0] if r else '')" "$1"; }
end=$(( $(date +%s) + DEADLINE_ACTIVE ))
last_state=""
while [[ $(date +%s) -lt $end ]]; do
  state=$(psql_q "SELECT state FROM tenant_installations WHERE tenant_id='$TENANT_ID'")
  if [[ "$state" != "$last_state" ]]; then
    printf '  state=%s\n' "$state"
    last_state="$state"
  fi
  if [[ "$state" == "active" ]]; then
    ok "installation state=active"
    break
  fi
  if [[ "$state" == "degraded" ]]; then
    fail "installation went to degraded — see tenant_installation_events"
  fi
  sleep 3
done
[[ "$last_state" == "active" ]] || {
  warn "installation did not reach active within deadline — dumping diagnostics"
  echo "== L1 tenant_installation_events =="
  "$PY_BIN" -c "
import psycopg2
c=psycopg2.connect('${PG_URL}')
cur=c.cursor()
cur.execute(\"SELECT event_type, from_state, to_state FROM tenant_installation_events WHERE installation_id IN (SELECT id FROM tenant_installations WHERE tenant_id='$TENANT_ID') ORDER BY timestamp\")
for r in cur.fetchall(): print(' ', r)
"
  echo "== L2 agent pods =="
  kubectl --context "$L2_CTX" -n "$AGENT_NS" get pods -o wide 2>&1 || true
  echo "== L2 agent logs =="
  kubectl --context "$L2_CTX" -n "$AGENT_NS" logs -l app.kubernetes.io/name=soctalk-cloud-agent --tail=80 2>&1 || true
  echo "== L2 tenant namespace =="
  kubectl --context "$L2_CTX" -n "$TENANT_NS" get all 2>&1 || true
  fail "installation never reached active"
}

# --- Post-active assertions -----------------------------------------

log "verify tenant-minimal chart landed in L2 (wazuh manager Ready)"
kubectl --context "$L2_CTX" -n "$TENANT_NS" rollout status \
  statefulset/tenant-e2e-l2-wazuh-manager --timeout=60s >/dev/null \
  || fail "wazuh-manager StatefulSet never became Ready in $TENANT_NS"
ok  "Wazuh manager Ready"

# Indexer and forwarder + mock-endpoint come up once the manager
# stabilizes; they can take another couple of minutes. Don't gate on
# them here — the Case-creation poll below is the real proof.
ok  "tenant pods coming up (indexer + forwarder + mock-endpoint)"

log "verify agent events recorded in tenant_installation_events"
EVT_COUNT=$("$PY_BIN" -c "
import psycopg2
c=psycopg2.connect('${PG_URL}')
cur=c.cursor()
cur.execute(\"SELECT COUNT(*) FROM tenant_installation_events WHERE installation_id IN (SELECT id FROM tenant_installations WHERE tenant_id='$TENANT_ID') AND event_type IN ('agent_registered','helm_apply_succeeded','provisioning_succeeded','probe_ready')\")
print(cur.fetchone()[0])
")
(( EVT_COUNT >= 4 )) \
  || fail "expected ≥4 installation events (agent_registered, helm_apply_succeeded, probe_ready, provisioning_succeeded), got $EVT_COUNT"
ok  "agent lifecycle events recorded ($EVT_COUNT)"

# --- Post-active: attack → alert → L1 case --------------------------
#
# The soctalk-tenant-minimal chart brings up Wazuh + the mock-endpoint
# attack-simulator + the forwarder in L2. The attack-simulator delays
# ATTACK_DELAY seconds (default 30) after the manager is reachable,
# then fires ATT&CK techniques every ATTACK_INTERVAL. The forwarder
# polls the indexer on a cursor and pushes to L1. The L1 native IR
# then runs triage_event → upsert_alert → case_from_alert.
#
# We consider the end-to-end chain proven when at least one Case row
# with tenant_id = $TENANT_ID appears in cases.

log "wait for first L1 Case (deadline ${DEADLINE_CASE}s)"
end=$(( $(date +%s) + DEADLINE_CASE ))
last_count=-1
while [[ $(date +%s) -lt $end ]]; do
  count=$("$PY_BIN" -c "
import psycopg2
c=psycopg2.connect('${PG_URL}')
cur=c.cursor()
cur.execute(\"SELECT COUNT(*) FROM cases WHERE tenant_id='$TENANT_ID'\")
print(cur.fetchone()[0])
")
  if [[ "$count" != "$last_count" ]]; then
    printf '  cases=%s\n' "$count"
    last_count="$count"
  fi
  if (( count > 0 )); then
    ok "Case(s) created: $count"
    break
  fi
  sleep 10
done
(( last_count > 0 )) || {
  warn "no Case created within deadline — dumping diagnostics"
  echo "== L2 adapter logs =="
  kubectl --context "$L2_CTX" -n "$TENANT_NS" \
    logs -l app.kubernetes.io/name=soctalk-adapter --tail=30 2>&1 || true
  echo "== L2 mock-endpoint logs =="
  kubectl --context "$L2_CTX" -n "$TENANT_NS" \
    logs -l app.kubernetes.io/name=soctalk-mock-endpoint --tail=15 2>&1 || true
  echo "== L2 all tenant pods =="
  kubectl --context "$L2_CTX" -n "$TENANT_NS" get pods -o wide 2>&1 | head -10 || true
  echo "== L2 mock-endpoint pod describe (if pull issue) =="
  kubectl --context "$L2_CTX" -n "$TENANT_NS" describe pod \
    -l app.kubernetes.io/name=soctalk-mock-endpoint 2>&1 | tail -20 || true
  fail "attack→alert→case chain did not close within deadline"
}

log "sample the top Case"
"$PY_BIN" -c "
import psycopg2
c=psycopg2.connect('${PG_URL}')
cur=c.cursor()
cur.execute(\"SELECT short_id, title, severity, status FROM cases WHERE tenant_id='$TENANT_ID' ORDER BY opened_at LIMIT 3\")
for r in cur.fetchall(): print('  ', r)
"

printf '\n\033[1;32m[ok]\033[0m    L1→L2 attack→alert→case proven end-to-end\n'
