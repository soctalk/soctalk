---
name: verify
description: Drive soctalk end-to-end locally — Postgres + migrations + live V1 API + runs worker + real alert injection — to verify changes at the production surfaces.
---

# Verifying soctalk end-to-end (no k8s needed)

The production surfaces are `uvicorn soctalk.core.api.app_v1:app` (system chart)
and `python -m soctalk.runs_worker.main` (tenant chart). Both can run locally
against a throwaway Postgres. Full recipe (~2 min to a claimable triage run):

## 1. Postgres + migrations

```bash
docker run -d --name verify-pg -e POSTGRES_USER=soctalk -e POSTGRES_PASSWORD=soctalk \
  -e POSTGRES_DB=soctalk -p 55432:5432 postgres:16-alpine
DATABASE_URL="postgresql+asyncpg://soctalk:soctalk@localhost:55432/soctalk" .venv/bin/alembic upgrade head
```

## 2. API

Role URLs can all point at the superuser locally (same trick as scripts/e2e-l1-l2-k3d.sh).
`SOCTALK_PUBLIC_ORIGIN` must match or CSRF blocks every mutating request.
`SOCTALK_PROVISIONING_WORKER=0` — no k8s here.

```bash
PGURL="postgresql+asyncpg://soctalk:soctalk@localhost:55432/soctalk"
DATABASE_URL="$PGURL" DATABASE_URL_APP="$PGURL" DATABASE_URL_MSSP="$PGURL" \
SOCTALK_AUTH_MODE=internal SOCTALK_ADAPTER_SIGNING_KEY=dev-signing-key \
SOCTALK_PROVISIONING_WORKER=0 SOCTALK_PUBLIC_ORIGIN="http://127.0.0.1:58000" \
.venv/bin/uvicorn soctalk.core.api.app_v1:app --host 127.0.0.1 --port 58000
# health: GET /health/live and /health/ready
```

## 3. Seed org + admin, create tenant

Seed an `Organization` + mssp_admin `User` + `PasswordCredential` via sqlmodel
(crib the python block in scripts/e2e-l1-l2-k3d.sh ~line 100), then:
login `POST /api/auth/login` (cookie jar + `Origin:` header required),
create tenant `POST /api/mssp/tenants {"slug":..., "display_name":...}`.

## 4. Inject an alert (adapter surface)

```python
from soctalk.core.tenancy.auth import mint_adapter_token, mint_worker_token
# both sign with SOCTALK_ADAPTER_SIGNING_KEY (env fallback)
```

`POST /api/internal/adapter/events` with `Authorization: Bearer <adapter-token>`,
body `{"tenant_id": ..., "events": [{source_event_id, rule_id, severity (>=8 → promoted), asset_ids, initial_iocs, description, title}]}`.
Response shows `action: promoted|merged|auto_closed` per event.

## 5. Runs worker (real LLM triage)

```bash
echo "<mint_worker_token output>" > /tmp/worker-token
set -a; source .env; set +a
unset OPENAI_API_KEY   # host env leak trips the provider mutual-exclusion check
SOCTALK_API_URL=http://127.0.0.1:58000 WORKER_TOKEN_PATH=/tmp/worker-token \
SOCTALK_LLM_PROVIDER=anthropic SOCTALK_FAST_MODEL=claude-sonnet-4-6 \
SOCTALK_REASONING_MODEL=claude-sonnet-4-6 \
.venv/bin/python -m soctalk.runs_worker.main
```

Watch for: `claim` 200s → `supervisor_decision` lines → `verdict_rendered` →
`run_complete status=completed tokens=N`. Escalations appear at
`GET /api/mssp/dashboard/pending-reviews` (MSSP cookie).

## Gotchas

- `.env` may pin a retired model (404 `not_found_error` from Anthropic) — override SOCTALK_FAST/REASONING_MODEL.
- MCP servers need `WAZUH_ENABLED=true` etc. flags, not just paths — without them enrichment no-ops gracefully.
- Kill the worker promptly after the run you care about — it keeps claiming and each triage run costs real LLM tokens.
- Signature coalescing only merges while an alert is still status='new'; promoted alerts never coalesce, so duplicate injections create duplicate investigations (and duplicate LLM runs).
