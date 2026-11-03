# demo-seed — realistic demo data through the front door (issue #72)

Seeds a SocTalk install with significant alert/investigation volume with
ZERO runtime LLM inference: every event enters via the real adapter API
with real occurrence timestamps, authorization facts via the real facts
API, and the reasoning tail is triaged by a real runs-worker whose only
reachable "model" is `provider.py` — a deterministic OpenAI-compatible
playback server serving prose written offline (no API tokens are spent
at runtime). All replay beats, guard rulings,
terminal closes, and fleet counters are genuinely emitted by the
pipeline; the only substitution is where the model text comes from.

Disclosure: verdict/supervisor prose on seeded demo tenants is scripted
playback, not live inference. Never present demo films as live model
output.

## Pieces

- `vendor_goldens.py` — regenerates `corpus/goldens/` (checksummed
  snapshot of soctalk-goldens `data_m0`; see MANIFEST.json). Requires the
  sibling checkout; goldens data dirs are gitignored there by design.
- `families.py` — authored event families + goldens-derived cases, built
  to the product's verified gates (severity/MITRE bands, rule-202
  operational groups, live authz-binding vocabulary action=rule_id).
- `provider.py` — the scripted provider. `uvicorn provider:app --port 8091`
  (env `SEED_MANIFEST` points at the manifest `seed.py` writes).
- `seed.py` — `run` (plan → manifest → facts → inject) and `verify`
  (fleet-day/live counters via the MSSP API).

## Local rehearsal (verify-skill stack)

1. Stand up Postgres+API per `.claude/skills/verify/SKILL.md`; seed an
   admin, create a tenant, mint an adapter + worker token.
2. `uvicorn provider:app --port 8091` (from this directory).
3. Run the worker pointed only at the stub. TWO env gotchas that are the
   actual cost-safety mechanism (learned the hard way):
   - `uv run --no-env-file` AND `ANTHROPIC_API_KEY=` (empty): the app calls
     `load_dotenv()` itself, so `--no-env-file` alone doesn't stop soctalk's
     `.env` from leaking `ANTHROPIC_API_KEY` and tripping the provider
     mutual-exclusion check. python-dotenv won't override an already-set
     (empty) var, so exporting it empty defeats the leak.
   - Full env: `ANTHROPIC_API_KEY= OPENAI_API_KEY=sk-demo
     SOCTALK_LLM_PROVIDER=openai OPENAI_BASE_URL=http://127.0.0.1:8091/v1
     SOCTALK_FAST_MODEL=demo-playback SOCTALK_REASONING_MODEL=demo-playback
     SOCTALK_API_URL=... WORKER_TOKEN_PATH=... uv run --no-env-file python
     -m soctalk.runs_worker.main`
4. `seed.py run --tenant-id ... --adapter-token ...`, wait for the worker
   to drain, then `seed.py verify ...`.

## Demo box runbook (demo.soctalk.ai)

Order matters: seed FIRST, then start the worker (the worker is
tenant-bound, not seed-bound — starting it before injection risks it
claiming pre-existing organic runs).

0. **Backup first — non-negotiable**:
   `ssh root@demo.soctalk.ai "kubectl exec -n soctalk-system soctalk-system-postgres-0 -- pg_dump -U soctalk_admin -d soctalk --clean --if-exists | gzip -9 > /root/soctalk-demo-backup-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"`
   and copy it off-box (kept in `~/Development/wa/soctalk-backups/`).
   **Rollback**: `gunzip -c <backup>.sql.gz | ssh root@demo.soctalk.ai "kubectl exec -i -n soctalk-system soctalk-system-postgres-0 -- psql -U soctalk_admin -d soctalk"`.
1. Scale the in-cluster worker down (its env points at real LLMs):
   `kubectl scale deploy/soctalk-runs-worker -n tenant-demo --replicas=0`.
2. **No-organic-runs gate**: our worker would close any
   pre-existing claimable run with a generic benign rationale. Confirm
   none exist for the demo tenant BEFORE starting it:
   `kubectl exec -n soctalk-system soctalk-system-postgres-0 -- psql -U soctalk_admin -d soctalk -c "SELECT count(*) FROM investigation_runs WHERE status='active';"`
   — must be 0 after the seed injects (see step 6). If organic active
   investigations exist on this tenant, do not proceed.
3. SSH-tunnel the API service:
   `ssh -L 8000:$(kubectl get svc -n soctalk-system soctalk-system-api -o jsonpath='{.spec.clusterIP}'):8000 root@demo.soctalk.ai`
   (adjust svc name/port to the chart).
4. Mint adapter + worker tokens with the install signing key
   (`kubectl get secret` in soctalk-system; `mint_adapter_token`/`mint_worker_token`).
5. Start `provider.py` locally (port 8091).
6. `seed.py run ... --api http://127.0.0.1:8000 --tz <audience-tz>` —
   injects alerts + facts and publishes the manifest atomically; creates
   the promoted runs. **Set `--tz` to the demo audience's timezone**
   (e.g. `America/Los_Angeles`): the fleet time-lapse windows on the
   *browser's* local day and closes are stamped at seed time, so a
   UTC-window seed viewed from another timezone splits arrivals and
   close counters across two lapse days (verified locally: UTC window →
   8/264 dots on "today"; tz-aligned window → 261/261 dots + all
   counters on one day, 19 distinct arrival hours).
7. Start the cost-safe worker via the launcher (scrubbed env + preflight
   that ABORTS unless every resolved tier points at the stub):
   `STUB=http://127.0.0.1:8091/v1 API=http://127.0.0.1:8000
   WORKER_TOKEN=/tmp/seed-worker-token scripts/demo-seed/run_worker.sh`
   Watch it drain; then `seed.py verify ...`; spot-check the UI.
8. Stop the local worker + provider; scale the in-cluster worker back:
   `kubectl scale deploy/soctalk-runs-worker -n tenant-demo --replicas=1`.

Cost guarantee: `run_worker.sh` starts the worker under
`env -i` with ONLY the stub vars, sets `ANTHROPIC_API_KEY=` empty, and runs
`preflight.py` which resolves every tier through the product's own config
loader and refuses to launch unless each one's base URL is the stub — so a
leaked per-tier var (`SOCTALK_FAST_BASE_URL=…modal…`, `SOCTALK_REASONING_
API_KEY=sk-ant-…`) cannot route a paid call. Stub-unreachable fails closed
(the run is marked failed), never falling back to a real provider.

## Validated distribution (local, seed=1, --noise 200)

260 alerts/day →
- 115 ingest rules-band closes (deterministic, no model)
- 12 operational closes (rule 202, in-graph, no model)
- 119 reasoning closes (scripted verdicts + reopened-then-re-closed noise)
- 14 escalations to the human queue, of which **14 are guard vetoes** —
  the model scripted `close` on a sudo case whose grant does not cover the
  activity, and the REAL verdict guard overrode it to `escalate`
  (`authz_class=contradicted`). This is the flagship trust beat, produced
  by the genuine guard, not scripted.
- reopen (~105) + attached (~42) recurrence texture across the day.
- $0 spend, 0 API tokens, 0 GPU minutes.

Known minor: a few self-escalate-family alerts fall to the generic close
fallback rather than self-escalating (the guard-veto path already supplies
ample human-lane volume). Refine the manifest host-key match if a larger
self-escalate share is wanted.

## Not yet wired (deliberate)

- Memoized-close volume: `verdict_memoization_enabled` defaults off in
  install policy; events already carry `template_hash`, so enabling the
  policy later makes repeat shapes memoize for free.
- Continuous daily driver (CronJob) and multi-tenant profiles.
