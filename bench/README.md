# Open-model triage benchmark (Modal + SGLang)

Qualifies open models (Qwen3-14B, Qwen3-32B, DeepSeek-R1-Distill-Qwen-32B) against
soctalk's triage output contract, using Modal's serverless GPUs so there's no
cluster to run. Each model is served by SGLang behind an OpenAI-compatible
endpoint — the same surface the future in-cluster self-hosted tier (#13) and the
`InferenceRequest` self-hosted path (#32) will use — and soctalk's existing
triage eval (`soctalk.evals.triage`) is pointed at it.

Because the eval drives the real supervisor and verdict nodes over the
*fabricated* golden alerts in `evals/golden_alerts.yaml`, no real tenant data
leaves the machine.

## What it measures

Per model, over the golden set:
- **routing accuracy** — does the supervisor pick an acceptable next action;
- **verdict accuracy** — does the verdict node pick an acceptable disposition within the confidence band;
- **schema errors** — how many trials failed because the model could not produce
  a valid `SupervisorDecision` / `VerdictDraft` at all (the key open-model risk;
  distinct from a wrong-but-valid answer).

## Prerequisites

- `modal` CLI authenticated: `modal token set --token-id ak-... --token-secret as-...`
  (or `modal setup`). Nothing secret is stored in this repo.
- The soctalk `.venv` active (the runner shells out to `python -m soctalk.evals.triage`).
- A Modal workspace with GPU access (the lineup uses one `A100-80GB` at a time).

## Run

```bash
# Validate the whole pipeline cheaply on one model first:
python bench/run_bench.py --smoke

# Full lineup, writing raw results:
python bench/run_bench.py --out bench/results.json

# One model, 3 trials for consistency:
python bench/run_bench.py --models Qwen/Qwen3-32B --trials 3
```

The runner deploys each model, waits out the cold start (weight load is minutes),
runs the eval, then `modal app stop`s it to release the GPU. Pass `--keep-up` to
leave endpoints warm between models (faster, but keeps billing).

## Cost

Each model holds one `A100-80GB` for the duration of weight load plus the eval
(roughly 10–20 minutes on a cold cache; faster once weights are cached in the
`soctalk-hf-cache` Modal Volume). The endpoint scales to zero after 5 idle
minutes. Watch actual spend in the Modal dashboard.

## Files

- `modal/sglang_service.py` — the Modal app; serves one model (env-selected) via
  `sglang.launch_server` with `response_format` JSON-schema (XGrammar) structured
  output and per-model tool-call / reasoning parsers.
- `run_bench.py` — the orchestrator (deploy → warm → eval → stop → compare).

## Notes

- The DeepSeek-R1 distill emits long chain-of-thought before its answer. Triage's
  token budgets are tight (router 1024, verdict 2048), so watch for schema errors
  caused by reasoning that overruns the budget before the structured answer — that
  is itself a finding, and the argument for the reason-then-extract path in #32.
- To pin a different SGLang build, set `SGLANG_IMAGE_TAG` (default `v0.5.8`).
