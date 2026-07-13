#!/usr/bin/env python3
"""Find the best PER-TIER model combination for soctalk triage.

The single-model bench (run_bench.py) showed the two tiers have different
winners — a small tight model routes best, a larger model reasons best — and
soctalk's eval scores routing and verdict INDEPENDENTLY (routing cases only hit
the fast/router tier, verdict cases only the reasoning tier). So the real
question is the best *combination*, which #4's per-tier providers let you run:
fast tier on one backend, reasoning tier on another.

This deploys each distinct self-hosted model once (kept warm), then runs the
golden eval for each (fast, reasoning) combo by wiring the SOCTALK_<TIER>_* env
(#4), including cross-provider hybrids (open fast + frontier verdict). Multiple
--trials beat single-run noise. All Modal apps are stopped at the end.

    # ANTHROPIC_API_KEY (frontier tier) + SGLANG_API_KEY (endpoint auth) in env
    python bench/run_combos.py --trials 3
    python bench/run_combos.py --trials 3 --combos open,hybrid,frontier
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_bench import ENGINES, deploy, stop, wait_ready  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# Tier specs: a self-hosted Modal HF model id, or the sentinel "frontier".
Q14 = "Qwen/Qwen3-14B"
Q32 = "Qwen/Qwen3-32B"
FRONTIER = "frontier"
FRONTIER_MODEL = "claude-sonnet-4-6"

# (label, fast_tier, reasoning_tier). Chosen from the single-model findings:
# Q14 routes 3/3 cheaply; Q32 verdicts 6/6; frontier is well-calibrated.
COMBOS: dict[str, tuple[str, str]] = {
    "open":      (Q14, Q32),        # all self-hosted: cheap router + strong verdict
    "hybrid":    (Q14, FRONTIER),   # open router + calibrated frontier verdict (the #4 thesis)
    "frontier":  (FRONTIER, FRONTIER),  # baseline
}


def _tier_env(prefix: str, model: str, urls: dict[str, str], sglang_key: str) -> dict[str, str]:
    if model == FRONTIER:
        return {f"SOCTALK_{prefix}_PROVIDER": "anthropic",
                f"SOCTALK_{prefix}_MODEL": FRONTIER_MODEL}
    return {f"SOCTALK_{prefix}_PROVIDER": "openai",
            f"SOCTALK_{prefix}_MODEL": model,
            f"SOCTALK_{prefix}_BASE_URL": f"{urls[model]}/v1",
            f"SOCTALK_{prefix}_API_KEY": sglang_key,
            f"SOCTALK_{prefix}_ENGINE": "sglang"}


def combo_env(fast: str, reasoning: str, urls: dict[str, str], sglang_key: str) -> dict:
    uses_anthropic = FRONTIER in (fast, reasoning)
    uses_openai = any(m != FRONTIER for m in (fast, reasoning))
    env = {**os.environ,
           "SOCTALK_EVAL_ROUTING_THRESHOLD": "0", "SOCTALK_EVAL_VERDICT_THRESHOLD": "0",
           # Global/default provider = the reasoning tier's (the fallback).
           "SOCTALK_LLM_PROVIDER": "anthropic" if reasoning == FRONTIER else "openai"}
    env.update(_tier_env("FAST", fast, urls, sglang_key))
    env.update(_tier_env("REASONING", reasoning, urls, sglang_key))
    # Global keys: anthropic only when a frontier tier is used; the Modal tiers
    # carry their own per-tier key, so no global OpenAI key is needed. Blank the
    # unused one so the #4 mutual-exclusion guard sees a clean single global key.
    env["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "") if uses_anthropic else ""
    env["ANTHROPIC_BASE_URL"] = ""
    env["OPENAI_API_KEY"] = ""  # per-tier keys supply the served endpoints
    env["OPENAI_BASE_URL"] = ""
    _ = uses_openai
    return env


def run_eval(label: str, env: dict, trials: int, concurrency: int) -> dict | None:
    print(f"  eval combo {label} ...", flush=True)
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "soctalk.evals.triage", "--json", "--label", label,
         "--trials", str(trials), "--concurrency", str(concurrency)],
        env=env, capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    sys.stderr.write(proc.stderr)
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        out["_elapsed_s"] = time.monotonic() - t0
        return out
    except (json.JSONDecodeError, IndexError):
        print(f"  ! {label}: no JSON from eval — skipped", flush=True)
        return None


def print_table(rows: list[dict]) -> None:
    print("\n" + "=" * 96)
    print("PER-TIER COMBINATION  (soctalk triage golden set: routing x3, verdict x6)")
    print("=" * 96)
    print(f"{'combo':10s} {'fast/router':26s} {'reasoning/verdict':26s} "
          f"{'routing':>10s} {'verdict':>10s} {'sch-err':>7s}")
    print("-" * 96)
    for r in rows:
        s = r["result"]["summary"]
        rt, vd = s.get("routing", {}), s.get("verdict", {})
        rt_s = f"{rt.get('accuracy', 0):.2f}" if rt else "-"
        vd_s = f"{vd.get('accuracy', 0):.2f}" if vd else "-"
        se = rt.get("schema_errors", 0) + vd.get("schema_errors", 0)
        print(f"{r['label']:10s} {r['fast'][:26]:26s} {r['reasoning'][:26]:26s} "
              f"{rt_s:>10s} {vd_s:>10s} {se:>7d}")
    print("-" * 96)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python bench/run_combos.py")
    p.add_argument("--combos", default="open,hybrid,frontier",
                   help="Comma-separated combo labels to run (default: all).")
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--engine", choices=sorted(ENGINES), default="sglang")
    args = p.parse_args(argv)

    engine = ENGINES[args.engine]
    sglang_key = os.getenv(engine["key_env"], "").strip()
    if not sglang_key:
        print(f"set {engine['key_env']} (endpoint auth token) first", file=sys.stderr)
        return 2

    chosen = [c.strip() for c in args.combos.split(",") if c.strip() in COMBOS]
    # Distinct self-hosted models needed across the chosen combos.
    needed = {m for c in chosen for m in COMBOS[c] if m != FRONTIER}
    if FRONTIER in {m for c in chosen for m in COMBOS[c]} and not os.getenv("ANTHROPIC_API_KEY"):
        print("a chosen combo uses the frontier tier but ANTHROPIC_API_KEY is unset",
              file=sys.stderr)
        return 2

    urls: dict[str, str] = {}
    rows: list[dict] = []
    try:
        for model in sorted(needed):
            print(f"### deploy {model}", flush=True)
            url = deploy(engine, model, sglang_key)
            wait_ready(engine, url, sglang_key)
            urls[model] = url
        for label in chosen:
            fast, reasoning = COMBOS[label]
            env = combo_env(fast, reasoning, urls, sglang_key)
            res = run_eval(label, env, args.trials, args.concurrency)
            if res is not None:
                rows.append({"label": label, "fast": fast, "reasoning": reasoning, "result": res})
    finally:
        for model in sorted(needed):
            stop(engine, model)

    if rows:
        print_table(rows)
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
