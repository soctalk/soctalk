#!/usr/bin/env python3
"""Realistic triage-TIME trial (#61): SocTalk's real eval over golden alerts.

Unlike run_concurrency.py (a synthetic token-throughput sweep), this drives
SocTalk's actual triage eval (`soctalk.evals.triage`) over the fabricated golden
alerts in evals/golden_alerts.yaml, at a chosen concurrency, and times the whole
thing. That is the apples-to-apples "how long does realistic triage take" number,
with real prompts and real (uncapped) reasoning output, not a fixed 200-token toy.

Two providers, identical eval, so Modal and RunPod are comparable:
  --provider modal    : deploy the model on Modal (vLLM) via run_bench, then eval, then stop.
  --provider endpoint : run the eval against an already-serving OpenAI endpoint (e.g. a RunPod pod).

Usage:
  python bench/triage_time.py --provider modal --gpu A10G --concurrency 8
  python bench/triage_time.py --provider endpoint --endpoint https://POD-8000.proxy.runpod.net \
      --api-key $VLLM_KEY --model deepseek-ai/DeepSeek-R1-Distill-Qwen-7B --concurrency 8
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from bench.run_bench import ENGINES, deploy, predownload, stop, wait_ready  # noqa: E402

GOLDEN = "evals/golden_alerts.yaml"


def _count_cases() -> int:
    import yaml
    d = yaml.safe_load(open(REPO / GOLDEN))
    cases = d.get("cases") if isinstance(d, dict) else d
    return len(cases) if hasattr(cases, "__len__") else 0


def run_timed_eval(url: str, api_key: str, model: str, concurrency: int) -> None:
    # Same env recipe run_bench uses to point the eval at a served endpoint.
    env = {
        **os.environ,
        "SOCTALK_LLM_PROVIDER": "openai",
        "OPENAI_BASE_URL": f"{url}/v1",
        "OPENAI_API_KEY": api_key,
        "SOCTALK_FAST_MODEL": model,
        "SOCTALK_REASONING_MODEL": model,
        "SOCTALK_EVAL_ROUTING_THRESHOLD": "0",
        "SOCTALK_EVAL_VERDICT_THRESHOLD": "0",
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_BASE_URL": "",
    }
    n_cases = _count_cases()
    print(
        f"  triage eval: {n_cases} golden alerts, concurrency={concurrency}, model={model}",
        flush=True,
    )
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "soctalk.evals.triage", "--json",
         "--label", model, "--concurrency", str(concurrency), "--golden", GOLDEN],
        env=env, capture_output=True, text=True, cwd=str(REPO),
    )
    wall = time.monotonic() - t0
    sys.stderr.write(proc.stderr[-2000:])
    summary = ""
    if proc.stdout.strip():
        summary = proc.stdout.strip().splitlines()[-1][:400]
    print("\n=== realistic triage time (#61) ===", flush=True)
    print(f"  cases            : {n_cases} (routing + verdict per case)")
    print(f"  concurrency      : {concurrency}")
    print(f"  TOTAL wall       : {wall:.1f} s")
    if n_cases:
        print(f"  per-case (wall/N): {wall / n_cases:.1f} s")
    print(f"  eval rc          : {proc.returncode}")
    print(f"  eval summary     : {summary}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["modal", "endpoint"], required=True)
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-R1-Distill-Qwen-7B")
    ap.add_argument("--concurrency", type=int, default=8)
    # modal-only
    ap.add_argument("--engine", default="vllm", choices=list(ENGINES))
    ap.add_argument("--gpu", default="A10G")
    ap.add_argument("--keep-up", action="store_true")
    # endpoint-only
    ap.add_argument("--endpoint", default=None)
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    if args.provider == "endpoint":
        if not args.endpoint or not args.api_key:
            print("endpoint mode needs --endpoint and --api-key", file=sys.stderr)
            return 2
        run_timed_eval(args.endpoint.rstrip("/"), args.api_key, args.model, args.concurrency)
        return 0

    # modal
    import secrets
    engine = ENGINES[args.engine]
    api_key = secrets.token_urlsafe(24)
    os.environ[engine["key_env"]] = api_key
    print(f"provider=modal engine={args.engine} gpu={args.gpu} model={args.model}", flush=True)
    predownload(engine, args.model)
    url = deploy(engine, args.model, api_key, gpu=args.gpu)
    try:
        wait_ready(engine, url, api_key)
        run_timed_eval(url, api_key, args.model, args.concurrency)
    finally:
        if not args.keep_up:
            stop(engine, args.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
