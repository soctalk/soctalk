#!/usr/bin/env python3
"""Concurrency / continuous-batching benchmark for the self-hosted tier (#61).

The runs-worker now executes investigations concurrently
(``WORKER_RUN_CONCURRENCY``) so a shared vLLM/SGLang backend's continuous batch
can fill. This driver proves the payoff at the backend directly: it deploys one
open model on Modal (reusing ``run_bench``'s deploy plumbing), then fires a fixed
number of identical triage-shaped requests at the OpenAI-compatible endpoint at
increasing client concurrency and measures aggregate throughput and cost-per-
request. If continuous batching works, throughput rises and cost-per-request
falls as concurrency increases, until the batch saturates.

No tenant data leaves the machine: the prompt is a fabricated triage snippet.

Usage (repo root, inside .venv, modal authenticated):
    python bench/run_concurrency.py                      # Qwen3-14B, N in 1,4,8
    python bench/run_concurrency.py --model Qwen/Qwen3-32B --requests 24 \
        --concurrencies 1,8,16 --max-tokens 256 --keep-up
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
import time
from pathlib import Path

import httpx

# Work both as a script (``python bench/run_concurrency.py``) and as a module:
# as a script, only bench/ is on sys.path, so put the repo root there too before
# importing the shared deploy plumbing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.run_bench import ENGINES, deploy, predownload, stop, wait_ready  # noqa: E402

# Approx Modal on-demand GPU pricing ($/hr) for the cost-per-request estimate.
# Modal has no consumer RTX cards; the low-end datacenter GPUs are the faithful
# proxies for the used RTX hardware a small self-hoster would actually own:
#   T4  (16GB)      ~ an older 16GB consumer card
#   A10G (24GB,Ampere) ~ RTX 3090 (same arch + VRAM)
#   L4  (24GB, Ada) ~ RTX 4090-class (Ada arch, 24GB; lower TDP so slower)
# For literal RTX silicon, test on Vast.ai/RunPod; the batching *scaling* holds.
GPU_HOURLY = {
    "T4": 0.59, "L4": 0.80, "A10G": 1.10, "L40S": 1.95,
    "A100-80GB": 3.00, "H100": 4.50,
}
GPU_BY_MODEL = {
    "Qwen/Qwen3-14B": "L40S",
    "Qwen/Qwen3-32B": "A100-80GB",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B": "A100-80GB",
    # Fits a 24GB low-end card (RTX 3090/4090 proxy) with KV-cache room to batch.
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B": "A10G",
}

# A fixed, fabricated triage-shaped prompt so every request does comparable work.
_PROMPT = (
    "You are a SOC triage assistant. A Wazuh alert fired: rule 5710 "
    "'sshd: Attempt to login using a non-existent user' from source IP "
    "203.0.113.44 against host web-01 at 02:14 UTC, 6 times in 40 seconds. "
    "No prior authorization record is on file. In two or three sentences, "
    "state whether this is likely benign or worth escalating and why."
)


async def _one_request(
    client: httpx.AsyncClient, url: str, api_key: str, model: str, max_tokens: int
) -> int:
    """Fire one chat completion; return completion_tokens (0 on failure)."""
    resp = await client.post(
        f"{url}/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": _PROMPT}],
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "stream": False,
        },
        timeout=300.0,
    )
    resp.raise_for_status()
    body = resp.json()
    return int(body.get("usage", {}).get("completion_tokens", 0))


async def _sweep(
    url: str, api_key: str, model: str, requests: int, concurrency: int, max_tokens: int
) -> dict:
    """Run `requests` requests at `concurrency` in flight; return timing/tokens."""
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency + 2)

    async with httpx.AsyncClient(limits=limits) as client:
        async def _guarded() -> int:
            async with sem:
                return await _one_request(client, url, api_key, model, max_tokens)

        t0 = time.monotonic()
        tokens = await asyncio.gather(*(_guarded() for _ in range(requests)))
        wall = time.monotonic() - t0

    total_tokens = sum(tokens)
    return {
        "concurrency": concurrency,
        "requests": requests,
        "wall_s": round(wall, 2),
        "total_completion_tokens": total_tokens,
        "agg_tokens_per_s": round(total_tokens / wall, 1) if wall else 0.0,
    }


def _print_table(rows: list[dict], gpu_hourly: float) -> None:
    gpu_per_s = gpu_hourly / 3600.0
    base = rows[0]["agg_tokens_per_s"] or 1.0
    print("\n=== continuous-batching sweep (#61) ===")
    print(f"{'N':>3} {'wall_s':>8} {'tok/s(agg)':>11} {'speedup':>8} {'$/1k req':>10}")
    for r in rows:
        cost_per_req = gpu_per_s * r["wall_s"] / r["requests"]
        speedup = r["agg_tokens_per_s"] / base
        print(
            f"{r['concurrency']:>3} {r['wall_s']:>8.2f} {r['agg_tokens_per_s']:>11.1f} "
            f"{speedup:>7.2f}x {cost_per_req * 1000:>9.3f}"
        )
    print(
        "\nHigher N filling the batch shows as rising tok/s(agg) and falling "
        "$/1k req, until the batch saturates."
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-14B")
    ap.add_argument("--engine", default="sglang", choices=list(ENGINES))
    ap.add_argument("--requests", type=int, default=16)
    ap.add_argument("--concurrencies", default="1,4,8")
    ap.add_argument("--max-tokens", type=int, default=200)
    ap.add_argument("--gpu", default=None, help="override GPU (else per-model default)")
    ap.add_argument("--keep-up", action="store_true", help="leave the endpoint warm")
    args = ap.parse_args()

    engine = ENGINES[args.engine]
    concurrencies = [int(x) for x in args.concurrencies.split(",")]
    api_key = secrets.token_urlsafe(24)
    gpu = args.gpu or GPU_BY_MODEL.get(args.model, "A100-80GB")
    # The service module calls require_auth(SPEC) at import, so the key must be in
    # the environment for BOTH the predownload and deploy subprocesses, not just
    # passed to deploy().
    os.environ[engine["key_env"]] = api_key

    print(f"model={args.model} engine={args.engine} gpu={gpu} "
          f"requests={args.requests} N={concurrencies}")
    predownload(engine, args.model)
    url = deploy(engine, args.model, api_key, gpu=gpu)
    try:
        wait_ready(engine, url, api_key)
        # One warm-up request so the first sweep isn't paying JIT/graph-capture.
        asyncio.run(_sweep(url, api_key, args.model, 1, 1, args.max_tokens))
        rows = [
            asyncio.run(
                _sweep(url, api_key, args.model, args.requests, n, args.max_tokens)
            )
            for n in concurrencies
        ]
        _print_table(rows, GPU_HOURLY.get(gpu, 3.0))
    finally:
        if not args.keep_up:
            stop(engine, args.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
