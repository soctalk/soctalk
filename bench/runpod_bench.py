#!/usr/bin/env python3
"""Continuous-batching concurrency sweep on RunPod real RTX silicon (#61).

Adjacent to bench/run_concurrency.py (which uses Modal's datacenter GPUs). RunPod
rents literal consumer cards (RTX 3090/4090/5090) on community cloud, so this gives
the real-hardware numbers the Modal A10G/L4 runs could only proxy. It rents one
GPU pod running vLLM's OpenAI-compatible server, fires the SAME sweep as the Modal
driver (reused verbatim from run_concurrency), then TERMINATES the pod in a finally
so a failure never leaves a GPU billing.

Requires RUNPOD_API_KEY in the environment (never store it in the repo).

Usage (repo root, .venv, RUNPOD_API_KEY set):
    python bench/runpod_bench.py                          # RTX 3090, DS-R1-7B
    python bench/runpod_bench.py --gpu "NVIDIA GeForce RTX 4090" --hourly 0.34
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.run_concurrency import _print_table, _sweep  # noqa: E402

REST = "https://rest.runpod.io/v1"
# Community-cloud $/hr for the cost column (verified via gpuTypes query 2026-07).
HOURLY = {
    "NVIDIA GeForce RTX 3090": 0.22,
    "NVIDIA GeForce RTX 3090 Ti": 0.27,
    "NVIDIA GeForce RTX 4090": 0.34,
    "NVIDIA GeForce RTX 5090": 0.69,
}


def _rest(key: str, method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{REST}{path}",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:800]
        raise RuntimeError(f"REST {method} {path} -> HTTP {e.code}: {detail}") from e


def deploy_pod(key: str, gpu: str, model: str, vllm_key: str, disk_gb: int) -> str:
    # vllm/vllm-openai ENTRYPOINT runs the OpenAI server; dockerStartCmd supplies
    # the flags (appended). Community cloud for the cheap consumer-card price.
    body = {
        "name": "soctalk-conc-" + gpu.split()[-1].lower(),
        "imageName": "vllm/vllm-openai:latest",
        "gpuTypeIds": [gpu],
        "gpuCount": 1,
        "cloudType": "COMMUNITY",
        "containerDiskInGb": disk_gb,
        "volumeInGb": 0,
        "ports": ["8000/http"],
        "dockerStartCmd": [
            "--model", model, "--max-model-len", "16384",
            "--gpu-memory-utilization", "0.92", "--port", "8000",
            "--api-key", vllm_key,
        ],
    }
    data = _rest(key, "POST", "/pods", body)
    pod_id = data.get("id") or (data.get("pod") or {}).get("id")
    if not pod_id:
        raise RuntimeError(f"no capacity / deploy failed for {gpu} (resp={data})")
    return pod_id


def terminate_pod(key: str, pod_id: str) -> None:
    try:
        _rest(key, "DELETE", f"/pods/{pod_id}")
        print(f"  terminated pod {pod_id}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  WARNING: terminate failed for {pod_id}: {e} — CHECK RUNPOD CONSOLE", flush=True)


def _pod_status(key: str, pod_id: str) -> str:
    try:
        d = _rest(key, "GET", f"/pods/{pod_id}")
        rt = d.get("runtime") or {}
        return (
            f"status={d.get('desiredStatus')} "
            f"uptime={rt.get('uptimeInSeconds')}s ports={rt.get('ports')}"
        )
    except Exception as e:  # noqa: BLE001
        return f"status-query-failed: {e}"


def wait_ready(key: str, pod_id: str, url: str, vllm_key: str, timeout_s: int = 30 * 60) -> None:
    deadline = time.time() + timeout_s
    health = f"{url}/v1/models"
    print("  warming (image pull + model download + vLLM load)", flush=True)
    i = 0
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                health, headers={"Authorization": f"Bearer {vllm_key}"}
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                if r.status == 200:
                    print("  ready", flush=True)
                    return
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        i += 1
        if i % 4 == 0:  # every ~60s, surface where the pod actually is
            elapsed = int(time.time() - (deadline - timeout_s))
            print(f"  [{elapsed}s] {_pod_status(key, pod_id)}", flush=True)
        time.sleep(15)
    raise TimeoutError(f"pod endpoint {url} not ready within {timeout_s}s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gpu", default="NVIDIA GeForce RTX 3090")
    ap.add_argument("--model", default="deepseek-ai/DeepSeek-R1-Distill-Qwen-7B")
    ap.add_argument("--requests", type=int, default=16)
    ap.add_argument("--concurrencies", default="1,4,8")
    ap.add_argument("--max-tokens", type=int, default=200)
    ap.add_argument("--disk-gb", type=int, default=40)
    ap.add_argument("--hourly", type=float, default=None, help="override $/hr for cost col")
    args = ap.parse_args()

    key = os.environ.get("RUNPOD_API_KEY", "").strip()
    if not key:
        print("RUNPOD_API_KEY not set", file=sys.stderr)
        return 2

    vllm_key = secrets.token_urlsafe(24)
    concurrencies = [int(x) for x in args.concurrencies.split(",")]
    hourly = args.hourly if args.hourly is not None else HOURLY.get(args.gpu, 0.5)

    print(f"gpu={args.gpu!r} model={args.model} requests={args.requests} "
          f"N={concurrencies} hourly=${hourly}/hr", flush=True)
    print("  deploying pod ...", flush=True)
    pod_id = deploy_pod(key, args.gpu, args.model, vllm_key, args.disk_gb)
    url = f"https://{pod_id}-8000.proxy.runpod.net"
    print(f"  pod={pod_id} endpoint={url}", flush=True)
    try:
        wait_ready(key, pod_id, url, vllm_key)
        # Warm-up so the first timed sweep isn't paying graph capture.
        asyncio.run(_sweep(url, vllm_key, args.model, 1, 1, args.max_tokens))
        rows = [
            asyncio.run(_sweep(url, vllm_key, args.model, args.requests, n, args.max_tokens))
            for n in concurrencies
        ]
        _print_table(rows, hourly)
    finally:
        terminate_pod(key, pod_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
