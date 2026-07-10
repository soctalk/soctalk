#!/usr/bin/env python3
"""Benchmark open models on Modal against soctalk's triage eval.

For each model in the lineup this:
  1. deploys the SGLang Modal app for that model (bench/modal/sglang_service.py),
  2. waits for the endpoint to finish cold-starting (weight load can take minutes),
  3. runs `python -m soctalk.evals.triage --json` pointed at the endpoint,
  4. stops the Modal app to release the GPU,
and prints a comparison table (routing / verdict accuracy + schema-error counts).

The eval drives the *real* supervisor and verdict nodes over the fabricated
golden alerts — no real tenant data leaves the machine — so this measures
whether a model can actually hold soctalk's triage output contract.

Usage (from repo root, inside the .venv):
    python bench/run_bench.py --smoke           # just Qwen3-14B, validate the pipeline
    python bench/run_bench.py                    # full lineup
    python bench/run_bench.py --models Qwen/Qwen3-32B

Prereqs: `modal` CLI authenticated (`modal token set ...`); the soctalk .venv
active so the eval imports resolve.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE = REPO_ROOT / "bench" / "modal" / "sglang_service.py"

LINEUP = [
    "Qwen/Qwen3-14B",
    "Qwen/Qwen3-32B",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
]

# GPU spec per model, for display and to decide whether a CPU pre-download is
# worth it (big multi-GPU models). Mirrors MODEL_CONFIGS in the service.
GPU_BY_MODEL = {
    "Qwen/Qwen3-14B": "A100-80GB",
    "Qwen/Qwen3-32B": "A100-80GB",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B": "A100-80GB",
    "Qwen/Qwen3-235B-A22B-Thinking-2507-FP8": "H100:4",
    "deepseek-ai/DeepSeek-V4-Flash": "H100:4",
}

WEB_URL_RE = re.compile(r"https://[^\s]+\.modal\.run")


def _slug(model: str) -> str:
    return model.split("/")[-1].lower().replace(".", "-").replace("_", "-")


def _app_name(model: str) -> str:
    return f"soctalk-sglang-{_slug(model)}"


def predownload(model: str) -> None:
    """Pre-stage weights into the Volume on a cheap CPU box so the GPU server
    isn't billing during the (multi-hundred-GB) download."""
    env = {**os.environ, "SGLANG_MODEL": model}
    print("  pre-downloading weights (CPU) ...", flush=True)
    proc = subprocess.run(
        ["modal", "run", f"{SERVICE}::download"],
        env=env, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"weight pre-download failed for {model}:\n{proc.stdout}\n{proc.stderr}")
    print("  weights cached", flush=True)


def deploy(model: str, api_key: str) -> str:
    """Deploy the Modal app for `model`; return the web endpoint URL."""
    env = {**os.environ, "SGLANG_MODEL": model, "SGLANG_API_KEY": api_key}
    print(f"  deploying {_app_name(model)} ...", flush=True)
    proc = subprocess.run(
        ["modal", "deploy", str(SERVICE)],
        env=env, capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"modal deploy failed for {model}:\n{out}")
    m = WEB_URL_RE.search(out)
    if not m:
        raise RuntimeError(f"could not find web URL in modal deploy output:\n{out}")
    url = m.group(0).rstrip("/")
    print(f"  endpoint: {url}", flush=True)
    return url


def wait_ready(url: str, api_key: str, timeout_s: int = 45 * 60) -> None:
    """Poll until the SGLang server has finished loading (forward pass OK)."""
    deadline = time.time() + timeout_s
    health = f"{url}/health_generate"
    print("  warming (weight load can take several minutes) ", end="", flush=True)
    while time.time() < deadline:
        try:
            req = urllib.request.Request(health, method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                if r.status == 200:
                    print(" ready", flush=True)
                    return
        except urllib.error.HTTPError as e:
            # An auth layer responding (401/403) still means the server is up.
            if e.code in (401, 403):
                print(" ready (authed)", flush=True)
                return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        print(".", end="", flush=True)
        time.sleep(10)
    raise TimeoutError(f"endpoint {url} not ready within {timeout_s}s")


def run_eval(model: str, url: str, api_key: str, trials: int, concurrency: int) -> dict:
    env = {
        **os.environ,
        "SOCTALK_LLM_PROVIDER": "openai",
        "OPENAI_BASE_URL": f"{url}/v1",
        "OPENAI_API_KEY": api_key,
        "SOCTALK_FAST_MODEL": model,
        "SOCTALK_REASONING_MODEL": model,
        # Do not let a threshold miss abort the sweep; we collect all scores.
        "SOCTALK_EVAL_ROUTING_THRESHOLD": "0",
        "SOCTALK_EVAL_VERDICT_THRESHOLD": "0",
    }
    # soctalk rejects both provider keys being set at once, and its config
    # loader calls load_dotenv() which would re-read ANTHROPIC_API_KEY from the
    # repo .env. dotenv uses override=False, so a present-but-empty value both
    # blocks the .env re-add and reads as "no key" — forcing the SGLang path.
    env["ANTHROPIC_API_KEY"] = ""
    env["ANTHROPIC_BASE_URL"] = ""
    print(f"  running triage eval against {model} ...", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "soctalk.evals.triage",
         "--json", "--label", model, "--trials", str(trials),
         "--concurrency", str(concurrency)],
        env=env, capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # Human scorecard is on stderr; JSON on stdout.
    sys.stderr.write(proc.stderr)
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as e:
        raise RuntimeError(f"could not parse eval JSON for {model}: {e}\nstdout:\n{proc.stdout}")


def stop(model: str) -> None:
    subprocess.run(["modal", "app", "stop", _app_name(model)],
                   capture_output=True, text=True)
    print(f"  stopped {_app_name(model)}", flush=True)


def print_table(rows: list[dict]) -> None:
    print("\n" + "=" * 92)
    print("BENCHMARK COMPARISON  (soctalk triage golden set)")
    print("=" * 92)
    hdr = f"{'model':44s} {'routing':>18s} {'verdict':>18s} {'schema-err':>10s}"
    print(hdr)
    print("-" * 92)
    for r in rows:
        s = r["result"]["summary"] if r.get("result") else {}
        rt = s.get("routing", {})
        vd = s.get("verdict", {})
        rt_s = f"{rt.get('passed', 0)}/{rt.get('total', 0)}={rt.get('accuracy', 0):.0%}" if rt else "-"
        vd_s = f"{vd.get('passed', 0)}/{vd.get('total', 0)}={vd.get('accuracy', 0):.0%}" if vd else "-"
        sch = (rt.get("schema_errors", 0) + vd.get("schema_errors", 0))
        note = "" if r.get("result") else f"  [FAILED: {r.get('error', '')[:40]}]"
        print(f"{r['model']:44s} {rt_s:>18s} {vd_s:>18s} {sch:>10d}  {r.get('gpu','')}{note}")
    print("=" * 92)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=None,
                    help="Subset of the lineup to run (default: all).")
    ap.add_argument("--smoke", action="store_true",
                    help="Validate the pipeline on Qwen3-14B only.")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--keep-up", action="store_true",
                    help="Do not stop the Modal app after each model (leaves GPUs warm).")
    ap.add_argument("--no-predownload", action="store_true",
                    help="Skip the CPU weight pre-stage (let the GPU box download weights).")
    ap.add_argument("--out", default=None, help="Write full JSON results to this path.")
    args = ap.parse_args()

    models = ["Qwen/Qwen3-14B"] if args.smoke else (args.models or LINEUP)
    api_key = "sk-bench-" + secrets.token_hex(16)

    rows: list[dict] = []
    for model in models:
        gpu = GPU_BY_MODEL.get(model, "A100-80GB")
        print(f"\n### {model}  ({gpu})")
        t0 = time.time()
        row: dict = {"model": model, "gpu": gpu}
        try:
            if not args.no_predownload:
                predownload(model)
            url = deploy(model, api_key)
            wait_ready(url, api_key)
            row["result"] = run_eval(model, url, api_key, args.trials, args.concurrency)
        except Exception as e:  # noqa: BLE001 — one model failing shouldn't sink the sweep
            row["error"] = str(e)
            print(f"  ERROR: {e}", flush=True)
        finally:
            if not args.keep_up:
                stop(model)
        row["seconds"] = round(time.time() - t0, 1)
        rows.append(row)

    print_table(rows)
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=2))
        print(f"\nfull results -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
