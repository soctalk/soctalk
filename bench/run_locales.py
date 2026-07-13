#!/usr/bin/env python3
"""Per-locale triage breakdown: does a model degrade on non-English alerts?

Runs the golden triage eval across locales (en/es/pt/zh — see
evals/golden_i18n.py) for a given model config, and prints a locale x metric
table. Same model, same expected decisions, only the alert PROSE changes, so a
per-locale accuracy or confidence drop measures the model's multilingual triage
ability — the language axis of the Chinese/open-model program (Codex idea #16).

Reuses the model lineup + env wiring from run_hosted.py (frontier / DeepSeek /
Qwen). Frontier needs only ANTHROPIC_API_KEY (no GPU):

    python bench/run_locales.py --only frontier
    python bench/run_locales.py --only deepseek-chat        # needs DEEPSEEK_API_KEY
    python bench/run_locales.py --only frontier --trials 3
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_hosted import ENDPOINTS, _base_env  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
EVALS = REPO_ROOT / "evals"

# (locale label, golden file). 'en' is the untranslated source.
LOCALES = [
    ("en", EVALS / "golden_alerts.yaml"),
    ("es", EVALS / "golden_alerts.es.yaml"),
    ("pt", EVALS / "golden_alerts.pt.yaml"),
    ("zh", EVALS / "golden_alerts.zh.yaml"),
]


def run_locale(env: dict, golden: Path, label: str, trials: int, concurrency: int) -> dict | None:
    proc = subprocess.run(
        [sys.executable, "-m", "soctalk.evals.triage", "--json", "--label", label,
         "--golden", str(golden), "--trials", str(trials), "--concurrency", str(concurrency)],
        env=env, capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    sys.stderr.write(proc.stderr)
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        print(f"  ! {label}: no JSON (endpoint/auth error?)", flush=True)
        return None


def print_table(model_label: str, rows: list[dict]) -> None:
    print("\n" + "=" * 78)
    print(f"PER-LOCALE TRIAGE BREAKDOWN — {model_label}")
    print("  (same cases + expected decisions; only alert prose is translated)")
    print("=" * 78)
    print(f"{'locale':8s} {'routing':>16s} {'verdict':>16s} {'schema-err':>12s}")
    print("-" * 78)
    for r in rows:
        s = r["result"]["summary"]
        rt, vd = s.get("routing", {}), s.get("verdict", {})
        rt_s = f"{rt.get('passed', 0)}/{rt.get('total', 0)} ({rt.get('accuracy', 0):.2f})" if rt else "-"
        vd_s = f"{vd.get('passed', 0)}/{vd.get('total', 0)} ({vd.get('accuracy', 0):.2f})" if vd else "-"
        se = rt.get("schema_errors", 0) + vd.get("schema_errors", 0)
        print(f"{r['locale']:8s} {rt_s:>16s} {vd_s:>16s} {se:>12d}")
    print("-" * 78)


def _custom_env(base_url: str, model: str, key: str) -> dict:
    """Env for an arbitrary OpenAI-compatible endpoint (e.g. a Modal-served
    open model) — both tiers on it, so per-locale is measured on one model."""
    return {**os.environ,
            "SOCTALK_EVAL_ROUTING_THRESHOLD": "0", "SOCTALK_EVAL_VERDICT_THRESHOLD": "0",
            "SOCTALK_LLM_PROVIDER": "openai",
            "OPENAI_BASE_URL": base_url if base_url.endswith("/v1") else f"{base_url}/v1",
            "OPENAI_API_KEY": key, "ANTHROPIC_API_KEY": "", "ANTHROPIC_BASE_URL": "",
            "SOCTALK_FAST_MODEL": model, "SOCTALK_REASONING_MODEL": model}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python bench/run_locales.py")
    p.add_argument("--only", nargs="*", default=["frontier"],
                   help="Endpoint labels from run_hosted.py (default: frontier).")
    p.add_argument("--base-url", default=None,
                   help="Custom OpenAI-compatible endpoint (e.g. a Modal URL); needs --model + --api-key-env.")
    p.add_argument("--model", default=None, help="Model id for --base-url.")
    p.add_argument("--api-key-env", default="SGLANG_API_KEY", help="Env var with the --base-url key.")
    p.add_argument("--label", default="custom", help="Label for the --base-url run.")
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--concurrency", type=int, default=4)
    args = p.parse_args(argv)

    # Ensure the locale files exist (regenerate is cheap + keeps them in sync).
    subprocess.run([sys.executable, str(EVALS / "golden_i18n.py")],
                   capture_output=True, cwd=str(REPO_ROOT))

    # Custom-endpoint mode: sweep locales on one arbitrary served model.
    if args.base_url:
        key = os.getenv(args.api_key_env, "").strip()
        env = _custom_env(args.base_url, args.model, key)
        rows = []
        print(f"### {args.label} ({args.model})")
        for locale, golden in LOCALES:
            if not golden.exists():
                continue
            print(f"  eval {args.label} @ {locale} ...", flush=True)
            res = run_locale(env, golden, f"{args.label}-{locale}", args.trials, args.concurrency)
            if res is not None:
                rows.append({"locale": locale, "result": res})
        if rows:
            print_table(args.label, rows)
            return 0
        return 1

    rc = 0
    for ep in [e for e in ENDPOINTS if e["label"] in args.only]:
        key = os.getenv(ep["key_env"], "").strip()
        if not key:
            print(f"skip {ep['label']}: {ep['key_env']} not set")
            continue
        env = _base_env(ep, key)
        rows = []
        print(f"### {ep['label']}")
        for locale, golden in LOCALES:
            if not golden.exists():
                print(f"  skip {locale}: {golden.name} missing")
                continue
            print(f"  eval {ep['label']} @ {locale} ...", flush=True)
            res = run_locale(env, golden, f"{ep['label']}-{locale}", args.trials, args.concurrency)
            if res is not None:
                rows.append({"locale": locale, "result": res})
        if rows:
            print_table(ep["label"], rows)
        else:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
