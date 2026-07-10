"""Correlation scorer spike gate (issue #30).

The issue mandates an offline replay with MANUALLY labeled same/different-
incident pairs before any production scorer — an unlabeled replay can't
measure false-attach precision (the riskiest number). This harness loads
the golden pairs, computes the scorer's entity_jaccard on each, sweeps a
threshold, and reports precision/recall so a human can pick theta_attach
and decide whether the scorer has earned enforcement.

    python -m soctalk.evals.correlation
    python -m soctalk.evals.correlation --min-precision 0.95

Exits non-zero if no threshold reaches --min-precision (default 0.9) at
non-trivial recall — the gate that keeps the scorer review-only until it
provably separates same- from different-incident pairs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from soctalk.core.ir.scorer import entity_jaccard

DEFAULT_PAIRS = Path(__file__).resolve().parents[3] / "evals" / "correlation_pairs.yaml"


def load_pairs(path: Path | str = DEFAULT_PAIRS) -> list[dict]:
    raw = yaml.safe_load(Path(path).read_text())
    out = []
    for p in raw["pairs"]:
        out.append({
            "id": p["id"],
            "same": bool(p["same_incident"]),
            "a": [tuple(k) for k in p["a"]],
            "b": [tuple(k) for k in p["b"]],
        })
    return out


def score_pairs(pairs: list[dict]) -> list[dict]:
    scored = []
    for p in pairs:
        s = entity_jaccard(p["a"], p["b"])
        scored.append({**p, "score": s})
    return scored


def sweep(scored: list[dict], steps: int = 21) -> list[dict]:
    """Threshold sweep — precision/recall of 'score >= theta => same'."""
    rows = []
    for i in range(steps):
        theta = i / (steps - 1)
        tp = sum(1 for s in scored if s["same"] and s["score"] >= theta)
        fp = sum(1 for s in scored if not s["same"] and s["score"] >= theta)
        fn = sum(1 for s in scored if s["same"] and s["score"] < theta)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        rows.append({"theta": round(theta, 3), "tp": tp, "fp": fp, "fn": fn,
                     "precision": round(precision, 3), "recall": round(recall, 3)})
    return rows


def best_threshold(sweep_rows: list[dict], min_precision: float) -> dict | None:
    """Highest-recall threshold that meets the precision floor."""
    ok = [r for r in sweep_rows if r["precision"] >= min_precision and r["recall"] > 0]
    if not ok:
        return None
    return max(ok, key=lambda r: (r["recall"], -r["theta"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m soctalk.evals.correlation")
    parser.add_argument("--pairs", default=str(DEFAULT_PAIRS))
    parser.add_argument("--min-precision", type=float, default=0.9)
    args = parser.parse_args(argv)

    pairs = load_pairs(args.pairs)
    scored = score_pairs(pairs)
    rows = sweep(scored)

    print("\n" + "=" * 68)
    print("CORRELATION SCORER SPIKE GATE")
    print("=" * 68)
    for s in sorted(scored, key=lambda x: -x["score"]):
        mark = "SAME" if s["same"] else "DIFF"
        print(f"  {mark}  score={s['score']:.3f}  {s['id']}")
    print("-" * 68)
    print("  theta  precision  recall  (tp/fp/fn)")
    for r in rows:
        if r["recall"] > 0:
            print(f"  {r['theta']:.2f}    {r['precision']:.3f}      {r['recall']:.3f}"
                  f"   ({r['tp']}/{r['fp']}/{r['fn']})")
    best = best_threshold(rows, args.min_precision)
    print("-" * 68)
    if best is None:
        print(f"GATE FAIL: no threshold reaches precision >= {args.min_precision} "
              f"at non-zero recall. Scorer stays review-only.")
        print("=" * 68)
        return 1
    print(f"GATE PASS: theta={best['theta']} → precision {best['precision']}, "
          f"recall {best['recall']}. Candidate theta_attach for enforcement.")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
