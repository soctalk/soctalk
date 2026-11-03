"""Cost-safety preflight for the demo seeder worker (issue #72).

The zero-API-token guarantee is only real if the worker CANNOT reach any
paid provider. Clearing ANTHROPIC_API_KEY is not enough: per-tier env
(SOCTALK_<TIER>_PROVIDER/_BASE_URL/_API_KEY/_ENGINE) can independently
point a tier at Anthropic or the Modal Qwen endpoint, and the presence of
tier config even relaxes the provider mutual-exclusion check.

This asserts, against the FULLY LOADED soctalk config (which itself calls
load_dotenv, so it sees any leak), that every resolved tier's base URL is
the local stub. Exit non-zero — and loud — otherwise. Run it immediately
before the worker, in the same environment.

    ALLOWED_STUB=http://127.0.0.1:8091/v1 python preflight.py
"""

from __future__ import annotations

import os
import sys

STUB = os.environ.get("ALLOWED_STUB", "http://127.0.0.1:8091/v1")


def _fail(msg: str) -> None:
    print(f"PREFLIGHT FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    # 1. Raw-env scan: any tier or global provider var that is NOT the stub
    #    is a potential paid egress. Fail closed on anything suspicious.
    suspicious = []
    for k, v in os.environ.items():
        ku = k.upper()
        is_tier_or_global = (
            ku.startswith("SOCTALK_FAST_")
            or ku.startswith("SOCTALK_REASONING_")
            or ku.startswith("SOCTALK_CHAT_")
            or ku.startswith("SOCTALK_EXTRACTION_")
            or ku in ("OPENAI_BASE_URL", "SOCTALK_LLM_PROVIDER")
        )
        if not is_tier_or_global:
            continue
        if ku.endswith("_BASE_URL") or ku == "OPENAI_BASE_URL":
            if v and STUB not in v:
                suspicious.append(f"{k}={v} (not the stub)")
        if ku.endswith("_API_KEY") and v and v != os.environ.get("OPENAI_API_KEY"):
            suspicious.append(f"{k} set to a non-stub key")
    if os.environ.get("ANTHROPIC_API_KEY"):
        suspicious.append("ANTHROPIC_API_KEY is set (must be empty/unset)")
    if suspicious:
        _fail("real-provider env present:\n  " + "\n  ".join(suspicious))

    # 2. Loaded-config check: resolve every tier through the product's own
    #    config loader (which runs load_dotenv) and assert the stub base URL.
    try:
        from soctalk.config import load_config
        from soctalk.inference import InferenceTier, resolve_tier
    except Exception as e:  # noqa: BLE001
        _fail(f"could not import soctalk config: {e}")

    cfg = load_config()  # Config; .llm is the LLMConfig resolve_tier wants
    for tier in (InferenceTier.ROUTER, InferenceTier.REASONING):
        try:
            resolved = resolve_tier(cfg.llm, tier)
        except Exception as e:  # noqa: BLE001
            _fail(f"tier {tier} did not resolve: {e}")
        scoped = getattr(resolved, "llm_config", None)
        base = getattr(scoped, "openai_base_url", None)
        provider = getattr(scoped, "provider", None)
        if provider == "anthropic":
            _fail(f"tier {tier} resolved to anthropic (paid)")
        if not base or STUB not in str(base):
            _fail(f"tier {tier} base_url={base!r} is not the stub {STUB!r}")

    print(f"PREFLIGHT OK: all tiers resolve to the stub {STUB}")


if __name__ == "__main__":
    main()
