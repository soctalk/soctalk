"""Scripted OpenAI-compatible provider (issue #72 demo seeding).

Deterministic playback of pre-authored triage responses — ZERO runtime
inference, no API tokens, no GPU. Serves the exact contract the product's
inference layer speaks for engine=openai_compatible (verified against
langchain_openai's function_calling path):

- POST /v1/chat/completions with tools + forced tool_choice
  (SupervisorDecision | ConstrainedSupervisorDecision | VerdictDraft)
- response: assistant message with tool_calls[0].function.{name,arguments}
  echoing the forced tool name, finish_reason="tool_calls". Usage is
  reported as ZERO: playback is not inference, and fake usage gets priced
  by the real cost governor (it tripped the demo box's $15/day tenant cap
  and froze run claims mid-drain).

Routing: the seeder writes a manifest (JSON: script-key → play) before
injecting; script keys are unique host tokens that appear verbatim in the
supervisor/verdict prompts. Router calls advance a per-key route counter
(INVESTIGATE → VERDICT); verdict calls return the authored VerdictDraft.

Unmatched verdict prompts get GENERIC_VERDICT, a benign close whose
rationale is explicitly marked as playback (so it can never be mistaken
for real analysis). This is correct on the seeded tenant, where the
in-cluster worker is scaled to zero and every reasoning call is either
ours or a reopened benign item. IMPORTANT: this worker is tenant-bound,
not seed-bound — before starting it against a live tenant, ensure there
are no pre-existing/organic claimable runs, or it will close them with
this generic rationale. The bootstrap runbook enforces this.

Run: uvicorn provider:app --port 8091   (manifest path via SEED_MANIFEST)
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

app = FastAPI()

MANIFEST_PATH = Path(os.environ.get("SEED_MANIFEST", Path(__file__).parent / "manifest.json"))
_manifest: dict[str, Any] = {}
_manifest_mtime = 0.0
_route_counts: dict[str, int] = defaultdict(int)

# Default for un-manifested reasoning calls. On the seeded demo tenant the
# in-cluster worker is scaled to zero, so EVERY alert reaching the reasoning
# tier is one of ours — and an un-manifested one is a benign item that
# recurred and reopened (reopen starts a fresh run). Re-closing it is the
# correct, honest disposition; escalating would flood the queue with noise.
GENERIC_VERDICT = {
    "decision": "close",
    "confidence": 0.86,
    "threat_assessment": "Recurring low-severity activity consistent with the prior benign disposition for this pattern.",
    "evidence_strength": "moderate",
    "potential_impact": "low",
    "urgency": "routine",
    "key_evidence": ["pattern previously assessed benign; recurrence carries no new indicators"],
    "gaps_in_evidence": ["full command/session context not captured by the decoder"],
    "assumptions_made": ["[demo playback] no curated assessment matched this alert shape"],
    "alternative_explanations": ["an operator repeating a routine task"],
    "recommendation": "Close as recurring benign activity; the reopen window continues to guard drift.",
}


def _load_manifest() -> dict[str, Any]:
    global _manifest, _manifest_mtime
    try:
        mtime = MANIFEST_PATH.stat().st_mtime
        if mtime != _manifest_mtime:
            _manifest = json.loads(MANIFEST_PATH.read_text())
            _manifest_mtime = mtime
    except FileNotFoundError:
        _manifest = {}
    return _manifest


def _prompt_text(body: dict) -> str:
    parts = []
    for m in body.get("messages", []):
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            parts.extend(p.get("text", "") for p in c if isinstance(p, dict))
    return "\n".join(parts)


def _match_key(text: str) -> str | None:
    for key in _load_manifest():
        if key in text:
            return key
    return None


def _schema_name(body: dict) -> str | None:
    """The forced structured-output schema, from whichever mechanism the
    client used: function_calling (tools + tool_choice, dict OR bare-string
    name) or json_schema response_format."""
    tc = body.get("tool_choice")
    if isinstance(tc, dict):
        name = (tc.get("function") or {}).get("name")
        if name:
            return name
    elif isinstance(tc, str) and tc not in ("auto", "required", "none"):
        return tc
    rf = body.get("response_format")
    if isinstance(rf, dict) and rf.get("type") == "json_schema":
        name = (rf.get("json_schema") or {}).get("name")
        if name:
            return name
    # vLLM guided decoding carries the schema in extra_body.structured_outputs
    # (not response_format) — support it so a tier that resolves engine=vllm
    # is still served rather than falling to the plain-completion branch.
    eb = body.get("extra_body") or {}
    so = eb.get("structured_outputs") if isinstance(eb, dict) else None
    if isinstance(so, dict):
        name = (so.get("json") or {}).get("title") or so.get("name")
        if name:
            return name
    tools = body.get("tools") or []
    if len(tools) == 1:
        return (tools[0].get("function") or {}).get("name")
    return None


def _tool_response(model: str, tool_name: str, args: dict, prompt_len: int) -> dict:
    # Return the payload BOTH as a tool_call (function_calling parser) AND as
    # message content JSON (json_schema/json_mode parser) — the product's
    # structured-output path varies by resolved decoding mode, and satisfying
    # both makes the stub robust to either.
    completion = json.dumps(args)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": completion,
                    "tool_calls": [
                        {
                            "id": f"call_{uuid.uuid4().hex[:16]}",
                            "type": "function",
                            "function": {"name": tool_name, "arguments": completion},
                        }
                    ],
                },
            }
        ],
        # Zero usage: playback is not inference. Non-zero fake usage gets
        # priced by the real cost governor and can trip the tenant daily
        # spend circuit breaker (observed on the demo box: $15 cap hit by
        # phantom spend, claims frozen mid-drain).
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }


def _supervisor_args(key: str | None, text: str) -> dict:
    play = _load_manifest().get(key or "", {})
    route = play.get("route") or ["INVESTIGATE", "VERDICT"]
    counter_key = key or f"generic:{hash(text[:200]) & 0xFFFF}"
    step = _route_counts[counter_key]
    _route_counts[counter_key] += 1
    action = route[step] if step < len(route) else "VERDICT"
    reasoning = {
        "INVESTIGATE": "Pull the surrounding log context before drawing any conclusion.",
        "ENRICH": "Check reputation on the involved observables.",
        "CONTEXTUALIZE": "Consult threat intelligence before weighing the evidence.",
        "VERDICT": "Evidence is sufficient for a decision.",
        "CLOSE": "Deterministic disposition applies.",
    }.get(action, "Proceeding with triage.")
    return {
        "next_action": action,
        "action_reasoning": reasoning,
        "tp_confidence": 0.5 if action != "VERDICT" else 0.4,
        "confidence_reasoning": "Confidence tracks the evidence gathered so far.",
        "specific_instructions": None,
    }


@app.get("/v1/models")
async def models() -> dict:
    return {"object": "list", "data": [{"id": "demo-playback", "object": "model"}]}


@app.post("/v1/chat/completions")
async def chat(request: Request) -> dict:
    body = await request.json()
    text = _prompt_text(body)
    model = body.get("model", "demo-playback")
    schema = _schema_name(body)
    key = _match_key(text)

    if schema and "SupervisorDecision" in schema:
        return _tool_response(model, schema, _supervisor_args(key, text), len(text))
    if schema and "Verdict" in schema:
        play = _load_manifest().get(key or "", {})
        verdict = play.get("verdict") or GENERIC_VERDICT
        return _tool_response(model, schema, verdict, len(text))
    if schema:
        # Unknown forced schema: an un-modeled structured call. Return the
        # generic verdict shape (it validates VerdictDraft, the only other
        # structured schema in the graph) rather than an empty object.
        return _tool_response(model, schema, GENERIC_VERDICT, len(text))

    # Plain completion (no schema): short deterministic content.
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "Acknowledged."},
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }
