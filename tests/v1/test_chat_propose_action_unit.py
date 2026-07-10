"""Chat agent: native propose_action tool replacing the <action> regex (#10).

The agent used to embed a proposed action as ``<action>{json}</action>`` in its
prose and regex-parse it out. Now the model CALLS a schema-enforced
propose_action tool; the loop maps the call through the same
``build_proposed_action`` validation and surfaces a confirm button. These cover
the pure mapping + the tool schema (the streaming loop itself is integration).
"""

from __future__ import annotations

from uuid import uuid4

from langchain_core.messages import AIMessage, SystemMessage

from soctalk.chat.actions import ALLOWED_ACTIONS
from soctalk.chat.agent import (
    _PROPOSE_ACTION_TOOL,
    _build_messages,
    _handle_propose_action,
)


def _valid_args(**over):
    args = {
        "action": "approve_review",
        "target": {"kind": "pending_review", "id": str(uuid4()), "title": "Review X"},
        "reason": "Confirmed-malicious IP and matching TTPs.",
        "evidence": [{"fact": "AbuseIPDB 0.97"}],
        "confidence": 0.9,
    }
    args.update(over)
    return args


# --------------------------------------------------------------- tool schema


def test_tool_schema_advertises_allowed_action_enum():
    fn = _PROPOSE_ACTION_TOOL["function"]
    assert fn["name"] == "propose_action"
    enum = fn["parameters"]["properties"]["action"]["enum"]
    assert set(enum) == set(ALLOWED_ACTIONS)
    # The confirm-only contract: no endpoint/url/body field is offered.
    props = fn["parameters"]["properties"]
    assert "endpoint" not in props and "url" not in props and "body" not in props
    assert fn["parameters"]["required"] == ["action", "target", "reason"]


# --------------------------------------------------------------- handler map


def test_handle_valid_action_builds_payload():
    tid = str(uuid4())
    payload, ack = _handle_propose_action(_valid_args(target={"kind": "pending_review", "id": tid}))
    assert payload is not None
    assert payload["type"] == "proposed_action"
    assert payload["action"] == "approve_review"
    assert payload["target"]["id"] == tid
    assert payload["confidence"] == 0.9
    assert "surfaced" in ack.lower()


def test_handle_unknown_verb_rejected_with_retry_hint():
    payload, ack = _handle_propose_action(_valid_args(action="delete_everything"))
    assert payload is None
    assert "rejected" in ack.lower()
    # The ack coaches the model to fix + retry rather than crashing the turn.
    assert "again" in ack.lower()


def test_handle_malformed_target_uuid_rejected():
    payload, ack = _handle_propose_action(
        _valid_args(target={"kind": "pending_review", "id": "not-a-uuid"})
    )
    assert payload is None
    assert "rejected" in ack.lower()


def test_handle_missing_target_rejected():
    args = _valid_args()
    del args["target"]
    payload, ack = _handle_propose_action(args)
    assert payload is None
    assert "rejected" in ack.lower()


def test_handle_confidence_clamped():
    payload, _ = _handle_propose_action(_valid_args(confidence=1.7))
    assert payload is not None
    assert payload["confidence"] == 1.0


def test_handle_strips_url_shaped_fields_via_builder():
    # build_proposed_action has no endpoint/body field — extra args are ignored,
    # so a model can't smuggle a URL target through the tool.
    payload, _ = _handle_propose_action(_valid_args())
    assert "endpoint" not in payload
    assert "url" not in payload


def test_handle_non_dict_target_rejected_not_raised():
    # A non-dict target must not raise AttributeError out of the handler (it
    # would abort the turn before the ToolMessage ack). Graceful reject instead.
    payload, ack = _handle_propose_action(_valid_args(target="not-a-dict"))
    assert payload is None
    assert "rejected" in ack.lower()


# --------------------------------------------------------- history replay


def test_prior_action_replayed_as_aimessage_not_system():
    # A persisted role='action' row must replay as an AIMessage — a non-leading
    # SystemMessage is rejected by langchain-anthropic and would break every
    # turn after the first proposed action.
    history = [
        {"role": "user", "content": {"text": "hi"}},
        {"role": "assistant", "content": {"text": "hello"}},
        {"role": "action", "content": {"action": "approve_review",
                                        "target": {"id": "abc"}}},
        {"role": "user", "content": {"text": "next"}},
    ]
    msgs = _build_messages(history, system_prompt="SYS")
    # Exactly one SystemMessage and it leads.
    assert isinstance(msgs[0], SystemMessage)
    assert sum(isinstance(m, SystemMessage) for m in msgs) == 1
    # The prior action rode in as an AIMessage.
    assert any(isinstance(m, AIMessage) and "prior_action" in m.content for m in msgs)
