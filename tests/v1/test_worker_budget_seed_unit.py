"""Per-run budget seed precedence in the runs-worker (issue #5).

A per-tenant cap is rendered into ``SOCTALK_CASE_RUN_{DOLLAR,TOKEN}_BUDGET`` env.
Both must give the env TOP precedence over the claim row so the tenant override
actually takes effect — previously the token seed was taken from the claim
unconditionally and the env was ignored for claimed runs (Codex).
"""

from __future__ import annotations

import pytest

from soctalk.runs_worker.main import _dollars_budget_kv, _tokens_budget_kv


def test_tokens_env_overrides_claim(monkeypatch):
    monkeypatch.setenv("SOCTALK_CASE_RUN_TOKEN_BUDGET", "50000")
    assert _tokens_budget_kv(200000) == {"tokens_budget": 50000}


def test_tokens_falls_back_to_claim_when_env_absent(monkeypatch):
    monkeypatch.delenv("SOCTALK_CASE_RUN_TOKEN_BUDGET", raising=False)
    assert _tokens_budget_kv(200000) == {"tokens_budget": 200000}


def test_tokens_non_positive_env_ignored(monkeypatch):
    # An operator typo (=0 / garbage) must not zero the budget; fall through.
    monkeypatch.setenv("SOCTALK_CASE_RUN_TOKEN_BUDGET", "0")
    assert _tokens_budget_kv(200000) == {"tokens_budget": 200000}
    monkeypatch.setenv("SOCTALK_CASE_RUN_TOKEN_BUDGET", "notanint")
    assert _tokens_budget_kv(200000) == {"tokens_budget": 200000}


def test_tokens_empty_when_nothing_positive(monkeypatch):
    monkeypatch.delenv("SOCTALK_CASE_RUN_TOKEN_BUDGET", raising=False)
    assert _tokens_budget_kv(0) == {}
    assert _tokens_budget_kv(None) == {}


def test_dollars_env_overrides_claim(monkeypatch):
    # Parity check for the pre-existing dollar path.
    monkeypatch.setenv("SOCTALK_CASE_RUN_DOLLAR_BUDGET", "2.5")
    assert _dollars_budget_kv(5.0) == {"dollars_budget": 2.5}


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
