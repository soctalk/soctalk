"""Per-tenant adapter ingest settings: API schema, resolver, render, chart, adapter.

The adapter has long honoured ``SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT``,
``SOCTALK_INGEST_INITIAL_TS``, ``SOCTALK_ADAPTER_AGENT_PREFIX`` and
``SOCTALK_ADAPTER_MIN_SEVERITY`` from its environment, but nothing set them
per tenant: the manager-agent exclusion was hard-wired on for every profile,
which on a ``provided`` tenant (agent 000 = the external manager, i.e. the
cloud wodles and remote syslog) dropped every such alert while the tenant
reported healthy. These tests pin the whole path from the onboarding payload
to the rendered env var, including the ``minSeverity: 0`` chart regression
where a truthiness test silently fell back to the adapter default.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soctalk.core.api.tenants import IngestSettings, normalize_ingest_initial_ts
from soctalk.core.provisioning.render import (
    render_tenant_values,
    resolve_ingest_settings,
)
from soctalk.core.tenancy.models import IntegrationConfig
from tests.v1.test_provisioning_render import (
    _helm_template,
    _make_branding,
    _make_integration,
    _make_tenant,
    _schema_accepts,
    _tenant_values_schema,
)

# ----- normalize_ingest_initial_ts -------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_initial_ts_blank_is_none(raw):
    assert normalize_ingest_initial_ts(raw) is None


def test_initial_ts_now_resolves_once_to_absolute_utc():
    before = datetime.now(UTC)
    out = normalize_ingest_initial_ts("now")
    after = datetime.now(UTC)
    assert out is not None and out.endswith("Z") and "now" not in out
    parsed = datetime.strptime(out, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    # millisecond precision: compare at that granularity
    assert before.replace(microsecond=0) <= parsed <= after


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-01-31T00:00:00Z", "2026-01-31T00:00:00.000Z"),
        ("2026-01-31T00:00:00.5Z", "2026-01-31T00:00:00.500Z"),
        ("2026-01-31T02:00:00+02:00", "2026-01-31T00:00:00.000Z"),
        (" 2026-01-31T00:00:00+00:00 ", "2026-01-31T00:00:00.000Z"),
    ],
)
def test_initial_ts_canonicalized_to_adapter_cursor_format(raw, expected):
    assert normalize_ingest_initial_ts(raw) == expected


@pytest.mark.parametrize("raw", ["2026-01-31T00:00:00", "yesterday", "2026-13-01T00:00:00Z"])
def test_initial_ts_rejects_naive_and_garbage(raw):
    with pytest.raises(ValueError):
        normalize_ingest_initial_ts(raw)


# ----- IngestSettings schema -------------------------------------------------


def test_ingest_settings_defaults_are_all_none():
    s = IngestSettings()
    assert s.model_dump() == {
        "exclude_manager_agent": None,
        "initial_ts": None,
        "agent_prefix": None,
        "min_severity": None,
    }


def test_ingest_settings_normalizes_prefix_and_ts():
    s = IngestSettings(agent_prefix="  linux-ep-  ", initial_ts="2026-01-31T01:00:00+01:00")
    assert s.agent_prefix == "linux-ep-"
    assert s.initial_ts == "2026-01-31T00:00:00.000Z"
    assert IngestSettings(agent_prefix="   ").agent_prefix is None


@pytest.mark.parametrize("sev", [-1, 16])
def test_ingest_settings_severity_bounds(sev):
    with pytest.raises(ValidationError):
        IngestSettings(min_severity=sev)


def test_ingest_settings_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        IngestSettings(exclude_manager=True)  # type: ignore[call-arg]


# ----- resolver ---------------------------------------------------------------


def _integration(**overrides) -> IntegrationConfig:
    cfg = IntegrationConfig(
        tenant_id=uuid4(), llm_base_url="https://api.openai.com/v1", llm_model="gpt-4o"
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def test_resolver_defaults_by_profile(monkeypatch):
    monkeypatch.delenv("SOCTALK_ADAPTER_MIN_SEVERITY", raising=False)
    provided = resolve_ingest_settings(_integration(), "provided")
    managed = resolve_ingest_settings(_integration(), "poc")
    assert provided["exclude_manager_agent"] is False
    assert managed["exclude_manager_agent"] is True
    assert provided["min_severity"] == managed["min_severity"] == 10
    assert provided["initial_ts"] is None and provided["agent_prefix"] is None


def test_resolver_install_severity_env_and_clamp(monkeypatch):
    monkeypatch.setenv("SOCTALK_ADAPTER_MIN_SEVERITY", "7")
    assert resolve_ingest_settings(_integration(), "provided")["min_severity"] == 7
    monkeypatch.setenv("SOCTALK_ADAPTER_MIN_SEVERITY", "99")
    assert resolve_ingest_settings(_integration(), "provided")["min_severity"] == 15
    monkeypatch.setenv("SOCTALK_ADAPTER_MIN_SEVERITY", "not-a-number")
    assert resolve_ingest_settings(_integration(), "provided")["min_severity"] == 10


def test_resolver_columns_override_defaults(monkeypatch):
    monkeypatch.setenv("SOCTALK_ADAPTER_MIN_SEVERITY", "10")
    cfg = _integration(
        wazuh_ingest_exclude_manager_agent=True,
        wazuh_ingest_min_severity=0,
        wazuh_ingest_initial_ts="2026-01-31T00:00:00.000Z",
        wazuh_ingest_agent_prefix="linux-ep-",
    )
    eff = resolve_ingest_settings(cfg, "provided")
    assert eff == {
        "exclude_manager_agent": True,
        "min_severity": 0,  # 0 is a real value, not "unset"
        "initial_ts": "2026-01-31T00:00:00.000Z",
        "agent_prefix": "linux-ep-",
    }
    # And the other direction: a managed profile can opt IN to agent 000.
    cfg2 = _integration(wazuh_ingest_exclude_manager_agent=False)
    assert resolve_ingest_settings(cfg2, "persistent")["exclude_manager_agent"] is False


# ----- render -----------------------------------------------------------------


def _render(profile: str, integration: IntegrationConfig) -> dict:
    t = _make_tenant(profile)
    integration.tenant_id = t.id
    if profile == "provided":
        integration.wazuh_indexer_url = "https://indexer.siem.example.test:9200"
        integration.wazuh_api_url = "https://manager.siem.example.test:55000"
    return render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile=profile,
    )


def test_render_provided_defaults_keep_manager_agent(monkeypatch):
    monkeypatch.delenv("SOCTALK_ADAPTER_MIN_SEVERITY", raising=False)
    idx = _render("provided", _make_integration(None))["adapter"]["wazuhIndexer"]
    assert idx["excludeManagerAgent"] is False
    assert idx["minSeverity"] == 10
    assert "initialTs" not in idx and "agentPrefix" not in idx


def test_render_managed_defaults_exclude_manager_agent():
    idx = _render("poc", _make_integration(None))["adapter"]["wazuhIndexer"]
    assert idx["excludeManagerAgent"] is True


def test_render_overrides_and_schema_accept_them():
    cfg = _make_integration(None)
    cfg.wazuh_ingest_exclude_manager_agent = True
    cfg.wazuh_ingest_min_severity = 0
    cfg.wazuh_ingest_initial_ts = "2026-01-31T00:00:00.000Z"
    cfg.wazuh_ingest_agent_prefix = "linux-ep-"
    values = _render("provided", cfg)
    idx = values["adapter"]["wazuhIndexer"]
    assert idx["excludeManagerAgent"] is True
    assert idx["minSeverity"] == 0
    assert idx["initialTs"] == "2026-01-31T00:00:00.000Z"
    assert idx["agentPrefix"] == "linux-ep-"
    assert _schema_accepts(values, _tenant_values_schema())


def test_schema_rejects_bad_ingest_values():
    base = _render("provided", _make_integration(None))
    schema = _tenant_values_schema()

    def with_indexer(**extra) -> dict:
        idx = {**base["adapter"]["wazuhIndexer"], **extra}
        return {**base, "adapter": {**base["adapter"], "wazuhIndexer": idx}}

    # The literal "now" must never reach the chart: the API resolves it once.
    assert not _schema_accepts(with_indexer(initialTs="now"), schema)
    assert not _schema_accepts(with_indexer(agentPrefix=""), schema)


# ----- chart -------------------------------------------------------------------


def _adapter_env(manifests: list[dict]) -> dict[str, str]:
    for doc in manifests:
        if not doc or doc.get("kind") != "Deployment":
            continue
        if doc["metadata"]["name"] != "soctalk-adapter":
            continue
        env = doc["spec"]["template"]["spec"]["containers"][0].get("env", [])
        return {e["name"]: e.get("value") for e in env if "value" in e}
    raise AssertionError("soctalk-adapter Deployment not rendered")


def test_chart_renders_ingest_env_and_honours_zero_and_false():
    """``minSeverity: 0`` and ``excludeManagerAgent: false`` must reach the
    adapter: a truthiness test (the old ``{{ if .minSeverity }}``) dropped
    both and left the adapter on its own defaults (10 / excluded)."""
    cfg = _make_integration(None)
    cfg.wazuh_ingest_exclude_manager_agent = False
    cfg.wazuh_ingest_min_severity = 0
    cfg.wazuh_ingest_initial_ts = "2026-01-31T00:00:00.000Z"
    cfg.wazuh_ingest_agent_prefix = "linux-ep-"
    env = _adapter_env(_helm_template(_render("provided", cfg), cilium=False))
    assert env["SOCTALK_ADAPTER_MIN_SEVERITY"] == "0"
    assert env["SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT"] == "0"
    assert env["SOCTALK_INGEST_INITIAL_TS"] == "2026-01-31T00:00:00.000Z"
    assert env["SOCTALK_ADAPTER_AGENT_PREFIX"] == "linux-ep-"


def test_chart_omits_unset_ingest_keys_and_emits_true_as_1():
    values = _render("poc", _make_integration(None))
    env = _adapter_env(_helm_template(values, cilium=False))
    assert env["SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT"] == "1"
    assert "SOCTALK_INGEST_INITIAL_TS" not in env
    assert "SOCTALK_ADAPTER_AGENT_PREFIX" not in env


# ----- adapter -----------------------------------------------------------------


class _CaptureClient:
    def __init__(self):
        self.body: dict = {}

    async def post(self, url, **kw):
        self.body = kw["json"]

        class _Resp:
            def raise_for_status(self): ...

            def json(self):
                return {"hits": {"hits": []}}

        return _Resp()


async def _query(monkeypatch, **env):
    import soctalk_adapter.main as m

    for k in (
        "SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT",
        "SOCTALK_ADAPTER_AGENT_PREFIX",
        "SOCTALK_ADAPTER_MIN_SEVERITY",
    ):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example.test:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "ro")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "ro-pw")
    client = _CaptureClient()
    await m._query_alerts(client, "2026-01-31T00:00:00.000Z", None, 100)
    return client.body["query"]["bool"]


async def test_adapter_excludes_manager_agent_by_default(monkeypatch):
    q = await _query(monkeypatch)
    assert {"term": {"agent.id": "000"}} in q.get("must_not", [])


async def test_adapter_env_zero_keeps_manager_agent(monkeypatch):
    q = await _query(monkeypatch, SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT="0")
    assert "must_not" not in q


async def test_adapter_prefix_and_severity_zero(monkeypatch):
    q = await _query(
        monkeypatch, SOCTALK_ADAPTER_AGENT_PREFIX="linux-ep-", SOCTALK_ADAPTER_MIN_SEVERITY="0"
    )
    assert {"prefix": {"agent.name": "linux-ep-"}} in q["filter"]
    assert {"range": {"rule.level": {"gte": 0}}} in q["filter"]
