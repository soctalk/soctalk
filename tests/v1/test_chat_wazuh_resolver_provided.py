"""Profile-aware Wazuh **manager-API** resolver tests (chat primitives).

Feature ``tenant.profile.provided.chat-manager-api``. These are pure unit
tests — no Postgres, no kube, no real network. The resolver's three I/O
seams are faked:

* the raw-SQL reads (``integration_configs`` / ``tenants`` /
  ``tenant_secrets``) via a tiny :class:`_FakeSession`;
* the cross-namespace k8s Secret read (``_k8s_secret_read``) via monkeypatch;
* the httpx manager client via an ``httpx.MockTransport`` injected through
  ``_client_kwargs``.

Coverage (acceptance bullets):

1/2/4/7 — ``provided`` resolves to ``IntegrationConfig.wazuh_api_url`` with
  creds from ``tenant-external-siem-creds`` (Bearer when ``WAZUH_API_TOKEN``
  present, else HTTP-Basic mint), verify == ``wazuh_verify_ssl``.
3/7 — ``poc`` / ``persistent`` resolution is byte-for-byte unchanged
  (in-cluster manager URL + ``wazuh-<slug>-wazuh-creds`` Secret).
5 — missing external URL / creds raises a typed error the chat tool layer
  surfaces as ``external Wazuh API not configured`` (never a raw 500).
6 — ``charts/soctalk-system`` permits API/controller egress to the external
  manager host; documented no-op when egress is unrestricted.
"""

from __future__ import annotations

import base64
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

import soctalk.chat.wazuh_primitives as wp
from soctalk.chat.wazuh_primitives import WazuhConfig


# In-cluster manager URL the controller writes for poc/persistent tenants
# (release = wazuh-<slug>, namespace = tenant-<slug>).
_IN_CLUSTER_URL = (
    "https://wazuh-acme-wazuh-manager.tenant-acme.svc.cluster.local:55000"
)
_IN_CLUSTER_INDEXER = (
    "https://wazuh-acme-wazuh-indexer.tenant-acme.svc.cluster.local:9200"
)
_EXTERNAL_URL = "https://wazuh.acme-external.example.com:55000"
_EXTERNAL_INDEXER = "https://indexer.acme-external.example.com:9200"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResult:
    """Stand-in for the object returned by ``AsyncSession.execute``."""

    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row


class _FakeSession:
    """Minimal ``AsyncSession`` for the resolver's raw-SQL reads.

    Routes by table name in the SQL text. ``tenant_secrets`` is routed
    by the hard-coded ``purpose='...'`` literal so a test can prove the
    resolver picks the *right* Secret pointer for the profile.
    """

    def __init__(
        self,
        *,
        profile=None,
        integration=None,
        wazuh_api_pointer=None,
        external_pointer=None,
    ):
        self.profile = profile
        self.integration = integration
        self.wazuh_api_pointer = wazuh_api_pointer
        self.external_pointer = external_pointer
        self.secret_purposes_queried: list[str] = []

    async def execute(self, statement, params=None):
        sql = str(statement).lower()
        if "from tenants" in sql:
            return _FakeResult(
                {"profile": self.profile} if self.profile is not None else None
            )
        if "integration_configs" in sql:
            return _FakeResult(self.integration)
        if "tenant_secrets" in sql:
            if "external-siem-creds" in sql:
                self.secret_purposes_queried.append("external-siem-creds")
                return _FakeResult(self.external_pointer)
            if "wazuh-api" in sql:
                self.secret_purposes_queried.append("wazuh-api")
                return _FakeResult(self.wazuh_api_pointer)
            return _FakeResult(None)
        return _FakeResult(None)


def _patch_secret_read(monkeypatch, creds):
    """Patch ``_k8s_secret_read`` to return ``creds`` and record calls."""
    calls: list[tuple[str, str]] = []

    async def _fake(namespace, name):
        calls.append((namespace, name))
        return dict(creds)

    monkeypatch.setattr(wp, "_k8s_secret_read", _fake)
    return calls


# ---------------------------------------------------------------------------
# Acceptance 1/2/4/7 — provided resolves to the external manager
# ---------------------------------------------------------------------------


async def test_provided_resolves_external_url_basic_creds(monkeypatch):
    """token-absent: external api_url + WAZUH_API_USERNAME/PASSWORD, no token."""
    db = _FakeSession(
        profile="provided",
        integration={
            "wazuh_api_url": _EXTERNAL_URL,
            "wazuh_indexer_url": _EXTERNAL_INDEXER,
            "wazuh_verify_ssl": False,
        },
        external_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "tenant-external-siem-creds",
        },
    )
    calls = _patch_secret_read(
        monkeypatch,
        {
            "WAZUH_API_USERNAME": "ext-api-user",
            "WAZUH_API_PASSWORD": "ext-api-pass",
            "INDEXER_USERNAME": "ext-idx-user",
            "INDEXER_PASSWORD": "ext-idx-pass",
        },
    )

    cfg = await wp._load_wazuh_config(db, uuid4())

    # Acceptance 1: manager base URL is the external api_url, NOT in-cluster.
    assert cfg.manager_url == _EXTERNAL_URL
    assert "svc.cluster.local" not in cfg.manager_url
    # Acceptance 2: basic creds read from tenant-external-siem-creds.
    assert cfg.manager_user == "ext-api-user"
    assert cfg.manager_password == "ext-api-pass"
    assert cfg.manager_token in (None, "")  # token-absent path
    # Acceptance 4: verify propagates from wazuh_verify_ssl.
    assert cfg.verify_ssl is False
    # Read the external Secret in the tenant namespace (parity w/ poc path).
    assert calls == [("tenant-acme", "tenant-external-siem-creds")]
    assert db.secret_purposes_queried == ["external-siem-creds"]


async def test_provided_resolves_with_token_bearer(monkeypatch):
    """token-present: WAZUH_API_TOKEN is carried on the resolved config."""
    db = _FakeSession(
        profile="provided",
        integration={
            "wazuh_api_url": _EXTERNAL_URL,
            "wazuh_indexer_url": _EXTERNAL_INDEXER,
            "wazuh_verify_ssl": True,
        },
        external_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "tenant-external-siem-creds",
        },
    )
    _patch_secret_read(
        monkeypatch,
        {
            "WAZUH_API_USERNAME": "ext-api-user",
            "WAZUH_API_PASSWORD": "ext-api-pass",
            "WAZUH_API_TOKEN": "pre-minted-jwt",
            "INDEXER_USERNAME": "ext-idx-user",
            "INDEXER_PASSWORD": "ext-idx-pass",
        },
    )

    cfg = await wp._load_wazuh_config(db, uuid4())

    assert cfg.manager_url == _EXTERNAL_URL
    assert cfg.manager_token == "pre-minted-jwt"
    assert cfg.verify_ssl is True


def test_client_verify_matches_wazuh_verify_ssl():
    """Acceptance 4: the httpx client's verify == cfg.verify_ssl."""
    insecure = WazuhConfig(
        manager_url=_EXTERNAL_URL,
        manager_user="u",
        manager_password="p",
        indexer_url=_EXTERNAL_INDEXER,
        indexer_user="iu",
        indexer_password="ip",
        verify_ssl=False,
    )
    secure = WazuhConfig(
        manager_url=_EXTERNAL_URL,
        manager_user="u",
        manager_password="p",
        indexer_url=_EXTERNAL_INDEXER,
        indexer_user="iu",
        indexer_password="ip",
        verify_ssl=True,
    )
    assert wp._client_kwargs(insecure)["verify"] is False
    assert wp._client_kwargs(secure)["verify"] is True


# ---------------------------------------------------------------------------
# Acceptance 2 — Bearer vs Basic auth wire behaviour on the manager client
# ---------------------------------------------------------------------------


def _mock_transport(requests):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"data": {"token": "minted-jwt"}})
        return httpx.Response(200, json={"data": {"affected_items": []}})

    return httpx.MockTransport(handler)


async def test_manager_client_token_present_uses_bearer_no_login(monkeypatch):
    """WAZUH_API_TOKEN present → Bearer that token; skip the login POST."""
    requests: list[httpx.Request] = []
    transport = _mock_transport(requests)
    monkeypatch.setattr(
        wp, "_client_kwargs", lambda cfg: {"transport": transport}
    )

    cfg = WazuhConfig(
        manager_url=_EXTERNAL_URL,
        manager_user="ext-api-user",
        manager_password="ext-api-pass",
        indexer_url=_EXTERNAL_INDEXER,
        indexer_user="iu",
        indexer_password="ip",
        verify_ssl=False,
        manager_token="pre-minted-jwt",
    )
    await wp._ManagerClient(cfg).get("/agents")

    # No authenticate POST — the static token is used directly.
    assert not any(
        r.url.path.endswith("/security/user/authenticate") for r in requests
    )
    gets = [r for r in requests if r.method == "GET"]
    assert len(gets) == 1
    assert gets[0].headers["Authorization"] == "Bearer pre-minted-jwt"


async def test_manager_client_token_absent_uses_basic_login(monkeypatch):
    """No token → HTTP-Basic POST /security/user/authenticate, then Bearer."""
    requests: list[httpx.Request] = []
    transport = _mock_transport(requests)
    monkeypatch.setattr(
        wp, "_client_kwargs", lambda cfg: {"transport": transport}
    )

    cfg = WazuhConfig(
        manager_url=_EXTERNAL_URL,
        manager_user="ext-api-user",
        manager_password="ext-api-pass",
        indexer_url=_EXTERNAL_INDEXER,
        indexer_user="iu",
        indexer_password="ip",
        verify_ssl=False,
        manager_token=None,
    )
    await wp._ManagerClient(cfg).get("/agents")

    auth_posts = [
        r
        for r in requests
        if r.method == "POST"
        and r.url.path.endswith("/security/user/authenticate")
    ]
    assert len(auth_posts) == 1
    expected = base64.b64encode(b"ext-api-user:ext-api-pass").decode()
    assert auth_posts[0].headers["Authorization"] == f"Basic {expected}"

    gets = [r for r in requests if r.method == "GET"]
    assert len(gets) == 1
    assert gets[0].headers["Authorization"] == "Bearer minted-jwt"


# ---------------------------------------------------------------------------
# Acceptance 3/7 — poc/persistent resolution is UNCHANGED (regression guard)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["poc", "persistent"])
async def test_poc_persistent_resolution_unchanged(monkeypatch, profile):
    db = _FakeSession(
        profile=profile,
        integration={
            "wazuh_enabled": True,
            "wazuh_url": _IN_CLUSTER_URL,
            "wazuh_indexer_url": _IN_CLUSTER_INDEXER,
            "wazuh_verify_ssl": False,
            # Present on the row but MUST be ignored for poc/persistent.
            "wazuh_api_url": "https://should-not-be-used.example.com:55000",
        },
        wazuh_api_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "wazuh-acme-wazuh-creds",
        },
        # An external pointer also exists; the in-cluster branch must not use it.
        external_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "tenant-external-siem-creds",
        },
    )
    calls = _patch_secret_read(
        monkeypatch,
        {
            "WAZUH_API_USERNAME": "in-cluster-user",
            "WAZUH_API_PASSWORD": "in-cluster-pass",
            "INDEXER_USERNAME": "in-cluster-idx",
            "INDEXER_PASSWORD": "in-cluster-idx-pass",
        },
    )

    cfg = await wp._load_wazuh_config(db, uuid4())

    # In-cluster manager URL, NOT the external api_url.
    assert cfg.manager_url == _IN_CLUSTER_URL
    assert "should-not-be-used" not in cfg.manager_url
    # Creds read from the wazuh-<slug>-wazuh-creds Secret.
    assert calls == [("tenant-acme", "wazuh-acme-wazuh-creds")]
    assert db.secret_purposes_queried == ["wazuh-api"]
    assert cfg.manager_user == "in-cluster-user"
    assert cfg.manager_password == "in-cluster-pass"
    # No static token on the in-cluster path.
    assert cfg.manager_token in (None, "")


# ---------------------------------------------------------------------------
# Acceptance 5 — missing external URL / creds → typed error, not raw 500
# ---------------------------------------------------------------------------


def test_external_siem_not_configured_is_wazuh_not_configured_subclass():
    # The chat tool layer only catches WazuhNotConfigured; the typed error
    # must be a subclass so it's surfaced (not an unhandled 500).
    assert issubclass(wp.ExternalSiemNotConfigured, wp.WazuhNotConfigured)


async def test_provided_missing_api_url_raises_typed_error(monkeypatch):
    db = _FakeSession(
        profile="provided",
        integration={
            "wazuh_api_url": None,
            "wazuh_indexer_url": None,
            "wazuh_verify_ssl": True,
        },
        external_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "tenant-external-siem-creds",
        },
    )
    _patch_secret_read(monkeypatch, {})

    with pytest.raises(wp.ExternalSiemNotConfigured) as exc:
        await wp._load_wazuh_config(db, uuid4())
    assert "external Wazuh API not configured" in str(exc.value)


async def test_provided_missing_creds_raises_typed_error(monkeypatch):
    db = _FakeSession(
        profile="provided",
        integration={
            "wazuh_api_url": _EXTERNAL_URL,
            "wazuh_indexer_url": _EXTERNAL_INDEXER,
            "wazuh_verify_ssl": True,
        },
        external_pointer={
            "k8s_namespace": "tenant-acme",
            "k8s_secret_name": "tenant-external-siem-creds",
        },
    )
    # No token and no username/password → unusable.
    _patch_secret_read(
        monkeypatch,
        {"INDEXER_USERNAME": "idx", "INDEXER_PASSWORD": "idxpw"},
    )

    with pytest.raises(wp.ExternalSiemNotConfigured) as exc:
        await wp._load_wazuh_config(db, uuid4())
    assert "external Wazuh API not configured" in str(exc.value)


async def test_chat_tool_surfaces_external_not_configured_error(monkeypatch):
    """Acceptance 5 end-to-end: a chat tool returns an error ToolResult
    (caught), not a raised exception / 500, when provided config is absent.
    """
    wp._PER_TENANT_CACHE.clear()
    db = _FakeSession(
        profile="provided",
        integration={
            "wazuh_api_url": None,
            "wazuh_indexer_url": None,
            "wazuh_verify_ssl": True,
        },
    )
    _patch_secret_read(monkeypatch, {})

    result = await wp.get_wazuh_agents(db, target_tenant_id=uuid4())

    assert isinstance(result.data, dict)
    assert "external Wazuh API not configured" in result.data["error"]
    wp._PER_TENANT_CACHE.clear()


# ---------------------------------------------------------------------------
# Acceptance 6 — control-plane egress permits reaching the external manager
# ---------------------------------------------------------------------------


def test_system_chart_permits_api_egress_to_external_manager():
    """charts/soctalk-system keeps API-pod egress open (so the resolver can
    reach the external Wazuh manager host) and documents the external-SIEM
    egress allowance as a no-op when egress is unrestricted / cilium off.
    """
    chart = (
        Path(__file__).resolve().parents[2]
        / "charts"
        / "soctalk-system"
        / "templates"
        / "50-networkpolicy.yaml"
    )
    text = chart.read_text()

    # The api-egress NetworkPolicy must exist and be permissive (open egress),
    # which is what lets the API/controller pod reach an external manager host.
    assert "api-egress" in text
    assert "- {}" in text  # permissive egress rule

    # And the provided-profile external manager egress must be documented so
    # operators of locked-down (Cilium) installs know to add an FQDN rule.
    lowered = text.lower()
    assert "external" in lowered and "wazuh" in lowered
    assert "provided" in lowered
