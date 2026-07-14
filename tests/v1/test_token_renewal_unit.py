"""Unit tests for tenant agent-token renewal (no DB, no cluster).

Guards the fix for the silent-triage-death bug: adapter (7d) / worker (30d)
internal tokens expired with no renewal, so a long-lived tenant's adapter and
runs-worker began 401'ing against the internal API. ``renew_agent_tokens``
re-mints both tokens for every active tenant and rewrites the Secrets; these
tests assert both tokens are written, that they actually verify (valid
signature, unexpired, right tenant), and that one failing namespace never
stalls the rest.
"""
from uuid import uuid4

import pytest

from soctalk.core.tenancy import auth as auth_mod
from soctalk.core.tenancy.auth import verify_adapter_token, verify_worker_token
from soctalk.core.tenancy.models import Tenant, TenantState
from soctalk.core.tenancy.token_renewal import renew_agent_tokens


@pytest.fixture(autouse=True)
def _stable_signing_key(monkeypatch):
    # Pin the adapter signing key so mint (inside renew) and verify agree
    # deterministically instead of relying on the per-process os.urandom cache.
    monkeypatch.setenv("SOCTALK_ADAPTER_SIGNING_KEY", "unit-test-signing-key")
    auth_mod.reset_adapter_signing_key_cache()
    yield
    auth_mod.reset_adapter_signing_key_cache()


class _Scalars:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class _Result:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _Scalars(self._items)


class _FakeSession:
    def __init__(self, tenants):
        self._tenants = tenants

    async def execute(self, _query):
        return _Result(self._tenants)


class _FakeK8s:
    def __init__(self, fail_ns: str | None = None):
        self.writes: list[tuple[str, str, str]] = []
        self.fail_ns = fail_ns

    async def put_secret(self, namespace, name, *, data, labels):
        if namespace == self.fail_ns:
            raise RuntimeError("k8s blip")
        self.writes.append((namespace, name, data["token"]))


def _active(slug: str) -> Tenant:
    return Tenant(
        id=uuid4(),
        slug=slug,
        display_name=slug,
        state=TenantState.ACTIVE.value,
        organization_id=uuid4(),
    )


@pytest.mark.asyncio
async def test_renew_writes_both_tokens_and_they_verify():
    t = _active("acme")
    k8s = _FakeK8s()
    n = await renew_agent_tokens(_FakeSession([t]), k8s)

    assert n == 1
    ns = "tenant-acme"
    by_name = {name: tok for (w_ns, name, tok) in k8s.writes if w_ns == ns}
    assert set(by_name) == {"adapter-token", "runs-worker-token"}

    a_ident = verify_adapter_token(by_name["adapter-token"])
    w_ident = verify_worker_token(by_name["runs-worker-token"])
    assert a_ident is not None and a_ident.tenant_id == t.id
    assert w_ident is not None and w_ident.tenant_id == t.id


@pytest.mark.asyncio
async def test_renew_is_best_effort_per_tenant():
    ok, bad = _active("ok-tenant"), _active("bad-tenant")
    # bad-tenant's namespace errors on the first put_secret; ok-tenant must
    # still be renewed and the count must reflect only the successes.
    k8s = _FakeK8s(fail_ns="tenant-bad-tenant")
    n = await renew_agent_tokens(_FakeSession([bad, ok]), k8s)

    assert n == 1
    written_ns = {w_ns for (w_ns, _n, _t) in k8s.writes}
    assert written_ns == {"tenant-ok-tenant"}


@pytest.mark.asyncio
async def test_renew_no_active_tenants_is_a_noop():
    k8s = _FakeK8s()
    assert await renew_agent_tokens(_FakeSession([]), k8s) == 0
    assert k8s.writes == []
