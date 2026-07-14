"""Pre-smoke cleanup: decommission stale ``ci-*`` tenants on the demo.

Each smoke run onboards a ``ci-<timestamp>`` tenant that runs a full Wazuh
stack. On a failed provision the tenant is left in state=``degraded`` (its
partial stack still holding node memory) rather than torn down, and these
accumulate across runs until the single-node demo box hits memory pressure —
at which point new tenants' ``wazuh-dashboard`` pods can't schedule within the
600s ``wait_workloads`` window, the smoke fails, and *another* degraded tenant
is left behind. A self-reinforcing cycle that eventually pins every deploy red.

Run this BEFORE the smoke so each deploy clears the previous runs' leftovers,
bounding accumulation to at most the current run's own tenant (which the smoke
decommissions itself). Best-effort: never fails the workflow — a cleanup hiccup
must not block a deploy.

Env contract (same as smoke_onboard.py):
- SMOKE_BASE_URL      (required, e.g. https://demo.soctalk.ai)
- SMOKE_ADMIN_EMAIL
- SMOKE_ADMIN_PW
- SMOKE_SLUG_PREFIX   (default: ci) — ONLY tenants whose slug starts with this
                       prefix are ever touched.
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ["SMOKE_BASE_URL"].rstrip("/")
ADMIN_EMAIL = os.environ["SMOKE_ADMIN_EMAIL"]
ADMIN_PW = os.environ["SMOKE_ADMIN_PW"]
SLUG_PREFIX = os.environ.get("SMOKE_SLUG_PREFIX", "ci")

# Never sweep the persistent demo tenant, whatever the prefix resolves to.
PROTECTED_SLUGS = {"demo"}


def _login() -> str:
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = json.dumps({"email": ADMIN_EMAIL, "password": ADMIN_PW}).encode()
    req = urllib.request.Request(
        f"{BASE}/api/auth/login",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=15) as r:
        r.read()
    for c in cj:
        if c.name == "soctalk_session":
            return c.value
    raise SystemExit("no soctalk_session cookie returned by login")


def _list_tenants(sess: str) -> list[dict]:
    req = urllib.request.Request(
        f"{BASE}/api/mssp/tenants",
        headers={"Cookie": f"soctalk_session={sess}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _decommission(sess: str, tenant_id: str, slug: str) -> bool:
    req = urllib.request.Request(
        f"{BASE}/api/mssp/tenants/{tenant_id}:decommission?force=true",
        # Origin satisfies the cookie-auth CSRF check for a raw (non-browser)
        # first-party POST — without it the API returns 403.
        headers={"Cookie": f"soctalk_session={sess}", "Origin": BASE},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        print(f"  decommissioned {slug} ({tenant_id})", flush=True)
        return True
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:200]
        except Exception:
            pass
        print(f"  warn: decommission {slug} failed: {e} :: {body}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  warn: decommission {slug} failed: {e}", flush=True)
    return False


def main() -> int:
    print(f"=== Sweeping stale '{SLUG_PREFIX}-*' tenants on {BASE} ===", flush=True)
    try:
        sess = _login()
        tenants = _list_tenants(sess)
    except Exception as e:  # noqa: BLE001 — cleanup is best-effort, never gate a deploy
        print(f"  warn: sweep skipped (login/list failed): {e}", flush=True)
        return 0

    stale = [
        t
        for t in tenants
        if t.get("slug", "").startswith(f"{SLUG_PREFIX}-")
        and t.get("slug") not in PROTECTED_SLUGS
        and t.get("state") != "archived"
    ]
    print(f"  found {len(stale)} stale tenant(s) to decommission", flush=True)
    for t in stale:
        _decommission(sess, t["id"], t.get("slug", "?"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
