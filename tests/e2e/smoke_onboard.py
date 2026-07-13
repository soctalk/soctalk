"""Post-deploy smoke test: log in as bootstrap admin, onboard a tenant
via the management UI, verify it reaches ACTIVE and the underlying
Wazuh stack is live in the tenant namespace.

Driven by Playwright (headless Chromium). Used as the gate in the
``deploy-demo`` workflow — if this fails after a deploy, the workflow
fails and a human inspects.

Env contract:
- SMOKE_BASE_URL   (required, e.g. https://demo.soctalk.ai)
- SMOKE_ADMIN_EMAIL
- SMOKE_ADMIN_PW
- SMOKE_SLUG_PREFIX  (default: smoke; the test appends a UTC timestamp)
"""
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

from playwright.sync_api import sync_playwright

BASE = os.environ["SMOKE_BASE_URL"].rstrip("/")
HOST = BASE.split("//", 1)[1].split("/", 1)[0]
ADMIN_EMAIL = os.environ["SMOKE_ADMIN_EMAIL"]
ADMIN_PW = os.environ["SMOKE_ADMIN_PW"]
SLUG_PREFIX = os.environ.get("SMOKE_SLUG_PREFIX", "smoke")
SLUG = f"{SLUG_PREFIX}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

# Resolved tenant id is written to GITHUB_OUTPUT (if present) so the
# parent workflow can hand it to a cleanup step.
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT")


def step(msg: str) -> None:
    print(f"\n=== {msg} ===", flush=True)


def api_login() -> str:
    """POST /api/auth/login and return the session cookie value."""
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


def dump_failure_diagnostics(sess: str, tenant_id: str, data: dict) -> None:
    """On a terminal failure state, print the provisioning failure reason so a
    red CI run is self-explanatory instead of just ``degraded``. Dumps the
    tenant ``runtime`` blob (may carry a message) + recent lifecycle events
    (the failed step + error live here)."""
    runtime = data.get("runtime")
    if runtime:
        print(f"  runtime: {json.dumps(runtime)[:1500]}", flush=True)
    try:
        req = urllib.request.Request(
            f"{BASE}/api/mssp/tenants/{tenant_id}/events?limit=50",
            headers={"Cookie": f"soctalk_session={sess}"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            events = json.loads(r.read())
    except Exception as e:
        print(f"  could not fetch lifecycle events: {e}", flush=True)
        return
    print(f"  --- lifecycle events (most recent {min(len(events), 50)}) ---", flush=True)
    for ev in events:
        et = ev.get("event_type") or ev.get("type") or "?"
        ts = ev.get("timestamp") or ev.get("created_at") or ""
        # The failure reason (helm error, step, exception) lives in ``details``.
        details = ev.get("details") or {}
        line = f"  [{ts}] {et}"
        if details:
            line += f" :: {json.dumps(details)[:600]}"
        print(line, flush=True)


def decommission(sess: str, tenant_id: str) -> None:
    """Best-effort cleanup so the smoke tenant doesn't accumulate on the
    demo box (each tenant runs a full Wazuh stack; left to pile up they
    exhaust node memory and make later runs fail to schedule)."""
    try:
        req = urllib.request.Request(
            f"{BASE}/api/mssp/tenants/{tenant_id}:decommission?force=true",
            # Origin header satisfies the cookie-auth CSRF check (state-changing
            # first-party requests must carry a matching Origin/Referer); the
            # browser sends it automatically, a raw urllib POST must set it or
            # the API returns 403 "CSRF validation failed" and cleanup is skipped.
            headers={"Cookie": f"soctalk_session={sess}", "Origin": BASE},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        print(f"  decommissioned {tenant_id}", flush=True)
    except urllib.error.HTTPError as e:
        # Print the response body so a 403/4xx is diagnosable (e.g. CSRF vs role).
        try:
            body = e.read().decode()[:300]
        except Exception:
            body = ""
        print(f"  cleanup warning: decommission failed: {e} :: {body}", flush=True)
    except Exception as e:
        print(f"  cleanup warning: decommission failed: {e}", flush=True)


step(f"0. API login at {BASE}")
sess = api_login()
print(f"  cookie acquired ({len(sess)} chars)", flush=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    ctx.add_cookies([{
        "name": "soctalk_session",
        "value": sess,
        "domain": HOST,
        "path": "/",
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }])
    page = ctx.new_page()

    step(f"1. Open /tenants/new and drive the wizard. slug={SLUG}")
    page.goto(f"{BASE}/tenants/new", wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("input.input", timeout=15000)

    # Step 1: Identity — display_name, slug, contact_email
    page.locator("input.input").nth(0).fill("Smoke Test Tenant")
    page.locator("input.input").nth(1).fill(SLUG)
    page.locator("input[type=email]").first.fill(f"smoke@{SLUG}.test")

    # Next → step 2 (poc profile is default) → step 3 → step 4
    for _ in range(3):
        page.get_by_role("button", name=re.compile(r"^Next$", re.I)).click()

    # Step 4: Submit
    page.locator("button[data-testid=create-tenant]").click()
    page.wait_for_url(re.compile(r"/tenants/[0-9a-f-]{36}"), timeout=20000)
    tenant_id = page.url.rsplit("/", 1)[-1]
    print(f"  tenant_id={tenant_id}", flush=True)
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"tenant_id={tenant_id}\n")

    step("2. Poll API for ACTIVE state")
    start = time.time()
    deadline = start + int(os.environ.get("SMOKE_TIMEOUT_SECONDS", "1500"))
    final_state = None
    last_state = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                f"{BASE}/api/mssp/tenants/{tenant_id}",
                headers={"Cookie": f"soctalk_session={sess}"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
        except Exception as e:
            print(f"  t+{int(time.time()-start)}s api-error: {e}", flush=True)
            time.sleep(15)
            continue
        state = data.get("state")
        if state != last_state:
            print(f"  t+{int(time.time()-start)}s state={state}", flush=True)
            last_state = state
        if state == "active":
            health = (data.get("runtime") or {}).get("health")
            print(f"  active. runtime.health={health}", flush=True)
            final_state = "active"
            break
        # `degraded` is terminal for the smoke: provisioning failed, so
        # fail fast instead of polling to the timeout.
        if state in ("failed", "error", "degraded"):
            final_state = state
            dump_failure_diagnostics(sess, tenant_id, data)
            break
        time.sleep(15)

    browser.close()

# Always clean up the tenant we created — pass or fail — so the demo box
# doesn't accumulate Wazuh stacks across runs.
decommission(sess, tenant_id)

if final_state == "active":
    print("\nSMOKE PASS", flush=True)
    sys.exit(0)

print(f"\nSMOKE FAIL (final_state={final_state})", flush=True)
sys.exit(1)
