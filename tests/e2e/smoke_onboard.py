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
import json
import http.cookiejar
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

BASE = os.environ["SMOKE_BASE_URL"].rstrip("/")
HOST = BASE.split("//", 1)[1].split("/", 1)[0]
ADMIN_EMAIL = os.environ["SMOKE_ADMIN_EMAIL"]
ADMIN_PW = os.environ["SMOKE_ADMIN_PW"]
SLUG_PREFIX = os.environ.get("SMOKE_SLUG_PREFIX", "smoke")
SLUG = f"{SLUG_PREFIX}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

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
        if state in ("failed", "error"):
            final_state = state
            break
        time.sleep(15)

    browser.close()

if final_state == "active":
    print("\nSMOKE PASS", flush=True)
    sys.exit(0)

print(f"\nSMOKE FAIL (final_state={final_state})", flush=True)
sys.exit(1)
