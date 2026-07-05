#!/usr/bin/env python3
"""
Verify SocTalk MSSP console is up + tenant is registered.

Runs against the tailnet-facing MSSP hostname. Ignores TLS (self-signed cert
during pilot). Screenshots the dashboard and the tenant detail page for the
launchpad's smoke-test report.
"""

import argparse
import os
import re
import sys
from pathlib import Path

from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="MSSP console URL, e.g. https://100.107.173.7")
    p.add_argument("--host-header", default=None,
                   help="Host header to send (needed when --url is an IP and Traefik routes by hostname)")
    p.add_argument("--email", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--tenant-slug", required=True, help="Tenant slug expected to be visible")
    p.add_argument("--out-dir", default="/tmp/lp-playwright/out")
    args = p.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings = {}
    # If a host-header is supplied, prefer letting the browser resolve the
    # hostname to the IP via Chromium's --host-resolver-rules (rather than a
    # forbidden Host-header override). That way SNI + Host + address all
    # match, and the URL becomes the real hostname.
    launch_args = []
    effective_url = args.url
    if args.host_header:
        # Extract IP from URL (assume https://<ip>).
        ip = args.url.split("//", 1)[-1].rstrip("/")
        launch_args.append(f"--host-resolver-rules=MAP {args.host_header} {ip}")
        effective_url = "https://" + args.host_header

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=launch_args)
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1600, "height": 1000})
        page = ctx.new_page()
        # Rewrite args.url so the rest of the flow uses the real hostname.
        args.url = effective_url
        page.set_default_timeout(30_000)

        # 1. Landing / login.
        try:
            page.goto(args.url + "/", wait_until="networkidle")
        except PWTimeout:
            page.goto(args.url + "/", wait_until="domcontentloaded")
        page.screenshot(path=str(out / "01-landing.png"), full_page=True)
        findings["landing_url"] = page.url

        # 2. Login — try common patterns.
        email_field = page.locator('input[type="email"], input[name="email"], input[autocomplete="username"]').first
        pw_field = page.locator('input[type="password"]').first
        try:
            email_field.wait_for(state="visible", timeout=15_000)
        except PWTimeout:
            # already logged in? or single-page app that redirects. try /login explicitly.
            page.goto(args.url + "/login", wait_until="domcontentloaded")
            email_field.wait_for(state="visible", timeout=15_000)

        email_field.fill(args.email)
        pw_field.fill(args.password)
        # Submit: click first button of type submit, or press Enter.
        submit = page.locator('button[type="submit"], button:has-text("Sign in"), button:has-text("Log in")').first
        try:
            submit.click(timeout=5_000)
        except PWTimeout:
            pw_field.press("Enter")

        # 3. Wait for post-login. Explicitly wait for /login to disappear
        #    from the URL (SPAs may not fire networkidle promptly).
        try:
            page.wait_for_url(lambda u: "/login" not in u, timeout=60_000)
        except PWTimeout:
            pass
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except PWTimeout:
            pass
        page.screenshot(path=str(out / "02-post-login.png"), full_page=True)
        findings["post_login_url"] = page.url

        # Failure signal: URL still contains "/login" means we probably didn't log in.
        if "/login" in page.url:
            print(f"FAIL: still on login page after submit ({page.url})")
            body_text = (page.locator("body").inner_text() or "")[:400]
            findings["login_body"] = body_text
            print(findings, file=sys.stderr)
            return 2

        # 4. Navigate to tenants. Try direct URLs first, then click a link.
        tenants_url_candidates = [
            args.url + "/tenants",
            args.url + "/customers",
            args.url + "/mssp/tenants",
        ]
        seen_tenant = False
        for u in tenants_url_candidates:
            try:
                page.goto(u, wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle", timeout=15_000)
            except (PWTimeout, PWError):
                continue
            if page.url.rstrip("/") == u.rstrip("/") or args.tenant_slug in (page.locator("body").inner_text() or "").lower():
                seen_tenant = args.tenant_slug in (page.locator("body").inner_text() or "").lower()
                break

        # If direct URL didn't work, try clicking a "Tenants" link.
        if not seen_tenant:
            try:
                page.get_by_role("link", name=re.compile("tenants|customers", re.I)).first.click()
                page.wait_for_load_state("networkidle", timeout=15_000)
            except (PWTimeout, PWError):
                pass

        page.screenshot(path=str(out / "03-tenants.png"), full_page=True)
        body_text = (page.locator("body").inner_text() or "").lower()
        findings["tenants_url"] = page.url
        findings["found_slug"] = args.tenant_slug in body_text

        if args.tenant_slug not in body_text:
            print(f"FAIL: tenant slug '{args.tenant_slug}' not visible in tenants page")
            print(f"      body preview: {body_text[:400]}")
            return 3

        # 5. Look for a status marker near the tenant row (online / active).
        status_hints = ["online", "active", "provisioning", "pending", "degraded"]
        status_seen = [s for s in status_hints if s in body_text]
        findings["status_hints_seen"] = status_seen

        print("PASS: MSSP console reachable, admin logged in, tenant visible")
        print(f"      slug '{args.tenant_slug}' present")
        print(f"      status markers seen: {status_seen}")
        print(f"      screenshots: {out}")
        for k, v in findings.items():
            print(f"      {k}={v}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
