# Launchpad e2e verification

## `verify_console.py`

Playwright-driven smoke that logs into the launchpad-provisioned MSSP console and confirms:

- The MSSP UI answers on the tailnet URL
- The admin credentials from `pilot.yaml` work
- The tenant slug from `pilot.yaml` is visible in `/tenants`
- Status markers (Active / Online / Degraded) render

Emits `PASS`/`FAIL` on stdout and saves annotated screenshots to `--out-dir` so a CI job can attach them to the run report.

### Setup (one-time)

```bash
python3 -m venv .venv
.venv/bin/pip install playwright
.venv/bin/playwright install chromium
```

### Run

Direct IP form (works even when your local resolver has no MagicDNS entry):

```bash
.venv/bin/python3 verify_console.py \
  --url https://<mssp-tailnet-ipv4> \
  --host-header lp-mssp.<your-tailnet>.ts.net \
  --email admin@my-pilot.demo \
  --password '<from-pilot.yaml>' \
  --tenant-slug acme \
  --out-dir /tmp/lp-out
```

`--host-header` uses Chromium's `--host-resolver-rules` so SNI, `Host:` header, and Traefik ingress-hostname-routing all line up on the real hostname without touching `/etc/hosts`.

Exit codes: `0` on pass, `2` if the login didn't clear, `3` if the tenant slug isn't rendered.
