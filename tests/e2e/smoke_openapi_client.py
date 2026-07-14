"""Post-deploy smoke test: generate a Python REST client from the live OpenAPI
schema and use it to consume the investigations API.

This is a dogfood test of the API descriptor: if the published
``/api/openapi.json`` can't be turned into a working client, or the generated
client can't list/read investigations, the schema (or the endpoints) regressed.
It caught, for example, a duplicate ``HeartbeatPayload`` model name that broke
codegen.

Steps:
  1. Download ``${SMOKE_BASE_URL}/api/openapi.json``.
  2. Generate a client package with ``openapi-python-client`` (must be on PATH;
     the CI job ``pip install``s it — locally, ``uvx openapi-python-client``).
  3. Log in for a session cookie.
  4. Use the *generated* client to list investigations, fetch one detail, and
     pull its events — asserting the typed models deserialize.

Env contract (shared with the other e2e smokes):
- SMOKE_BASE_URL   (required, e.g. https://demo.soctalk.ai)
- SMOKE_ADMIN_EMAIL
- SMOKE_ADMIN_PW
"""
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import httpx

BASE = os.environ["SMOKE_BASE_URL"].rstrip("/")
ADMIN_EMAIL = os.environ["SMOKE_ADMIN_EMAIL"]
ADMIN_PW = os.environ["SMOKE_ADMIN_PW"]


def step(msg: str) -> None:
    print(f"\n=== {msg} ===", flush=True)


def _generator_argv() -> list[str]:
    """Locate the openapi-python-client CLI (installed, or via uvx)."""
    if shutil.which("openapi-python-client"):
        return ["openapi-python-client"]
    if shutil.which("uvx"):
        return ["uvx", "openapi-python-client"]
    raise SystemExit(
        "openapi-python-client not found: `pip install openapi-python-client` "
        "(or install uv for `uvx`)"
    )


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="soctalk-openapi-"))

    step(f"1. Download OpenAPI schema from {BASE}/api/openapi.json")
    spec_path = work / "openapi.json"
    with urllib.request.urlopen(f"{BASE}/api/openapi.json", timeout=20) as r:
        spec = json.loads(r.read())
    spec_path.write_text(json.dumps(spec))
    print(f"  {len(spec.get('paths', {}))} paths, title={spec['info']['title']}", flush=True)

    step("2. Generate a Python client with openapi-python-client")
    out_dir = work / "gen"
    proc = subprocess.run(
        [
            *_generator_argv(),
            "generate",
            "--path", str(spec_path),
            "--output-path", str(out_dir),
            "--meta", "setup",
            "--overwrite",
        ],
        capture_output=True,
        text=True,
    )
    combined = proc.stdout + proc.stderr
    print("  " + combined.strip().replace("\n", "\n  "), flush=True)
    # openapi-python-client keeps going past a bad schema but prints these
    # markers — treat them as a codegen regression (e.g. two models sharing a
    # class name, which is what shipped a broken /api/openapi.json before).
    for marker in ("Unable to parse", "duplicate models"):
        if marker.lower() in combined.lower():
            print(f"SMOKE FAIL (codegen emitted '{marker}')", flush=True)
            return 1
    if proc.returncode != 0:
        print(f"SMOKE FAIL (generator exit {proc.returncode})", flush=True)
        return 1

    # Locate the generated package (dir containing client.py) and import it.
    pkg_dir = next(
        (p.parent for p in out_dir.glob("*/client.py")), None
    )
    if pkg_dir is None:
        print("SMOKE FAIL (no generated package found)", flush=True)
        return 1
    pkg_name = pkg_dir.name
    sys.path.insert(0, str(out_dir))
    client_mod = importlib.import_module(pkg_name)
    inv_api = f"{pkg_name}.api.investigations_bridge"

    def _op(name: str):
        return importlib.import_module(f"{inv_api}.{name}")

    list_inv = _op("list_investigations_api_investigations_get")
    get_inv = _op("get_investigation_api_investigations_investigation_id_get")
    get_events = _op("get_events_api_investigations_investigation_id_events_get")
    print(f"  generated + imported package '{pkg_name}'", flush=True)

    step("3. Log in for a session cookie")
    with httpx.Client(base_url=BASE, timeout=20) as h:
        h.post(
            "/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PW},
        ).raise_for_status()
        session = h.cookies["soctalk_session"]
    print("  cookie acquired", flush=True)

    step("4. Consume investigations through the generated client")
    client = client_mod.Client(
        base_url=BASE,
        cookies={"soctalk_session": session},
        timeout=httpx.Timeout(20),
        raise_on_unexpected_status=True,
    )

    page = list_inv.sync(client=client, page=1, page_size=5)
    # Typed model — attribute access proves deserialization worked.
    assert type(page).__name__ == "InvestigationList", f"unexpected: {type(page)!r}"
    assert isinstance(page.total, int), "total not an int"
    print(f"  list: total={page.total}, returned={len(page.items)}", flush=True)

    if not page.items:
        print("  no investigations on this instance — list-only smoke PASS", flush=True)
        print("SMOKE PASS", flush=True)
        return 0

    first = page.items[0]
    print(
        f"  first: {str(first.id)[:8]} status={first.status} "
        f"sev={first.max_severity} title={first.title[:48]!r}",
        flush=True,
    )

    detail = get_inv.sync(client=client, investigation_id=str(first.id))
    assert type(detail).__name__ == "Investigation", f"unexpected: {type(detail)!r}"
    assert str(detail.id) == str(first.id), "detail id mismatch"
    alerts = getattr(detail, "alert_count", "?")
    print(f"  detail: id={str(detail.id)[:8]} alerts={alerts}", flush=True)

    events = get_events.sync(client=client, investigation_id=str(first.id))
    n_events = len(events) if isinstance(events, list) else "?"
    print(f"  events: {n_events}", flush=True)

    print("SMOKE PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
