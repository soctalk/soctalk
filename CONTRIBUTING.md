# Contributing to SocTalk

This guide covers local development setup specific to this repository. For
architecture, the multi-tenant model, and the deployment shape, see
[`README.md`](README.md) and [`docs/multi-tenant/`](docs/multi-tenant/).

---

## Working with the Nix dev shell

This repository ships a Nix flake (`flake.nix` → `nix/shells/default.nix`)
that pins Python 3.11, Node 20, PostgreSQL 16 client tools, and the
compile-time libraries every Python wheel in `pyproject.toml` needs at
runtime. **All Python tooling in this repo (pytest, alembic, the API
server, runs-worker, opencode, patagon, etc.) must be invoked from inside
this shell.**

### Why the shell is mandatory

The SQLAlchemy `greenlet` wheel ships a C extension whose `NEEDED` ELF
entry references `libstdc++.so.6`. On NixOS this library does not live on
any default linker search path; it is provisioned in the Nix store under
`/nix/store/<hash>-gcc-<version>-lib/lib/`. The dev shell's `shellHook`
exports

```
LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH:$LD_LIBRARY_PATH"
```

so any child process can `dlopen` libstdc++ (and the other native deps
listed in `nix/shells/default.nix`'s `NIX_LD_LIBRARY_PATH` block:
openssl, postgresql client lib, zlib) without ceremony.

Outside the shell, `LD_LIBRARY_PATH` is unset and you will see

```
ImportError: libstdc++.so.6: cannot open shared object file
```

the moment anything imports `sqlalchemy.ext.asyncio` or `greenlet`.

### Entering the shell

Two equivalent options:

```bash
# Option A — direnv (recommended; auto-enters on cd)
direnv allow      # one-time per checkout
cd /path/to/soctalk

# Option B — manual
nix develop
```

Both run the `shellHook` (which exports `LD_LIBRARY_PATH`, activates the
project venv at `.venv/`, sets `PYTHONPATH=src:…`, and installs Python
deps on first entry).

### Launching tools that drive Python

Anything that spawns `pytest` / `alembic` / the API as a child process
inherits its parent's environment. Concretely:

| Tool | Launch from |
|---|---|
| `pytest`, `alembic`, `uvicorn`, `python -m soctalk.*` | Any shell that is the Nix dev shell (Option A or B above). |
| `opencode` | The same dev shell. `cd` into the project, then `direnv allow` (one-time), then `opencode`. If opencode is started from a desktop launcher or a terminal that did not enter the dev shell, it will not have `LD_LIBRARY_PATH` set and `patagon_check` (which spawns `pytest`) will fail with the libstdc++ ImportError. Restart opencode from inside the dev shell to recover. |
| `just` recipes | Inside or outside the dev shell — the `integration-*` recipes wrap their Python invocations in `direnv exec .` so they self-bootstrap. |

### Project-local Kubernetes config

The dev shell auto-exports `KUBECONFIG=$PWD/.kube/config` (see `.envrc`).
Every cluster operation invoked from inside the project — `k3d cluster
create`, `helm install`, `kubectl …` — reads and writes that file. The
user's `~/.kube/config` is left alone.

* `scripts/dev-up.sh` (full k3d + Cilium + cert-manager) and
  `scripts/local-up.sh` (slim k3d) both materialise the cluster's
  kubeconfig into `$PWD/.kube/config`. They no longer touch
  `~/.kube/config`.
* `scripts/local-down.sh` and `k3d cluster delete <name>` remove the
  cluster; the kubeconfig file is left for inspection (delete manually
  with `rm .kube/config` if you want a clean slate).
* `starship` (or any prompt that reads `kubectl config current-context`)
  only shows the cluster badge while you're in the project directory.
* Outside the project, `KUBECONFIG` is unset and `kubectl` falls back to
  `~/.kube/config`, which is whatever lab/cloud context you had before.

If you want to merge a project-local cluster into your normal kubeconfig
on an ad-hoc basis, set `KUBECONFIG=$PWD/.kube/config:~/.kube/config`
for that one command and `kubectl config view --merge --flatten` will
emit a combined config.

### Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| `ImportError: libstdc++.so.6: cannot open shared object file` from any Python tool. | Process spawned outside the dev shell. `echo $LD_LIBRARY_PATH` is empty or doesn't contain a `gcc-*-lib` path. | Re-launch the tool from the dev shell. Verify with `echo $LD_LIBRARY_PATH \| tr ':' '\n' \| grep gcc`. |
| `ConnectionRefusedError: [Errno 111] Connect call failed ('127.0.0.1', 5432)` from integration tests. | The V1 multi-tenant Postgres container isn't running. | `just integration-up`. |
| `ConnectionRefusedError: ... ('127.0.0.1', 5433)` from legacy event-store tests. | The legacy single-tenant Postgres container isn't running. | `just integration-up` (brings up both). |
| `permission denied for table tenants` during a test. | The DB was bootstrapped with the wrong superuser, leaving tables owned by `soctalk` instead of `soctalk_admin`. | `just integration-wipe && just integration-up` to re-bootstrap from clean. |
| `nix --version` is slow or behaves oddly inside the dev shell. | `LD_LIBRARY_PATH` is now set in the shell scope and `nix` is finding a foreign libstdc++. | Unset for that one command: `env -u LD_LIBRARY_PATH nix --version`. The flake scopes the export to the shellHook (not the derivation) so `nix` outside the dev shell is unaffected. |

---

## Running tests

```bash
# Unit suite (no Postgres needed; ~2 seconds)
pytest -m "not integration"

# Full V1 + legacy suite against local Postgres (~25 seconds)
just integration-up               # one-time per session
just integration-test             # full V1 tree
just integration-test tests/v1/test_rls_isolation.py -v    # narrow to one file
just integration-test -k provided -v                       # filter + verbose

# Teardown when done for the day
just integration-down             # keeps data
# or
just integration-wipe             # drops volumes; next up re-bootstraps
```

CI runs the same suite. See `.github/workflows/v1-ci.yml` for the exact
sequence.

---

## Code style

- Python: `ruff check src/ tests/`, `mypy src/` (strict).
- Frontend: `cd frontend && pnpm check` (svelte-check), `pnpm test`
  (Playwright).
- Helm charts: `helm lint charts/soctalk-system` and
  `helm lint charts/soctalk-tenant`.

---

## Filing a change

1. Branch from `main`.
2. Keep changes focused — feature work goes under `src/soctalk/core/`;
   single-tenant legacy code under `src/soctalk/` outside `core/`.
3. Migrations are forward-only. Each migration that touches a
   tenant-scoped table must ship with an RLS-behavior test under
   `tests/v1/`.
4. PR description should reference the relevant doc under
   `docs/multi-tenant/` (security-model, postgres-rls, etc.) when
   touching invariants.
