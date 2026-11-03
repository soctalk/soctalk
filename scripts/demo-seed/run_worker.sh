#!/usr/bin/env bash
# Cost-safe launcher for the demo-seed runs-worker (issue #72).
#
# Starts the worker in a SCRUBBED environment (env -i) so no leaked
# per-tier provider var (SOCTALK_FAST_*, SOCTALK_REASONING_*, ANTHROPIC_*,
# a stray OPENAI_BASE_URL) can route a call to a paid provider — the P0
# hole. Runs preflight.py first and refuses to start the worker unless
# every resolved tier points at the local stub.
#
# Usage:
#   STUB=http://127.0.0.1:8091/v1 API=http://127.0.0.1:8000 \
#   WORKER_TOKEN=/tmp/seed-worker-token PROJECT=/path/to/soctalk \
#   scripts/demo-seed/run_worker.sh
set -euo pipefail

STUB="${STUB:-http://127.0.0.1:8091/v1}"
API="${API:-http://127.0.0.1:8000}"
WORKER_TOKEN="${WORKER_TOKEN:-/tmp/seed-worker-token}"
PROJECT="${PROJECT:-$(cd "$(dirname "$0")/../.." && pwd)}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# A minimal, explicit environment. env -i drops EVERYTHING (including any
# .env-independent shell exports); we then add back only what the worker
# needs and the single stub key. ANTHROPIC_API_KEY is set EMPTY so the
# app's own load_dotenv() cannot re-populate it (dotenv won't override a
# set var). PATH is derived from the resolved uv location so env -i can't
# strip the interpreter off PATH (exit 127).
UV_BIN="${UV_BIN:-$(command -v uv || true)}"
[[ -n "$UV_BIN" ]] || { echo "uv not found on PATH; set UV_BIN=" >&2; exit 1; }
UV_DIR="$(dirname "$UV_BIN")"
CLEAN=(
  env -i
  PATH="$UV_DIR:/usr/bin:/bin:/usr/local/bin:$HOME/.local/bin"
  HOME="$HOME"
  ANTHROPIC_API_KEY=
  OPENAI_API_KEY=sk-demo-playback
  OPENAI_BASE_URL="$STUB"
  SOCTALK_LLM_PROVIDER=openai
  SOCTALK_FAST_MODEL=demo-playback
  SOCTALK_REASONING_MODEL=demo-playback
  SOCTALK_API_URL="$API"
  WORKER_TOKEN_PATH="$WORKER_TOKEN"
  ALLOWED_STUB="$STUB"
  SOCTALK_DOTENV_DISABLE=1
)

echo "== preflight: asserting stub-only routing =="
"${CLEAN[@]}" uv run --no-env-file --project "$PROJECT" python "$HERE/preflight.py"

echo "== starting cost-safe worker (stub: $STUB) =="
exec "${CLEAN[@]}" uv run --no-env-file --project "$PROJECT" python -m soctalk.runs_worker.main
