#!/usr/bin/env bash
# Wait for the soctalk-postgres container to accept connections.
#
# Used by ``just integration-up`` between ``docker compose up -d postgres``
# and the role-bootstrap SQL.
#
# Polls ``pg_isready`` from inside the container so we don't need
# pg_isready (or any postgres client) on the host. Times out after
# TIMEOUT_SECONDS (default 30).
#
# Env knobs:
#   CONTAINER         container name to exec into (default: soctalk-postgres)
#   PGUSER            postgres role to probe with (default: soctalk)
#   PGDATABASE        database name (default: soctalk)
#   TIMEOUT_SECONDS   total wait budget (default: 30)

set -euo pipefail

CONTAINER="${CONTAINER:-soctalk-postgres}"
PGUSER="${PGUSER:-soctalk}"
PGDATABASE="${PGDATABASE:-soctalk}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

while true; do
    if docker exec "$CONTAINER" \
        pg_isready -U "$PGUSER" -d "$PGDATABASE" -q >/dev/null 2>&1
    then
        exit 0
    fi
    if (( $(date +%s) >= deadline )); then
        echo "wait-for-pg: ${CONTAINER} did not become ready within ${TIMEOUT_SECONDS}s" >&2
        # Surface the most recent container logs so failures are easier to debug.
        docker logs --tail 40 "$CONTAINER" >&2 || true
        exit 1
    fi
    sleep 1
done
