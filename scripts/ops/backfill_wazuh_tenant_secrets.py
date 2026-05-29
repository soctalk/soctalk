#!/usr/bin/env python3
"""Backfill ``tenant_secrets`` rows for ``purpose='wazuh-api'`` + indexer URLs.

This is the one-shot ops script the Phase 5 plan calls out: tenants that
were provisioned BEFORE the chat MSSP work ran don't have a
``tenant_secrets`` row pointing at their Wazuh credentials Secret, and
their ``integration_configs.wazuh_indexer_url`` is NULL. The new
provisioning controller handles new tenants automatically (see
``controller._step_mint_secrets`` + ``_step_write_integration_config``);
this script catches existing ones.

The script is intentionally kept OUT of Alembic — migrations run in CI
and local dev contexts where the Kubernetes API is unavailable. Touching
k8s from a migration would fail those runs for reasons unrelated to the
DB schema. Run this from a shell that has DB + cluster access (e.g.
``kubectl exec`` on the API pod, or locally with kubeconfig +
``DATABASE_URL`` pointed at the same Postgres the cluster uses).

Idempotent: only inserts the ``wazuh-api`` row when missing, only sets
``wazuh_indexer_url`` when NULL. Logs every action so an operator can
audit what landed.

Usage::

    DATABASE_URL=postgresql+asyncpg://soctalk_admin:…@…:5432/soctalk \\
    python scripts/ops/backfill_wazuh_tenant_secrets.py

    # dry-run (prints what would change, no writes)
    python scripts/ops/backfill_wazuh_tenant_secrets.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession


def _database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL not set")
    # Accept either driver form.
    return url.replace("postgresql://", "postgresql+asyncpg://")


def _release_wazuh(slug: str) -> str:
    """Match controller.py: release_wazuh = f"wazuh-{slug}"."""
    return f"wazuh-{slug}"


def _wazuh_secret_name(slug: str) -> str:
    """Match the wazuh chart's rendered credentials Secret name."""
    return f"{_release_wazuh(slug)}-wazuh-creds"


def _wazuh_manager_url(slug: str) -> str:
    namespace = f"tenant-{slug}"
    return (
        f"https://{_release_wazuh(slug)}-wazuh-manager."
        f"{namespace}.svc.cluster.local:55000"
    )


def _wazuh_indexer_url(slug: str) -> str:
    namespace = f"tenant-{slug}"
    return (
        f"https://{_release_wazuh(slug)}-wazuh-indexer."
        f"{namespace}.svc.cluster.local:9200"
    )


async def _list_tenants(db: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            text(
                "SELECT id::text, slug FROM tenants "
                "WHERE state = 'active' "
                "ORDER BY slug"
            )
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def _has_wazuh_secret_row(
    db: AsyncSession, tenant_id: str
) -> bool:
    row = (
        await db.execute(
            text(
                "SELECT 1 FROM tenant_secrets "
                "WHERE tenant_id = :t AND purpose = 'wazuh-api' LIMIT 1"
            ),
            {"t": tenant_id},
        )
    ).first()
    return row is not None


async def _read_integration_url(
    db: AsyncSession, tenant_id: str
) -> tuple[str | None, str | None] | None:
    row = (
        await db.execute(
            text(
                "SELECT wazuh_url, wazuh_indexer_url "
                "FROM integration_configs WHERE tenant_id = :t"
            ),
            {"t": tenant_id},
        )
    ).mappings().first()
    if row is None:
        return None
    return (row["wazuh_url"], row["wazuh_indexer_url"])


async def _insert_wazuh_secret_row(
    db: AsyncSession, tenant_id: str, slug: str
) -> None:
    namespace = f"tenant-{slug}"
    secret_name = _wazuh_secret_name(slug)
    await db.execute(
        text(
            """
            INSERT INTO tenant_secrets (
                id, tenant_id, purpose, k8s_namespace, k8s_secret_name,
                k8s_secret_key, version_label, created_at
            ) VALUES (
                gen_random_uuid(), :t, 'wazuh-api', :ns, :name,
                'multi', 'v1', now()
            )
            """
        ),
        {"t": tenant_id, "ns": namespace, "name": secret_name},
    )


async def _update_indexer_url(
    db: AsyncSession, tenant_id: str, indexer_url: str
) -> None:
    await db.execute(
        text(
            "UPDATE integration_configs SET wazuh_indexer_url = :u "
            "WHERE tenant_id = :t AND wazuh_indexer_url IS NULL"
        ),
        {"t": tenant_id, "u": indexer_url},
    )


async def _run(dry_run: bool) -> int:
    engine = create_async_engine(_database_url(), future=True)
    inserted_rows = 0
    indexer_set = 0
    skipped = 0
    async with engine.connect() as conn:
        async with conn.begin():
            session = AsyncSession(bind=conn)
            tenants = await _list_tenants(session)
            print(f"found {len(tenants)} active tenants")
            for t in tenants:
                tid = t["id"]
                slug = t["slug"]
                # Wazuh secret row.
                if await _has_wazuh_secret_row(session, tid):
                    print(f"  {slug}: tenant_secrets(wazuh-api) already present")
                    skipped += 1
                else:
                    if dry_run:
                        print(
                            f"  {slug}: would INSERT tenant_secrets row "
                            f"-> tenant-{slug}/{_wazuh_secret_name(slug)}"
                        )
                    else:
                        await _insert_wazuh_secret_row(session, tid, slug)
                        print(
                            f"  {slug}: inserted tenant_secrets row "
                            f"-> tenant-{slug}/{_wazuh_secret_name(slug)}"
                        )
                    inserted_rows += 1
                # Indexer URL.
                urls = await _read_integration_url(session, tid)
                if urls is None:
                    print(f"  {slug}: no integration_configs row; skipping indexer URL")
                else:
                    mgr_url, idx_url = urls
                    if idx_url:
                        print(f"  {slug}: wazuh_indexer_url already set")
                    else:
                        target = _wazuh_indexer_url(slug)
                        if dry_run:
                            print(f"  {slug}: would SET wazuh_indexer_url = {target}")
                        else:
                            await _update_indexer_url(session, tid, target)
                            print(f"  {slug}: set wazuh_indexer_url = {target}")
                        indexer_set += 1
            if dry_run:
                await conn.rollback()
    await engine.dispose()
    print(
        f"\nsummary: inserted {inserted_rows} tenant_secrets row(s); "
        f"set {indexer_set} indexer URL(s); skipped {skipped} already-present"
    )
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without writing.",
    )
    args = p.parse_args()
    sys.exit(asyncio.run(_run(args.dry_run)))


if __name__ == "__main__":
    main()
