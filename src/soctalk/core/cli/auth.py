"""CLI for operator-side auth bootstrap.

Usage:

    soctalk-auth set-password <email>
    soctalk-auth create-admin <email>

``set-password`` prompts for a new password (twice, no-echo) and writes a
``password_credentials`` row. If one already exists, it is updated.
``must_change`` is not set — this is for the operator's own account, not
an admin-forced reset.

``create-admin`` bootstraps a first MSSP admin on a fresh install: creates
the Organization row if none exists, creates the user with role
``mssp_admin`` (idempotent — an existing user just gets a password reset),
and prompts for the password. This is what makes a bare docker-compose
install loggable-into.

Connects to the database using ``DATABASE_URL_MSSP`` (the BYPASSRLS role),
which lets the CLI work regardless of whether the target user is
tenant-scoped.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.auth.models import PasswordCredential
from soctalk.core.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    validate_password,
)
from soctalk.core.observability.audit import log_audit
from soctalk.core.tenancy.models import User


def _read_password() -> str:
    while True:
        p1 = getpass.getpass("New password: ")
        try:
            validate_password(p1)
        except PasswordPolicyError as exc:
            print(f"  ✗ {exc}")
            continue
        p2 = getpass.getpass("Confirm password: ")
        if p1 != p2:
            print("  ✗ Passwords do not match. Try again.")
            continue
        return p1


async def _set_password(email: str) -> int:
    url = os.getenv("DATABASE_URL_MSSP")
    if not url:
        print("DATABASE_URL_MSSP must be set.", file=sys.stderr)
        return 2

    engine = create_async_engine(url, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sm() as db:  # type: AsyncSession
            user = (
                await db.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is None:
                print(f"No user with email {email!r}.", file=sys.stderr)
                return 1

            print(f"User found: {user.email} ({user.role})")
            print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            plain = _read_password()

            cred = (
                await db.execute(
                    select(PasswordCredential).where(
                        PasswordCredential.user_id == user.id
                    )
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if cred is None:
                cred = PasswordCredential(
                    user_id=user.id,
                    password_hash=hash_password(plain),
                    must_change=False,
                    updated_at=now,
                    consecutive_failures=0,
                )
                db.add(cred)
            else:
                cred.password_hash = hash_password(plain)
                cred.must_change = False
                cred.updated_at = now
                cred.consecutive_failures = 0
                cred.locked_until = None
                db.add(cred)

            await log_audit(
                db,
                action="auth.password.reset.admin",
                actor_principal="cli",
                actor_id="cli:set-password",
                tenant_id=user.tenant_id,
                resource_type="user",
                resource_id=str(user.id),
                notes="set via soctalk-auth CLI",
            )
            await db.commit()
            print(f"Password set for {email}.")
            return 0
    finally:
        await engine.dispose()


async def _create_admin(email: str, display_name: str | None) -> int:
    url = os.getenv("DATABASE_URL_MSSP")
    if not url:
        print("DATABASE_URL_MSSP must be set.", file=sys.stderr)
        return 2

    from uuid import uuid4

    from soctalk.core.tenancy.models import Organization

    engine = create_async_engine(url, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sm() as db:  # type: AsyncSession
            org = (await db.execute(select(Organization))).scalars().first()
            if org is None:
                org = Organization(
                    mssp_id=uuid4(),
                    mssp_name="SocTalk MSSP",
                    install_id=uuid4(),
                    install_label="bootstrap",
                )
                db.add(org)
                await db.flush()
                print("Organization created.")

            user = (
                await db.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is None:
                user = User(
                    email=email,
                    display_name=display_name or email.split("@")[0],
                    user_type="mssp",
                    role="mssp_admin",
                )
                db.add(user)
                await db.flush()
                print(f"MSSP admin created: {email}")
            else:
                print(f"User already exists: {email} ({user.role}) — setting password.")

            print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            plain = _read_password()

            cred = (
                await db.execute(
                    select(PasswordCredential).where(
                        PasswordCredential.user_id == user.id
                    )
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if cred is None:
                db.add(
                    PasswordCredential(
                        user_id=user.id,
                        password_hash=hash_password(plain),
                        must_change=False,
                        updated_at=now,
                        consecutive_failures=0,
                    )
                )
            else:
                cred.password_hash = hash_password(plain)
                cred.must_change = False
                cred.updated_at = now
                cred.consecutive_failures = 0
                cred.locked_until = None
                db.add(cred)

            await log_audit(
                db,
                action="auth.admin.bootstrap",
                actor_principal="cli",
                actor_id="cli:create-admin",
                tenant_id=user.tenant_id,
                resource_type="user",
                resource_id=str(user.id),
                notes="created via soctalk-auth CLI",
            )
            await db.commit()
            print(f"Admin ready: {email}. You can now log in.")
            return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soctalk-auth")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("set-password", help="Set a user's password.")
    sp.add_argument("email", help="Email of the user.")

    ca = sub.add_parser(
        "create-admin",
        help="Bootstrap the first MSSP admin (org + user + password).",
    )
    ca.add_argument("email", help="Email for the admin user.")
    ca.add_argument("--display-name", default=None, help="Display name (default: email local part).")

    args = parser.parse_args(argv)

    if args.cmd == "set-password":
        return asyncio.run(_set_password(args.email))
    if args.cmd == "create-admin":
        return asyncio.run(_create_admin(args.email, args.display_name))
    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
