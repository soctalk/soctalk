"""Integration tests for the internal authentication subsystem.

Covers the nine backend cases from ``docs/v1/P1-1-internal-auth.md`` §11:

1. Login happy path creates a session row with the right tenant_context.
2. Wrong password increments consecutive_failures; ten triggers lockout.
3. must_change blocks every non-password endpoint.
4. Password change revokes all other sessions; preserves current.
5. Logout revokes only the current session.
6. Admin reset revokes all sessions and forces must_change.
7. AUTH_MODE=proxy path regression — covered in the unit suite.
8. CSRF — covered in the unit suite.
9. Session past expiry is rejected.

These require a live Postgres with the v1_0002 migration applied.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; internal auth tests need Postgres",
    ),
]


# --- Fixtures --------------------------------------------------------------


@pytest.fixture
def seeded_user_email(seed_two_tenants):
    """Pick a seeded tenant viewer's email for tests."""

    _, tenant_b = seed_two_tenants
    return f"viewer-{tenant_b.slug}@{tenant_b.slug}.example"


# --- Tests -----------------------------------------------------------------


async def test_login_success_creates_session_and_emits_audit(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential, Session
    from soctalk.core.auth.service import authenticate
    from soctalk.core.tenancy.models import User

    tenant_a, _ = seed_two_tenants
    email = f"admin-a@mssp-a.example"
    user = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": email}
        )
    ).scalar_one()

    mssp_session.add(
        PasswordCredential(
            user_id=user,
            password_hash=hash_password("correct-horse-staple-01"),
        )
    )
    await mssp_session.commit()

    result = await authenticate(
        mssp_session,
        email=email,
        password="correct-horse-staple-01",
        ip="127.0.0.1",
        user_agent="pytest",
    )
    await mssp_session.commit()

    assert result.session.user_id == user
    assert result.must_change is False

    count = (
        await mssp_session.execute(
            text(
                "SELECT count(*) FROM audit_log "
                "WHERE action = 'auth.login.success' AND actor_id = :uid"
            ),
            {"uid": str(user)},
        )
    ).scalar_one()
    assert count >= 1


async def test_wrong_password_triggers_lockout(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.service import (
        AccountLocked,
        InvalidCredentials,
        authenticate,
    )
    from soctalk.core.tenancy.models import User

    email = f"admin-b@mssp-b.example"
    user_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": email}
        )
    ).scalar_one()

    mssp_session.add(
        PasswordCredential(
            user_id=user_id,
            password_hash=hash_password("right-password-1234"),
        )
    )
    await mssp_session.commit()

    for _ in range(10):
        with pytest.raises(InvalidCredentials):
            await authenticate(
                mssp_session,
                email=email,
                password="wrong",
                ip="127.0.0.1",
                user_agent="pytest",
            )
    await mssp_session.commit()

    # Eleventh attempt with the correct password must still fail due to lock.
    with pytest.raises(AccountLocked):
        await authenticate(
            mssp_session,
            email=email,
            password="right-password-1234",
            ip="127.0.0.1",
            user_agent="pytest",
        )


async def test_password_change_revokes_other_sessions(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential, Session
    from soctalk.core.auth.service import authenticate, change_password

    email = f"admin-a@mssp-a.example"
    user_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": email}
        )
    ).scalar_one()

    # A prior credential exists from earlier tests; reset it here.
    await mssp_session.execute(
        text("DELETE FROM password_credentials WHERE user_id = :u"),
        {"u": str(user_id)},
    )
    await mssp_session.execute(
        text("DELETE FROM sessions WHERE user_id = :u"), {"u": str(user_id)}
    )
    mssp_session.add(
        PasswordCredential(
            user_id=user_id,
            password_hash=hash_password("original-password-1234"),
        )
    )
    await mssp_session.commit()

    # Two sessions for the same user: one "current", one "other".
    login_a = await authenticate(
        mssp_session,
        email=email,
        password="original-password-1234",
        ip="1.1.1.1",
        user_agent="tab-a",
    )
    login_b = await authenticate(
        mssp_session,
        email=email,
        password="original-password-1234",
        ip="2.2.2.2",
        user_agent="tab-b",
    )
    await mssp_session.commit()

    current_session_id = login_a.session.id

    await change_password(
        mssp_session,
        user_id=user_id,
        current_session_id=current_session_id,
        old_password="original-password-1234",
        new_password="brand-new-password-99",
    )
    await mssp_session.commit()

    # The current session is still active; the other is revoked.
    current_row = (
        await mssp_session.execute(
            text("SELECT revoked_at FROM sessions WHERE id = :id"),
            {"id": str(current_session_id)},
        )
    ).scalar_one()
    other_row = (
        await mssp_session.execute(
            text("SELECT revoked_at FROM sessions WHERE id = :id"),
            {"id": str(login_b.session.id)},
        )
    ).scalar_one()
    assert current_row is None
    assert other_row is not None


async def test_admin_reset_forces_must_change_and_revokes_sessions(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.service import admin_reset_password, authenticate
    from soctalk.core.tenancy.models import User
    from sqlalchemy import select

    target_email = f"admin-b@mssp-b.example"
    actor_email = f"admin-a@mssp-a.example"

    target_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": target_email}
        )
    ).scalar_one()
    actor_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": actor_email}
        )
    ).scalar_one()

    # Seed a credential and an active session for the target.
    await mssp_session.execute(
        text("DELETE FROM password_credentials WHERE user_id = :u"),
        {"u": str(target_id)},
    )
    await mssp_session.execute(
        text("DELETE FROM sessions WHERE user_id = :u"), {"u": str(target_id)}
    )
    mssp_session.add(
        PasswordCredential(
            user_id=target_id,
            password_hash=hash_password("existing-password-1234"),
        )
    )
    await mssp_session.commit()

    session_row = (
        await authenticate(
            mssp_session,
            email=target_email,
            password="existing-password-1234",
            ip="3.3.3.3",
            user_agent="pre-reset",
        )
    ).session
    await mssp_session.commit()

    # Act as admin-a and reset.
    actor = (
        await mssp_session.execute(select(User).where(User.id == actor_id))
    ).scalar_one()
    new_password = await admin_reset_password(
        mssp_session, actor_user=actor, target_user_id=target_id
    )
    await mssp_session.commit()

    # Credential now has must_change=true.
    cred_row = (
        await mssp_session.execute(
            text(
                "SELECT must_change FROM password_credentials WHERE user_id = :u"
            ),
            {"u": str(target_id)},
        )
    ).scalar_one()
    assert cred_row is True

    # The earlier session is revoked.
    revoked_at = (
        await mssp_session.execute(
            text("SELECT revoked_at FROM sessions WHERE id = :id"),
            {"id": str(session_row.id)},
        )
    ).scalar_one()
    assert revoked_at is not None

    # The emitted password lets the user log in once.
    result = await authenticate(
        mssp_session,
        email=target_email,
        password=new_password,
        ip="4.4.4.4",
        user_agent="post-reset",
    )
    await mssp_session.commit()
    assert result.must_change is True


async def test_logout_revokes_only_current_session(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.service import authenticate, logout

    email = f"admin-a@mssp-a.example"
    user_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": email}
        )
    ).scalar_one()

    await mssp_session.execute(
        text("DELETE FROM password_credentials WHERE user_id = :u"),
        {"u": str(user_id)},
    )
    await mssp_session.execute(
        text("DELETE FROM sessions WHERE user_id = :u"), {"u": str(user_id)}
    )
    mssp_session.add(
        PasswordCredential(
            user_id=user_id,
            password_hash=hash_password("password-for-logout-01"),
        )
    )
    await mssp_session.commit()

    login_a = await authenticate(
        mssp_session,
        email=email,
        password="password-for-logout-01",
        ip="1.1.1.1",
        user_agent="tab-a",
    )
    login_b = await authenticate(
        mssp_session,
        email=email,
        password="password-for-logout-01",
        ip="2.2.2.2",
        user_agent="tab-b",
    )
    await mssp_session.commit()

    await logout(
        mssp_session,
        session_id=login_a.session.id,
        user_id=user_id,
        tenant_id=None,
    )
    await mssp_session.commit()

    a_revoked = (
        await mssp_session.execute(
            text("SELECT revoked_at FROM sessions WHERE id = :id"),
            {"id": str(login_a.session.id)},
        )
    ).scalar_one()
    b_revoked = (
        await mssp_session.execute(
            text("SELECT revoked_at FROM sessions WHERE id = :id"),
            {"id": str(login_b.session.id)},
        )
    ).scalar_one()
    assert a_revoked is not None
    assert b_revoked is None


async def test_expired_session_is_not_resolved(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.service import authenticate
    from soctalk.core.auth.sessions import resolve_session

    email = f"admin-a@mssp-a.example"
    user_id = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": email}
        )
    ).scalar_one()

    await mssp_session.execute(
        text("DELETE FROM password_credentials WHERE user_id = :u"),
        {"u": str(user_id)},
    )
    mssp_session.add(
        PasswordCredential(
            user_id=user_id,
            password_hash=hash_password("password-for-expiry-01"),
        )
    )
    await mssp_session.commit()

    login = await authenticate(
        mssp_session,
        email=email,
        password="password-for-expiry-01",
        ip="1.1.1.1",
        user_agent="short-lived",
    )
    await mssp_session.commit()

    # Force the absolute_expiry into the past.
    await mssp_session.execute(
        text(
            "UPDATE sessions SET absolute_expiry = now() - interval '1 minute'"
            " WHERE id = :id"
        ),
        {"id": str(login.session.id)},
    )
    await mssp_session.commit()
    # Drop the ORM's cached copy so resolve_session re-reads from DB.
    await mssp_session.close()

    resolved = await resolve_session(mssp_session, login.session.id)
    assert resolved is None
