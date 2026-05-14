"""Async DB session factory and FastAPI middleware for V1.

V1 handlers require ``request.state.db`` to be populated before the
ingress-handoff auth middleware can perform user lookups, and before any
endpoint can touch the DB.

Two session factories:

- :func:`get_app_sessionmaker`. ``soctalk_app`` role (RLS-subject); default
  for all requests.
- :func:`get_mssp_sessionmaker`. ``soctalk_mssp`` role (BYPASSRLS); used
  only inside ``system_context()``. The middleware does not attach this
  session automatically: system code paths open their own.

``DATABASE_URL_APP`` / ``DATABASE_URL_MSSP`` env vars come from the
`soctalk-system-postgres-{app,mssp}-creds` Secrets mounted by the chart.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

if TYPE_CHECKING:
    from fastapi import FastAPI


_APP_ENGINE: AsyncEngine | None = None
_MSSP_ENGINE: AsyncEngine | None = None
_APP_SM: async_sessionmaker[AsyncSession] | None = None
_MSSP_SM: async_sessionmaker[AsyncSession] | None = None


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


def _ensure_app_engine() -> AsyncEngine:
    global _APP_ENGINE, _APP_SM
    if _APP_ENGINE is None:
        url = _require("DATABASE_URL_APP")
        _APP_ENGINE = create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=int(os.getenv("SOCTALK_DB_APP_POOL_SIZE", "25")),
            max_overflow=int(os.getenv("SOCTALK_DB_APP_MAX_OVERFLOW", "15")),
            pool_recycle=int(os.getenv("SOCTALK_DB_POOL_RECYCLE", "1800")),
        )
        _APP_SM = async_sessionmaker(_APP_ENGINE, expire_on_commit=False)
    return _APP_ENGINE


def _ensure_mssp_engine() -> AsyncEngine:
    global _MSSP_ENGINE, _MSSP_SM
    if _MSSP_ENGINE is None:
        url = _require("DATABASE_URL_MSSP")
        _MSSP_ENGINE = create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=int(os.getenv("SOCTALK_DB_MSSP_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("SOCTALK_DB_MSSP_MAX_OVERFLOW", "5")),
            pool_recycle=int(os.getenv("SOCTALK_DB_POOL_RECYCLE", "1800")),
        )
        _MSSP_SM = async_sessionmaker(_MSSP_ENGINE, expire_on_commit=False)
    return _MSSP_ENGINE


def get_app_sessionmaker() -> async_sessionmaker[AsyncSession]:
    _ensure_app_engine()
    assert _APP_SM is not None
    return _APP_SM


def get_mssp_sessionmaker() -> async_sessionmaker[AsyncSession]:
    _ensure_mssp_engine()
    assert _MSSP_SM is not None
    return _MSSP_SM


async def dispose_engines() -> None:
    """Used by app lifespan on shutdown."""
    global _APP_ENGINE, _MSSP_ENGINE
    if _APP_ENGINE is not None:
        await _APP_ENGINE.dispose()
        _APP_ENGINE = None
    if _MSSP_ENGINE is not None:
        await _MSSP_ENGINE.dispose()
        _MSSP_ENGINE = None


class DBSessionMiddleware:
    """Pure-ASGI middleware attaching an app-role session to every HTTP request.

    Must be installed **before** the auth handoff middleware, so that user
    lookups can use the session. Only HTTP scopes are wrapped; lifespan and
    websocket scopes pass through unchanged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        sm = get_app_sessionmaker()
        async with sm() as session:
            status_code = 500
            finalized = False

            async def send_with_status(message: Message) -> None:
                nonlocal status_code, finalized
                if message["type"] == "http.response.start":
                    status_code = int(message["status"])
                    # Finalize the transaction BEFORE the response goes
                    # on the wire. Otherwise the client can receive
                    # state-bearing artifacts (e.g. a Set-Cookie session
                    # id) and fire a follow-up request before our COMMIT
                    # is durable on Postgres — a concurrent SELECT on a
                    # different pooled connection misses the row, and
                    # the auth middleware evicts the freshly-minted
                    # cookie. Committing here makes the contract
                    # explicit: by the time bytes leave, the
                    # transaction is durable. Long-lived streaming
                    # endpoints (SSE) already close their session
                    # before yielding (see legacy_stubs.events_stream),
                    # so this commit happens on a no-op session.
                    if not finalized:
                        finalized = True
                        if 200 <= status_code < 400:
                            await session.commit()
                        else:
                            await session.rollback()
                await send(message)

            # Attach through FastAPI's Request.state machinery. Starlette
            # stores a mutable state mapping on the ASGI scope.
            state = scope.setdefault("state", {})
            state["db"] = session
            try:
                await self.app(scope, receive, send_with_status)
            except Exception:
                if not finalized:
                    await session.rollback()
                raise
            if not finalized:
                # Handler returned without ever sending a response
                # (rare — e.g. WebSocket-style upgrade or empty
                # generator). Default to commit on success-shaped
                # status, rollback otherwise.
                if 200 <= status_code < 400:
                    await session.commit()
                else:
                    await session.rollback()


async def yield_mssp_session() -> AsyncIterator[AsyncSession]:
    """Convenience generator for MSSP/system-context code paths."""
    sm = get_mssp_sessionmaker()
    async with sm() as session:
        yield session


def install_db_middleware(app: "FastAPI") -> None:
    """Wire the DB middleware into a FastAPI app.

    Middleware ordering matters: FastAPI applies middlewares in **reverse** of
    the order they are added. To ensure DB runs first (outermost on request,
    innermost on response), add it *after* the ingress handoff middleware.
    """
    app.add_middleware(DBSessionMiddleware)


__all__ = [
    "DBSessionMiddleware",
    "dispose_engines",
    "get_app_sessionmaker",
    "get_mssp_sessionmaker",
    "install_db_middleware",
    "yield_mssp_session",
]
