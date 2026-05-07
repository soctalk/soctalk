"""Branding endpoints: per-tenant and install-level.

- ``GET /api/tenant/branding``: called by the customer UI; returns the
  current tenant's branding (scope from JWT).
- ``PATCH /api/mssp/tenants/{id}/branding``: mssp_admin updates.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import resolve_request_tenant
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_role, require_tenant_role
from soctalk.core.tenancy.models import BrandingConfig, Role

tenant_router = APIRouter(prefix="/api/tenant", tags=["tenant-branding"])
mssp_router = APIRouter(prefix="/api/mssp/tenants", tags=["mssp-tenant-branding"])


class BrandingRead(BaseModel):
    app_name: str
    logo_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    favicon_url: str | None = None


class BrandingUpdate(BaseModel):
    app_name: str | None = Field(default=None, max_length=255)
    logo_url: str | None = Field(default=None, max_length=500)
    primary_color: str | None = Field(default=None, max_length=16)
    secondary_color: str | None = Field(default=None, max_length=16)
    favicon_url: str | None = Field(default=None, max_length=500)


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


@tenant_router.get(
    "/branding",
    response_model=BrandingRead,
    dependencies=[Depends(require_tenant_role())],
)
async def get_own_branding(request: Request) -> BrandingRead:
    tid = resolve_request_tenant(request)
    if tid is None:
        raise HTTPException(400, "tenant context missing")
    session = _db(request)
    async with tenant_context(session, tid):
        result = await session.execute(
            select(BrandingConfig).where(BrandingConfig.tenant_id == tid)
        )
    b = result.scalar_one_or_none()
    if b is None:
        # Reasonable default: we don't 404 on missing branding.
        return BrandingRead(app_name="SocTalk")
    return BrandingRead(
        app_name=b.app_name,
        logo_url=b.logo_url,
        primary_color=b.primary_color,
        secondary_color=b.secondary_color,
        favicon_url=b.favicon_url,
    )


@mssp_router.patch(
    "/{tenant_id}/branding",
    response_model=BrandingRead,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def update_tenant_branding(
    tenant_id: UUID, payload: BrandingUpdate, request: Request
) -> BrandingRead:
    session = _db(request)
    async with tenant_context(session, tenant_id):
        result = await session.execute(
            select(BrandingConfig).where(BrandingConfig.tenant_id == tenant_id)
        )
        b = result.scalar_one_or_none()
        if b is None:
            b = BrandingConfig(tenant_id=tenant_id, app_name="SocTalk")
            session.add(b)
        if payload.app_name is not None:
            b.app_name = payload.app_name
        if payload.logo_url is not None:
            b.logo_url = payload.logo_url
        if payload.primary_color is not None:
            b.primary_color = payload.primary_color
        if payload.secondary_color is not None:
            b.secondary_color = payload.secondary_color
        if payload.favicon_url is not None:
            b.favicon_url = payload.favicon_url
        await session.flush()
    return BrandingRead(
        app_name=b.app_name,
        logo_url=b.logo_url,
        primary_color=b.primary_color,
        secondary_color=b.secondary_color,
        favicon_url=b.favicon_url,
    )
