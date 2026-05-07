"""Unauthenticated public endpoints for slug-driven tenant landing.

Slugs are intentionally public — they're in URLs, in DNS, and visible
to anyone trying to onboard. We expose a thin lookup so the frontend
can fetch branding pre-login (apply theme/logo before the user has
typed anything) and pin tenant context for the impersonation flow.

NOT exposed here: tenant id ↔ user enumeration, sensitive config,
runtime state. Just identity + branding (app_name / colors / logo).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.models import BrandingConfig, Organization, Tenant


router = APIRouter(prefix="/api/public", tags=["public-tenant"])


class PublicBranding(BaseModel):
    app_name: str
    logo_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    favicon_url: str | None = None


class PublicTenant(BaseModel):
    id: str
    slug: str
    display_name: str
    state: str
    branding: PublicBranding


def _db(request: Request) -> AsyncSession:
    s = getattr(request.state, "db", None)
    if s is None:
        raise HTTPException(500, "db session not attached")
    return s


@router.get("/tenant-by-slug/{slug}", response_model=PublicTenant)
async def tenant_by_slug(slug: str, request: Request) -> PublicTenant:
    """Resolve a public slug to identity + branding.

    No auth: slugs are intentionally public-facing (DNS, URLs). Both
    ``tenants`` and ``branding_configs`` have no RLS policies — they're
    read freely under the soctalk_app role. Slugs are constrained to
    ``[a-z0-9-]{3,32}`` at provisioning so probing random patterns
    can't cheaply enumerate.
    """
    if not slug or len(slug) > 64:
        raise HTTPException(400, "invalid slug")

    db = _db(request)
    tenant_row = (
        await db.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalar_one_or_none()
    if tenant_row is None:
        raise HTTPException(404, "tenant not found")
    if tenant_row.state in ("decommissioning", "archived", "purged"):
        raise HTTPException(410, "tenant retired")
    branding_row = (
        await db.execute(
            select(BrandingConfig).where(
                BrandingConfig.tenant_id == tenant_row.id
            )
        )
    ).scalar_one_or_none()

    return PublicTenant(
        id=str(tenant_row.id),
        slug=tenant_row.slug,
        display_name=tenant_row.display_name,
        state=tenant_row.state,
        branding=PublicBranding(
            app_name=(branding_row.app_name if branding_row else tenant_row.display_name),
            logo_url=branding_row.logo_url if branding_row else None,
            primary_color=branding_row.primary_color if branding_row else None,
            secondary_color=branding_row.secondary_color if branding_row else None,
            favicon_url=branding_row.favicon_url if branding_row else None,
        ),
    )


class PublicMssp(BaseModel):
    id: str
    slug: str
    display_name: str
    branding: PublicBranding


class PublicScope(BaseModel):
    kind: str  # 'mssp' | 'tenant'
    id: str
    slug: str
    display_name: str
    state: str | None = None
    branding: PublicBranding


@router.get("/scope-by-slug/{slug}", response_model=PublicScope)
async def scope_by_slug(slug: str, request: Request) -> PublicScope:
    """Resolve any slug — MSSP or tenant — to its public scope.

    Single entry point so the canonical UI doesn't need to encode
    ``mssp.`` vs ``customer.`` in hostnames. Slugs MUST be globally
    unique across organizations + tenants for this to work; we look
    up MSSPs first (rare, low cardinality), then tenants. A collision
    returns the MSSP — provisioning is expected to reject overlapping
    slugs at create-time.
    """
    if not slug or len(slug) > 64:
        raise HTTPException(400, "invalid slug")
    db = _db(request)
    mssp_row = (
        await db.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if mssp_row is not None:
        return PublicScope(
            kind="mssp",
            id=str(mssp_row.id),
            slug=mssp_row.slug,
            display_name=mssp_row.mssp_name,
            branding=PublicBranding(
                app_name=mssp_row.mssp_name,
                logo_url=mssp_row.logo_url,
                primary_color=mssp_row.primary_color,
                secondary_color=mssp_row.secondary_color,
                favicon_url=mssp_row.favicon_url,
            ),
        )
    tenant_row = (
        await db.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalar_one_or_none()
    if tenant_row is None:
        raise HTTPException(404, "slug not found")
    if tenant_row.state in ("decommissioning", "archived", "purged"):
        raise HTTPException(410, "tenant retired")
    branding_row = (
        await db.execute(
            select(BrandingConfig).where(BrandingConfig.tenant_id == tenant_row.id)
        )
    ).scalar_one_or_none()
    return PublicScope(
        kind="tenant",
        id=str(tenant_row.id),
        slug=tenant_row.slug,
        display_name=tenant_row.display_name,
        state=tenant_row.state,
        branding=PublicBranding(
            app_name=(branding_row.app_name if branding_row else tenant_row.display_name),
            logo_url=branding_row.logo_url if branding_row else None,
            primary_color=branding_row.primary_color if branding_row else None,
            secondary_color=branding_row.secondary_color if branding_row else None,
            favicon_url=branding_row.favicon_url if branding_row else None,
        ),
    )


@router.get("/mssp-by-slug/{slug}", response_model=PublicMssp)
async def mssp_by_slug(slug: str, request: Request) -> PublicMssp:
    """Resolve an MSSP slug to identity + branding.

    Used by the canonical UI when the URL is ``<slug>.mssp.<base>`` so
    the login page renders the MSSP's branding pre-login. No auth —
    same threat model as tenant-by-slug (slugs are public DNS).
    """
    if not slug or len(slug) > 64:
        raise HTTPException(400, "invalid slug")
    db = _db(request)
    row = (
        await db.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "mssp not found")
    return PublicMssp(
        id=str(row.id),
        slug=row.slug,
        display_name=row.mssp_name,
        branding=PublicBranding(
            app_name=row.mssp_name,
            logo_url=row.logo_url,
            primary_color=row.primary_color,
            secondary_color=row.secondary_color,
            favicon_url=row.favicon_url,
        ),
    )
