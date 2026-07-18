// Shared spec helpers.
//
// Two hard-won rules encoded here (both learned from broken specs):
// 1. NEVER register a bare '**/api/**' catch-all — the glob also matches the
//    vite dev-module graph (/src/lib/api/client.ts, ...) and blanks the page.
//    Mock specific endpoints, or filter on `pathname.startsWith('/api/')` and
//    route.continue() everything else.
// 2. /auth/me MUST return a `permissions` array — since the RBAC capability
//    layer (#50), nav items and panels gate on permissions, not role strings.
//    A user object without permissions renders an almost-empty shell.
import type { Page } from '@playwright/test';

export const TENANT_ID = '11111111-1111-1111-1111-111111111111';

/** Full mssp_admin capability set, mirroring ROLE_PERMISSIONS server-side. */
export const MSSP_ADMIN_PERMISSIONS = [
	'view_investigations',
	'triage_investigation',
	'review_decide',
	'approve_proposal',
	'view_alerts',
	'view_dashboard',
	'view_analytics',
	'view_audit',
	'use_chat',
	'view_triage_policies',
	'view_engagements',
	'view_authorization_facts',
	'view_tenants',
	'authorize_engagement',
	'manage_authorization_facts',
	'approve_privileged_proposal',
	'configure_integrations',
	'manage_external_siem',
	'configure_llm',
	'manage_branding',
	'manage_users',
	'manage_triage_policies',
	'manage_tenant_lifecycle'
];

export function msspAdminUser(overrides: Record<string, unknown> = {}) {
	return {
		user_id: '00000000-0000-0000-0000-000000000001',
		email: 'admin@mssp.example',
		user_type: 'mssp',
		role: 'mssp_admin',
		tenant_id: null,
		current_tenant: null,
		current_tenant_slug: null,
		permissions: MSSP_ADMIN_PERMISSIONS,
		...overrides
	};
}

// Mock /api/auth/me with an mssp_admin identity. The route pattern ends in
// "auth/me", which never collides with vite module URLs.
export async function mockAuthMe(page: Page, overrides: Record<string, unknown> = {}) {
	await page.route('**/auth/me', (route) =>
		route.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify(msspAdminUser(overrides))
		})
	);
}
