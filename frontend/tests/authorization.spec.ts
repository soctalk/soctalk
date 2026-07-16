import { test, expect } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

function fact(id: string, scope = { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }) {
	return {
		id,
		kind: 'grant',
		track: 'account',
		source_type: 'analyst_asserted',
		trust: 60,
		scope,
		valid_until: '2026-12-31T00:00:00Z',
		created_by: 'admin',
		provenance: {}
	};
}

test.describe('Authorization facts page', () => {
	test.beforeEach(async ({ page }) => {
		const facts = [fact('CHG-1001')];
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					user_id: 'u1',
					email: 'admin@mssp.example',
					user_type: 'mssp',
					role: 'mssp_admin',
					tenant_id: null,
					current_tenant: TID,
					current_tenant_slug: 'acme',
					permissions: ['view_investigations','triage_investigation','review_decide','approve_proposal','view_alerts','view_dashboard','view_analytics','view_audit','use_chat','view_triage_policies','view_engagements','view_authorization_facts','view_tenants','authorize_engagement','manage_authorization_facts','approve_privileged_proposal','configure_integrations','manage_external_siem','configure_llm','manage_branding','manage_users','manage_triage_policies','manage_tenant_lifecycle']
				})
			})
		);
		await page.route('**/api/mssp/tenants/*/authorization/facts/*/revoke', async (route) => {
			facts.length = 0; // soft-delete → gone from the list
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ revoked: true })
			});
		});
		await page.route('**/api/mssp/tenants/*/authorization/facts', async (route) => {
			if (route.request().method() === 'POST') {
				const body = JSON.parse(route.request().postData() || '{}');
				const f = body.fact ?? {};
				facts.push(fact(f.id || 'NEW', f.scope));
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({ stored: f.id })
				});
			} else {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({ facts })
				});
			}
		});
	});

	test('lists authorization facts with scope', async ({ page }) => {
		await page.goto('/authorization');
		await expect(page.getByRole('heading', { name: 'Authorization facts' })).toBeVisible();
		await expect(page.getByText('CHG-1001')).toBeVisible();
		await expect(page.getByText('svc-deploy · db-01 · sudo-exec')).toBeVisible();
	});

	test('creates a fact via the editor', async ({ page }) => {
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		const editor = page.locator('textarea');
		await expect(editor).toBeVisible();
		await editor.fill(
			JSON.stringify({ kind: 'grant', id: 'CHG-2002', track: 'account', scope: { subject: 'x' } })
		);
		await page.getByRole('button', { name: 'Create' }).click();
		await expect(page.getByText('CHG-2002')).toBeVisible();
	});

	test('revokes a fact (soft delete)', async ({ page }) => {
		page.on('dialog', (d) => d.accept('offboarded'));
		await page.goto('/authorization');
		await expect(page.getByText('CHG-1001')).toBeVisible();
		await page.getByRole('button', { name: 'Revoke' }).click();
		await expect(page.getByText('No authorization facts for this tenant yet.')).toBeVisible();
	});

	test('manager reviews (approves) a pending tenant-asserted fact', async ({ page }) => {
		let status = 'pending';
		await page.route('**/api/mssp/tenants/*/authorization/facts/*/review', async (route) => {
			status = 'approved';
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ reviewed: 'TA-1', status: 'approved' })
			});
		});
		await page.route('**/api/mssp/tenants/*/authorization/facts', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					facts: [
						{
							id: 'TA-1',
							kind: 'grant',
							track: 'account',
							source_type: 'tenant_asserted',
							trust: 20,
							review_status: status,
							scope: { subject: 'svc', target: 'db-01', action: 'sudo' }
						}
					]
				})
			});
		});
		await page.goto('/authorization');
		await expect(page.getByText('awaiting review')).toBeVisible();
		await page.getByRole('button', { name: 'Approve' }).click();
		await expect(page.getByText('approved')).toBeVisible();
		await expect(page.getByRole('button', { name: 'Approve' })).toHaveCount(0);
	});

	test('a view-only role sees the facts but no write controls (RBAC)', async ({ page }) => {
		// override the identity: an operator who can VIEW but lacks manage_authorization_facts
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					user_id: 'u2',
					email: 'analyst@mssp.example',
					user_type: 'mssp',
					role: 'analyst',
					tenant_id: null,
					current_tenant: TID,
					current_tenant_slug: 'acme',
					permissions: ['view_authorization_facts', 'view_investigations']
				})
			})
		);
		await page.goto('/authorization');
		await expect(page.getByText('CHG-1001')).toBeVisible(); // read still works
		await expect(page.getByRole('button', { name: '+ New fact' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
	});
});
