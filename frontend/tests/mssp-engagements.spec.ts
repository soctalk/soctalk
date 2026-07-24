import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

const MANAGER_PERMS = [
	'view_authorization_facts', 'manage_authorization_facts', 'view_tenants', 'view_dashboard',
	'view_engagements', 'authorize_engagement'
];
// Analyst tier: can see engagements, cannot declare or revoke them.
const ANALYST_PERMS = ['view_authorization_facts', 'view_tenants', 'view_dashboard', 'view_engagements'];

function seedEngagement(over: Record<string, unknown> = {}) {
	return {
		id: 'eng-1', name: 'Q3 external pentest', kind: 'pentest',
		starts_at: '2026-08-01T09:00:00Z', ends_at: '2026-08-05T18:00:00Z',
		scope_source_ips: ['203.0.113.0/24'], scope_hosts: ['web-01'], scope_techniques: ['T1078'],
		revoked_at: null, created_at: '2026-07-20T00:00:00Z',
		declared_test_count: 3, out_of_scope_count: 0, ...over
	};
}

// Wire the MSSP identity plus the MSSP engagements endpoints. Returns handles on
// what the page actually sent, so the tests assert the declared payload and the
// tenant it was scoped to -- not merely that a request happened.
async function wire(
	page: Page,
	opts: { perms?: string[]; tenant?: string | null; engagements?: Record<string, unknown>[] } = {}
) {
	const list = opts.engagements ?? [seedEngagement()];
	const captured: { body: Record<string, unknown> | null; url: string | null } = { body: null, url: null };
	const tenant = opts.tenant === undefined ? TID : opts.tenant;

	await page.route('**/auth/me', (r) =>
		r.fulfill({
			status: 200, contentType: 'application/json', body: JSON.stringify({
				user_id: 'u1', email: 'admin@mssp.example', user_type: 'mssp', role: 'mssp_admin',
				tenant_id: null, current_tenant: tenant, current_tenant_slug: tenant ? 'acme' : null,
				permissions: opts.perms ?? MANAGER_PERMS
			})
		})
	);
	await page.route('**/api/mssp/tenants/*/authorization/facts', (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: [] }) })
	);
	await page.route('**/api/mssp/tenants/*/engagements/*/revoke', async (route) => {
		captured.url = route.request().url();
		list.length = 0;
		await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: 'revoked' }) });
	});
	await page.route('**/api/mssp/tenants/*/engagements*', async (route) => {
		captured.url = route.request().url();
		if (route.request().method() === 'POST') {
			captured.body = JSON.parse(route.request().postData() || '{}');
			list.push(seedEngagement({ id: 'eng-2', ...captured.body }));
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'eng-2' }) });
		} else {
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(list) });
		}
	});
	return captured;
}

test.describe('MSSP engagements', () => {
	test('the Engagements tab lists the tenant engagements', async ({ page }) => {
		await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: 'Engagements' }).click();
		await expect(page.getByText('Q3 external pentest')).toBeVisible();
		await expect(page.getByText('203.0.113.0/24')).toBeVisible();
	});

	test('deep link ?tab=engagements opens straight onto the tab', async ({ page }) => {
		await wire(page);
		await page.goto('/authorization?tab=engagements');
		await expect(page.getByText('Q3 external pentest')).toBeVisible();
	});

	test('declares an engagement against the pinned tenant (payload is legal)', async ({ page }) => {
		const cap = await wire(page, { engagements: [] });
		await page.goto('/authorization?tab=engagements');
		await page.getByRole('button', { name: 'Declare engagement' }).click();

		await page.getByPlaceholder('Q3 external pentest').fill('Red team Q4');
		await page.locator('input[type=datetime-local]').first().fill('2026-09-01T09:00');
		await page.locator('input[type=datetime-local]').last().fill('2026-09-10T17:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		await page.getByPlaceholder('web-01, db-01').fill('app-01');
		await page.getByRole('button', { name: 'Declare', exact: true }).click();

		await expect(page.getByText('Red team Q4')).toBeVisible();
		expect(cap.body?.name).toBe('Red team Q4');
		expect(cap.body?.scope_source_ips).toEqual(['198.51.100.0/24']);
		expect(cap.body?.scope_hosts).toEqual(['app-01']);
		// Scoped to the tenant pinned in the switcher, never a tenant-side route.
		expect(cap.url).toContain(`/api/mssp/tenants/${TID}/engagements`);
	});

	test('blocks an unbounded scope before it reaches the server', async ({ page }) => {
		const cap = await wire(page, { engagements: [] });
		await page.goto('/authorization?tab=engagements');
		await page.getByRole('button', { name: 'Declare engagement' }).click();

		await page.getByPlaceholder('Q3 external pentest').fill('No scope');
		await page.locator('input[type=datetime-local]').first().fill('2026-09-01T09:00');
		await page.locator('input[type=datetime-local]').last().fill('2026-09-10T17:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		// No hosts and no techniques: the server would 400, so the form must refuse first.
		await page.getByRole('button', { name: 'Declare', exact: true }).click();

		await expect(page.locator('.alert')).toBeVisible();
		expect(cap.body).toBeNull();
	});

	test('analyst tier sees engagements but gets no declare or revoke controls', async ({ page }) => {
		await wire(page, { perms: ANALYST_PERMS });
		await page.goto('/authorization?tab=engagements');
		await expect(page.getByText('Q3 external pentest')).toBeVisible();
		await expect(page.getByRole('button', { name: 'Declare engagement' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
	});

	test('without a pinned tenant the tab asks for one instead of failing', async ({ page }) => {
		await wire(page, { tenant: null });
		await page.goto('/authorization?tab=engagements');
		await expect(page.getByText(/Select a tenant/i)).toBeVisible();
		// The button only exists once /auth/me has hydrated the permission stores, and
		// that can lag under a loaded run. Wait for it to appear before asserting its
		// state, rather than racing hydration with a bare toBeDisabled().
		const declare = page.getByRole('button', { name: 'Declare engagement' });
		await expect(declare).toBeVisible({ timeout: 15000 });
		await expect(declare).toBeDisabled();
	});
});
