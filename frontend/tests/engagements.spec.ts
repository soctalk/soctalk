import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

function me(role: string, permissions: string[]) {
	return {
		user_id: 'u1', email: `${role}@acme.example`, user_type: 'tenant', role,
		tenant_id: TID, current_tenant: null, permissions
	};
}

// Window entirely in the past → client should derive status 'expired' (the DTO
// has no status field; this exercises the derivation fix).
const PAST_ENGAGEMENT = {
	id: 'eng-1', name: 'Q3 external pentest', kind: 'pentest',
	starts_at: '2020-07-01T00:00:00Z', ends_at: '2020-07-03T00:00:00Z',
	scope_source_ips: ['203.0.113.0/24'], scope_hosts: ['web-01'], scope_techniques: [],
	revoked_at: null, out_of_scope_count: 3
};

async function wireTenant(page: Page, perms: string[]) {
	const store: Record<string, unknown>[] = [PAST_ENGAGEMENT];
	const captured: { body: Record<string, unknown> | null } = { body: null };
	await page.route('**/auth/me', (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me('tenant_manager', perms)) })
	);
	await page.route('**/api/tenant/engagements**', async (route) => {
		if (route.request().method() === 'POST') {
			captured.body = JSON.parse(route.request().postData() || '{}');
			store.push({ ...PAST_ENGAGEMENT, id: 'eng-2', ...captured.body, revoked_at: null });
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'eng-2' }) });
		} else {
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(store) });
		}
	});
	return captured;
}

test.describe('Tenant engagements — structured declare', () => {
	test('lists with a client-derived status badge and out-of-scope count', async ({ page }) => {
		await wireTenant(page, ['tenant_view_engagements', 'tenant_authorize_engagement']);
		await page.goto('/my-authorization?tab=engagements');
		await expect(page.getByText('Q3 external pentest')).toBeVisible();
		await expect(page.getByText('expired')).toBeVisible(); // derived, not from the wire
		await expect(page.getByText(/3 out of scope/)).toBeVisible();
	});

	test('declares an engagement with techniques (payload upper-cases and includes them)', async ({ page }) => {
		const cap = await wireTenant(page, ['tenant_view_engagements', 'tenant_authorize_engagement']);
		await page.goto('/my-authorization?tab=engagements');
		await page.getByRole('button', { name: '+ Declare engagement' }).click();
		await page.getByPlaceholder('Q3 external pentest').fill('adhoc redteam');
		await page.locator('input[type=datetime-local]').first().fill('2026-08-01T09:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-08-14T18:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		await page.getByPlaceholder('T1078, T1110.001').fill('t1078, T1110.001');
		await page.getByRole('button', { name: 'Declare', exact: true }).click();
		await expect(page.getByText('adhoc redteam')).toBeVisible();

		expect(cap.body).toMatchObject({
			name: 'adhoc redteam', kind: 'pentest',
			scope_source_ips: ['198.51.100.0/24'],
			scope_techniques: ['T1078', 'T1110.001'] // upper-cased
		});
	});

	test('validation: no host and no technique is blocked client-side', async ({ page }) => {
		const cap = await wireTenant(page, ['tenant_view_engagements', 'tenant_authorize_engagement']);
		await page.goto('/my-authorization?tab=engagements');
		await page.getByRole('button', { name: '+ Declare engagement' }).click();
		await page.getByPlaceholder('Q3 external pentest').fill('too broad');
		await page.locator('input[type=datetime-local]').first().fill('2026-08-01T09:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-08-14T18:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		// no hosts, no techniques
		await page.getByRole('button', { name: 'Declare', exact: true }).click();
		await expect(page.getByText(/at least one host or one technique/i)).toBeVisible();
		expect(cap.body).toBeNull();
	});

	test('validation: a malformed technique is blocked client-side', async ({ page }) => {
		const cap = await wireTenant(page, ['tenant_view_engagements', 'tenant_authorize_engagement']);
		await page.goto('/my-authorization?tab=engagements');
		await page.getByRole('button', { name: '+ Declare engagement' }).click();
		await page.getByPlaceholder('Q3 external pentest').fill('bad tech');
		await page.locator('input[type=datetime-local]').first().fill('2026-08-01T09:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-08-14T18:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		await page.getByPlaceholder('T1078, T1110.001').fill('not-a-technique');
		await page.getByRole('button', { name: 'Declare', exact: true }).click();
		await expect(page.getByText(/T1078/)).toBeVisible(); // the technique-format error mentions T1078
		expect(cap.body).toBeNull();
	});

	test('a tenant viewer sees engagements but cannot declare or revoke', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me('customer_viewer', ['tenant_view_engagements'])) })
		);
		await page.route('**/api/tenant/engagements**', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([PAST_ENGAGEMENT]) })
		);
		await page.goto('/my-authorization?tab=engagements');
		await expect(page.getByText('Q3 external pentest')).toBeVisible();
		await expect(page.getByRole('button', { name: '+ Declare engagement' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
	});
});
