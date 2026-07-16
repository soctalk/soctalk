import { test, expect } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

function me(role: string, permissions: string[]) {
	return {
		user_id: 'u1',
		email: `${role}@acme.example`,
		user_type: 'tenant',
		role,
		tenant_id: TID,
		current_tenant: null,
		permissions
	};
}

const ENGAGEMENT = {
	id: 'eng-1',
	name: 'Q3 external pentest',
	kind: 'pentest',
	status: 'active',
	starts_at: '2026-07-01T00:00:00Z',
	ends_at: '2026-07-03T00:00:00Z',
	scope_source_ips: ['203.0.113.0/24'],
	scope_hosts: ['web-01'],
	scope_techniques: []
};

test.describe('Tenant engagements (self-service)', () => {
	test('tenant_manager declares its own engagement', async ({ page }) => {
		const store = [ENGAGEMENT];
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(
					me('tenant_manager', ['tenant_view_engagements', 'tenant_authorize_engagement'])
				)
			})
		);
		await page.route('**/api/tenant/engagements**', async (route) => {
			if (route.request().method() === 'POST') {
				store.push({ ...ENGAGEMENT, id: 'eng-2', name: 'adhoc redteam' });
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({ id: 'eng-2' })
				});
			} else {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify(store)
				});
			}
		});

		await page.goto('/my-authorization?tab=engagements');
		await expect(page.getByRole('heading', { name: 'Authorization' })).toBeVisible();
		await expect(page.getByText('Q3 external pentest')).toBeVisible();

		await page.getByRole('button', { name: '+ Declare engagement' }).click();
		await page.getByPlaceholder('Q3 external pentest').fill('adhoc redteam');
		await page.locator('input[type=datetime-local]').first().fill('2026-08-01T09:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-08-01T17:00');
		await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
		await page.getByRole('button', { name: 'Declare', exact: true }).click();
		await expect(page.getByText('adhoc redteam')).toBeVisible();
	});

	test('a tenant viewer sees engagements but cannot declare', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('customer_viewer', ['tenant_view_engagements']))
			})
		);
		await page.route('**/api/tenant/engagements**', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([ENGAGEMENT]) })
		);

		await page.goto('/my-authorization?tab=engagements');
		await expect(page.getByText('Q3 external pentest')).toBeVisible(); // read works
		await expect(page.getByRole('button', { name: '+ Declare engagement' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
	});
});
