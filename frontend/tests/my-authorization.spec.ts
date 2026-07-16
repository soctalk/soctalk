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

const APPROVED_FACT = {
	id: 'connector:1',
	kind: 'grant',
	track: 'account',
	source_type: 'connector_verified',
	trust: 100,
	review_status: 'approved',
	scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }
};

test.describe('Tenant authorization facts (self-service)', () => {
	test('tenant_manager asserts a fact that lands awaiting review', async ({ page }) => {
		const store = [APPROVED_FACT];
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(
					me('tenant_manager', [
						'tenant_view_authorization_facts',
						'tenant_assert_authorization_facts'
					])
				)
			})
		);
		await page.route('**/api/tenant/authorization/facts', async (route) => {
			if (route.request().method() === 'POST') {
				store.push({
					...APPROVED_FACT,
					id: 'tenant:x',
					source_type: 'tenant_asserted',
					trust: 20,
					review_status: 'pending'
				});
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({ stored: 'tenant:x', review_status: 'pending' })
				});
			} else {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({ facts: store })
				});
			}
		});

		await page.goto('/my-authorization');
		await expect(page.getByRole('heading', { name: 'Authorization facts' })).toBeVisible();
		await page.getByRole('button', { name: '+ Assert fact' }).click();
		await page.getByRole('button', { name: 'Submit for review' }).click();
		await expect(page.getByText('awaiting review')).toBeVisible();
	});

	test('a tenant viewer can read facts but cannot assert', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('customer_viewer', ['tenant_view_authorization_facts']))
			})
		);
		await page.route('**/api/tenant/authorization/facts', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ facts: [APPROVED_FACT] })
			})
		);
		await page.goto('/my-authorization');
		await expect(page.getByText('svc-deploy · db-01 · sudo-exec')).toBeVisible();
		await expect(page.getByRole('button', { name: '+ Assert fact' })).toHaveCount(0);
	});
});
