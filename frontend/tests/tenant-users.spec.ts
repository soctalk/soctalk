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

const ADMIN_PERMS = ['tenant_view_investigations', 'tenant_manage_users'];

test.describe('Tenant user management (self-service)', () => {
	test('tenant_admin provisions a tenant_analyst and sees the one-time password', async ({
		page
	}) => {
		const store: Array<Record<string, unknown>> = [];
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('tenant_admin', ADMIN_PERMS))
			})
		);
		await page.route('**/api/tenant/users', async (route) => {
			if (route.request().method() === 'POST') {
				const created = {
					id: 'nu1',
					email: 'analyst@acme.example',
					display_name: 'analyst',
					role: 'tenant_analyst',
					active: true,
					temporary_password: 'Tmp-abc123XYZ'
				};
				store.push(created);
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify(created)
				});
			} else {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify(store)
				});
			}
		});

		await page.goto('/tenant-users');
		await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();
		await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
		await page.getByRole('button', { name: '+ Add user' }).click();
		await page.getByPlaceholder('analyst@your-org.com').fill('analyst@acme.example');
		await page.getByRole('button', { name: 'Create user' }).click();
		// one-time password is surfaced, and the new analyst appears in the list
		await expect(page.getByText('Tmp-abc123XYZ')).toBeVisible();
		await expect(page.getByRole('cell', { name: 'analyst@acme.example' })).toBeVisible();
	});

	test('a non-admin tenant user has no Users nav and no add control', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('tenant_analyst', ['tenant_view_investigations', 'tenant_review_decide']))
			})
		);
		await page.route('**/api/tenant/users', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
		);

		await page.goto('/tenant-users');
		await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: '+ Add user' })).toHaveCount(0);
	});
});
