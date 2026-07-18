import { test, expect } from '@playwright/test';

function me(role: string, permissions: string[]) {
	return {
		user_id: 'u1',
		email: `${role}@mssp.example`,
		user_type: 'mssp',
		role,
		tenant_id: null,
		current_tenant: null,
		permissions
	};
}

const ADMIN_PERMS = ['manage_users', 'review_decide', 'use_chat'];

test.describe('MSSP staff user management', () => {
	test('mssp_admin provisions a staff analyst and sees the one-time password', async ({ page }) => {
		const store: Array<Record<string, unknown>> = [
			{ id: 'u1', email: 'admin@mssp.example', display_name: 'admin', role: 'mssp_admin', active: true }
		];
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me('mssp_admin', ADMIN_PERMS)) })
		);
		await page.route('**/api/mssp/users', async (route) => {
			if (route.request().method() === 'POST') {
				const created = {
					id: 'u2',
					email: 'analyst@mssp.example',
					display_name: 'analyst',
					role: 'analyst',
					active: true,
					temporary_password: 'Tmp-STAFF-9xyz'
				};
				store.push(created);
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(created) });
			} else {
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(store) });
			}
		});

		await page.goto('/mssp-users');
		await expect(page.getByRole('link', { name: 'Staff Users' })).toBeVisible();
		await expect(page.getByRole('heading', { name: 'Staff users' })).toBeVisible();
		await page.getByRole('button', { name: '+ Add user' }).click();
		await page.getByPlaceholder('analyst@your-mssp.example').fill('analyst@mssp.example');
		await page.getByRole('button', { name: 'Create user' }).click();
		await expect(page.getByText('Tmp-STAFF-9xyz')).toBeVisible();
		await expect(page.getByRole('cell', { name: 'analyst@mssp.example' })).toBeVisible();
	});

	test('a non-admin MSSP user has no Staff Users nav and no add control', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('analyst', ['review_decide', 'use_chat']))
			})
		);
		await page.route('**/api/mssp/users', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
		);

		await page.goto('/mssp-users');
		await expect(page.getByRole('link', { name: 'Staff Users' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: '+ Add user' })).toHaveCount(0);
	});
});
