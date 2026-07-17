import { test } from '@playwright/test';
test.skip(!process.env.IAM_LIVE, 'live-only screenshots');

test('tenant iam screenshots', async ({ page }) => {
	const email = 'priya.sharma@acme.example';
	page.on('dialog', (d) => d.accept());

	await page.goto('/login');
	await page.locator('input[type=email]').fill('admin@acme.example');
	await page.locator('input[type=password]').fill('Admin-pw-123456');
	await page.getByRole('button', { name: 'Sign in' }).click();

	// Tenant Users panel (own org), add-user form open with a tenant role picked
	await page.getByRole('link', { name: 'Users', exact: true }).click();
	await page.getByRole('button', { name: '+ Add user' }).click();
	await page.getByPlaceholder('analyst@your-org.com').fill(email);
	await page.getByPlaceholder('Jordan Rivera').fill('Priya Sharma');
	await page.locator('select').last().selectOption('tenant_analyst');
	await page.screenshot({ path: 'test-results/iam-tenant/01-add-user.png', fullPage: true });

	// Created: one-time password + user in the list (tenant roles)
	await page.getByRole('button', { name: 'Create user' }).click();
	await page.getByText('One-time temporary password').waitFor();
	await page.screenshot({ path: 'test-results/iam-tenant/02-created.png', fullPage: true });

	// Promote analyst -> manager inline
	await page.locator('tr', { hasText: email }).getByRole('combobox').selectOption('tenant_manager');
	await page.locator('tr', { hasText: email }).getByRole('combobox').waitFor();
	await page.screenshot({ path: 'test-results/iam-tenant/03-promoted.png', fullPage: true });

	// Deactivate -> Reactivate offered
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Deactivate' }).click();
	await page.locator('tr', { hasText: email }).getByText('deactivated').waitFor();
	await page.screenshot({ path: 'test-results/iam-tenant/04-deactivated.png', fullPage: true });

	// Reactivate -> back to active
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Reactivate' }).click();
	await page.locator('tr', { hasText: email }).getByText('active', { exact: true }).waitFor();
	await page.screenshot({ path: 'test-results/iam-tenant/05-reactivated.png', fullPage: true });
});
