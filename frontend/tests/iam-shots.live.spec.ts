import { test } from '@playwright/test';
test.skip(!process.env.IAM_LIVE, 'live-only screenshots');

test('iam screenshots', async ({ page }) => {
	const email = 'jordan.rivera@mssp.example';
	page.on('dialog', (d) => d.accept());

	// 1. Login page
	await page.goto('/login');
	await page.locator('input[type=email]').fill('admin@iam.example');
	await page.locator('input[type=password]').fill('Admin-pw-123456');
	await page.screenshot({ path: 'test-results/iam/01-login.png' });
	await page.getByRole('button', { name: 'Sign in' }).click();

	// 2. Staff Users, add-user form open with a role picked
	await page.getByRole('link', { name: 'Staff Users' }).click();
	await page.getByRole('button', { name: '+ Add user' }).click();
	await page.getByPlaceholder('analyst@your-mssp.example').fill(email);
	await page.locator('input:not([type=email]):not([type=password])').first().fill('Jordan Rivera');
	await page.locator('select').last().selectOption('analyst');
	await page.screenshot({ path: 'test-results/iam/02-add-user.png', fullPage: true });

	// 3. Created: one-time password revealed + user in the list
	await page.getByRole('button', { name: 'Create user' }).click();
	await page.getByText('One-time temporary password').waitFor();
	await page.screenshot({ path: 'test-results/iam/03-created.png', fullPage: true });

	// 4. Promoted analyst -> manager (inline role change)
	const rowSel = page.locator('tr', { hasText: email }).getByRole('combobox');
	await rowSel.selectOption('mssp_manager');
	await page.locator('tr', { hasText: email }).getByRole('combobox').waitFor();
	await page.screenshot({ path: 'test-results/iam/04-promoted.png', fullPage: true });

	// 5. Deactivated -> status flips, Reactivate offered
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Deactivate' }).click();
	await page.locator('tr', { hasText: email }).getByText('deactivated').waitFor();
	await page.screenshot({ path: 'test-results/iam/05-deactivated.png', fullPage: true });

	// 6. Reactivated -> back to active
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Reactivate' }).click();
	await page.locator('tr', { hasText: email }).getByText('active', { exact: true }).waitFor();
	await page.screenshot({ path: 'test-results/iam/06-reactivated.png', fullPage: true });
});
