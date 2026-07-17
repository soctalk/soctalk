import { test, expect } from '@playwright/test';

// Gated: only runs with IAM_LIVE=1 against a live stack. The default suite mocks the API, so this
// live spec would otherwise fail with no backend.
test.skip(!process.env.IAM_LIVE, 'live IAM e2e — set IAM_LIVE=1 with the stack up');

// LIVE end-to-end IAM workflow against a real API (no route mocks). Requires the stack up:
//   - API on :8000 (SOCTALK_AUTH_MODE=internal, SOCTALK_PUBLIC_ORIGIN=http://localhost:5173)
//   - a seeded mssp_admin: admin@iam.example / Admin-pw-123456
// The dev server (playwright webServer) proxies /api -> :8000.

test('IAM: admin provisions, promotes, deactivates, and reactivates a staff user', async ({
	page
}) => {
	const email = `iam-${Date.now()}@iam.example`;
	page.on('dialog', (d) => d.accept()); // auto-accept the deactivate confirm()

	// 1. Sign in as the MSSP admin
	await page.goto('/login');
	await page.locator('input[type=email]').fill('admin@iam.example');
	await page.locator('input[type=password]').fill('Admin-pw-123456');
	await page.getByRole('button', { name: 'Sign in' }).click();

	// 2. Open the Staff Users admin surface (nav item appears once permissions load)
	await expect(page.getByRole('link', { name: 'Staff Users' })).toBeVisible({ timeout: 15000 });
	await page.getByRole('link', { name: 'Staff Users' }).click();
	await expect(page.getByRole('heading', { name: 'Staff users' })).toBeVisible();

	// 3. Provision a new analyst login -> one-time temporary password is surfaced
	await page.getByRole('button', { name: '+ Add user' }).click();
	await page.getByPlaceholder('analyst@your-mssp.example').fill(email);
	await page.getByRole('button', { name: 'Create user' }).click();
	await expect(page.getByText('One-time temporary password')).toBeVisible();

	const row = page.locator('tr', { hasText: email });
	await expect(row).toBeVisible();
	await expect(row.getByRole('combobox')).toHaveValue('analyst');

	// 4. Promote analyst -> manager (inline role change, persisted via PATCH)
	await row.getByRole('combobox').selectOption('mssp_manager');
	await expect(page.locator('tr', { hasText: email }).getByRole('combobox')).toHaveValue(
		'mssp_manager'
	);

	// 5. Deactivate -> status flips and sessions are revoked server-side
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Deactivate' }).click();
	await expect(page.locator('tr', { hasText: email }).getByText('deactivated')).toBeVisible();

	// 6. Reactivate -> back to active
	await page.locator('tr', { hasText: email }).getByRole('button', { name: 'Reactivate' }).click();
	await expect(page.locator('tr', { hasText: email }).getByText('active', { exact: true })).toBeVisible();
});
