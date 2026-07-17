import { test, expect } from '@playwright/test';

// LIVE M3 proof: an analyst answers an ASK_AUTHORIZATION question by saving a reusable
// authorization. Gated on M3_LIVE=1 with the stack up and a seeded pending review that carries
// an authorization_question in its enrichments (see scratchpad/seed_m3_review.py).
//   - API on :8000 (SOCTALK_AUTH_MODE=internal, SOCTALK_PUBLIC_ORIGIN=http://localhost:5173)
//   - mssp_admin admin@iam.example / Admin-pw-123456
test.skip(!process.env.M3_LIVE, 'live M3 e2e — set M3_LIVE=1 with the stack up');

test('analyst authorizes an activity from the review queue', async ({ page }) => {
	// 1. Sign in as the MSSP admin
	await page.goto('/login');
	await page.locator('input[type=email]').fill('admin@iam.example');
	await page.locator('input[type=password]').fill('Admin-pw-123456');
	await page.getByRole('button', { name: 'Sign in' }).click();

	// 2. Open the review queue and expand the seeded review
	await page.getByRole('link', { name: 'Reviews' }).click();
	await expect(page.getByRole('heading', { name: 'Unrecognized SSH by deploy on web01' })).toBeVisible({
		timeout: 15000
	});
	await page.getByRole('button', { name: /Unrecognized SSH by deploy on web01/ }).click();

	// 3. The typed authorization question is shown
	await expect(page.getByText('Authorization question')).toBeVisible();
	await expect(
		page.getByRole('button', { name: 'Confirm authorized — save reusable authorization' })
	).toBeVisible();
	await page.screenshot({ path: 'test-results/m3/01-question.png', fullPage: true });

	// 4. Answer it — save a reusable authorization (default 90-day expiry)
	await page
		.getByRole('button', { name: 'Confirm authorized — save reusable authorization' })
		.click();

	// 5. The authorization is saved and the review leaves the queue (the durable outcome — a
	//    reusable analyst_asserted grant now covers the activity, so it is no longer asked).
	await expect(
		page.getByRole('heading', { name: 'Unrecognized SSH by deploy on web01' })
	).toHaveCount(0, { timeout: 10000 });
	await expect(page.getByText('All Caught Up!')).toBeVisible();
	await page.screenshot({ path: 'test-results/m3/02-saved.png', fullPage: true });
});
