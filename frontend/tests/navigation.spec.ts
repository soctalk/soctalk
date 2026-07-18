import { test, expect, type Page } from '@playwright/test';
import { TENANT_ID, mockAuthMe } from './helpers';

// Specific mocks only — a bare '**/api/**' catch-all also intercepts the vite
// dev-module graph (/src/lib/api/...) and blanks the page (see helpers.ts).
async function mockData(page: Page) {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	const empty = {
		items: [],
		total: 0,
		page: 1,
		page_size: 20,
		has_more: false
	};
	const overview = {
		open_investigations: 0,
		pending_reviews: 0,
		avg_time_to_triage_seconds: null,
		avg_time_to_verdict_seconds: null,
		investigations_created_today: 0,
		investigations_closed_today: 0,
		escalations_today: 0,
		auto_closed_today: 0,
		malicious_observables_today: 0,
		verdict_breakdown: {},
		severity_breakdown: {}
	};
	const json = (body) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
	await page.route('**/api/metrics/overview*', (r) => r.fulfill(json(overview)));
	await page.route('**/api/metrics/hourly*', (r) => r.fulfill(json({ metrics: [] })));
	await page.route('**/api/investigations*', (r) => r.fulfill(json(empty)));
	await page.route('**/api/review/pending*', (r) => r.fulfill(json(empty)));
	await page.route('**/api/audit*', (r) => r.fulfill(json(empty)));
	await page.route('**/api/events/stream*', (r) =>
		r.fulfill({ status: 200, contentType: 'text/event-stream', body: '' })
	);
}

test.describe('Navigation', () => {
	test.beforeEach(async ({ page }) => {
		await mockData(page);
	});

	test('can navigate to dashboard', async ({ page }) => {
		await page.goto('/');
		await expect(page).toHaveTitle(/SocTalk/);
	});

	test('can navigate to investigations page', async ({ page }) => {
		await page.goto('/investigations');
		await expect(page).toHaveTitle(/SocTalk/);
		await expect(page).toHaveURL(/\/investigations/);
	});

	test('can navigate to analytics page', async ({ page }) => {
		await page.goto('/analytics');
		await expect(page).toHaveTitle(/SocTalk/);
		await expect(page).toHaveURL(/\/analytics/);
	});

	test('can navigate to audit page', async ({ page }) => {
		await page.goto('/audit');
		await expect(page).toHaveTitle(/SocTalk/);
		await expect(page).toHaveURL(/\/audit/);
	});

	test('can navigate to review page', async ({ page }) => {
		await page.goto('/review');
		await expect(page).toHaveTitle(/SocTalk/);
		await expect(page).toHaveURL(/\/review/);
	});

	test('sidebar navigation links exist', async ({ page }) => {
		await page.goto('/');

		// Wait for page to load
		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });

		// Check sidebar navigation links
		await expect(page.getByRole('link', { name: /Dashboard/i })).toBeVisible();
		await expect(page.getByRole('link', { name: /Investigations/i })).toBeVisible();
	});

	test('sidebar navigation works', async ({ page }) => {
		await page.goto('/');

		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });

		// Navigate to investigations via sidebar
		await page.getByRole('link', { name: /Investigations/i }).click();

		// Should navigate to investigations page
		await expect(page).toHaveURL(/\/investigations/);
	});
});

test.describe('Page Structure', () => {
	test.beforeEach(async ({ page }) => {
		await mockData(page);
	});

	test('has app shell structure', async ({ page }) => {
		await page.goto('/');

		// Wait for content to load
		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });

		// Check for main layout elements
		await expect(page.locator('body')).toBeVisible();
	});

	test('is responsive', async ({ page }) => {
		// Test mobile viewport
		await page.setViewportSize({ width: 375, height: 667 });
		await page.goto('/');

		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });

		// Page should still be visible
		await expect(page.locator('body')).toBeVisible();

		// Test tablet viewport
		await page.setViewportSize({ width: 768, height: 1024 });
		await page.goto('/');

		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });
		await expect(page.locator('body')).toBeVisible();

		// Test desktop viewport
		await page.setViewportSize({ width: 1920, height: 1080 });
		await page.goto('/');

		await expect(page.locator('.animate-spin')).not.toBeVisible({ timeout: 10000 });
		await expect(page.locator('body')).toBeVisible();
	});
});
