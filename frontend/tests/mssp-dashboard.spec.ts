// MSSP cross-tenant dashboard ('/' when no tenant is pinned).
//
// Exists because pinning current_tenant in the other dashboard specs (needed
// for the tenant-scoped views they assert) left this variant with zero e2e
// coverage — flagged in the #52 test-fix review. The variant switch itself
// (pinned → legacy tenant dashboard) is asserted here too.
import { test, expect, type Page } from '@playwright/test';
import { TENANT_ID, mockAuthMe } from './helpers';

const json = (body: unknown) => ({
	status: 200,
	contentType: 'application/json',
	body: JSON.stringify(body)
});

async function mockMsspDashboard(page: Page) {
	await page.route('**/api/mssp/dashboard/pending-reviews*', (r) =>
		r.fulfill(
			json({
				items: [
					{
						investigation_id: '33333333-3333-3333-3333-333333333333',
						tenant_id: TENANT_ID,
						tenant_slug: 'acme',
						title: 'Suspicious sudo on db-01',
						severity: 'high',
						requested_at: '2026-07-01T00:00:00Z',
						age_seconds: 3600
					}
				]
			})
		)
	);
	await page.route('**/api/mssp/dashboard/open-by-tenant*', (r) =>
		r.fulfill(
			json({
				items: [
					{
						tenant_id: TENANT_ID,
						tenant_slug: 'acme',
						display_name: 'Acme Corp',
						open_investigations: 3,
						pending_reviews: 1,
						max_severity: 'high'
					}
				]
			})
		)
	);
	await page.route('**/api/mssp/dashboard/stuck-investigations*', (r) =>
		r.fulfill(json({ items: [] }))
	);
	await page.route('**/api/mssp/dashboard/tenant-health*', (r) => r.fulfill(json({ items: [] })));
	await page.route('**/api/mssp/dashboard/repeated-iocs*', (r) => r.fulfill(json({ items: [] })));
}

test.describe('MSSP cross-tenant dashboard', () => {
	test('unpinned MSSP user gets the cross-tenant dashboard at /', async ({ page }) => {
		await mockAuthMe(page); // no current_tenant → isMsspScope
		await mockMsspDashboard(page);
		await page.goto('/');

		await expect(page.getByRole('heading', { name: 'MSSP Dashboard' })).toBeVisible();
		await expect(page.getByTestId('strip-pending-reviews')).toBeVisible();
		await expect(page.getByTestId('panel-open-by-tenant')).toBeVisible();
		await expect(page.getByText('Acme Corp')).toBeVisible();
	});

	test('pinning a tenant flips / to the tenant-scoped dashboard', async ({ page }) => {
		await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
		await page.route('**/api/metrics/overview*', (r) =>
			r.fulfill(
				json({
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
				})
			)
		);
		await page.route('**/api/metrics/hourly*', (r) => r.fulfill(json({ metrics: [] })));
		await page.route('**/api/investigations*', (r) =>
			r.fulfill(json({ items: [], total: 0, page: 1, page_size: 20, has_more: false }))
		);
		await page.goto('/');

		await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
		await expect(
			page.getByRole('heading', { name: 'Open Investigations', exact: true })
		).toBeVisible();
		await expect(page.getByRole('heading', { name: 'MSSP Dashboard' })).toHaveCount(0);
	});
});
