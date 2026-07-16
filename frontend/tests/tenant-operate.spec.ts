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

const REVIEW = {
	id: 'rev-1',
	investigation_id: 'inv-1',
	status: 'pending',
	title: 'Suspicious sudo on db-01',
	description: 'svc-deploy ran sudo',
	max_severity: 'high',
	alert_count: 1,
	malicious_count: 0,
	suspicious_count: 1,
	clean_count: 0,
	findings: [],
	enrichments: {},
	misp_context: null,
	ai_decision: 'needs_more_info',
	ai_confidence: 0.5,
	ai_assessment: 'unclear',
	ai_recommendation: 'review',
	timeout_seconds: 3600,
	created_at: '2026-07-16T00:00:00Z',
	expires_at: null
};

const PENDING = { items: [REVIEW], total: 1, page: 1, page_size: 50, has_more: false };

// tenant_analyst = the co-managed-SOC operator: full read+write over its own tenant's reviews.
const ANALYST_PERMS = [
	'tenant_view_investigations',
	'tenant_review_decide',
	'tenant_triage_investigation',
	'tenant_use_chat'
];
// customer_viewer = read-only stakeholder: no operate capability.
const VIEWER_PERMS = ['tenant_view_investigations'];

test.describe('Tenant co-managed SOC operate surface', () => {
	test('tenant_analyst can act on its own tenant reviews and sees operate nav', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('tenant_analyst', ANALYST_PERMS))
			})
		);
		await page.route('**/review/pending**', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(PENDING) })
		);

		await page.goto('/review');
		// operate nav is visible
		await expect(page.getByRole('link', { name: 'Reviews' })).toBeVisible();
		await expect(page.getByRole('link', { name: 'Chat' })).toBeVisible();
		// the review is listed; expand it, then Take Action reveals the decide controls
		await expect(page.getByText('Suspicious sudo on db-01')).toBeVisible();
		await page.getByRole('button', { name: /Suspicious sudo on db-01/ }).click();
		await page.getByRole('button', { name: 'Take Action' }).click();
		await expect(page.getByRole('button', { name: /Approve & Escalate/ })).toBeVisible();
		await expect(page.getByRole('button', { name: /Reject & Close/ })).toBeVisible();
	});

	test('customer_viewer is read-only: no operate nav, no decide controls', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(me('customer_viewer', VIEWER_PERMS))
			})
		);
		// A customer_viewer reads at 'customer' audience server-side, so the mssp_only operate
		// queue comes back empty — mirror that here rather than codifying an exposure.
		await page.route('**/review/pending**', (r) =>
			r.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ items: [], total: 0, page: 1, page_size: 50, has_more: false })
			})
		);

		await page.goto('/review');
		// operate nav is gated off for the read-only stakeholder
		await expect(page.getByRole('link', { name: 'Chat' })).toHaveCount(0);
		await expect(page.getByRole('link', { name: 'Reviews' })).toHaveCount(0);
		// and there is no decide surface anywhere on the page
		await expect(page.getByRole('button', { name: 'Take Action' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: /Approve & Escalate/ })).toHaveCount(0);
	});
});
