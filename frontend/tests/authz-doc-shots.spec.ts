/**
 * Screenshot generator for the soctalk-docs Authorization tutorial.
 * Mocks auth + data and drives the revamped structured UI. Not an assertion
 * spec — run explicitly: `pnpm exec playwright test tests/authz-doc-shots.spec.ts`.
 * Output lands in test-results/authz-docs/ and is copied into the docs repo.
 */
import { test } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';
const OUT = 'test-results/authz-docs';

const MSSP_PERMS = [
	'view_investigations','triage_investigation','review_decide','approve_proposal','view_alerts',
	'view_dashboard','view_analytics','view_audit','use_chat','view_triage_policies','view_engagements',
	'view_authorization_facts','view_tenants','authorize_engagement','manage_authorization_facts',
	'approve_privileged_proposal','configure_integrations','manage_external_siem','configure_llm',
	'manage_branding','manage_users','manage_triage_policies','manage_tenant_lifecycle'
];

function mssp() {
	return {
		user_id: 'u1', email: 'ops@acme-mssp.example', user_type: 'mssp', role: 'mssp_admin',
		tenant_id: null, current_tenant: TID, current_tenant_slug: 'acme', permissions: MSSP_PERMS
	};
}
function tenant(perms: string[]) {
	return { user_id: 'u2', email: 'rakesh.kumar@acme.example', user_type: 'tenant', role: 'tenant_manager', tenant_id: TID, current_tenant: null, permissions: perms };
}

const FACTS = [
	{ id: 'CHG-1001', kind: 'grant', track: 'account', grant_class: 'change_ticket', source_type: 'analyst_asserted', trust: 60, review_status: 'approved', scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }, valid_until: '2026-12-31T00:00:00Z', created_by: 'ops@acme-mssp.example', provenance: {} },
	{ id: 'tenant:acme:9f2', kind: 'grant', track: 'account', grant_class: 'standing_baseline', source_type: 'tenant_asserted', trust: 20, review_status: 'pending', scope: { subject: 'backup-svc', target: 'db-01', action: 'file-read' }, created_by: 'rakesh.kumar@acme.example', provenance: {} },
	{ id: 'FRZ-Q4', kind: 'change_freeze', track: 'fim', source_type: 'system_asserted', trust: 80, review_status: 'approved', freeze_scope: { config_classes: ['kernel', 'sudoers'] }, start: '2026-12-15T00:00:00Z', end: '2026-12-31T00:00:00Z', provenance: {} }
];

test('mssp authorization shots', async ({ page }) => {
	await page.route('**/auth/me', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(mssp()) }));
	await page.route('**/api/mssp/tenants/*/authorization/facts', (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: FACTS }) })
	);

	await page.setViewportSize({ width: 1500, height: 860 });
	await page.goto('/authorization');
	await page.getByRole('heading', { name: 'Authorization facts' }).waitFor();
	await page.getByText('CHG-1001').first().waitFor();
	await page.getByText(/permits svc-deploy/).first().waitFor();
	await page.waitForTimeout(300);
	await page.screenshot({ path: `${OUT}/authz-facts-list.png` });

	// The structured New-fact wizard, filled for the change-ticket use case.
	await page.setViewportSize({ width: 1320, height: 1300 });
	await page.getByRole('button', { name: '+ New fact' }).click();
	await page.getByPlaceholder('CHG-1001').fill('CHG-1042');
	await page.getByPlaceholder('svc-deploy').fill('svc-deploy');
	await page.getByPlaceholder('db-01').fill('db-01');
	await page.getByPlaceholder('sudo-exec').fill('sudo-exec');
	await page.locator('input[type=date]').nth(1).fill('2026-12-31');
	await page.waitForTimeout(400);
	// scroll the modal container to the top so the "Reads as" preview + heading show
	await page.locator('div.fixed.inset-0').first().evaluate((el) => (el.scrollTop = 0));
	await page.locator('div.card.max-w-2xl').screenshot({ path: `${OUT}/authz-new-fact.png` });
});

test('tenant engagement shot', async ({ page }) => {
	await page.route('**/auth/me', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(tenant(['tenant_view_engagements', 'tenant_authorize_engagement', 'tenant_view_authorization_facts'])) }));
	await page.route('**/api/tenant/engagements**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) }));

	await page.setViewportSize({ width: 1320, height: 900 });
	await page.goto('/my-authorization?tab=engagements');
	await page.getByRole('button', { name: '+ Declare engagement' }).click();
	await page.getByPlaceholder('Q3 external pentest').fill('Q4 external pentest');
	await page.locator('input[type=datetime-local]').first().fill('2026-11-03T09:00');
	await page.locator('input[type=datetime-local]').nth(1).fill('2026-11-14T18:00');
	await page.getByPlaceholder('203.0.113.0/24').fill('198.51.100.0/24');
	await page.getByPlaceholder('web-01, db-01').fill('web-01, web-02');
	await page.getByPlaceholder('T1078, T1110.001').fill('T1078, T1110.001');
	await page.waitForTimeout(400);
	await page.screenshot({ path: `${OUT}/authz-engagement.png` });
});
