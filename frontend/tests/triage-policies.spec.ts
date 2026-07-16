import { test, expect } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

const BUILTINS = [
	{
		id: 'dual-use-privileged-exec',
		version: 2,
		tenant: '*',
		status: 'active',
		priority: 10,
		source: 'built-in',
		applies_to: { rule_groups: ['sudo', 'su'], rule_ids: [], authorization_tracks: ['account'] },
		required_steps: ['gather_authorization_context'],
		decision_modules: ['authorization_engine'],
		deterministic_disposition: null,
		legal_actions: { triage: ['ENRICH', 'VERDICT'], decide: ['ENRICH', 'VERDICT'] },
		close_signoff_data_classes: ['pci'],
		guardrails: []
	},
	{
		id: 'agent-health-operational',
		version: 1,
		tenant: '*',
		status: 'active',
		priority: 50,
		source: 'built-in',
		applies_to: { rule_groups: ['agent_flooding'], rule_ids: ['202'], authorization_tracks: [] },
		required_steps: [],
		decision_modules: [],
		deterministic_disposition: 'close_operational',
		legal_actions: {},
		close_signoff_data_classes: [],
		guardrails: []
	}
];

function authoredRow(id: string) {
	return {
		triage_policy_id: id,
		revision: 1,
		status: 'shadow',
		definition: { id, priority: 70, status: 'shadow', applies_to: { rule_groups: ['g'] } }
	};
}

test.describe('Triage Policies page', () => {
	test.beforeEach(async ({ page }) => {
		// authored store, mutated by POST so the create flow round-trips
		const authored = [authoredRow('existing-pb')];

		// Specific mocks only — a catch-all '**/api/**' also intercepts the app's
		// own dev module graph and blanks the page.
		// MSSP identity pinned to a tenant so the authored section is active
		await page.route('**/auth/me', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({
					user_id: 'u1',
					email: 'admin@mssp.example',
					user_type: 'mssp',
					role: 'mssp_admin',
					tenant_id: null,
					current_tenant: TID,
					current_tenant_slug: 'acme',
					permissions: ['view_investigations','triage_investigation','review_decide','approve_proposal','view_alerts','view_dashboard','view_analytics','view_audit','use_chat','view_triage_policies','view_engagements','view_authorization_facts','view_tenants','authorize_engagement','manage_authorization_facts','approve_privileged_proposal','configure_integrations','manage_external_siem','configure_llm','manage_branding','manage_users','manage_triage_policies','manage_tenant_lifecycle']
				})
			});
		});
		await page.route('**/api/mssp/triage-policies', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(BUILTINS)
			});
		});
		await page.route('**/api/mssp/tenants/*/triage-policies', async (route) => {
			const req = route.request();
			if (req.method() === 'POST') {
				const body = JSON.parse(req.postData() || '{}');
				const row = authoredRow(body.definition.id);
				authored.push(row);
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify(row)
				});
			} else {
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify(authored)
				});
			}
		});
	});

	test('renders the built-in playbooks with status + source', async ({ page }) => {
		await page.goto('/triage-policies');
		await expect(page).toHaveTitle(/Triage Policies/);
		await expect(page.getByText('dual-use-privileged-exec')).toBeVisible();
		await expect(page.getByText('agent-health-operational')).toBeVisible();
		// source + status badges render
		await expect(page.getByText('built-in').first()).toBeVisible();
	});

	test('expands a built-in to show its gates', async ({ page }) => {
		await page.goto('/triage-policies');
		await page.getByText('dual-use-privileged-exec').click();
		await expect(page.getByText('Required steps before verdict:')).toBeVisible();
		await expect(page.getByText('gather_authorization_context')).toBeVisible();
		await expect(page.getByText('Close requires human sign-off for data classes:')).toBeVisible();
	});

	test('lists authored triage policies for the pinned tenant', async ({ page }) => {
		await page.goto('/triage-policies');
		await expect(page.getByRole('heading', { name: 'Authored triage policies' })).toBeVisible();
		await expect(page.getByText('existing-pb')).toBeVisible();
		// the visual editor entry point is a link; the raw-JSON modal is a button
		await expect(page.getByRole('link', { name: '+ New triage policy' })).toBeVisible();
	});

	test('creates an authored triage policy via the raw JSON modal', async ({ page }) => {
		await page.goto('/triage-policies');
		// header JSON button opens the raw-JSON create modal (visual editor is a separate page)
		await page.getByRole('button', { name: 'JSON', exact: true }).first().click();
		const editor = page.locator('textarea');
		await expect(editor).toBeVisible();
		await editor.fill(
			JSON.stringify({ id: 'brand-new-pb', priority: 70, applies_to: { rule_groups: ['x'] } })
		);
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await expect(page.getByText('brand-new-pb')).toBeVisible();
	});

	test('activates an authored playbook (governs) and shows the rollout note', async ({ page }) => {
		let active = false;
		await page.route('**/api/mssp/tenants/*/triage-policies/*/activate', async (route) => {
			active = true;
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ ...authoredRow('existing-pb'), status: 'active' })
			});
		});
		await page.route('**/api/mssp/tenants/*/triage-policies', async (route) => {
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify([{ ...authoredRow('existing-pb'), status: active ? 'active' : 'shadow' }])
			});
		});
		await page.goto('/triage-policies');
		await page.getByRole('button', { name: 'Activate' }).click();
		await expect(page.getByText(/worker rollout was queued/)).toBeVisible();
		await expect(page.getByRole('button', { name: 'Deactivate' })).toBeVisible();
	});

	test('surfaces a server validation error', async ({ page }) => {
		// override POST to reject
		await page.route('**/api/mssp/tenants/*/triage-policies', async (route) => {
			if (route.request().method() === 'POST') {
				await route.fulfill({
					status: 400,
					contentType: 'application/json',
					body: JSON.stringify({ detail: 'priority must be >= 60' })
				});
			} else {
				await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
			}
		});
		await page.goto('/triage-policies');
		await page.getByRole('button', { name: 'JSON', exact: true }).first().click();
		await page.locator('textarea').fill(JSON.stringify({ id: 'x', priority: 5 }));
		await page.getByRole('button', { name: 'Save', exact: true }).click();
		await expect(page.getByText('priority must be >= 60')).toBeVisible();
	});

	test('visual editor creates a policy at /triage-policies/editor', async ({ page }) => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		let captured: any = null;
		await page.route('**/api/mssp/tenants/*/triage-policies', async (route) => {
			if (route.request().method() === 'POST') {
				captured = JSON.parse(route.request().postData() || '{}');
				await route.fulfill({
					status: 200,
					contentType: 'application/json',
					body: JSON.stringify({
						triage_policy_id: captured?.definition?.id,
						revision: 1,
						status: 'shadow',
						definition: captured?.definition
					})
				});
			} else {
				await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
			}
		});
		await page.goto('/triage-policies/editor');
		await page.getByPlaceholder('my-triage-policy').fill('editor-smoke-pb');
		await page.getByPlaceholder('sudo, su').fill('authentication_success, sshd');
		await page.getByRole('button', { name: /Create \(shadow\)/ }).click();
		await expect.poll(() => captured?.definition?.id).toBe('editor-smoke-pb');
		expect(captured?.definition?.applies_to?.rule_groups).toContain('authentication_success');
	});

});
