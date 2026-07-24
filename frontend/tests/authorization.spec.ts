import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

const MSSP_PERMS = [
	'view_investigations','triage_investigation','review_decide','approve_proposal','view_alerts',
	'view_dashboard','view_analytics','view_audit','use_chat','view_triage_policies','view_engagements',
	'view_authorization_facts','view_tenants','authorize_engagement','manage_authorization_facts',
	'approve_privileged_proposal','configure_integrations','manage_external_siem','configure_llm',
	'manage_branding','manage_users','manage_triage_policies','manage_tenant_lifecycle'
];

function seedFact(id: string) {
	return {
		id, kind: 'grant', track: 'account', source_type: 'analyst_asserted', trust: 60,
		grant_class: 'change_ticket', scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' },
		valid_until: '2026-12-31T00:00:00Z', created_by: 'admin', provenance: {}
	};
}

// Wire the MSSP identity + a capturing facts endpoint. Returns a getter for the
// last POSTed fact body so tests can assert the exact payload the structured
// form emitted (the real point: legality parity with the server validators).
async function wire(page: Page, opts: { perms?: string[] } = {}) {
	const facts: Record<string, unknown>[] = [seedFact('CHG-1001')];
	const captured: { body: Record<string, unknown> | null } = { body: null };
	await page.route('**/auth/me', (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
			user_id: 'u1', email: 'admin@mssp.example', user_type: 'mssp', role: 'mssp_admin',
			tenant_id: null, current_tenant: TID, current_tenant_slug: 'acme',
			permissions: opts.perms ?? MSSP_PERMS
		}) })
	);
	await page.route('**/api/mssp/tenants/*/authorization/facts/*/revoke', async (route) => {
		facts.length = 0;
		await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ revoked: true }) });
	});
	await page.route('**/api/mssp/tenants/*/authorization/facts', async (route) => {
		if (route.request().method() === 'POST') {
			const body = JSON.parse(route.request().postData() || '{}');
			captured.body = body.fact ?? {};
			facts.push({ ...seedFact((captured.body!.id as string) || 'NEW'), ...captured.body });
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ stored: captured.body!.id }) });
		} else {
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts }) });
		}
	});
	return captured;
}

test.describe('MSSP authorization facts — structured CRUD', () => {
	test('lists facts with a human-readable summary', async ({ page }) => {
		await wire(page);
		await page.goto('/authorization');
		await expect(page.getByRole('heading', { name: 'Authorization facts' })).toBeVisible();
		await expect(page.getByText('CHG-1001').first()).toBeVisible();
		await expect(page.getByText(/svc-deploy/).first()).toBeVisible();
	});

	test('creates a change-ticket grant via the structured form (payload is legal)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		// kind=grant, track=account, grant_class=change_ticket are the defaults.
		await page.getByPlaceholder('CHG-1001').fill('CHG-2002');
		await page.getByPlaceholder('svc-deploy').fill('svc-deploy');
		await page.getByPlaceholder('db-01').fill('db-01');
		await page.getByPlaceholder('sudo-exec').fill('sudo-exec');
		await page.locator('input[type=date]').nth(1).fill('2026-12-31'); // valid_until (required for change_ticket)
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('CHG-2002').first()).toBeVisible();

		expect(cap.body).toMatchObject({
			id: 'CHG-2002', kind: 'grant', track: 'account', grant_class: 'change_ticket',
			scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }
		});
		expect(cap.body!.valid_until).toBeTruthy();
		// server stamps these — the form must NOT send them
		expect(cap.body!.source_type).toBeUndefined();
		expect(cap.body!.trust).toBeUndefined();
	});

	test('creates a FIM prohibition — omits account-only fields', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Prohibition/ }).click();
		await page.getByLabel('Track').selectOption('fim');
		await page.getByPlaceholder('CHG-1001').fill('POL-1');
		await page.getByPlaceholder('/etc/sudoers*').fill('/etc/sudoers');
		await page.getByPlaceholder('modify, delete').fill('modify, delete');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('POL-1')).toBeVisible();

		expect(cap.body).toMatchObject({ kind: 'prohibition', track: 'fim', forbid_change_type: ['modify', 'delete'] });
		expect(cap.body!.forbid_action).toBeUndefined();
		expect(cap.body!.forbid_account_type).toBeUndefined();
	});

	test('legality: a change ticket without a valid-until date is blocked client-side', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByPlaceholder('CHG-1001').fill('CHG-BAD');
		// no valid_until
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText(/change-ticket grant needs/i)).toBeVisible();
		expect(cap.body).toBeNull(); // never hit the server
	});

	test('revokes a fact (soft delete)', async ({ page }) => {
		page.on('dialog', (d) => d.accept('offboarded'));
		await wire(page);
		await page.goto('/authorization');
		await expect(page.getByText('CHG-1001').first()).toBeVisible();
		await page.getByRole('button', { name: 'Revoke' }).click();
		await expect(page.getByText('No authorization facts for this tenant yet.')).toBeVisible();
	});

	test('view-only role sees facts but no write controls (RBAC)', async ({ page }) => {
		await wire(page, { perms: ['view_authorization_facts', 'view_investigations'] });
		await page.goto('/authorization');
		await expect(page.getByText('CHG-1001').first()).toBeVisible();
		await expect(page.getByRole('button', { name: '+ New fact' })).toHaveCount(0);
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
	});

	test('creates a routine-observation grant (seen_count; no valid_until)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByLabel('Grant class').selectOption('routine_observation');
		await page.getByPlaceholder('CHG-1001').fill('OBS-1');
		await page.getByPlaceholder('svc-deploy').fill('backup-svc');
		await page.getByLabel('Seen count').fill('42');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('OBS-1')).toBeVisible();
		expect(cap.body).toMatchObject({ kind: 'grant', grant_class: 'routine_observation', seen_count: 42 });
		expect(cap.body!.valid_until).toBeUndefined();
		expect(cap.body!.cab_required).toBeUndefined();
	});

	test('creates an account prohibition (forbid_action + applies_to.env)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Prohibition/ }).click();
		await page.getByPlaceholder('CHG-1001').fill('POL-2');
		await page.getByPlaceholder('interactive-shell').fill('interactive-shell');
		await page.getByPlaceholder('prod, staging').fill('prod');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('POL-2')).toBeVisible();
		expect(cap.body).toMatchObject({ kind: 'prohibition', track: 'account', forbid_action: 'interactive-shell', applies_to: { env: ['prod'] } });
		expect(cap.body!.forbid_change_type).toBeUndefined();
	});

	test('creates an account change-freeze (envs only, no config_classes)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Change freeze/ }).click();
		await page.getByPlaceholder('CHG-1001', { exact: true }).fill('FRZ-1');
		await page.locator('input[type=datetime-local]').nth(0).fill('2026-12-15T00:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-12-31T00:00');
		await page.getByPlaceholder('prod').fill('prod, staging');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('FRZ-1')).toBeVisible();
		expect(cap.body).toMatchObject({ kind: 'change_freeze', track: 'account', freeze_scope: { envs: ['prod', 'staging'] } });
		expect(cap.body!.start).toBeTruthy();
		expect(cap.body!.end).toBeTruthy();
		expect((cap.body!.freeze_scope as Record<string, unknown>).config_classes).toBeUndefined();
	});

	test('creates a FIM change-freeze (config_classes only, no envs)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Change freeze/ }).click();
		await page.getByLabel('Track').selectOption('fim');
		await page.getByPlaceholder('CHG-1001', { exact: true }).fill('FRZ-2');
		await page.locator('input[type=datetime-local]').nth(0).fill('2026-12-15T00:00');
		await page.locator('input[type=datetime-local]').nth(1).fill('2026-12-31T00:00');
		await page.getByPlaceholder('kernel, sudoers').fill('kernel, sudoers');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('FRZ-2')).toBeVisible();
		expect(cap.body).toMatchObject({ kind: 'change_freeze', track: 'fim', freeze_scope: { config_classes: ['kernel', 'sudoers'] } });
		expect((cap.body!.freeze_scope as Record<string, unknown>).envs).toBeUndefined();
	});

	test('creates an asset entity_context (no account-only attributes)', async ({ page }) => {
		const cap = await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Entity context/ }).click();
		// entity_type defaults to 'asset'
		await page.getByPlaceholder('CHG-1001').fill('ENT-1');
		await page.getByRole('textbox', { name: 'Name', exact: true }).fill('db-01');
		await page.getByPlaceholder('prod').fill('prod');
		await page.getByRole('button', { name: 'Create fact' }).click();
		await expect(page.getByText('ENT-1')).toBeVisible();
		expect(cap.body).toMatchObject({ kind: 'entity_context', entity_type: 'asset', name: 'db-01', environment: 'prod' });
		expect(cap.body!.account_type).toBeUndefined();
		expect(cap.body!.privileged).toBeUndefined();
		expect(cap.body!.linked_orgs).toBeUndefined();
	});

	// READ: every kind renders its own human-readable summary and a Revoke control.
	test('lists every kind with a correct summary + a delete control', async ({ page }) => {
		const facts = [
			{ id: 'G1', kind: 'grant', track: 'account', grant_class: 'change_ticket', source_type: 'analyst_asserted', trust: 60, scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }, valid_until: '2026-12-31T00:00:00Z' },
			{ id: 'P1', kind: 'prohibition', track: 'account', source_type: 'analyst_asserted', trust: 60, forbid_action: 'interactive-shell', forbid_account_type: 'service' },
			{ id: 'F1', kind: 'change_freeze', track: 'account', source_type: 'system_asserted', trust: 80, freeze_scope: { envs: ['prod'] }, start: '2026-12-15T00:00:00Z', end: '2026-12-31T00:00:00Z' },
			{ id: 'E1', kind: 'entity_context', track: 'account', source_type: 'connector_verified', trust: 100, entity_type: 'asset', name: 'web-01', environment: 'prod' }
		];
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
				user_id: 'u1', email: 'admin@mssp.example', user_type: 'mssp', role: 'mssp_admin',
				tenant_id: null, current_tenant: TID, current_tenant_slug: 'acme', permissions: MSSP_PERMS
			}) })
		);
		await page.route('**/api/mssp/tenants/*/authorization/facts', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts }) })
		);
		await page.goto('/authorization');
		await expect(page.getByText(/Change ticket G1 permits/)).toBeVisible();
		await expect(page.getByText(/may not interactive-shell/)).toBeVisible();
		await expect(page.getByText(/Change freeze on prod/)).toBeVisible();
		await expect(page.getByText(/web-01 is a/)).toBeVisible();
		await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(4);
	});

	// REVIEW: the approve/reject lifecycle on a pending tenant-asserted fact.
	// `decision` param drives which button; the capturing mock proves the UI
	// sends the right one and re-renders the resulting status.
	async function wireReview(page: Page, expected: 'approve' | 'reject') {
		const captured: { decision: string | null } = { decision: null };
		let status = 'pending';
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
				user_id: 'u1', email: 'admin@mssp.example', user_type: 'mssp', role: 'mssp_admin',
				tenant_id: null, current_tenant: TID, current_tenant_slug: 'acme', permissions: MSSP_PERMS
			}) })
		);
		await page.route('**/api/mssp/tenants/*/authorization/facts/*/review', async (route) => {
			captured.decision = JSON.parse(route.request().postData() || '{}').decision;
			status = captured.decision === 'approve' ? 'approved' : 'rejected';
			await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ reviewed: 'TA-1', status }) });
		});
		await page.route('**/api/mssp/tenants/*/authorization/facts', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: [
				{ id: 'TA-1', kind: 'grant', track: 'account', grant_class: 'standing_baseline', source_type: 'tenant_asserted', trust: 20, review_status: status, scope: { subject: 'svc', target: 'db-01', action: 'sudo' } }
			] }) })
		);
		void expected;
		return captured;
	}

	test('approves a pending tenant-asserted fact', async ({ page }) => {
		const cap = await wireReview(page, 'approve');
		await page.goto('/authorization');
		await expect(page.getByText('awaiting review')).toBeVisible();
		await page.getByRole('button', { name: 'Approve' }).click();
		await expect(page.getByText('approved')).toBeVisible();
		expect(cap.decision).toBe('approve');
		await expect(page.getByRole('button', { name: 'Approve' })).toHaveCount(0);
	});

	test('rejects a pending tenant-asserted fact', async ({ page }) => {
		const cap = await wireReview(page, 'reject');
		await page.goto('/authorization');
		await expect(page.getByText('awaiting review')).toBeVisible();
		await page.getByRole('button', { name: 'Reject' }).click();
		await expect(page.getByText('rejected')).toBeVisible();
		expect(cap.decision).toBe('reject');
	});

	// Entity context adds the whole ENTITY block, making the dialog taller than a
	// laptop viewport. Centering on the scrolling overlay used to push the panel's
	// top off-screen (y = -185 at 1280x720) where scrolling could never reach it.
	test('new-fact dialog is fully reachable when taller than the viewport', async ({ page }) => {
		await page.setViewportSize({ width: 1280, height: 720 });
		await wire(page);
		await page.goto('/authorization');
		await page.getByRole('button', { name: '+ New fact' }).click();
		await page.getByRole('button', { name: /Entity context/ }).click();

		const panel = page.locator('.card.max-w-2xl');
		const title = page.getByRole('heading', { name: /New authorization fact/i });
		const box = await panel.boundingBox();

		expect(box!.height).toBeGreaterThan(page.viewportSize()!.height); // else this proves nothing
		expect(box!.y).toBeGreaterThanOrEqual(0);
		await expect(title).toBeInViewport();

		// Both ends stay reachable by scrolling.
		await page.getByRole('button', { name: 'Create fact' }).scrollIntoViewIfNeeded();
		await expect(page.getByRole('button', { name: 'Create fact' })).toBeInViewport();
		await title.scrollIntoViewIfNeeded();
		await expect(title).toBeInViewport();
	});
});
