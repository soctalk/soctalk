import { test, expect, type Page } from '@playwright/test';

/**
 * Tenant detail — "External SIEM" panel (feature tenant.external-siem.detail-panel).
 *
 * Covers:
 *  - the panel renders for a poc-profile tenant (it is profile-agnostic),
 *  - the read view shows the masked GET .../external-siem fields,
 *  - the panel polls GET .../adapter-status and STOPS polling when the user
 *    navigates away (the page unmounts → the interval is cleared),
 *  - the inline Edit form PATCHes .../external-siem then refreshes + toasts.
 *
 * The whole /api surface is mocked at the browser so neither the FastAPI
 * backend nor Postgres need to be up. (Playwright e2e may not execute headless
 * in every sandbox; this file is still authored so it runs wherever a browser
 * is available.)
 */

const TENANT_ID = '22222222-2222-2222-2222-222222222222';

const MSSP_USER = {
	user_id: '00000000-0000-0000-0000-000000000001',
	email: 'admin@mssp.example',
	user_type: 'mssp_admin',
	role: 'mssp_admin',
	tenant_id: null,
	current_tenant: null
};

// poc profile on purpose — the panel must be visible for ANY profile, not just
// 'provided'.
const TENANT = {
	id: TENANT_ID,
	slug: 'acme',
	display_name: 'Acme Corp',
	state: 'active',
	profile: 'poc',
	created_at: '2026-01-01T00:00:00Z',
	state_changed_at: '2026-01-01T00:00:00Z',
	runtime: null
};

const SIEM_READ = {
	indexer_url: 'https://indexer.acme:9200',
	indexer_username: 'indexer-ro',
	api_url: 'https://wazuh.acme:55000',
	api_username: 'soctalk-adapter',
	has_indexer_password: true,
	has_api_password: true,
	has_api_token: false,
	verify_ssl: true
};

const ADAPTER_STATUS = {
	reachable: true,
	ok: true,
	alerts_forwarded: 12,
	last_alert_ts: '2026-06-09T12:00:00+00:00',
	last_ingest_error: null
};

interface MockHandles {
	adapterStatusCount: () => number;
	lastPatchBody: () => Record<string, unknown> | null;
}

/** Mock every /api call; returns handles to inspect adapter polling + PATCH. */
async function mockApi(page: Page): Promise<MockHandles> {
	let adapterStatusCount = 0;
	let lastPatchBody: Record<string, unknown> | null = null;
	// Mutable so a PATCH can flip has_* presence on the subsequent read.
	let siemRead = { ...SIEM_READ };

	await page.route('**/api/**', async (route) => {
		const req = route.request();
		const method = req.method();
		const path = new URL(req.url()).pathname;
		const json = (body: unknown, status = 200) =>
			route.fulfill({
				status,
				contentType: 'application/json',
				body: JSON.stringify(body)
			});

		if (path.includes('/auth/me')) return json(MSSP_USER);
		if (path.includes('/events/stream')) {
			return route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
		}
		if (path.endsWith('/adapter-status')) {
			adapterStatusCount += 1;
			return json(ADAPTER_STATUS);
		}
		if (path.endsWith('/external-siem')) {
			if (method === 'PATCH') {
				lastPatchBody = req.postDataJSON();
				siemRead = {
					...siemRead,
					...(lastPatchBody as Partial<typeof siemRead>),
					// Re-derive masked presence flags from what was sent.
					has_indexer_password:
						siemRead.has_indexer_password || !!(lastPatchBody as Record<string, unknown>).indexer_password,
					has_api_password:
						siemRead.has_api_password || !!(lastPatchBody as Record<string, unknown>).api_password,
					has_api_token:
						siemRead.has_api_token || !!(lastPatchBody as Record<string, unknown>).api_token
				};
				return json(siemRead);
			}
			return json(siemRead);
		}
		// /tenants/<id>/events
		if (/\/tenants\/[^/]+\/events$/.test(path)) return json([]);
		// /tenants/<id> (detail)
		if (/\/tenants\/[^/]+$/.test(path) && method === 'GET') return json(TENANT);
		// /tenants (list)
		if (path.endsWith('/tenants') && method === 'GET') return json([TENANT]);
		return json({});
	});

	return {
		adapterStatusCount: () => adapterStatusCount,
		lastPatchBody: () => lastPatchBody
	};
}

test.describe('Tenant detail — External SIEM panel', () => {
	test('renders for a poc-profile tenant with the masked read fields', async ({ page }) => {
		await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);

		const panel = page.getByTestId('external-siem-panel');
		await expect(panel).toBeVisible();
		await expect(panel.getByText('External SIEM')).toBeVisible();

		// Read view — URLs + usernames are shown verbatim.
		await expect(page.getByTestId('siem-indexer-url')).toContainText('https://indexer.acme:9200');
		await expect(page.getByTestId('siem-indexer-username')).toContainText('indexer-ro');
		await expect(page.getByTestId('siem-api-url')).toContainText('https://wazuh.acme:55000');
		await expect(page.getByTestId('siem-api-username')).toContainText('soctalk-adapter');
		await expect(page.getByTestId('siem-verify-ssl')).toBeVisible();

		// Credential presence rendered as ✔ / ✘ (present passwords, absent token).
		await expect(page.getByTestId('siem-has-indexer-password')).toContainText('✔');
		await expect(page.getByTestId('siem-has-api-password')).toContainText('✔');
		await expect(page.getByTestId('siem-has-api-token')).toContainText('✘');
	});

	test('polls adapter-status and shows ingest fields', async ({ page }) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);

		await expect(page.getByTestId('external-siem-panel')).toBeVisible();
		// At least one poll fires on mount.
		await expect.poll(() => handles.adapterStatusCount()).toBeGreaterThanOrEqual(1);

		await expect(page.getByTestId('adapter-alerts-forwarded')).toContainText('12');
		await expect(page.getByTestId('adapter-last-alert-ts')).toContainText('2026');
		// last_ingest_error is null → 'OK'.
		await expect(page.getByTestId('adapter-last-ingest-error')).toContainText('OK');
	});

	test('adapter-status polling STOPS when navigating away', async ({ page }) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);

		await expect(page.getByTestId('external-siem-panel')).toBeVisible();
		await expect.poll(() => handles.adapterStatusCount()).toBeGreaterThanOrEqual(1);

		// Navigate away — the detail page unmounts, clearing the poll interval.
		await page.getByRole('button', { name: '← Tenants' }).click();
		await expect(page).toHaveURL(/\/tenants$/);

		const countAfterNav = handles.adapterStatusCount();
		// Wait longer than one 10s poll interval; the count must NOT grow.
		await page.waitForTimeout(11000);
		expect(handles.adapterStatusCount()).toBe(countAfterNav);
	});

	test('Edit reveals an inline form, PATCHes, refreshes and toasts', async ({ page }) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('external-siem-panel')).toBeVisible();

		await page.getByTestId('siem-edit').click();

		// Both credential pairs are present in the in-place form.
		await expect(page.locator('input[name="indexer_url"]')).toBeVisible();
		await expect(page.locator('input[name="indexer_password"]')).toHaveAttribute('type', 'password');
		await expect(page.locator('input[name="api_url"]')).toBeVisible();
		await expect(page.locator('input[name="api_password"]')).toHaveAttribute('type', 'password');
		await expect(page.locator('input[name="api_token"]')).toHaveAttribute('type', 'password');

		await page.fill('input[name="indexer_password"]', 'rotated-idx-pw');
		await page.fill('input[name="api_password"]', 'rotated-api-pw');

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/external-siem') && r.method() === 'PATCH'
		);
		await page.getByTestId('siem-save').click();
		await patchReq;

		// PATCH body carried the rotated credentials.
		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		expect(handles.lastPatchBody()).toMatchObject({
			indexer_password: 'rotated-idx-pw',
			api_password: 'rotated-api-pw'
		});

		// Toast confirms + the read view returns (form closed).
		await expect(page.getByText('External SIEM')).toBeVisible();
		await expect(page.locator('input[name="api_password"]')).toHaveCount(0);
	});
});
