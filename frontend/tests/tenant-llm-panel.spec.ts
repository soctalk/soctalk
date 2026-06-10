import { test, expect, type Page } from '@playwright/test';

/**
 * Tenant detail — "LLM Configuration" panel (feature tenant.llm.detail-panel).
 *
 * Covers:
 *  - the masked read view renders provider/base_url/model + the key preview
 *    (has_api_key=true) or the shared-install-key messaging (false),
 *  - the inline Edit form PATCHes .../llm with ONLY the changed fields and a
 *    blank "Replace API key" field is OMITTED from the payload,
 *  - the clear-key flow requires an inline confirm before DELETE .../llm/api-key
 *    and the panel re-fetches into the shared-key state afterwards,
 *  - the plaintext key NEVER appears in the page content in any state.
 *
 * The whole /api surface is mocked at the browser so neither the FastAPI
 * backend nor Postgres need to be up (mirrors tenant-external-siem-panel.spec.ts).
 */

const TENANT_ID = '33333333-3333-3333-3333-333333333333';

// A "plaintext" key the operator types — must never surface in the DOM.
const SECRET_KEY = 'sk-PLAINTEXT-SECRET-do-not-render-1234567890';

const MSSP_USER = {
	user_id: '00000000-0000-0000-0000-000000000001',
	email: 'admin@mssp.example',
	user_type: 'mssp_admin',
	role: 'mssp_admin',
	tenant_id: null,
	current_tenant: null
};

// poc profile on purpose — the panel must be visible for ANY profile.
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

const LLM_READ_WITH_KEY = {
	provider: 'openai-compatible',
	base_url: 'https://llm.acme.example/v1',
	model: 'gpt-4o-mini',
	has_api_key: true,
	api_key_preview: 'sk-…7890'
};

const LLM_READ_NO_KEY = {
	provider: 'openai-compatible',
	base_url: 'https://llm.acme.example/v1',
	model: 'gpt-4o-mini',
	has_api_key: false,
	api_key_preview: ''
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

interface MockHandles {
	lastPatchBody: () => Record<string, unknown> | null;
	patchCount: () => number;
	clearCount: () => number;
}

/** Mock every /api call; returns handles to inspect PATCH / DELETE traffic. */
async function mockApi(
	page: Page,
	initialRead: typeof LLM_READ_WITH_KEY = LLM_READ_WITH_KEY
): Promise<MockHandles> {
	let lastPatchBody: Record<string, unknown> | null = null;
	let patchCount = 0;
	let clearCount = 0;
	// Mutable so a PATCH / DELETE flips the masked state on the subsequent read.
	let llmRead = { ...initialRead };

	await page.route('**/api/**', async (route) => {
		const req = route.request();
		const method = req.method();
		const path = new URL(req.url()).pathname;
		// The '**/api/**' glob also matches Vite dev-module URLs such as
		// /src/lib/api/client.ts — let anything that is not a real backend
		// call fall through so the app bundle can load.
		if (!path.startsWith('/api/')) return route.continue();
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
		if (path.endsWith('/adapter-status')) return json({ reachable: true, ok: true });
		if (path.endsWith('/external-siem')) return json(SIEM_READ);
		if (path.endsWith('/llm/api-key') && method === 'DELETE') {
			clearCount += 1;
			llmRead = { ...llmRead, has_api_key: false, api_key_preview: '' };
			return route.fulfill({ status: 204, body: '' });
		}
		if (path.endsWith('/llm')) {
			if (method === 'PATCH') {
				patchCount += 1;
				lastPatchBody = req.postDataJSON();
				const body = lastPatchBody as Record<string, unknown>;
				llmRead = {
					...llmRead,
					...(body.provider !== undefined ? { provider: body.provider as string } : {}),
					...(body.base_url !== undefined ? { base_url: body.base_url as string } : {}),
					...(body.model !== undefined ? { model: body.model as string } : {}),
					// A sent key is masked server-side: presence flag + tail preview only.
					...(body.api_key !== undefined
						? {
								has_api_key: true,
								api_key_preview: `sk-…${String(body.api_key).slice(-4)}`
							}
						: {})
				};
				return json(llmRead);
			}
			return json(llmRead);
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
		lastPatchBody: () => lastPatchBody,
		patchCount: () => patchCount,
		clearCount: () => clearCount
	};
}

test.describe('Tenant detail — LLM Configuration panel', () => {
	test('renders the masked read view with the key preview when a key is set', async ({ page }) => {
		await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);

		const panel = page.getByTestId('llm-config-panel');
		await expect(panel).toBeVisible();
		await expect(panel.getByText('LLM Configuration')).toBeVisible();

		await expect(page.getByTestId('llm-provider')).toContainText('openai-compatible');
		await expect(page.getByTestId('llm-base-url')).toContainText('https://llm.acme.example/v1');
		await expect(page.getByTestId('llm-model')).toContainText('gpt-4o-mini');
		// has_api_key=true → masked preview, NOT the shared-key messaging.
		await expect(page.getByTestId('llm-api-key-preview')).toContainText('sk-…7890');
		await expect(page.getByTestId('llm-shared-key-note')).toHaveCount(0);
		// Clear-key affordance exists only when a key is present.
		await expect(page.getByTestId('llm-clear-key')).toBeVisible();
		// Rollout semantics note.
		await expect(page.getByTestId('llm-rollout-note')).toContainText('re-render of the tenant release');
		await expect(page.getByTestId('llm-rollout-note')).toContainText('within seconds');
	});

	test('shows the shared-install-key messaging when no tenant key is set', async ({ page }) => {
		await mockApi(page, LLM_READ_NO_KEY);
		await page.goto(`/tenants/${TENANT_ID}`);

		await expect(page.getByTestId('llm-config-panel')).toBeVisible();
		await expect(page.getByTestId('llm-shared-key-note')).toContainText(
			'using MSSP shared install key'
		);
		await expect(page.getByTestId('llm-api-key-preview')).toHaveCount(0);
		await expect(page.getByTestId('llm-clear-key')).toHaveCount(0);
	});

	test('PATCH carries ONLY the changed fields; a blank key is omitted', async ({ page }) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await expect(page.getByTestId('llm-edit-form')).toBeVisible();

		// Provider select + password-type key input are present.
		await expect(page.locator('select[name="provider"]')).toBeVisible();
		await expect(page.locator('input[name="api_key"]')).toHaveAttribute('type', 'password');

		// Change ONLY the model; leave provider/base_url/key untouched.
		await page.fill('input[name="model"]', 'claude-sonnet-4');

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		// Exactly { model } — no api_key, no provider, no base_url.
		expect(handles.lastPatchBody()).toEqual({ model: 'claude-sonnet-4' });

		// Read view returns with the refreshed masked state.
		await expect(page.getByTestId('llm-model')).toContainText('claude-sonnet-4');
		await expect(page.locator('input[name="api_key"]')).toHaveCount(0);
	});

	test('replacing the key sends api_key but the plaintext NEVER appears in the page', async ({
		page
	}) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await page.fill('input[name="api_key"]', SECRET_KEY);

		// Even while typed, the password input must not leak the key into the DOM.
		expect(await page.content()).not.toContain(SECRET_KEY);

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		expect(handles.lastPatchBody()).toEqual({ api_key: SECRET_KEY });

		// Back to the read view — only the masked tail is rendered.
		await expect(page.getByTestId('llm-api-key-preview')).toContainText('sk-…7890');
		expect(await page.content()).not.toContain(SECRET_KEY);
	});

	test('base URL must start with http(s):// — invalid value blocks the PATCH', async ({
		page
	}) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await page.fill('input[name="base_url"]', 'ftp://bad.example');
		await page.getByTestId('llm-save').click();

		await expect(page.getByTestId('llm-form-error')).toContainText('http:// or https://');
		expect(handles.patchCount()).toBe(0);
		// The form stays open for correction.
		await expect(page.getByTestId('llm-edit-form')).toBeVisible();
	});

	test('clear-key requires confirm, DELETEs, then shows the shared-key state', async ({
		page
	}) => {
		const handles = await mockApi(page);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();
		await expect(page.getByTestId('llm-api-key-preview')).toContainText('sk-…7890');

		// First click only reveals the confirm step — no DELETE yet.
		await page.getByTestId('llm-clear-key').click();
		await expect(page.getByTestId('llm-clear-key-confirm-row')).toBeVisible();
		expect(handles.clearCount()).toBe(0);

		// Cancel backs out without a DELETE.
		await page.getByTestId('llm-clear-key-cancel').click();
		await expect(page.getByTestId('llm-clear-key-confirm-row')).toHaveCount(0);
		expect(handles.clearCount()).toBe(0);

		// Confirm path fires the DELETE and the panel re-fetches into shared-key.
		await page.getByTestId('llm-clear-key').click();
		const delReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm/api-key') && r.method() === 'DELETE'
		);
		await page.getByTestId('llm-clear-key-confirm').click();
		await delReq;

		await expect.poll(() => handles.clearCount()).toBe(1);
		await expect(page.getByTestId('llm-shared-key-note')).toContainText(
			'using MSSP shared install key'
		);
		await expect(page.getByTestId('llm-api-key-preview')).toHaveCount(0);
		await expect(page.getByTestId('llm-clear-key')).toHaveCount(0);
	});
});
