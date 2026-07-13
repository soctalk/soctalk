import { test, expect, type Page } from '@playwright/test';

/**
 * Tenant detail — "LLM Configuration" panel, per-tier MODEL CHAIN editor
 * (issue #12 / #4). A hybrid tenant routes the fast (router) and/or reasoning
 * (verdict) tier to a DEDICATED backend — its own provider/base_url/model/
 * engine/decoding + optional own key.
 *
 * Covers:
 *  - the read view renders the chain when ``tiers`` is present,
 *  - enabling a tier + filling its fields PATCHes a ``tiers`` map with the tier
 *    block (and OMITS api_key_plain when the key field is left blank → keep),
 *  - a cross-provider tier with no key is blocked client-side (no PATCH),
 *  - a tier key typed into the password field NEVER appears in the DOM.
 *
 * Whole /api surface mocked at the browser (mirrors tenant-llm-panel.spec.ts).
 */

const TENANT_ID = '44444444-4444-4444-4444-444444444444';
const TIER_SECRET = 'sk-TIER-PLAINTEXT-never-render-9876543210';

const MSSP_USER = {
	user_id: '00000000-0000-0000-0000-000000000001',
	email: 'admin@mssp.example',
	user_type: 'mssp_admin',
	role: 'mssp_admin',
	tenant_id: null,
	current_tenant: null
};

const TENANT = {
	id: TENANT_ID,
	slug: 'hybrid',
	display_name: 'Hybrid Corp',
	state: 'active',
	profile: 'poc',
	created_at: '2026-01-01T00:00:00Z',
	state_changed_at: '2026-01-01T00:00:00Z',
	runtime: null
};

interface TierRead {
	provider: string | null;
	base_url: string | null;
	model: string | null;
	engine: string | null;
	decoding_mode: string | null;
	temperature: number | null;
	max_tokens: number | null;
	has_api_key: boolean;
}
interface LlmRead {
	provider: string;
	base_url: string;
	model: string;
	fast_model: string | null;
	reasoning_model: string | null;
	temperature: number;
	max_tokens: number;
	has_api_key: boolean;
	api_key_preview: string;
	tiers: Record<string, TierRead> | null;
}

// Anthropic primary; NO chain yet — the operator will add a fast tier.
const READ_SINGLE: LlmRead = {
	provider: 'anthropic',
	base_url: 'https://api.anthropic.com',
	model: 'claude-sonnet-4-6',
	fast_model: null,
	reasoning_model: null,
	temperature: 0.0,
	max_tokens: 4096,
	has_api_key: true,
	api_key_preview: 'sk-ant-…7890',
	tiers: null
};

// A hybrid read — the fast tier already runs on a self-hosted sglang backend.
const READ_HYBRID: LlmRead = {
	...READ_SINGLE,
	tiers: {
		fast: {
			provider: 'openai-compatible',
			base_url: 'http://sglang.internal:8000/v1',
			model: 'qwen3-32b',
			engine: 'sglang',
			decoding_mode: 'json_object',
			temperature: null,
			max_tokens: null,
			has_api_key: true
		}
	}
};

interface MockHandles {
	lastPatchBody: () => Record<string, unknown> | null;
	patchCount: () => number;
}

async function mockApi(page: Page, initialRead: LlmRead): Promise<MockHandles> {
	let lastPatchBody: Record<string, unknown> | null = null;
	let patchCount = 0;
	let llmRead = { ...initialRead };

	await page.route('**/api/**', async (route) => {
		const req = route.request();
		const method = req.method();
		const path = new URL(req.url()).pathname;
		if (!path.startsWith('/api/')) return route.continue();
		const json = (body: unknown, status = 200) =>
			route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

		if (path.includes('/auth/me')) return json(MSSP_USER);
		if (path.includes('/events/stream'))
			return route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
		if (path.endsWith('/adapter-status')) return json({ reachable: true, ok: true });
		if (path.endsWith('/external-siem')) return json({});
		if (path.endsWith('/llm')) {
			if (method === 'PATCH') {
				patchCount += 1;
				lastPatchBody = req.postDataJSON();
				const body = lastPatchBody as Record<string, unknown>;
				// Emulate the backend: sanitize the tiers map into the read view
				// (has_api_key per tier, plaintext stripped).
				if (body.tiers !== undefined) {
					const t = body.tiers as Record<string, Record<string, unknown>> | null;
					llmRead = {
						...llmRead,
						tiers:
							t && Object.keys(t).length
								? Object.fromEntries(
										Object.entries(t).map(([k, v]) => [
											k,
											{
												provider: (v.provider as string) ?? null,
												base_url: (v.base_url as string) ?? null,
												model: (v.model as string) ?? null,
												engine: (v.engine as string) ?? null,
												decoding_mode: (v.decoding_mode as string) ?? null,
												temperature: (v.temperature as number) ?? null,
												max_tokens: (v.max_tokens as number) ?? null,
												// keep semantics: a prior key persists unless '' clears it.
												has_api_key:
													v.api_key_plain !== undefined
														? !!v.api_key_plain
														: (llmRead.tiers?.[k]?.has_api_key ?? false)
											}
										])
									)
								: null
					};
				}
				return json(llmRead);
			}
			return json(llmRead);
		}
		if (/\/tenants\/[^/]+\/events$/.test(path)) return json([]);
		if (/\/tenants\/[^/]+$/.test(path) && method === 'GET') return json(TENANT);
		if (path.endsWith('/tenants') && method === 'GET') return json([TENANT]);
		return json({});
	});

	return { lastPatchBody: () => lastPatchBody, patchCount: () => patchCount };
}

test.describe('Tenant detail — LLM model chain editor', () => {
	test('renders the chain read view when a tier backend is set', async ({ page }) => {
		await mockApi(page, READ_HYBRID);
		await page.goto(`/tenants/${TENANT_ID}`);

		await expect(page.getByTestId('llm-config-panel')).toBeVisible();
		const chain = page.getByTestId('llm-chain-view');
		await expect(chain).toBeVisible();
		const fast = page.getByTestId('llm-chain-fast');
		await expect(fast).toContainText('sglang');
		await expect(fast).toContainText('qwen3-32b');
		await expect(fast).toContainText('json_object');
		await expect(fast).toContainText('own key');
		// Reasoning tier has no dedicated backend → not rendered in the chain.
		await expect(page.getByTestId('llm-chain-reasoning')).toHaveCount(0);
	});

	test('adding a fast tier PATCHes a tiers map; blank key is omitted (keep)', async ({ page }) => {
		const handles = await mockApi(page, READ_SINGLE);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await expect(page.getByTestId('llm-chain-editor')).toBeVisible();

		// Enable the fast tier and fill an openai-compatible sglang backend WITH
		// its own key (cross-provider from the anthropic primary).
		await page.getByTestId('llm-tier-fast-enabled').check();
		await page.getByTestId('llm-tier-fast-provider').selectOption('openai-compatible');
		await page.getByTestId('llm-tier-fast-engine').selectOption('sglang');
		await page.getByTestId('llm-tier-fast-base-url').fill('http://sglang.internal:8000/v1');
		await page.getByTestId('llm-tier-fast-model').fill('qwen3-32b');
		await page.getByTestId('llm-tier-fast-decoding').selectOption('json_object');
		await page.getByTestId('llm-tier-fast-api-key').fill(TIER_SECRET);
		expect(await page.content()).not.toContain(TIER_SECRET);

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		const body = handles.lastPatchBody() as Record<string, unknown>;
		expect(body.tiers).toEqual({
			fast: {
				provider: 'openai-compatible',
				base_url: 'http://sglang.internal:8000/v1',
				model: 'qwen3-32b',
				engine: 'sglang',
				decoding_mode: 'json_object',
				api_key_plain: TIER_SECRET
			}
		});
		// Chain read view now shows the fast tier; plaintext never rendered.
		await expect(page.getByTestId('llm-chain-fast')).toContainText('qwen3-32b');
		expect(await page.content()).not.toContain(TIER_SECRET);
	});

	test('editing a tier model without touching its key OMITS api_key_plain (keep)', async ({
		page
	}) => {
		const handles = await mockApi(page, READ_HYBRID);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await expect(page.getByTestId('llm-tier-fast-enabled')).toBeChecked();
		// Change only the model; leave the key field blank.
		await page.getByTestId('llm-tier-fast-model').fill('qwen3-14b');

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		const body = handles.lastPatchBody() as Record<string, unknown>;
		const tiers = body.tiers as Record<string, Record<string, unknown>>;
		expect(tiers.fast.model).toBe('qwen3-14b');
		// keep: no key typed → api_key_plain omitted so the backend carries it forward.
		expect(tiers.fast).not.toHaveProperty('api_key_plain');
	});

	test('per-tier sampling rides the tiers block and renders in the chain view', async ({
		page
	}) => {
		const handles = await mockApi(page, READ_SINGLE);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await page.getByTestId('llm-tier-fast-enabled').check();
		await page.getByTestId('llm-tier-fast-provider').selectOption('anthropic');
		await page.getByTestId('llm-tier-fast-base-url').fill('https://api.anthropic.com');
		await page.getByTestId('llm-tier-fast-model').fill('claude-haiku-4-5');
		// Per-tier sampling override.
		await page.getByTestId('llm-tier-fast-temperature').fill('0.4');
		await page.getByTestId('llm-tier-fast-max-tokens').fill('1024');

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		const body = handles.lastPatchBody() as Record<string, unknown>;
		const tiers = body.tiers as Record<string, Record<string, unknown>>;
		expect(tiers.fast.temperature).toBe(0.4);
		expect(tiers.fast.max_tokens).toBe(1024);
		// Chain read view shows the override.
		await expect(page.getByTestId('llm-chain-fast')).toContainText('0.4');
		await expect(page.getByTestId('llm-chain-fast')).toContainText('1024');
	});

	test('out-of-range per-tier temperature is blocked client-side (no PATCH)', async ({ page }) => {
		const handles = await mockApi(page, READ_SINGLE);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await page.getByTestId('llm-tier-fast-enabled').check();
		await page.getByTestId('llm-tier-fast-provider').selectOption('anthropic');
		await page.getByTestId('llm-tier-fast-base-url').fill('https://api.anthropic.com');
		await page.getByTestId('llm-tier-fast-model').fill('claude-haiku-4-5');
		await page.getByTestId('llm-tier-fast-temperature').fill('3');

		await page.getByTestId('llm-save').click();
		await expect(page.getByTestId('llm-form-error')).toContainText('temperature must be between 0 and 2');
		expect(handles.patchCount()).toBe(0);
	});

	test('cross-provider tier with no key is blocked client-side (no PATCH)', async ({ page }) => {
		const handles = await mockApi(page, READ_SINGLE);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await page.getByTestId('llm-tier-fast-enabled').check();
		// openai-compatible tier over the anthropic primary, but NO key supplied.
		await page.getByTestId('llm-tier-fast-provider').selectOption('openai-compatible');
		await page.getByTestId('llm-tier-fast-base-url').fill('http://sglang.internal:8000/v1');
		await page.getByTestId('llm-tier-fast-model').fill('qwen3-32b');

		await page.getByTestId('llm-save').click();
		await expect(page.getByTestId('llm-form-error')).toContainText('needs its own API key');
		expect(handles.patchCount()).toBe(0);
		await expect(page.getByTestId('llm-edit-form')).toBeVisible();
	});

	test('disabling the only tier clears the chain back to single-provider ({})', async ({
		page
	}) => {
		const handles = await mockApi(page, READ_HYBRID);
		await page.goto(`/tenants/${TENANT_ID}`);
		await expect(page.getByTestId('llm-config-panel')).toBeVisible();

		await page.getByTestId('llm-edit').click();
		await expect(page.getByTestId('llm-tier-fast-enabled')).toBeChecked();
		await page.getByTestId('llm-tier-fast-enabled').uncheck();

		const patchReq = page.waitForRequest(
			(r) => new URL(r.url()).pathname.endsWith('/llm') && r.method() === 'PATCH'
		);
		await page.getByTestId('llm-save').click();
		await patchReq;

		await expect.poll(() => handles.lastPatchBody()).not.toBeNull();
		const body = handles.lastPatchBody() as Record<string, unknown>;
		// {} = clear back to single-provider.
		expect(body.tiers).toEqual({});
		await expect(page.getByTestId('llm-chain-view')).toHaveCount(0);
	});
});
