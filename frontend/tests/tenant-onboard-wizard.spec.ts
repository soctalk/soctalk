import { test, expect, type Page } from '@playwright/test';

/**
 * Onboarding wizard — conditional "External SIEM" step (profile=provided).
 *
 * Covers tenant.profile.provided.wizard-step:
 *  - step labels are computed reactively (5 with provided, 4 otherwise),
 *  - the External SIEM step renders the nested-credential fields,
 *  - step validity gates the Next button (empty api_password blocks),
 *  - submit posts a nested ``external_siem`` object (not flat wazuh_* fields),
 *  - switching profile away from provided clears the captured creds.
 *
 * And tenant.llm.wizard-fields:
 *  - the External SIEM step surfaces a REQUIRED 'LLM credentials' sub-section
 *    (provider select + password key input) that also gates Next,
 *  - the provided payload carries llm_provider + llm_api_key,
 *  - the poc flow submits without a key and the payload OMITS llm_api_key,
 *  - the plaintext key never appears in the Review step content.
 *
 * And tenant.llm.models.wizard:
 *  - the 'LLM (advanced)' disclosure offers optional Fast/Thinking model
 *    inputs ('leave blank to use the primary model'),
 *  - filling them puts llm_fast_model + llm_reasoning_model in the payload
 *    and surfaces them on the Review LLM row,
 *  - flows that leave them blank OMIT both keys from the payload.
 *
 * The whole /api surface is mocked at the browser so neither the FastAPI
 * backend nor Postgres need to be up.
 */

const MSSP_USER = {
	user_id: '00000000-0000-0000-0000-000000000001',
	email: 'admin@mssp.example',
	user_type: 'mssp_admin',
	role: 'mssp_admin',
	tenant_id: null,
	current_tenant: null
};

const TENANT_RESPONSE = {
	id: '11111111-1111-1111-1111-111111111111',
	slug: 'acme',
	display_name: 'Acme Corp',
	state: 'provisioning',
	profile: 'provided',
	created_at: '2026-01-01T00:00:00Z',
	state_changed_at: '2026-01-01T00:00:00Z'
};

/** Mock every /api call; the onboard POST is fulfilled with a tenant row. */
async function mockApi(page: Page) {
	await page.route('**/api/**', async (route) => {
		const req = route.request();
		const url = req.url();
		// The '**/api/**' glob also matches Vite dev-module URLs such as
		// /src/lib/api/client.ts — let anything that is not a real backend
		// call fall through so the app bundle can load.
		const path = new URL(url).pathname;
		if (!path.startsWith('/api/')) return route.continue();
		if (url.includes('/auth/me')) {
			return route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify(MSSP_USER)
			});
		}
		if (url.includes('/tenants/onboard') && req.method() === 'POST') {
			return route.fulfill({
				status: 202,
				contentType: 'application/json',
				body: JSON.stringify(TENANT_RESPONSE)
			});
		}
		if (url.includes('/events/stream')) {
			// EventSource — keep it quiet with an empty event stream.
			return route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
		}
		return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
	});
}

async function gotoWizard(page: Page) {
	await mockApi(page);
	await page.goto('/tenants/new');
	await expect(page.getByTestId('wizard-step').first()).toBeVisible();
}

/** Advance from Identity → Profile with valid identity material. */
async function fillIdentityAndContinue(page: Page) {
	await page.fill('input[name="display_name"]', 'Acme Corp');
	await page.fill('input[name="slug"]', 'acme');
	await page.getByRole('button', { name: 'Next' }).click();
	// Now on the Profile step.
	await expect(page.locator('input[value="provided"]')).toBeVisible();
}

test.describe('Tenant onboarding wizard — External SIEM step', () => {
	test('provided profile yields 5 step labels including External SIEM; poc yields 4', async ({
		page
	}) => {
		await gotoWizard(page);

		// Default profile is poc → 4 labels, no External SIEM.
		await expect(page.getByTestId('wizard-step')).toHaveCount(4);
		await expect(page.getByTestId('wizard-step')).toHaveText([
			'1. Identity',
			'2. Profile',
			'3. Branding',
			'4. Review'
		]);

		await fillIdentityAndContinue(page);
		await page.check('input[value="provided"]');

		// provided profile → 5 labels with External SIEM in position 3.
		await expect(page.getByTestId('wizard-step')).toHaveCount(5);
		await expect(page.getByTestId('wizard-step')).toHaveText([
			'1. Identity',
			'2. Profile',
			'3. External SIEM',
			'4. Branding',
			'5. Review'
		]);
	});

	test('External SIEM step renders nested credential fields with correct types', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);
		await page.check('input[value="provided"]');
		await page.getByRole('button', { name: 'Next' }).click();

		// On the External SIEM step now.
		await expect(page.locator('input[name="indexer_url"]')).toBeVisible();
		await expect(page.locator('input[name="indexer_username"]')).toBeVisible();
		await expect(page.locator('input[name="indexer_password"]')).toHaveAttribute(
			'type',
			'password'
		);
		await expect(page.locator('input[name="api_url"]')).toBeVisible();
		await expect(page.locator('input[name="api_username"]')).toBeVisible();
		await expect(page.locator('input[name="api_password"]')).toHaveAttribute('type', 'password');
		await expect(page.locator('input[name="api_token"]')).toHaveAttribute('type', 'password');
		// verify_ssl is a checkbox, checked by default.
		await expect(page.locator('input[name="verify_ssl"]')).toBeChecked();
	});

	test('cannot advance past External SIEM with empty api_password or LLM key; full creds POST nested external_siem + llm fields', async ({
		page
	}) => {
		const LLM_KEY = 'sk-provided-tenant-key-9876';
		await gotoWizard(page);
		await fillIdentityAndContinue(page);
		await page.check('input[value="provided"]');
		await page.getByRole('button', { name: 'Next' }).click();

		// The prominent LLM credentials sub-section is always visible on this
		// step: provider select + password-type key input (autocomplete off).
		await expect(page.getByTestId('wizard-llm-credentials')).toBeVisible();
		await expect(page.locator('select[name="llm_provider"]')).toBeVisible();
		await expect(page.locator('input[name="llm_api_key"]')).toHaveAttribute('type', 'password');
		await expect(page.locator('input[name="llm_api_key"]')).toHaveAttribute(
			'autocomplete',
			'off'
		);

		// Fill every required field EXCEPT api_password — Next stays disabled.
		await page.fill('input[name="indexer_url"]', 'https://indexer.example.com:9200');
		await page.fill('input[name="indexer_username"]', 'admin');
		await page.fill('input[name="indexer_password"]', 'indexpass');
		await page.fill('input[name="api_url"]', 'https://wazuh.example.com:55000');
		await page.fill('input[name="api_username"]', 'wazuh-wui');
		await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();

		// Supplying api_password is NOT enough — the LLM key is required too.
		await page.fill('input[name="api_password"]', 'apipass');
		await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();

		// The LLM key completes the step validity.
		await page.selectOption('select[name="llm_provider"]', 'anthropic');
		await page.fill('input[name="llm_api_key"]', LLM_KEY);
		await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled();

		// External SIEM → Branding → Review.
		await page.getByRole('button', { name: 'Next' }).click();
		await page.getByRole('button', { name: 'Next' }).click();

		// Review shows set + last-4 mask; the plaintext key is NEVER rendered.
		await expect(page.getByTestId('review-llm-key')).toContainText('set (…9876)');
		expect(await page.content()).not.toContain(LLM_KEY);

		const onboardReq = page.waitForRequest(
			(r) => r.url().includes('/tenants/onboard') && r.method() === 'POST'
		);
		await page.getByTestId('create-tenant').click();
		const body = (await onboardReq).postDataJSON();

		expect(body.profile).toBe('provided');
		expect(body.llm_provider).toBe('anthropic');
		expect(body.llm_api_key).toBe(LLM_KEY);
		// Fast/Thinking overrides were left blank → both keys ABSENT.
		expect(body).not.toHaveProperty('llm_fast_model');
		expect(body).not.toHaveProperty('llm_reasoning_model');
		// Nested object — supersedes the old flat wazuh_* payload.
		expect(body.external_siem).toMatchObject({
			indexer_url: 'https://indexer.example.com:9200',
			indexer_username: 'admin',
			indexer_password: 'indexpass',
			api_url: 'https://wazuh.example.com:55000',
			api_username: 'wazuh-wui',
			api_password: 'apipass',
			verify_ssl: true
		});
		// Flat fields must be gone.
		expect(body.wazuh_api_url).toBeUndefined();
		expect(body.wazuh_indexer_url).toBeUndefined();
		expect(body.wazuh_api_password).toBeUndefined();
	});

	test('poc flow submits without an LLM key and the payload OMITS llm_api_key', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);

		// Default poc profile — the optional key lives inside the disclosure
		// with the shared-install-key helper text.
		await page.getByText('LLM (advanced)').click();
		await expect(page.locator('input[name="llm_api_key"]')).toHaveAttribute('type', 'password');
		await expect(
			page.getByText('leave blank to use the MSSP shared install key')
		).toBeVisible();

		// Profile → Branding → Review with the key left blank.
		await page.getByRole('button', { name: 'Next' }).click();
		await page.getByRole('button', { name: 'Next' }).click();
		await expect(page.getByTestId('review-llm-key')).toContainText('not set');

		const onboardReq = page.waitForRequest(
			(r) => r.url().includes('/tenants/onboard') && r.method() === 'POST'
		);
		await page.getByTestId('create-tenant').click();
		const body = (await onboardReq).postDataJSON();

		expect(body.profile).toBe('poc');
		expect(body.llm_api_key).toBeUndefined();
		// Blank Fast/Thinking model overrides are likewise OMITTED.
		expect(body).not.toHaveProperty('llm_fast_model');
		expect(body).not.toHaveProperty('llm_reasoning_model');
	});

	test('filling Fast + Thinking models includes llm_fast_model/llm_reasoning_model in the payload and on Review', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);

		// The overrides live in the same 'LLM (advanced)' disclosure as the
		// Model input, each with the use-the-primary-model helper text.
		await page.getByText('LLM (advanced)').click();
		await expect(page.locator('input[name="llm_fast_model"]')).toBeVisible();
		await expect(page.locator('input[name="llm_reasoning_model"]')).toBeVisible();
		await expect(
			page.getByText('leave blank to use the primary model')
		).toHaveCount(2);
		await page.fill('input[name="llm_fast_model"]', 'gpt-4o-mini');
		await page.fill('input[name="llm_reasoning_model"]', 'o3');

		// Both fields are optional — Next stays enabled throughout.
		await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled();

		// Profile → Branding → Review.
		await page.getByRole('button', { name: 'Next' }).click();
		await page.getByRole('button', { name: 'Next' }).click();
		await expect(page.getByTestId('review-llm')).toHaveText(
			'openai-compatible · gpt-4o · fast: gpt-4o-mini · thinking: o3'
		);

		const onboardReq = page.waitForRequest(
			(r) => r.url().includes('/tenants/onboard') && r.method() === 'POST'
		);
		await page.getByTestId('create-tenant').click();
		const body = (await onboardReq).postDataJSON();

		expect(body.profile).toBe('poc');
		expect(body.llm_fast_model).toBe('gpt-4o-mini');
		expect(body.llm_reasoning_model).toBe('o3');
	});

	test('blank overrides never render an empty literal on the Review LLM row', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);

		// Straight through with the overrides untouched.
		await page.getByRole('button', { name: 'Next' }).click();
		await page.getByRole('button', { name: 'Next' }).click();
		await expect(page.getByTestId('review-llm')).toHaveText(
			'openai-compatible · gpt-4o'
		);
	});

	test('switching provided → poc clears external_siem and drops back to 4 steps', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);
		await page.check('input[value="provided"]');
		await page.getByRole('button', { name: 'Next' }).click();

		// Capture a value in the External SIEM step.
		await page.fill('input[name="indexer_url"]', 'https://indexer.example.com:9200');
		await page.getByRole('button', { name: 'Back' }).click();

		// Back on Profile: switch away from provided.
		await page.check('input[value="poc"]');
		await expect(page.getByTestId('wizard-step')).toHaveCount(4);
		await expect(page.getByText('External SIEM')).toHaveCount(0);

		// Re-selecting provided shows a *blank* form (creds were cleared).
		await page.check('input[value="provided"]');
		await page.getByRole('button', { name: 'Next' }).click();
		await expect(page.locator('input[name="indexer_url"]')).toHaveValue('');
	});
});
