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

	test('cannot advance past External SIEM with empty api_password; full creds POST nested external_siem', async ({
		page
	}) => {
		await gotoWizard(page);
		await fillIdentityAndContinue(page);
		await page.check('input[value="provided"]');
		await page.getByRole('button', { name: 'Next' }).click();

		// Fill every required field EXCEPT api_password — Next stays disabled.
		await page.fill('input[name="indexer_url"]', 'https://indexer.example.com:9200');
		await page.fill('input[name="indexer_username"]', 'admin');
		await page.fill('input[name="indexer_password"]', 'indexpass');
		await page.fill('input[name="api_url"]', 'https://wazuh.example.com:55000');
		await page.fill('input[name="api_username"]', 'wazuh-wui');
		await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();

		// Supplying api_password satisfies the step validity.
		await page.fill('input[name="api_password"]', 'apipass');
		await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled();

		// External SIEM → Branding → Review.
		await page.getByRole('button', { name: 'Next' }).click();
		await page.getByRole('button', { name: 'Next' }).click();

		const onboardReq = page.waitForRequest(
			(r) => r.url().includes('/tenants/onboard') && r.method() === 'POST'
		);
		await page.getByTestId('create-tenant').click();
		const body = (await onboardReq).postDataJSON();

		expect(body.profile).toBe('provided');
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
