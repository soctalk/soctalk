import { test, expect } from '@playwright/test';

const TID = '11111111-1111-1111-1111-111111111111';

function me(role: string, permissions: string[]) {
	return {
		user_id: 'u1', email: `${role}@acme.example`, user_type: 'tenant', role,
		tenant_id: TID, current_tenant: null, permissions
	};
}

const APPROVED_FACT = {
	id: 'connector:1', kind: 'grant', track: 'account', source_type: 'connector_verified',
	trust: 100, review_status: 'approved',
	scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }
};

test.describe('Tenant authorization facts (self-service) — structured form', () => {
	test('tenant_manager asserts a standing-baseline fact via the form; lands awaiting review', async ({ page }) => {
		const store: Record<string, unknown>[] = [APPROVED_FACT];
		const captured: { body: Record<string, unknown> | null } = { body: null };
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(
				me('tenant_manager', ['tenant_view_authorization_facts', 'tenant_assert_authorization_facts'])
			) })
		);
		await page.route('**/api/tenant/authorization/facts', async (route) => {
			if (route.request().method() === 'POST') {
				captured.body = (JSON.parse(route.request().postData() || '{}').fact) ?? {};
				store.push({ ...APPROVED_FACT, ...captured.body, id: 'tenant:x', source_type: 'tenant_asserted', trust: 20, review_status: 'pending' });
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ stored: 'tenant:x', review_status: 'pending' }) });
			} else {
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: store }) });
			}
		});

		await page.goto('/my-authorization');
		await expect(page.getByRole('heading', { name: 'Authorization' })).toBeVisible();
		await page.getByRole('button', { name: '+ Assert fact' }).click();
		// tenant mode: no id field (server generates one). standing_baseline needs no valid_until.
		await page.getByLabel('Grant class').selectOption('standing_baseline');
		await page.getByPlaceholder('svc-deploy').fill('backup-svc');
		await page.getByPlaceholder('sudo-exec').fill('file-read');
		await page.getByRole('button', { name: 'Submit for review' }).click();
		await expect(page.getByText('awaiting review')).toBeVisible();

		expect(captured.body).toMatchObject({ kind: 'grant', grant_class: 'standing_baseline', scope: { subject: 'backup-svc', action: 'file-read' } });
		expect(captured.body!.valid_until).toBeUndefined(); // baseline is unbounded
		expect(captured.body!.source_type).toBeUndefined(); // server-stamped
		expect(String(captured.body!.id)).toMatch(/^draft-/); // placeholder the server overwrites
	});

	test('asserting an account entity_context carries the account-only attributes', async ({ page }) => {
		const captured: { body: Record<string, unknown> | null } = { body: null };
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(
				me('tenant_manager', ['tenant_view_authorization_facts', 'tenant_assert_authorization_facts'])
			) })
		);
		await page.route('**/api/tenant/authorization/facts', async (route) => {
			if (route.request().method() === 'POST') {
				captured.body = (JSON.parse(route.request().postData() || '{}').fact) ?? {};
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ stored: 'tenant:y', review_status: 'pending' }) });
			} else {
				await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: [] }) });
			}
		});
		await page.goto('/my-authorization');
		await page.getByRole('button', { name: '+ Assert fact' }).click();
		await page.getByRole('button', { name: /Entity context/ }).click();
		await page.getByLabel('Type').selectOption('account');
		await page.getByRole('textbox', { name: 'Name', exact: true }).fill('jump-01'); // entity name
		await page.getByLabel('Account type').selectOption('human');
		await page.getByText('Privileged', { exact: true }).click();
		await page.getByRole('button', { name: 'Submit for review' }).click();

		await expect.poll(() => captured.body).not.toBeNull();
		expect(captured.body).toMatchObject({ kind: 'entity_context', entity_type: 'account', name: 'jump-01', account_type: 'human', privileged: true });
	});

	test('a tenant viewer can read facts but cannot assert', async ({ page }) => {
		await page.route('**/auth/me', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me('customer_viewer', ['tenant_view_authorization_facts'])) })
		);
		await page.route('**/api/tenant/authorization/facts', (r) =>
			r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ facts: [APPROVED_FACT] }) })
		);
		await page.goto('/my-authorization');
		await expect(page.getByText(/svc-deploy/).first()).toBeVisible();
		await expect(page.getByRole('button', { name: '+ Assert fact' })).toHaveCount(0);
	});
});
