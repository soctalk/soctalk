import { test, expect, type Page } from '@playwright/test';

// Admin password reset from the user-admin pages (internal-auth §8.5): a
// permission-gated "Reset password" action per row, never on your own row,
// a confirmation step, then the one-time password shown once with a copy
// button and gone once the dialog closes.

type Row = { id: string; email: string; display_name: string; role: string; active: boolean };

interface Surface {
	name: string;
	path: string;
	listGlob: string;
	resetGlob: string;
	resetPath: (id: string) => string;
	me: Record<string, unknown>;
	users: Row[];
	target: Row;
	inactive: Row;
}

const TID = '11111111-1111-1111-1111-111111111111';

const MSSP: Surface = {
	name: 'MSSP staff users',
	path: '/mssp-users',
	listGlob: '**/api/mssp/users',
	resetGlob: '**/api/mssp/users/*/password/reset',
	resetPath: (id) => `/api/mssp/users/${id}/password/reset`,
	me: {
		user_id: 'u1',
		email: 'admin@example.test',
		user_type: 'mssp',
		role: 'mssp_admin',
		tenant_id: null,
		current_tenant: null,
		permissions: ['manage_users', 'review_decide', 'use_chat']
	},
	users: [
		{ id: 'u1', email: 'admin@example.test', display_name: 'admin', role: 'mssp_admin', active: true },
		{ id: 'u2', email: 'analyst@example.test', display_name: 'analyst', role: 'analyst', active: true },
		{ id: 'u3', email: 'former@example.test', display_name: 'former', role: 'analyst', active: false }
	],
	target: { id: 'u2', email: 'analyst@example.test', display_name: 'analyst', role: 'analyst', active: true },
	inactive: { id: 'u3', email: 'former@example.test', display_name: 'former', role: 'analyst', active: false }
};

const TENANT: Surface = {
	name: 'tenant users',
	path: '/tenant-users',
	listGlob: '**/api/tenant/users',
	resetGlob: '**/api/tenant/users/*/password/reset',
	resetPath: (id) => `/api/tenant/users/${id}/password/reset`,
	me: {
		user_id: 't1',
		email: 'owner@example.test',
		user_type: 'tenant',
		role: 'tenant_admin',
		tenant_id: TID,
		current_tenant: null,
		permissions: ['tenant_view_investigations', 'tenant_manage_users']
	},
	users: [
		{ id: 't1', email: 'owner@example.test', display_name: 'owner', role: 'tenant_admin', active: true },
		{ id: 't2', email: 'member@example.test', display_name: 'member', role: 'tenant_analyst', active: true },
		{ id: 't3', email: 'gone@example.test', display_name: 'gone', role: 'tenant_analyst', active: false }
	],
	target: { id: 't2', email: 'member@example.test', display_name: 'member', role: 'tenant_analyst', active: true },
	inactive: { id: 't3', email: 'gone@example.test', display_name: 'gone', role: 'tenant_analyst', active: false }
};

const TEMP = 'Tmp-OneTime-7Qx9zKp2';

async function mockSurface(page: Page, s: Surface, me = s.me) {
	const resets: string[] = [];
	await page.route('**/auth/me', (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me) })
	);
	await page.route(s.listGlob, (r) =>
		r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(s.users) })
	);
	await page.route(s.resetGlob, async (r) => {
		expect(r.request().method()).toBe('POST');
		const path = new URL(r.request().url()).pathname;
		resets.push(path);
		const id = path.split('/').at(-3) as string;
		await r.fulfill({
			status: 200,
			contentType: 'application/json',
			body: JSON.stringify({ user_id: id, temporary_password: TEMP, must_change: true })
		});
	});
	return resets;
}

function row(page: Page, email: string) {
	return page.locator('tr', { hasText: email });
}

async function passwordAnywhere(page: Page): Promise<boolean> {
	return page.evaluate(
		(pw) =>
			document.body.innerText.includes(pw) ||
			Array.from(document.querySelectorAll('input')).some((i) => i.value === pw),
		TEMP
	);
}

for (const s of [MSSP, TENANT]) {
	test.describe(`Password reset on ${s.name}`, () => {
		test('offered for other active users, never on your own row', async ({ page }) => {
			await mockSurface(page, s);
			await page.goto(s.path);
			await expect(row(page, s.target.email)).toBeVisible();

			await expect(row(page, s.target.email).getByRole('button', { name: 'Reset password' })).toBeVisible();
			await expect(row(page, String(s.me.email)).getByRole('button', { name: 'Reset password' })).toHaveCount(0);
			// A deactivated user cannot sign in; reactivate first.
			await expect(row(page, s.inactive.email).getByRole('button', { name: 'Reset password' })).toHaveCount(0);
		});

		test('confirm, then the one-time password is shown once and gone after closing', async ({ page }) => {
			const resets = await mockSurface(page, s);
			await page.goto(s.path);
			await row(page, s.target.email).getByRole('button', { name: 'Reset password' }).click();

			const dialog = page.getByRole('dialog');
			await expect(dialog).toBeVisible();
			await expect(dialog).toContainText(`Reset the password of ${s.target.email}?`);
			await expect(dialog).toContainText(
				"Generates a one-time password, revokes all of this user's active sessions, and forces them to change it at next login."
			);
			// Nothing happens until the admin confirms.
			expect(resets).toEqual([]);

			await dialog.getByRole('button', { name: 'Reset password' }).click();
			await expect(dialog).toContainText(`Temporary password for ${s.target.email}`);
			await expect(dialog.getByRole('textbox')).toHaveValue(TEMP);
			await expect(dialog.getByRole('button', { name: 'Copy and close' })).toBeVisible();
			expect(resets).toEqual([s.resetPath(s.target.id)]);

			await dialog.getByRole('button', { name: 'Close', exact: true }).click();
			await expect(page.getByRole('dialog')).toHaveCount(0);
			expect(await passwordAnywhere(page)).toBe(false);

			// Reopening starts over at the confirmation; the old password is not retrievable.
			await row(page, s.target.email).getByRole('button', { name: 'Reset password' }).click();
			await expect(page.getByRole('dialog')).toContainText(`Reset the password of ${s.target.email}?`);
			expect(await passwordAnywhere(page)).toBe(false);
			await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
			await expect(page.getByRole('dialog')).toHaveCount(0);
			expect(resets).toHaveLength(1);
		});

		test('copy and close puts the password on the clipboard and closes', async ({ page, context }) => {
			await context.grantPermissions(['clipboard-read', 'clipboard-write']);
			await mockSurface(page, s);
			await page.goto(s.path);
			await row(page, s.target.email).getByRole('button', { name: 'Reset password' }).click();
			const dialog = page.getByRole('dialog');
			await dialog.getByRole('button', { name: 'Reset password' }).click();
			await expect(dialog.getByRole('textbox')).toHaveValue(TEMP);

			await dialog.getByRole('button', { name: 'Copy and close' }).click();
			await expect(page.getByRole('dialog')).toHaveCount(0);
			expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(TEMP);
			expect(await passwordAnywhere(page)).toBe(false);
		});

		test('a failed reset keeps the dialog on the confirmation with the error', async ({ page }) => {
			await mockSurface(page, s);
			await page.unroute(s.resetGlob);
			await page.route(s.resetGlob, (r) =>
				r.fulfill({
					status: 409,
					contentType: 'application/json',
					body: JSON.stringify({ detail: 'user is deactivated; reactivate the user first' })
				})
			);
			await page.goto(s.path);
			await row(page, s.target.email).getByRole('button', { name: 'Reset password' }).click();
			const dialog = page.getByRole('dialog');
			await dialog.getByRole('button', { name: 'Reset password' }).click();
			await expect(dialog.getByRole('alert')).toContainText('reactivate the user first');
			await expect(dialog.getByRole('textbox')).toHaveCount(0);
			await expect(dialog.getByRole('button', { name: 'Reset password' })).toBeEnabled();
		});
	});
}

test('no reset action without the user-management permission', async ({ page }) => {
	await mockSurface(page, MSSP, {
		...MSSP.me,
		role: 'analyst',
		permissions: ['review_decide', 'use_chat']
	});
	await page.goto(MSSP.path);
	await expect(row(page, MSSP.target.email)).toBeVisible();
	await expect(page.getByRole('button', { name: 'Reset password' })).toHaveCount(0);
});

test('an mssp_admin is not offered a reset of a platform_admin', async ({ page }) => {
	const platform: Row = {
		id: 'u9',
		email: 'root@example.test',
		display_name: 'root',
		role: 'platform_admin',
		active: true
	};
	await mockSurface(page, { ...MSSP, users: [...MSSP.users, platform] });
	await page.goto(MSSP.path);
	await expect(row(page, platform.email)).toBeVisible();
	await expect(row(page, platform.email).getByRole('button', { name: 'Reset password' })).toHaveCount(0);
	await expect(row(page, MSSP.target.email).getByRole('button', { name: 'Reset password' })).toBeVisible();
});
