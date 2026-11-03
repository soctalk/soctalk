import { test, expect, type Page } from '@playwright/test';

// A failed sign-in must be visible on the sign-in screen. The login page
// used to report failures only through a toast, and the toast container is
// mounted inside the app shell, which /login does not render: a wrong
// password produced no feedback at all.

async function mockSignedOut(page: Page) {
	await page.route('**/auth/me', (route) =>
		route.fulfill({
			status: 401,
			contentType: 'application/json',
			body: JSON.stringify({ detail: 'Not authenticated.' })
		})
	);
}

async function mockLogin(page: Page, status: number, detail: unknown) {
	await page.route('**/auth/login', (route) =>
		route.fulfill({
			status,
			contentType: 'application/json',
			body: JSON.stringify({ detail })
		})
	);
}

async function signIn(page: Page) {
	await page.goto('/login');
	await page.getByLabel('Email').fill('analyst@example.test');
	await page.getByLabel('Password').fill('wrong-password');
	await page.getByRole('button', { name: 'Sign in' }).click();
}

test.describe('Sign-in errors', () => {
	test('wrong credentials show an error on the sign-in screen', async ({ page }) => {
		await mockSignedOut(page);
		await mockLogin(page, 401, 'Invalid credentials.');
		await signIn(page);

		const alert = page.getByRole('alert');
		await expect(alert).toBeVisible();
		await expect(alert).toContainText('Invalid credentials.');
		// It stays until the next attempt instead of timing out like a toast.
		await page.waitForTimeout(6000);
		await expect(alert).toBeVisible();
		await expect(page).toHaveURL(/\/login/);
	});

	test('the error clears when the user tries again', async ({ page }) => {
		await mockSignedOut(page);
		await mockLogin(page, 401, 'Invalid credentials.');
		await signIn(page);
		await expect(page.getByRole('alert')).toBeVisible();

		// Hold the second attempt open: the old error must be gone meanwhile.
		await page.unroute('**/auth/login');
		let release: () => void = () => {};
		const held = new Promise<void>((r) => (release = r));
		await page.route('**/auth/login', async (route) => {
			await held;
			await route.fulfill({
				status: 401,
				contentType: 'application/json',
				body: JSON.stringify({ detail: 'Invalid credentials.' })
			});
		});
		await page.getByRole('button', { name: 'Sign in' }).click();
		await expect(page.getByRole('alert')).toHaveCount(0);
		release();
		await expect(page.getByRole('alert')).toBeVisible();
	});

	test('rate limiting is explained', async ({ page }) => {
		await mockSignedOut(page);
		await mockLogin(page, 429, 'Too many attempts. Try again later.');
		await signIn(page);
		await expect(page.getByRole('alert')).toContainText('Too many sign-in attempts');
	});

	test('a locked account says until when, not raw JSON', async ({ page }) => {
		await mockSignedOut(page);
		await mockLogin(page, 423, { reason: 'locked', locked_until: '2030-01-02T03:04:05+00:00' });
		await signIn(page);

		const alert = page.getByRole('alert');
		await expect(alert).toContainText('locked');
		await expect(alert).toContainText('2030');
		await expect(alert).not.toContainText('{');
	});

	test('an unreachable API is reported, not swallowed', async ({ page }) => {
		await mockSignedOut(page);
		await page.route('**/auth/login', (route) =>
			route.fulfill({ status: 502, contentType: 'text/plain', body: 'Bad Gateway' })
		);
		await signIn(page);
		await expect(page.getByRole('alert')).toContainText('Bad Gateway');
	});
});
