import { test, expect, type Page } from '@playwright/test';

// Session expiry and return-to-page (docs/multi-tenant/internal-auth.md §8.4,
// §8.6, §8.7). Sessions expire server-side (idle or absolute); from then on
// the API answers 401. The SPA used to stay put and render "not
// authenticated" on every page, always landed on / after signing in, and
// signed out without saying so.

const USER = {
	user_id: '00000000-0000-0000-0000-0000000000a1',
	email: 'analyst@example.test',
	user_type: 'mssp',
	role: 'mssp_analyst',
	tenant_id: null,
	current_tenant: null,
	current_tenant_slug: null,
	permissions: ['view_investigations', 'view_dashboard', 'view_analytics', 'view_audit']
};

const EMPTY_LIST = { items: [], total: 0, page: 1, page_size: 20, has_more: false };

interface FakeBackend {
	/** Whether the browser's session cookie is still valid. */
	signedIn: boolean;
	/** Sign-ins answer must_change=true. */
	mustChange: boolean;
	/** Sign-ins answer 401 (wrong password). */
	wrongPassword: boolean;
}

/** One route for every /api call, answering like the real API would for the
 *  current session state. Filtering on the pathname (not a `**\/api/**` glob)
 *  keeps vite's own /src/lib/api/* module requests untouched. */
async function fakeBackend(page: Page, initial: Partial<FakeBackend> = {}): Promise<FakeBackend> {
	const state: FakeBackend = { signedIn: false, mustChange: false, wrongPassword: false, ...initial };
	await page.route(
		(url) => url.pathname.startsWith('/api/'),
		async (route) => {
			const { pathname } = new URL(route.request().url());
			const json = (status: number, body: unknown) =>
				route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

			if (pathname === '/api/auth/login') {
				if (state.wrongPassword) return json(401, { detail: 'Invalid credentials.' });
				state.signedIn = true;
				return json(200, { user: USER, must_change: state.mustChange });
			}
			if (pathname === '/api/auth/logout') {
				state.signedIn = false;
				return json(200, { success: true });
			}
			if (!state.signedIn) {
				return json(401, {
					detail: pathname === '/api/auth/me' ? 'Not authenticated.' : 'authentication required'
				});
			}
			if (pathname === '/api/auth/me') return json(200, USER);
			if (pathname === '/api/events/stream') return route.fulfill({ status: 204 });
			if (pathname === '/api/investigations') return json(200, EMPTY_LIST);
			return json(404, { detail: 'not mocked' });
		}
	);
	return state;
}

/** Full document loads of the sign-in page (one per redirect). */
function countLoginLoads(page: Page): string[] {
	const loads: string[] = [];
	page.on('request', (r) => {
		if (r.resourceType() === 'document' && /\/login$/.test(new URL(r.url()).pathname)) {
			loads.push(r.url());
		}
	});
	return loads;
}

async function signIn(
	page: Page,
	labels = { email: 'Email', password: 'Password', submit: 'Sign in' }
) {
	await page.getByLabel(labels.email).fill('analyst@example.test');
	await page.getByLabel(labels.password).fill('a-password-for-tests');
	await page.getByRole('button', { name: labels.submit }).click();
}

function params(page: Page): URLSearchParams {
	return new URL(page.url()).searchParams;
}

async function openInvestigations(page: Page, path = '/investigations') {
	await page.goto(path);
	// The list rendered: the session was valid when the page loaded.
	await expect(page.locator('table')).toBeVisible();
}

test.describe('Session expiry', () => {
	test('a 401 on a signed-in page sends the user to sign-in, then back', async ({ page }) => {
		const api = await fakeBackend(page, { signedIn: true });
		await openInvestigations(page);
		const loginLoads = countLoginLoads(page);

		api.signedIn = false; // the session expires server-side
		await page.getByRole('link', { name: 'Audit Log' }).click();

		await expect(page).toHaveURL(/\/login\?/);
		expect(params(page).get('expired')).toBe('1');
		expect(params(page).get('next')).toBe('/audit');
		const notice = page.getByTestId('login-notice');
		await expect(notice).toHaveText('Your session expired. Please sign in again.');
		// Informational, not a sign-in failure.
		await expect(notice).toHaveAttribute('role', 'status');
		await expect(page.getByRole('alert')).toHaveCount(0);
		await expect(page.getByText('authentication required')).toHaveCount(0);
		expect(loginLoads).toHaveLength(1);

		await signIn(page);
		await expect(page).toHaveURL((url) => url.pathname === '/audit');
	});

	test('several requests failing at once redirect only once', async ({ page }) => {
		const api = await fakeBackend(page, { signedIn: true });
		await openInvestigations(page);
		const loginLoads = countLoginLoads(page);

		api.signedIn = false;
		// The dashboard fires several API calls in parallel; all of them 401.
		await page.getByRole('link', { name: 'Dashboard' }).click();

		await expect(page.getByTestId('login-notice')).toHaveText(
			'Your session expired. Please sign in again.'
		);
		expect(params(page).get('expired')).toBe('1');
		// next=/ is the default landing route anyway.
		expect(params(page).get('next')).toBeNull();
		await page.waitForLoadState('networkidle');
		expect(loginLoads).toHaveLength(1);
	});

	test('the locale prefix survives the round trip', async ({ page }) => {
		const api = await fakeBackend(page, { signedIn: true });
		await openInvestigations(page, '/pt-br/investigations');

		api.signedIn = false;
		// Any in-page data call: change the status filter.
		await page.locator('select').first().selectOption('pending');

		await expect(page).toHaveURL(/\/pt-br\/login\?/);
		expect(params(page).get('expired')).toBe('1');
		expect(params(page).get('next')).toBe('/investigations');
		await expect(page.getByTestId('login-notice')).toHaveText(
			'Sua sessão expirou. Entre novamente.'
		);

		await signIn(page, { email: 'E-mail', password: 'Senha', submit: 'Entrar' });
		await expect(page).toHaveURL((url) => url.pathname === '/pt-br/investigations');
	});

	test('a wrong password after expiry shows the inline error and stays put', async ({ page }) => {
		const api = await fakeBackend(page, { signedIn: true });
		await openInvestigations(page);
		const loginLoads = countLoginLoads(page);
		api.signedIn = false;
		await page.getByRole('link', { name: 'Audit Log' }).click();
		await expect(page.getByTestId('login-notice')).toBeVisible();
		const expiredUrl = page.url();

		api.wrongPassword = true;
		await signIn(page);

		const alert = page.getByRole('alert');
		await expect(alert).toContainText('Invalid credentials.');
		// The expiry notice gives way to the error instead of sitting next to it.
		await expect(page.getByTestId('login-notice')).toHaveCount(0);
		expect(page.url()).toBe(expiredUrl);
		expect(loginLoads).toHaveLength(1);

		// The next attempt still goes back to the page the user was on.
		api.wrongPassword = false;
		await page.getByRole('button', { name: 'Sign in' }).click();
		await expect(page).toHaveURL((url) => url.pathname === '/audit');
	});
});

test.describe('Deep links while signed out', () => {
	test('sign-in returns to the requested page, without an expiry notice', async ({ page }) => {
		await fakeBackend(page, { signedIn: false });
		await page.goto('/investigations?status=pending');

		await expect(page).toHaveURL(/\/login\?/);
		expect(params(page).get('next')).toBe('/investigations?status=pending');
		expect(params(page).get('expired')).toBeNull();
		await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
		await expect(page.getByTestId('login-notice')).toHaveCount(0);

		await signIn(page);
		await expect(page).toHaveURL(
			(url) => url.pathname === '/investigations' && url.search === '?status=pending'
		);
	});

	test('must_change sign-in goes to the password page, not to next', async ({ page }) => {
		await fakeBackend(page, { signedIn: false, mustChange: true });
		await page.goto('/investigations');
		await expect(page).toHaveURL(/\/login\?/);
		expect(params(page).get('next')).toBe('/investigations');

		await signIn(page);
		await expect(page).toHaveURL(
			(url) => url.pathname === '/account/password' && url.search === '?must_change=1'
		);
	});
});

test.describe('Hostile next values are ignored', () => {
	for (const hostile of ['//evil.example', 'https://evil.example', '/\\evil.example']) {
		test(`next=${hostile}`, async ({ page, baseURL }) => {
			await page.route(
				(url) => url.hostname === 'evil.example',
				(route) => route.abort()
			);
			await fakeBackend(page, { signedIn: false });
			await page.goto(`/login?expired=1&next=${encodeURIComponent(hostile)}`);
			await expect(page.getByTestId('login-notice')).toBeVisible();

			await signIn(page);
			await expect(page).toHaveURL(
				(url) => url.origin === new URL(baseURL!).origin && url.pathname === '/'
			);
		});
	}
});

test.describe('Sign out', () => {
	test('lands on sign-in with a signed-out notice', async ({ page }) => {
		await fakeBackend(page, { signedIn: true });
		await openInvestigations(page);

		await page.getByRole('button', { name: 'Log out' }).click();

		await expect(page).toHaveURL(/\/login\?/);
		expect(params(page).get('signed_out')).toBe('1');
		expect(params(page).get('expired')).toBeNull();
		const notice = page.getByTestId('login-notice');
		await expect(notice).toHaveText('You have been signed out.');
		await expect(page.getByRole('alert')).toHaveCount(0);

		// Signing back in from here goes to the landing route.
		await signIn(page);
		await expect(page).toHaveURL((url) => url.pathname === '/');
	});
});
