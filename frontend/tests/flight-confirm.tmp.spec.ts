// Throwaway confirmation capture (#72): real backend, real triage data,
// stills of the fleet live head and a per-alert replay. Not part of the suite.
import { test, expect, type Page } from '@playwright/test';

const OUT = process.env.OUT ?? 'test-results/demo';
const ORIGIN = 'http://localhost:5173';

test.use({ viewport: { width: 1440, height: 960 } });
test.describe.configure({ mode: 'serial' });

async function login(page: Page) {
	await page.goto('/login');
	await page.locator('input[type=email]').fill('e2e-admin@acme.example');
	await page.locator('input[type=password]').fill('e2e-admin-pw-12345');
	await page.getByRole('button', { name: 'Sign in' }).click();
	await expect(page.getByText('e2e-admin@acme.example')).toBeVisible({ timeout: 15000 });
	const resp = await page.request.post('/api/auth/assume-tenant', {
		headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
		data: { slug: 'acme' }
	});
	expect(resp.ok()).toBeTruthy();
}

test('capture: fleet live head on real data', async ({ page }) => {
	await page.addInitScript(() => {
		sessionStorage.setItem(`soctalk-fleet-catchup-${new Date().toISOString().slice(0, 10)}`, '1');
	});
	await login(page);
	await page.goto('/');
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible({ timeout: 15000 });
	await page.waitForTimeout(1200);
	await page.getByTestId('fleet-panel').screenshot({ path: `${OUT}/confirm-fleet-live.png` });
});

test('capture: real triage replay per alert', async ({ page }) => {
	await login(page);
	const list = await (
		await page.request.get('/api/investigations?page_size=50', { headers: { Origin: ORIGIN } })
	).json();
	const inv =
		list.items.find((i: { title?: string | null }) => i.title?.includes('brute force')) ??
		list.items[0];
	await page.goto(`/investigations/${inv.id}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 20000 });
	const scrubber = page.getByTestId('replay-transport').locator('input[type="range"]');
	await scrubber.evaluate((el) => {
		const input = el as HTMLInputElement;
		input.value = input.max;
		input.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.waitForTimeout(900);
	await page.screenshot({ path: `${OUT}/confirm-replay.png` });
});
