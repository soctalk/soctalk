import { expect, test } from '@playwright/test';
import { TOKEN } from '../playwright.config';

// Full pilot through the web UI ONLY: launch form → gate → live events →
// complete → access panel. Deploys a real MSSP + tenant on the qemu host.
const SSH_HOST = process.env.E2E_SSH_HOST ?? '';
const WORK_DIR = process.env.E2E_WORK_DIR ?? '';
const TAILNET = process.env.E2E_TAILNET ?? '';
const SSH_PUBKEY = process.env.E2E_SSH_PUBKEY ?? '';

test('web UI deploys qemu MSSP + tenant end-to-end', async ({ page }) => {
	test.skip(!SSH_HOST || !TAILNET || !SSH_PUBKEY || !WORK_DIR, 'E2E env not set');

	// --- launch screen ---
	await page.goto(`/?t=${TOKEN}`);
	await expect(page.getByTestId('wordmark')).toBeVisible();

	await page.getByTestId('ssh-host').fill(SSH_HOST);
	await page.getByTestId('work-dir').fill(WORK_DIR);
	await page.getByTestId('tailnet').fill(TAILNET);
	await page.getByTestId('ssh-pubkey').fill(SSH_PUBKEY);
	await expect(page.getByTestId('preview-ribbon')).toContainText(SSH_HOST);

	await page.getByTestId('launch').click();
	await expect(page).toHaveURL(/\/runs\/web-/, { timeout: 15_000 });

	// --- live run view ---
	await expect(page.getByTestId('run-status')).toBeVisible();
	await expect(page.getByTestId('event-feed')).toBeVisible();

	// Tailscale ACL gate opens after the MSSP VM is up (fresh VM: boot +
	// cloud-init + tailscale join — allow 20 minutes).
	await expect(page.getByTestId('gate-modal')).toBeVisible({ timeout: 20 * 60 * 1000 });
	await page.getByTestId('gate-confirm').click();
	await expect(page.getByTestId('gate-modal')).toBeHidden({ timeout: 30_000 });

	// --- completion (tenant VM + full SocTalk install + Wazuh operational) ---
	// The engine blocks completion until the tenant's Wazuh stack (manager,
	// indexer, dashboard) is Running; the readiness line lands in the feed.
	await expect(page.getByTestId('event-feed')).toContainText('wazuh operational', {
		timeout: 35 * 60 * 1000,
	});
	await expect(page.getByTestId('run-status')).toHaveAttribute('data-status', 'complete', {
		timeout: 5 * 60 * 1000,
	});

	// --- access panel assertions ---
	await expect(page.getByTestId('access-panel')).toBeVisible();
	await expect(page.getByTestId('mssp-url')).toHaveText(`https://lp-mssp.${TAILNET}/`);
	await expect(page.getByTestId('mssp-login')).toHaveText('admin@launchpad.demo');

	// Both VMs must have real tailnet IPs (CGNAT 100.64/10).
	await expect(page.getByTestId('vm-ip-mssp')).toHaveText(/^100\./);
	await expect(page.getByTestId('vm-ip-tenant-acme')).toHaveText(/^100\./);
});
