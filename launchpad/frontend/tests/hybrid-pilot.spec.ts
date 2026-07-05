import { expect, test } from '@playwright/test';
import { TOKEN } from '../playwright.config';

// Hybrid pilot through the web UI: MSSP on qemu (NUC) + tenant on VMware ESXi.
// Exercises per-VM target routing end-to-end from the browser. Needs both the
// qemu and the ESXi env vars set.
const SSH_HOST = process.env.E2E_SSH_HOST ?? '';
const WORK_DIR = process.env.E2E_WORK_DIR ?? '';
const ESXI_URL = process.env.E2E_ESXI_URL ?? '';
const DATASTORE = process.env.E2E_ESXI_DATASTORE ?? 'datastore1';
const NETWORK = process.env.E2E_ESXI_NETWORK ?? 'VM Network';
const TAILNET = process.env.E2E_TAILNET ?? '';
const SSH_PUBKEY = process.env.E2E_SSH_PUBKEY ?? '';

test('web UI deploys hybrid qemu MSSP + vmware tenant end-to-end', async ({ page }) => {
	test.skip(
		!SSH_HOST || !WORK_DIR || !ESXI_URL || !TAILNET || !SSH_PUBKEY,
		'E2E hybrid env not set',
	);

	// --- launch screen, hybrid preset (shows both qemu + vmware field groups) ---
	await page.goto(`/?t=${TOKEN}`);
	await page.getByTestId('preset-hybrid').click();
	await page.getByTestId('ssh-host').fill(SSH_HOST); // MSSP on qemu
	await page.getByTestId('work-dir').fill(WORK_DIR);
	await page.getByTestId('esxi-url').fill(ESXI_URL); // tenant on ESXi
	await page.getByTestId('datastore').fill(DATASTORE);
	await page.getByTestId('network').fill(NETWORK);
	await page.getByTestId('tailnet').fill(TAILNET);
	await page.getByTestId('ssh-pubkey').fill(SSH_PUBKEY);
	await expect(page.getByTestId('preview-ribbon')).toContainText('MSSP qemu');
	await expect(page.getByTestId('preview-ribbon')).toContainText('tenant ESXi');

	await page.getByTestId('launch').click();
	await expect(page).toHaveURL(/\/runs\/web-/, { timeout: 15_000 });

	// --- gate after MSSP (qemu, fast) is up on the tailnet ---
	await expect(page.getByTestId('gate-modal')).toBeVisible({ timeout: 20 * 60 * 1000 });
	await page.getByTestId('gate-confirm').click();
	await expect(page.getByTestId('gate-modal')).toBeHidden({ timeout: 30_000 });

	// --- completion requires the tenant (VMware) Wazuh stack Running ---
	await expect(page.getByTestId('event-feed')).toContainText('wazuh operational', {
		timeout: 40 * 60 * 1000,
	});
	await expect(page.getByTestId('run-status')).toHaveAttribute('data-status', 'complete', {
		timeout: 5 * 60 * 1000,
	});

	// --- access panel ---
	await expect(page.getByTestId('access-panel')).toBeVisible();
	await expect(page.getByTestId('mssp-url')).toHaveText(`https://lp-mssp.${TAILNET}/`);
	await expect(page.getByTestId('vm-ip-mssp')).toHaveText(/^100\./);
	await expect(page.getByTestId('vm-ip-tenant-acme')).toHaveText(/^100\./);
});
