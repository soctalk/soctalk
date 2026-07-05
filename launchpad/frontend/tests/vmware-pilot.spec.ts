import { expect, test } from '@playwright/test';
import { TOKEN } from '../playwright.config';

// VMware-only pilot through the web UI: MSSP AND tenant both on a standalone
// ESXi host. Same flow as the qemu spec, driven via the vmware preset card.
// Extra env (on top of the shared ones):
//   E2E_ESXI_URL        e.g. https://localhost:4433 (SSH tunnel to ESXi)
//   E2E_ESXI_DATASTORE  e.g. datastore1
//   E2E_ESXI_NETWORK    e.g. VM Network
const ESXI_URL = process.env.E2E_ESXI_URL ?? '';
const DATASTORE = process.env.E2E_ESXI_DATASTORE ?? 'datastore1';
const NETWORK = process.env.E2E_ESXI_NETWORK ?? 'VM Network';
const TAILNET = process.env.E2E_TAILNET ?? '';
const SSH_PUBKEY = process.env.E2E_SSH_PUBKEY ?? '';

test('web UI deploys vmware MSSP + tenant end-to-end', async ({ page }) => {
	test.skip(!ESXI_URL || !TAILNET || !SSH_PUBKEY, 'E2E ESXi env not set');

	// --- launch screen, vmware preset ---
	await page.goto(`/?t=${TOKEN}`);
	await page.getByTestId('preset-vmware').click();
	await page.getByTestId('esxi-url').fill(ESXI_URL);
	await page.getByTestId('datastore').fill(DATASTORE);
	await page.getByTestId('network').fill(NETWORK);
	await page.getByTestId('tailnet').fill(TAILNET);
	await page.getByTestId('ssh-pubkey').fill(SSH_PUBKEY);
	await expect(page.getByTestId('preview-ribbon')).toContainText('ESXi');

	await page.getByTestId('launch').click();
	await expect(page).toHaveURL(/\/runs\/web-/, { timeout: 15_000 });

	// --- gate after MSSP import + boot + tailnet join (OVA import is the
	// slow part on ESXi: download + upload through the tunnel) ---
	await expect(page.getByTestId('gate-modal')).toBeVisible({ timeout: 25 * 60 * 1000 });
	await page.getByTestId('gate-confirm').click();
	await expect(page.getByTestId('gate-modal')).toBeHidden({ timeout: 30_000 });

	// --- completion requires the tenant Wazuh stack Running (engine gate) ---
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
