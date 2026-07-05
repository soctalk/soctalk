import { defineConfig } from '@playwright/test';

// The E2E drives the REAL launchpad binary (embedded SPA) against real
// infrastructure. Required env:
//   TAILSCALE_API_KEY      tailnet API key (server-side only, never in UI)
//   LAUNCHPAD_PLUGIN_DIR   plugin search dir
//   E2E_SSH_HOST           qemu host, e.g. user@100.x.y.z
//   E2E_WORK_DIR           VM work dir on that host
//   E2E_TAILNET            tailnet name, e.g. tailxxxx.ts.net
//   E2E_SSH_PUBKEY         SSH public key authorized on the VMs
const TOKEN = 'e2e-playwright-token';

export default defineConfig({
	testDir: './tests',
	timeout: 60 * 60 * 1000, // full pilot: VM boots + k3s + helm installs
	expect: { timeout: 30_000 },
	retries: 0,
	workers: 1,
	reporter: [['list']],
	use: {
		baseURL: `http://127.0.0.1:8899`,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
	},
	webServer: {
		command: `../cli/bin/launchpad ui --port 8899 --no-open --token ${TOKEN}`,
		url: 'http://127.0.0.1:8899/',
		reuseExistingServer: false,
		timeout: 15_000,
		env: {
			TAILSCALE_API_KEY: process.env.TAILSCALE_API_KEY ?? '',
			LAUNCHPAD_PLUGIN_DIR: process.env.LAUNCHPAD_PLUGIN_DIR ?? '',
			ESXI_USERNAME: process.env.ESXI_USERNAME ?? '',
			ESXI_PASSWORD: process.env.ESXI_PASSWORD ?? '',
			HOME: process.env.HOME ?? '',
			PATH: process.env.PATH ?? '',
			SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK ?? '',
		},
	},
});

export { TOKEN };
