import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// adapter-node so the canonical UI ships as a Node server
		// container, matching the chart's existing UI deployment shape
		// (port 3000, ``node build``). Was adapter-static; switched to
		// node so /api requests proxy through SvelteKit hooks rather
		// than needing a separate nginx in front.
		adapter: adapter({ out: 'build' }),
		alias: {
			$lib: './src/lib',
			$components: './src/lib/components',
			$stores: './src/lib/stores',
			$api: './src/lib/api'
		}
	}
};

export default config;
