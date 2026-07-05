import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// SPA mode: the Go binary is the server; unknown paths fall back to
		// index.html so /runs/[id] survives a hard refresh.
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: 'index.html',
			precompress: false,
		}),
		alias: {
			$lib: './src/lib',
		},
	},
};

export default config;
