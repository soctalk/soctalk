import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Dev-server proxy to a FastAPI backend OR a remote ingress.
//
// Default ``API_URL=http://127.0.0.1:8000`` matches the local
// ``uvicorn`` workflow. To iterate against a *cluster* L1 install
// (skipping the docker-build cycle), set:
//
//     API_URL=http://192.168.1.28 API_HOST=demo2.soctalk.ai pnpm dev
//
// ``API_URL`` points at the cluster ingress, and ``API_HOST`` is the
// virtual hostname the ingress routes by. The proxy rewrites the
// outgoing Host header to that value so Traefik's host-rule matches
// the right release. ``changeOrigin: true`` only rewrites the host
// to match the *URL's* host, so without ``API_HOST`` we'd hit the
// ingress with ``Host: 192.168.1.28`` and the L1 install rejects it
// (no host rule matches).
const apiUrl = process.env.API_URL || 'http://127.0.0.1:8000';
const apiHost = process.env.API_HOST;

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		proxy: {
			'/api': {
				target: apiUrl,
				changeOrigin: true,
				configure: apiHost
					? (proxy) => {
							proxy.on('proxyReq', (proxyReq) => {
								proxyReq.setHeader('host', apiHost);
								// Origin matters for CSRF on the L1 — set it
								// to the ingress hostname too so the API's
								// origin check sees a value matching its
								// configured allow-list (the slug-driven
								// landing on the cluster expects this).
								proxyReq.setHeader('origin', `http://${apiHost}`);
							});
					  }
					: undefined
			}
		}
	}
});
