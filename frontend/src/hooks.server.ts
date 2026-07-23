import type { Handle } from '@sveltejs/kit';

// Server-side security headers. The UI ships via @sveltejs/adapter-node
// (a Node server, port 3000), so this handle runs on every response and
// is the right place to stamp them — the app set none before, leaving it
// clickjackable and without HSTS.
//
// Scope note: this is the safe, non-breaking set. A full resource CSP
// (script-src / style-src / connect-src) must be introduced via the
// SvelteKit `kit.csp` config so it can hash the inline bootstrap assets;
// setting a strict one by hand here would break the SPA. `frame-ancestors
// 'none'` gives clickjacking protection today without that machinery.
export const handle: Handle = async ({ event, resolve }) => {
	const response = await resolve(event);
	const h = response.headers;
	h.set('X-Content-Type-Options', 'nosniff');
	h.set('X-Frame-Options', 'DENY');
	h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
	h.set('Content-Security-Policy', "frame-ancestors 'none'");
	// HSTS: the app is served over TLS behind the ingress. Browsers ignore
	// this header on plain-HTTP dev origins, so it is safe to set always.
	h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
	return response;
};
