// Pure SPA: no prerender, no SSR. The canonical UI now ships via
// adapter-node so server runtime exists, but every page mounts data
// from /api at runtime — there's nothing meaningful to prerender, and
// dynamic routes like /investigations/[id] would error during the
// crawl. Rendering happens entirely client-side.
import { redirect } from '@sveltejs/kit';
import { cookieRedirect, initLocaleFromUrl } from '$lib/i18n';

export const prerender = false;
export const ssr = false;

// i18n (#52): activate the URL's locale before anything renders, and honor a
// previously chosen locale (cookie) when the user lands on an unprefixed URL.
// Explicit URL locale always wins; en-US stays unprefixed.
export const load = ({ url }: { url: URL }) => {
	const target = cookieRedirect(url.pathname, url.search);
	if (target) redirect(307, target);
	const locale = initLocaleFromUrl(url.pathname);
	return { locale };
};
