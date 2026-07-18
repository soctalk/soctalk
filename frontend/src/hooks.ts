// Universal reroute (#52): resolve `/pt-br/investigations` to the
// `/investigations` route. IMPORTANT: reroute changes route RESOLUTION only —
// `page.url.pathname` and the address bar keep the locale prefix, which is why
// all path comparisons go through stripLocale() and all links/gotos through
// localizeHref()/localizedGoto() (src/lib/i18n).
import type { Reroute } from '@sveltejs/kit';
import { localeFromPathname, stripLocale } from '$lib/i18n/locales';

export const reroute: Reroute = ({ url }) => {
	if (localeFromPathname(url.pathname)) return stripLocale(url.pathname);
};
