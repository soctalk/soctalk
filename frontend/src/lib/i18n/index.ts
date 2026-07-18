// Locale/path boundary for URL-prefixed locales (#52).
//
// SvelteKit's `reroute` hook maps `/pt-br/investigations` onto the
// `/investigations` route but does NOT rewrite `page.url.pathname` or the
// address bar — so every path comparison and every `goto()`/href in the app
// must go through the helpers here. Precedence: explicit URL locale >
// cookie (unprefixed entry redirect only) > baseLocale.
//
// en-US is the unprefixed default: `/investigations` is English,
// `/pt-br/investigations` is Portuguese. `/en-us/...` is accepted and treated
// as English for symmetry (videos/docs can always use a prefix).
import { goto } from '$app/navigation';
import { baseLocale, cookieName, overwriteGetLocale, type Locale } from '$lib/paraglide/runtime';
import {
	localeFromPathname,
	segmentForLocale,
	stripLocale,
	SUPPORTED_LOCALES
} from './locales';

export * from './locales';

let current: Locale = baseLocale;

/** Resolve + activate the locale for a URL. Called from the root layout load
 *  BEFORE anything renders, so message functions never see a stale locale. */
export function initLocaleFromUrl(pathname: string): Locale {
	current = localeFromPathname(pathname) ?? baseLocale;
	overwriteGetLocale(() => current);
	if (typeof document !== 'undefined') document.documentElement.lang = current;
	return current;
}

export function currentLocale(): Locale {
	return current;
}

/** Prefix an app-internal path with the active (or given) locale.
 *  en-US stays unprefixed. External/api/hash hrefs pass through untouched. */
export function localizeHref(path: string, locale: Locale = current): string {
	if (!path.startsWith('/') || path.startsWith('/api/')) return path;
	const bare = stripLocale(path);
	if (locale === baseLocale) return bare;
	const seg = segmentForLocale(locale);
	if (!seg) return bare;
	return bare === '/' ? `/${seg}` : `/${seg}${bare}`;
}

/** `goto` that keeps the active locale prefix. Drop-in for `goto('/x')`. */
export function localizedGoto(
	path: string,
	opts?: Parameters<typeof goto>[1]
): ReturnType<typeof goto> {
	return goto(localizeHref(path), opts);
}

/** Persist the choice + hard-navigate to the same page under the new locale.
 *  A full document load (not goto) on purpose: messages are evaluated at
 *  render time, so a reload guarantees every surface re-renders localized. */
export function switchLocale(locale: Locale, pathname: string, search = ''): void {
	document.cookie = `${cookieName}=${locale}; path=/; max-age=34560000; samesite=lax`;
	window.location.href = localizeHref(stripLocale(pathname), locale) + search;
}

/** Cookie-driven redirect target for unprefixed entries, or null. */
export function cookieRedirect(pathname: string, search = ''): string | null {
	if (typeof document === 'undefined') return null;
	if (localeFromPathname(pathname)) return null; // explicit URL locale wins
	const m = document.cookie.match(new RegExp(`(?:^|; )${cookieName}=([^;]+)`));
	const loc = m?.[1] as Locale | undefined;
	if (!loc || loc === baseLocale || !SUPPORTED_LOCALES.includes(loc)) return null;
	return localizeHref(pathname, loc) + search;
}
