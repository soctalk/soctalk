// Sign-in redirects (docs/multi-tenant/internal-auth.md §8.4, §8.6, §8.7).
//
// - A 401 on a session the SPA knew it had means the session expired (idle or
//   absolute): send the browser to `/login?expired=1&next=<page>`.
// - A signed-out visit to a deep link goes to `/login?next=<page>`.
// - Sign-out goes to `/login?signed_out=1`.
// - After sign-in the login page returns to `next` when it is a same-origin
//   app path, otherwise to the landing route.
//
// `next` is always stored WITHOUT a locale prefix: the login URL carries the
// prefix, and the login page re-applies its own locale on the way back, so a
// language switch on the sign-in screen is honoured.
//
// No $app/* imports: the pure helpers are unit-tested under vitest.
import { get } from 'svelte/store';
import { authSession } from '$lib/stores';
import { segmentOf, stripLocale } from '$lib/i18n/locales';

// Throwaway base for resolving `next`. Anything that resolves to a different
// origin was not a same-origin path.
const NEXT_BASE = 'http://next.invalid';

/** A safe `next` value (locale-stripped path + query + hash), or null.
 *
 *  Accepts only a path starting with a single `/`. Rejects absolute URLs,
 *  protocol-relative `//host`, `javascript:` and similar, and `/login` itself
 *  (which would strand the user on the form). Resolving against a fixed origin
 *  also catches the forms browsers normalise into another host: a backslash
 *  read as a slash (`/\host`) and tabs or newlines dropped from the URL
 *  (`/<TAB>/host`). */
export function safeNextPath(raw: string | null | undefined): string | null {
	if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) return null;
	let url: URL;
	try {
		url = new URL(raw, NEXT_BASE);
	} catch {
		return null;
	}
	if (url.origin !== NEXT_BASE) return null;
	const path = stripLocale(url.pathname);
	if (path === '/login' || path.startsWith('/login/')) return null;
	return path + url.search + url.hash;
}

/** `/login` with the requested notice and return path. Not localized: pass it
 *  through `localizedGoto`/`localizeHref`. A `next` of `/` is dropped because
 *  it is the default anyway. */
export function loginPath(
	opts: { next?: string | null; expired?: boolean; signedOut?: boolean } = {}
): string {
	const params = new URLSearchParams();
	if (opts.expired) params.set('expired', '1');
	if (opts.signedOut) params.set('signed_out', '1');
	const next = safeNextPath(opts.next);
	if (next && next !== '/') params.set('next', next);
	const qs = params.toString();
	return qs ? `/login?${qs}` : '/login';
}

/** The page the browser is on, as a `next` value. */
export function currentNextPath(): string | null {
	if (typeof window === 'undefined') return null;
	const { pathname, search, hash } = window.location;
	return safeNextPath(stripLocale(pathname) + search + hash);
}

// One redirect per page: when several requests fail together only the first
// navigates. The page is replaced, so this never needs resetting.
let redirecting = false;

// Loop guard across page loads: if a session that /auth/me reports as valid
// keeps answering 401 elsewhere, the login page would forward the user back
// and the next 401 would send them to sign-in again, forever. A second expiry
// redirect this soon after the last one leaves the error on the page instead.
const LAST_REDIRECT_KEY = 'soctalk.sessionExpiredAt';
const LOOP_WINDOW_MS = 10_000;

function recentlyRedirected(): boolean {
	try {
		const last = Number(sessionStorage.getItem(LAST_REDIRECT_KEY));
		return Number.isFinite(last) && Date.now() - last < LOOP_WINDOW_MS;
	} catch {
		return false;
	}
}

function noteRedirect(): void {
	try {
		sessionStorage.setItem(LAST_REDIRECT_KEY, String(Date.now()));
	} catch {
		/* storage unavailable: the in-page guard still applies */
	}
}

/** Handle a 401 from an API call. Returns true when the browser is being sent
 *  to sign-in; the caller should then not surface the failure on the page.
 *
 *  Does nothing unless the SPA holds a signed-in identity: before the session
 *  check settles, or once signed out, a 401 is the ordinary signed-out state
 *  and the root layout routes it to `/login` (without `expired=1`). Never
 *  redirects from the login page. Callers must not route the auth endpoints'
 *  own 401s here (`/auth/me`, `/auth/login`, `/auth/logout`). */
export function handleUnauthorized(): boolean {
	if (typeof window === 'undefined') return false;
	if (redirecting) return true;
	if (!get(authSession).user) return false;
	const { pathname } = window.location;
	if (stripLocale(pathname) === '/login') return false;
	if (recentlyRedirected()) return false;

	redirecting = true;
	noteRedirect();
	// Keep the locale prefix the user is browsing under.
	const seg = segmentOf(pathname);
	const target = loginPath({ expired: true, next: currentNextPath() });
	// A full load, not goto(): it drops every store and cached response that
	// belonged to the expired session before someone else may sign in here.
	window.location.assign(seg ? `/${seg}${target}` : target);
	return true;
}

/** Stand-in result for a request whose 401 is being handled by a redirect:
 *  it never settles, so the page keeps its loading state until it is replaced
 *  instead of flashing "not authenticated". */
export function pendingForever<T>(): Promise<T> {
	return new Promise<T>(() => {});
}
