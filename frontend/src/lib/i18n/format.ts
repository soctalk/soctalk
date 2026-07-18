// Intl formatters bound to the ACTIVE locale (#52) — not the browser locale.
// Bare `x.toLocaleString()` follows the runner/browser language, so a
// recording of /zh-cn on an English machine would still show English dates.
// Screens should adopt these instead of calling toLocale* directly; the sweep
// of existing call sites is tracked under #52's remaining-screens extraction.
import { currentLocale } from './index';

export function formatDate(d: Date | string | number): string {
	return new Date(d).toLocaleDateString(currentLocale());
}

export function formatDateTime(d: Date | string | number): string {
	return new Date(d).toLocaleString(currentLocale());
}

export function formatTime(d: Date | string | number): string {
	return new Date(d).toLocaleTimeString(currentLocale());
}

export function formatNumber(n: number, opts?: Intl.NumberFormatOptions): string {
	return new Intl.NumberFormat(currentLocale(), opts).format(n);
}

export function formatList(items: string[]): string {
	try {
		return new Intl.ListFormat(currentLocale(), { type: 'conjunction' }).format(items);
	} catch {
		return items.join(', ');
	}
}
