// Server-authoritative live clock (issue #72).
//
// The live head must never be the browser's clock: `sync()` captures the
// offset between the server's now() and performance.now(), and the store's
// value is derived from that offset. requestAnimationFrame only schedules
// repaints — a backgrounded tab recomputes correctly on return, no drift.

import { writable, type Readable } from 'svelte/store';

export interface ServerClock extends Readable<number> {
	/** Feed a server_now ISO timestamp from any API response. */
	sync: (serverNowIso: string) => void;
	start: () => void;
	stop: () => void;
	destroy: () => void;
}

export function createServerClock(): ServerClock {
	let offsetMs: number | null = null; // serverEpochMs - performance.now()
	let raf: number | null = null;
	const { subscribe, set } = writable<number>(0);

	const nowMs = () => (offsetMs === null ? 0 : offsetMs + performance.now());

	const frame = () => {
		set(nowMs());
		raf = requestAnimationFrame(frame);
	};

	const start = () => {
		if (raf !== null || typeof requestAnimationFrame === 'undefined') return;
		set(nowMs());
		raf = requestAnimationFrame(frame);
	};

	const stop = () => {
		if (raf !== null && typeof cancelAnimationFrame !== 'undefined') cancelAnimationFrame(raf);
		raf = null;
	};

	return {
		subscribe,
		sync: (serverNowIso: string) => {
			const parsed = Date.parse(serverNowIso);
			if (!Number.isNaN(parsed)) {
				offsetMs = parsed - performance.now();
				set(nowMs());
			}
		},
		start,
		stop,
		destroy: stop
	};
}
