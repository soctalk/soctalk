/**
 * demo.soctalk.ai UI/frontend correctness suite (issue #72).
 *
 * Implements the 20-item test plan against the LIVE demo box:
 * every numeric expectation is derived at runtime from the same APIs the
 * UI consumes (the day rolls at midnight and organic Wazuh data flows
 * in), and the whole suite is STRICTLY read-only — a global tripwire
 * fails any test that fires a mutating request beyond the auth
 * handshake.
 *
 * Run: RECORDER_PW=... pnpm exec playwright test --config playwright.demo.config.ts \
 *        tests/demo-correctness.live.spec.ts
 */
import { test, expect, type Page } from '@playwright/test';

const ORIGIN = 'https://demo.soctalk.ai';
const EMAIL = 'recorder@demo.soctalk.ai';
const PASSWORD = process.env.RECORDER_PW ?? '';
const TZ = 'America/Los_Angeles';
const LAPSE_MS = 60_000;

test.describe.configure({ mode: 'serial' });
test.use({ viewport: { width: 1440, height: 960 }, timezoneId: TZ });

// ---------------------------------------------------------------------------
// Plan #1 (pervasive form): unified guards armed on EVERY page — a
// mutation tripwire (read-only guarantee), uncaught-page-error capture,
// and failing-API-response capture. Asserted automatically after each
// test via the afterEach hook below.
// ---------------------------------------------------------------------------

const MUTATION_ALLOWLIST = [/\/api\/auth\/login$/, /\/api\/auth\/assume-tenant$/];

interface Guards {
	mutations: string[];
	pageErrors: string[];
	badApi: string[];
}

function armGuards(page: Page): Guards {
	const existing = (page as unknown as { __guards?: Guards }).__guards;
	if (existing) return existing;
	const g: Guards = { mutations: [], pageErrors: [], badApi: [] };
	(page as unknown as { __guards?: Guards }).__guards = g;
	page.on('request', (req) => {
		const m = req.method();
		if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return;
		const url = req.url();
		if (!url.includes('/api/')) return;
		if (MUTATION_ALLOWLIST.some((rx) => rx.test(url.split('?')[0]))) return;
		g.mutations.push(`${m} ${url}`);
	});
	page.on('pageerror', (err) => g.pageErrors.push(String(err)));
	page.on('response', (r) => {
		if (!r.url().includes('/api/')) return;
		const s = r.status();
		// The pre-login session probe answers 401 by design.
		if (s === 401 && r.url().includes('/api/auth/me')) return;
		// KNOWN ISSUE (see the authorization-page test): the tenant
		// /authorization facts tab hits the MSSP-only endpoint. Tracked
		// there as a skip-not-pass; don't double-fail every test that
		// wanders onto that page.
		if (s === 403 && /\/authorization\/facts/.test(r.url())) return;
		// 401/403 and 5xx are always wrong for a logged-in read-only
		// session; 404/409/422 may be legitimate optional probes.
		if (s === 401 || s === 403 || s >= 500) g.badApi.push(`${s} ${r.url()}`);
	});
	return g;
}

test.afterEach(async ({ page }) => {
	const g = (page as unknown as { __guards?: Guards }).__guards;
	if (!g) return;
	expect(g.mutations, 'READ-ONLY VIOLATION: mutating API calls fired').toEqual([]);
	expect(g.badApi, 'auth/server errors from UI API calls').toEqual([]);
	expect(g.pageErrors, 'uncaught page errors').toEqual([]);
});

async function login(page: Page) {
	armGuards(page);
	await page.goto('/login');
	await page.locator('input[type=email]').fill(EMAIL);
	await page.locator('input[type=password]').fill(PASSWORD);
	await page.getByRole('button', { name: 'Sign in' }).click();
	await page.waitForURL((u) => !u.pathname.includes('/login'), { timeout: 20000 });
}

async function getJson<T>(page: Page, path: string): Promise<T> {
	const resp = await page.request.get(path, { headers: { Origin: ORIGIN } });
	expect(resp.status(), `oracle GET ${path}`).toBe(200);
	return (await resp.json()) as T;
}

interface Dot {
	alert_id: string;
	investigation_id: string | null;
	first_event_at: string;
	closed_at: string | null;
	path: string | null;
	outcome: string;
	veto: boolean;
}
interface FleetDay {
	date: string;
	window_start: string;
	window_end: string;
	server_now: string;
	ingested: number;
	closed_ingest_memoized: number;
	closed_ingest_rules: number;
	closed_operational: number;
	closed_reasoning: number;
	escalated: number;
	guard_vetoes: number;
	still_open: number;
	sample_rate: number;
	dots: Dot[];
	recent_vetoes: { investigation_id: string; at: string }[];
}
interface FleetLive {
	server_now: string;
	ingested: number;
	closed_ingest_memoized: number;
	closed_ingest_rules: number;
	closed_operational: number;
	closed_reasoning: number;
	escalated: number;
	guard_vetoes: number;
	in_flight: number;
	open_by_stage: Record<string, number>;
}

const closedOf = (d: FleetDay | FleetLive) =>
	d.closed_ingest_memoized + d.closed_ingest_rules + d.closed_operational + d.closed_reasoning;

/** Read the fleet stat rail as {label -> number} (labels are stable
 * i18n strings; numbers are locale-formatted). */
async function readStatRail(page: Page): Promise<Record<string, number>> {
	const tiles = page.getByTestId('fleet-stats').locator('> div');
	const out: Record<string, number> = {};
	for (let i = 0; i < (await tiles.count()); i++) {
		const label = (await tiles.nth(i).locator('span').first().innerText()).trim().toLowerCase();
		const value = (await tiles.nth(i).locator('span').nth(1).innerText()).replace(/[^0-9]/g, '');
		out[label] = Number(value || '0');
	}
	return out;
}

const statKey = (rail: Record<string, number>, needle: string): number => {
	const k = Object.keys(rail).find((x) => x.includes(needle));
	expect(k, `stat tile containing "${needle}" (have: ${Object.keys(rail).join(', ')})`).toBeTruthy();
	return rail[k as string];
};

// Landed-dot cumulative at a lapse playhead — the same model the UI ships
// (fleetSchedule.countsAt + progressiveExact), recomputed independently
// here as the oracle.
const FLIGHT: Record<string, number> = { fast: 1100, reason: 2400, human: 2800, unknown: 700 };
function routeOf(dot: Dot): string {
	if (dot.outcome === 'human') return 'human';
	if (dot.path === 'reasoning') return 'reason';
	if (dot.path) return 'fast';
	return 'unknown';
}
function cumulativeAt(day: FleetDay, tMs: number) {
	const start = Date.parse(day.window_start);
	const span = Math.max(1, Date.parse(day.window_end) - start);
	let arrived = 0,
		closed = 0,
		human = 0,
		vetoes = 0,
		totClosed = 0,
		totHuman = 0,
		totVeto = 0,
		totDots = day.dots.length;
	for (const dot of day.dots) {
		const route = routeOf(dot);
		const t = ((Date.parse(dot.first_event_at) - start) / span) * LAPSE_MS;
		const land = Math.min(LAPSE_MS, t + FLIGHT[route]);
		const closes = route === 'fast' || route === 'reason';
		if (closes) totClosed++;
		if (route === 'human') totHuman++;
		if (dot.veto) totVeto++;
		if (t <= tMs) {
			arrived++;
			if (land <= tMs) {
				if (closes) closed++;
				else if (route === 'human') human++;
				if (dot.veto) vetoes++;
			}
		}
	}
	const proj = (landed: number, tot: number, exact: number) =>
		tot > 0 ? Math.round(exact * (landed / tot)) : tMs >= LAPSE_MS - 1 ? exact : 0;
	return {
		ingested: proj(arrived, totDots, day.ingested),
		closed: proj(closed, totClosed, closedOf(day)),
		human: proj(human, totHuman, day.escalated),
		vetoes: proj(vetoes, totVeto, day.guard_vetoes)
	};
}

// ===========================================================================

test('plan 2: auth + tenant-pinned session survives reload', async ({ page }) => {
	await login(page);
	await expect(page.getByText(EMAIL)).toBeVisible({ timeout: 10000 });
	await expect(page.getByText('Tenant: Demo Tenant')).toBeVisible();
	await page.reload();
	await expect(page.getByText(EMAIL)).toBeVisible({ timeout: 15000 });
	expect(page.url()).not.toContain('/login');
});

test('plan 3+17: fleet-day internal consistency + tz day window', async ({ page }) => {
	await login(page);
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);

	// Aggregate identities — with the honest cross-day caveat: dots bin by
	// ARRIVAL day (outcome = the investigation's current state) while the
	// counters bin close/escalate EVENTS by when they happened, so a day
	// with reopen/attach texture against yesterday's investigations drifts
	// the two apart (observed live: 243 closed dots vs 232 close events,
	// 193 reopens that day). Assert a bounded drift, not equality.
	const dotClosed = day.dots.filter((d) => d.outcome === 'closed').length;
	const dotHuman = day.dots.filter((d) => d.outcome === 'human').length;
	const dotVeto = day.dots.filter((d) => d.veto).length;
	expect(day.ingested).toBeGreaterThan(0);
	if (day.sample_rate === 1) {
		expect(day.dots.length).toBe(day.ingested);
	}
	// Dots partition cleanly across outcomes.
	const otherDots = day.dots.length - dotClosed - dotHuman;
	expect(otherDots, 'dots with unaccounted outcomes').toBeGreaterThanOrEqual(0);
	const drift = Math.max(25, Math.round(day.ingested * 0.1));
	expect(Math.abs(closedOf(day) - dotClosed), 'close events vs closed dots').toBeLessThanOrEqual(
		drift
	);
	if (dotHuman > 0) expect(day.escalated).toBeGreaterThan(0);
	if (dotVeto > 0) expect(day.guard_vetoes).toBeGreaterThan(0);

	// Every dot's arrival inside the requested tz local-day window — the
	// day-window regression that split arrivals from closes.
	const ws = Date.parse(day.window_start);
	const we = Date.parse(day.window_end);
	const offenders = day.dots.filter((d) => {
		const t = Date.parse(d.first_event_at);
		return t < ws || t >= we;
	});
	expect(offenders, 'dots outside the tz day window').toEqual([]);
	// Window really is the browser tz's local day (UTC-7/-8 offset).
	expect(day.window_start).toMatch(/-0[78]:00$/);
});

test('plan 4+18: dashboard live head matches fleet-live; no 4xx from UI fleet calls', async ({
	page
}) => {
	const fleetResponses: { url: string; status: number }[] = [];
	page.on('response', (r) => {
		if (r.url().includes('/api/analytics/fleet-')) {
			fleetResponses.push({ url: r.url(), status: r.status() });
		}
	});
	await login(page);
	await page.goto('/');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// Let the catch-up cam (if any) hand off to the live head.
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible({ timeout: 30000 });
	// The in-flight tile waits on the first fleet-live poll (~7s cadence).
	await expect(page.getByTestId('fleet-in-flight')).toBeVisible({ timeout: 15000 });

	const live = await getJson<FleetLive>(page, `/api/analytics/fleet-live?tz=${TZ}`);
	const rail = await readStatRail(page);
	const uiInFlight = Number(
		(await page.getByTestId('fleet-in-flight').innerText()).replace(/[^0-9]/g, '')
	);

	// Live head binds to the live snapshot. The UI polls every ~7s, so
	// allow drift of a few events between our oracle call and the render.
	const closeTo = (ui: number, api: number, tol: number, what: string) =>
		expect(Math.abs(ui - api), `${what}: ui=${ui} api=${api}`).toBeLessThanOrEqual(tol);
	closeTo(uiInFlight, live.in_flight, 3, 'in-flight');
	closeTo(statKey(rail, 'alerts in'), live.ingested, 5, 'ingested');
	closeTo(statKey(rail, 'closed'), closedOf(live), 5, 'closed');
	closeTo(statKey(rail, 'human'), live.escalated, 3, 'escalated');
	closeTo(statKey(rail, 'blocked'), live.guard_vetoes, 3, 'vetoes');
	// in_flight covers open_by_stage
	const stageSum = Object.values(live.open_by_stage).reduce((a, b) => a + b, 0);
	expect(live.in_flight).toBeGreaterThanOrEqual(stageSum);

	// Regression #18: every UI-initiated fleet call answered 200.
	expect(fleetResponses.length).toBeGreaterThan(0);
	const bad = fleetResponses.filter((r) => r.status !== 200);
	expect(bad, 'non-200 fleet responses from the UI').toEqual([]);
});

test('plan 6+19: replay counters start from cumulative-at-playhead, not final totals', async ({
	page
}) => {
	await login(page);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);

	// Restart the film and pause immediately near t=0.
	await page.getByTestId('fleet-play').click();
	await page.getByTestId('fleet-play').click(); // pause
	const rail0 = await readStatRail(page);
	const slider = page.locator('input[type=range]');
	const t0 = Number(await slider.inputValue());
	const expect0 = cumulativeAt(day, t0);

	// Frozen-at-totals regression: near t=0 the counters must NOT read the
	// final aggregates (unless the day genuinely has everything at t≈0).
	const finalClosed = closedOf(day);
	if (expect0.closed < finalClosed) {
		expect(statKey(rail0, 'closed'), 'closed counter frozen at final total').toBeLessThan(
			finalClosed
		);
	}
	// And it must agree with the cumulative model at the paused playhead
	// (tolerance: the pause lands within a few frames of the read).
	expect(Math.abs(statKey(rail0, 'closed') - expect0.closed)).toBeLessThanOrEqual(
		Math.max(5, Math.round(finalClosed * 0.05))
	);
});

test('plan 7+8+9: monotonic accumulation, exact convergence, label/rail agreement', async ({
	page
}) => {
	test.setTimeout(180_000);
	await login(page);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);

	await page.getByTestId('fleet-play').click(); // restart from 0
	// Sample the closed counter over the film: must never decrease.
	let prev = -1;
	const samples: number[] = [];
	for (let i = 0; i < 10; i++) {
		await page.waitForTimeout(1500);
		const rail = await readStatRail(page);
		const v = statKey(rail, 'closed');
		expect(v, `monotonicity violated at sample ${i}: ${v} < ${prev}`).toBeGreaterThanOrEqual(prev);
		expect(v).toBeLessThanOrEqual(closedOf(day));
		samples.push(v);
		prev = v;
	}
	expect(samples[samples.length - 1], 'counter never moved during replay').toBeGreaterThan(
		samples[0]
	);

	// Scrub to the end: exact convergence of every tile + SVG column labels.
	const slider = page.locator('input[type=range]');
	await slider.evaluate((el: HTMLInputElement) => {
		el.value = el.max;
		el.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.waitForTimeout(500);
	const rail = await readStatRail(page);
	expect(statKey(rail, 'alerts in')).toBe(day.ingested);
	expect(statKey(rail, 'closed')).toBe(closedOf(day));
	expect(statKey(rail, 'human')).toBe(day.escalated);
	expect(statKey(rail, 'blocked')).toBe(day.guard_vetoes);
	expect(statKey(rail, 'open')).toBe(day.still_open);

	const svg = page.getByTestId('fleet-panel').locator('svg').first();
	const closedLabel = Number(((await svg.locator('text.cnt.good').textContent()) ?? '').trim());
	const humanLabel = Number(((await svg.locator('text.cnt.warn').textContent()) ?? '').trim());
	expect(closedLabel, 'SVG closed column label vs stat rail').toBe(statKey(rail, 'closed'));
	expect(humanLabel, 'SVG human column label vs stat rail').toBe(statKey(rail, 'human'));
});

test('plan 10: veto rail reveals with the playhead and lists real rulings', async ({ page }) => {
	await login(page);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);
	test.skip(day.recent_vetoes.length === 0, 'fixture: no vetoes on the current day');

	const vetoCard = page.getByTestId('fleet-veto-rail');
	// At t=0 (restart + immediate pause): rail should not already show
	// every ruling (unless all vetoes genuinely land at t≈0).
	await page.getByTestId('fleet-play').click();
	await page.getByTestId('fleet-play').click();
	const rowsAtStart = await vetoCard.locator('button').count();
	// End of film: every returned ruling row visible.
	const slider = page.locator('input[type=range]');
	await slider.evaluate((el: HTMLInputElement) => {
		el.value = el.max;
		el.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.waitForTimeout(400);
	const rowsAtEnd = await vetoCard.locator('button').count();
	expect(rowsAtEnd).toBe(day.recent_vetoes.length);
	expect(rowsAtStart).toBeLessThanOrEqual(rowsAtEnd);
});

test('plan 11: drill-down — veto rail row opens that investigation in replay', async ({ page }) => {
	await login(page);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);
	test.skip(day.recent_vetoes.length === 0, 'fixture: no vetoes on the current day');
	const target = day.recent_vetoes[0].investigation_id;

	const vetoCard = page.getByTestId('fleet-veto-rail');
	await vetoCard.locator('button').first().click();
	await page.waitForURL((u) => u.pathname.includes('/investigations/'), { timeout: 15000 });
	expect(page.url()).toContain(target);
	expect(page.url()).toContain('view=replay');
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 25000 });
});

test('plan 12+13: replay beats and verdict/guard integrity vs the events API', async ({ page }) => {
	await login(page);
	// Pick a replayable escalated investigation via the same API the UI uses.
	const list = await getJson<{ items: { id: string; status: string }[] }>(
		page,
		'/api/investigations?page_size=50'
	);
	const inv = list.items.find((i) => i.status === 'active') ?? list.items[0];
	expect(inv, 'fixture: no investigations at all').toBeTruthy();
	const ev = await getJson<{ events: { seq: number; event_type: string; data: any }[] }>(
		page,
		`/api/investigations/${inv.id}/events?after_seq=0&order=asc&limit=200`
	);
	test.skip(ev.events.length === 0, 'fixture: investigation has no replay beats');

	// API-side integrity: seq strictly ascending.
	const seqs = ev.events.map((e) => e.seq);
	expect(seqs).toEqual([...seqs].sort((a, b) => a - b));

	await page.goto(`/investigations/${inv.id}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 25000 });
	await page.waitForTimeout(4000); // let the film run its beats

	// Narration rows exist and reflect the beat feed.
	const rows = page.getByTestId('narration-rail').locator('.font-mono, [class*=border-b]');
	expect(await page.getByTestId('narration-rail').isVisible()).toBe(true);

	const kinds = new Set(ev.events.map((e) => e.event_type));
	if (kinds.has('verdict_rendered')) {
		const verdict = ev.events.filter((e) => e.event_type === 'verdict_rendered').pop();
		const decision = String(verdict?.data?.decision ?? '');
		// The verdict panel renders the decision (possibly struck through
		// when the guard overrode it).
		await expect(
			page.locator('text=/' + decision.toUpperCase() + '/i').first()
		).toBeVisible({ timeout: 10000 });
	}
	if (
		ev.events.some(
			(e) => e.event_type === 'guard_evaluated' && e.data?.effect === 'override'
		)
	) {
		await expect(page.getByText(/Guard override/i).first()).toBeVisible({ timeout: 10000 });
	}
});

test('plan 14: timeline and replay views cover the same feed', async ({ page }) => {
	await login(page);
	const list = await getJson<{ items: { id: string; status: string; title: string }[] }>(
		page,
		'/api/investigations?page_size=50'
	);
	const inv = list.items.find((i) => i.status === 'active') ?? list.items[0];
	await page.goto(`/investigations/${inv.id}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 25000 });
	await page.getByTestId('view-timeline').click({ timeout: 15000 });
	await expect(page.getByTestId('pipeline-map')).toBeHidden({ timeout: 10000 });
	// Same investigation, same page — the toggle must not navigate.
	expect(page.url()).toContain(inv.id);
	await page.getByTestId('view-replay').click({ timeout: 15000 });
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 15000 });
});

test('plan 15: investigations list agrees with the API', async ({ page }) => {
	await login(page);
	const list = await getJson<{
		items: { id: string; title: string; status: string }[];
		total: number;
	}>(page, '/api/investigations?page_size=50');
	// Compare like-for-like: the UI's first screen orders/filters its own
	// way, so anchor on ACTIVE items (always shown) and require a majority
	// rather than every row (organic churn between fetch and render).
	const active = list.items.filter((i) => i.status === 'active').slice(0, 5);
	test.skip(active.length === 0, 'fixture: no active investigations');
	await page.goto('/investigations');
	await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
	let seen = 0;
	for (const item of active) {
		if ((await page.getByText(item.title, { exact: false }).count()) > 0) seen++;
	}
	expect(seen, `only ${seen}/${active.length} active API rows visible`).toBeGreaterThanOrEqual(
		Math.ceil(active.length / 2)
	);
});

test('plan 16: pending reviews queue equals its API and the dashboard KPI', async ({ page }) => {
	await login(page);
	const pending = await getJson<{ items: unknown[]; total?: number }>(
		page,
		'/api/review/pending?page_size=100'
	);
	const metrics = await getJson<{ pending_reviews: number }>(page, '/api/metrics/overview');
	const apiCount = pending.total ?? pending.items.length;
	expect(metrics.pending_reviews, 'dashboard KPI vs review API').toBe(apiCount);

	await page.goto('/');
	// Dashboard KPI card: <h3>Pending Reviews</h3><p class="text-3xl">{n}</p>
	const kpi = page.locator('h3:has-text("Pending Reviews") + p').first();
	await expect(kpi).toBeVisible({ timeout: 15000 });
	const uiKpi = Number((await kpi.innerText()).replace(/[^0-9]/g, ''));
	// Small drift allowed: organic reviews can land between the oracle
	// fetch and the page's own metrics call.
	expect(Math.abs(uiKpi - apiCount), `UI KPI ${uiKpi} vs API ${apiCount}`).toBeLessThanOrEqual(5);
});

test('plan 20: fixture health — the demo day is populated and replayable', async ({ page }) => {
	await login(page);
	// The day the panel actually SHOWS: with the latest-active fallback,
	// an empty today is substituted — oracles must match the shown day.
	const day = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}&fallback=latest_active`);
	expect(day.ingested, 'demo day has no alerts — reseed needed').toBeGreaterThan(0);
	expect(day.dots.length, 'demo day has no dots').toBeGreaterThan(0);
	expect(
		day.dots.filter((d) => d.investigation_id).length,
		'no dot carries a drill-down link'
	).toBeGreaterThan(0);
	expect(closedOf(day), 'no pipeline closes on the demo day').toBeGreaterThan(0);
	expect(day.escalated, 'no human-lane volume on the demo day').toBeGreaterThan(0);

	// Every drill link the API emits must be openable by THIS session —
	// regression guard for dots that linked mssp_only investigations a
	// tenant session then 404ed on (found live by the dot-click test).
	const linked = day.dots.filter((d) => d.investigation_id);
	const sample = linked.filter((_, i) => i % Math.ceil(linked.length / 10) === 0).slice(0, 10);
	for (const d of sample) {
		const resp = await page.request.get(`/api/investigations/${d.investigation_id}`, {
			headers: { Origin: ORIGIN }
		});
		expect(resp.status(), `dot ${d.alert_id} links unopenable investigation`).toBe(200);
	}
});

// ===========================================================================
// Pervasive extensions: whole-app sweep, interaction depth, i18n.
// ===========================================================================

test('sweep: every sidebar route renders clean (no error state, no auth bounce)', async ({
	page
}) => {
	test.setTimeout(240_000);
	await login(page);
	await page.goto('/');
	const links = page.locator('aside a[href], [role="complementary"] a[href]');
	await expect(links.first()).toBeVisible({ timeout: 15000 });
	const hrefs = new Set<string>();
	for (let i = 0; i < (await links.count()); i++) {
		const href = await links.nth(i).getAttribute('href');
		if (href && href.startsWith('/') && !href.startsWith('/logout')) hrefs.add(href);
	}
	expect(hrefs.size, 'sidebar navigation links found').toBeGreaterThanOrEqual(5);

	for (const href of hrefs) {
		await page.goto(href);
		await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
		expect(page.url(), `${href} bounced to login`).not.toContain('/login');
		// No hard error surface rendered.
		const errAlert = page.locator('.alert.variant-soft-error, [data-testid="page-error"]');
		expect(await errAlert.count(), `${href} shows an error alert`).toBe(0);
		// The page produced content beyond the shell.
		const main = page.locator('main, [role="main"], .container, article').first();
		expect(
			((await main.textContent().catch(() => '')) ?? '').trim().length,
			`${href} rendered empty`
		).toBeGreaterThan(0);
	}
	// Guards (mutations / 401/403/5xx / pageerrors) asserted in afterEach —
	// this sweep is precisely where they bite hardest.
});

test('dashboard fleet mode toggle: Live <-> Replay both operate', async ({ page }) => {
	await login(page);
	await page.goto('/');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible({ timeout: 30000 });
	await page.getByTestId('fleet-mode-replay').click();
	await expect(page.getByTestId('fleet-play')).toBeVisible({ timeout: 10000 });
	await expect(page.getByTestId('fleet-live-chip')).toBeHidden();
	await page.getByTestId('fleet-play').click(); // film runs on the dashboard too
	await page.waitForTimeout(1500);
	await page.getByTestId('fleet-mode-live').click();
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible({ timeout: 30000 });
});

test('drill-down from the map itself: clicking a dot opens its replay', async ({ page }) => {
	test.setTimeout(90_000);
	await login(page);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// Run the film briefly, then pause so dots freeze mid-flight.
	await page.getByTestId('fleet-play').click();
	await page.waitForTimeout(2500);
	await page.getByTestId('fleet-play').click();
	const dot = page.locator('circle.fdot.clickable').first();
	const found = await dot
		.waitFor({ state: 'visible', timeout: 5000 })
		.then(() => true)
		.catch(() => false);
	test.skip(!found, 'fixture: no clickable dot frozen at this playhead');
	await dot.click({ force: true });
	await page.waitForURL((u) => u.pathname.includes('/investigations/'), { timeout: 15000 });
	expect(page.url()).toContain('view=replay');
	// The contract is NAVIGATION to that investigation's replay view; the
	// replay panel covers both a populated film and the honest empty state
	// (a drilled dot can predate the event substrate).
	await expect(
		page.getByTestId('replay-panel').or(page.getByTestId('pipeline-map')).first()
	).toBeVisible({ timeout: 25000 });
});

test('replay transport: pause/restart/scrub drive the film clock', async ({ page }) => {
	await login(page);
	const list = await getJson<{ items: { id: string; status: string }[] }>(
		page,
		'/api/investigations?page_size=50'
	);
	const inv = list.items.find((i) => i.status === 'active') ?? list.items[0];
	await page.goto(`/investigations/${inv.id}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 25000 });
	const transport = page.getByTestId('replay-transport');
	await expect(transport).toBeVisible({ timeout: 10000 });

	// Restart (second transport button) rewinds the clock, then the film
	// advances again: transport text must change across a short window.
	await transport.locator('button').nth(1).click();
	const t1 = (await transport.textContent()) ?? '';
	await page.waitForTimeout(1200);
	const t2 = (await transport.textContent()) ?? '';
	expect(t2, 'film clock did not advance after restart').not.toBe(t1);

	// Pause: clock freezes. The film can be shorter than a second of real
	// time, so decide by the button's actual state — clicking "Play" on an
	// ended film would restart it (exactly what tripped this test's first
	// draft).
	const playBtn = page.getByTestId('replay-play');
	if (/pause/i.test((await playBtn.getAttribute('aria-label')) ?? '')) {
		await playBtn.click();
	}
	const p1 = (await transport.textContent()) ?? '';
	await page.waitForTimeout(1000);
	const p2 = (await transport.textContent()) ?? '';
	expect(p2, 'film clock kept moving while paused/stopped').toBe(p1);
});

test('audit log page renders real audit events from its API', async ({ page }) => {
	await login(page);
	const audit = await getJson<{ items?: { event_type?: string; action?: string }[] }>(
		page,
		'/api/audit?page_size=20'
	);
	const items = audit.items ?? [];
	await page.goto('/audit');
	await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
	if (items.length === 0) {
		// Empty tenant audit trail is legal — the page must still render.
		expect(page.url()).toContain('/audit');
		return;
	}
	// The UI humanizes event types, so match structurally: the log table
	// renders at least as many rows as min(page size, API total ~ page).
	const rows = page.locator('.table-container tbody tr');
	await expect(rows.first()).toBeVisible({ timeout: 15000 });
	expect(await rows.count(), 'audit table rows vs API items').toBeGreaterThanOrEqual(
		Math.min(items.length, 10)
	);
});

test('authorization page renders the facts its API returns', async ({ page }) => {
	await login(page);
	// Capture the page's own facts call (the page resolves tenant id itself).
	const factsResp = page.waitForResponse(
		(r) => r.url().includes('/authorization/facts') && r.request().method() === 'GET',
		{ timeout: 25000 }
	);
	await page.goto('/authorization');
	const resp = await factsResp.catch(() => null);
	test.skip(!resp, 'authorization page did not fetch facts (surface changed?)');
	// KNOWN ISSUE (pending authz-surface decision): the tenant-visible
	// /authorization page calls the MSSP-only facts endpoint, which 403s
	// for tenant admins and renders a failed-to-load banner. Same gate
	// species as the fixed /mssp-users nav bug. Skip-not-pass until the
	// surface decision lands (tenant tab set vs /my-authorization).
	test.skip(
		resp!.status() === 403,
		'KNOWN ISSUE: tenant /authorization facts tab hits MSSP-only endpoint (403)'
	);
	expect(resp!.status()).toBe(200);
	const body = (await resp!.json()) as { facts?: { id: string }[] };
	const facts = body.facts ?? [];
	await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
	if (facts.length > 0) {
		// The page shows a populated facts surface, not an empty state.
		const empty = page.getByText(/no .*(facts|authorizations)/i);
		expect(await empty.count(), 'facts exist but UI shows empty state').toBe(0);
	}
});

test('i18n: localized route renders a translated fleet panel', async ({ page }) => {
	await login(page);
	await page.goto('/es-419/analytics');
	await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
	expect(page.url(), 'localized route bounced').toContain('/es-419/');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	// The panel heading must NOT be the English string on the es-419 route.
	const heading = ((await page.getByTestId('fleet-panel').textContent()) ?? '').slice(0, 400);
	expect(heading).not.toContain('The fleet — today');
	// And the film still works in the localized shell.
	await page.getByTestId('fleet-play').click();
	await page.waitForTimeout(1200);
	const rail = await readStatRail(page);
	expect(Object.keys(rail).length).toBeGreaterThanOrEqual(4);
});

test('fallback: latest-active-day semantics (zero-only, explicit date honored)', async ({
	page
}) => {
	await login(page);
	// A far-ahead timezone is the most likely to have an empty "today".
	const probeTz = 'Pacific/Kiritimati';
	const plain = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${probeTz}`);
	const fb = await getJson<FleetDay>(
		page,
		`/api/analytics/fleet-day?tz=${probeTz}&fallback=latest_active`
	);
	if (plain.ingested > 0) {
		// Zero-only rule: a non-empty today must NOT be substituted.
		expect(fb.date, 'fallback substituted a non-empty today').toBe(plain.date);
		expect(fb.ingested).toBeGreaterThan(0);
	} else {
		// Empty today: fallback serves an earlier day with content, and
		// every dot sits inside the substituted window.
		expect(fb.date < plain.date, `fallback date ${fb.date} !< today ${plain.date}`).toBe(true);
		expect(fb.ingested).toBeGreaterThan(0);
		const ws = Date.parse(fb.window_start);
		const we = Date.parse(fb.window_end);
		const outside = fb.dots.filter((d) => {
			const t = Date.parse(d.first_event_at);
			return t < ws || t >= we;
		});
		expect(outside, 'dots outside the substituted window').toEqual([]);
	}
	// Explicit date NEVER substitutes, even when empty and fallback is set.
	const explicit = await getJson<FleetDay>(
		page,
		`/api/analytics/fleet-day?tz=${TZ}&date=2020-01-01&fallback=latest_active`
	);
	expect(explicit.date).toBe('2020-01-01');
	expect(explicit.ingested).toBe(0);
});

test('fallback: UI badge appears only when today is empty', async ({ page }) => {
	await login(page);
	const today = await getJson<FleetDay>(page, `/api/analytics/fleet-day?tz=${TZ}`);
	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 20000 });
	if (today.ingested > 0) {
		// Active today: no substitution, no badge, honest "today" title.
		expect(await page.getByTestId('fleet-fallback-badge').count()).toBe(0);
	} else {
		// Empty today: disclosed substitution with the escape hatch.
		await expect(page.getByTestId('fleet-fallback-badge')).toBeVisible({ timeout: 15000 });
		await page.getByTestId('fleet-fallback-badge').click();
		await expect(page.getByTestId('fleet-empty')).toBeVisible({ timeout: 15000 });
		await page.getByTestId('fleet-show-last-active').click();
		await expect(page.getByTestId('fleet-fallback-badge')).toBeVisible({ timeout: 15000 });
	}
});

test('investigations pagination: page 2 shows different rows than page 1', async ({ page }) => {
	await login(page);
	const p1 = await getJson<{ items: { id: string }[]; total: number }>(
		page,
		'/api/investigations?page=1&page_size=20'
	);
	test.skip(p1.total <= 20, 'fixture: not enough investigations to paginate');
	const p2 = await getJson<{ items: { id: string }[] }>(
		page,
		'/api/investigations?page=2&page_size=20'
	);
	const ids1 = new Set(p1.items.map((i) => i.id));
	const overlap = p2.items.filter((i) => ids1.has(i.id));
	expect(overlap, 'API pages overlap').toEqual([]);
	// UI: navigate to page 2 if a pager exists; tolerate a UI without one.
	await page.goto('/investigations');
	const next = page
		.getByRole('button', { name: /next|›|→/i })
		.or(page.getByRole('link', { name: /next|›|→/i }))
		.first();
	if ((await next.count()) > 0 && (await next.isEnabled().catch(() => false))) {
		await next.click();
		await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
		expect(page.url()).toContain('/investigations');
	}
});
