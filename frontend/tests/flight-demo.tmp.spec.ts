// Throwaway demo driver (#72): renders the real flight-recorder UI with
// mock data and captures stills + video. Not part of the suite.
import { test, expect, type Page } from '@playwright/test';
import { TENANT_ID, mockAuthMe } from './helpers';

const OUT = process.env.OUT ?? 'test-results/demo';

test.use({ viewport: { width: 1440, height: 960 }, video: { mode: 'on', size: { width: 1440, height: 960 } } });

const T0 = Date.parse('2026-07-24T10:31:00Z');
const at = (s: number) => new Date(T0 + s * 1000).toISOString();

// ---- Film A: full reasoning close (brute force covered by a pentest engagement)
const INV_A = '550e8400-e29b-41d4-a716-446655440801';
const filmA = [
	{ event_type: 'alert_ingested', timestamp: at(0), data: { rule_id: '5763', initial_hypothesis: 'ssh brute force' } },
	{ event_type: 'policy_resolved', timestamp: at(0.4), data: { triage_policy: null, deterministic_disposition: null, vetoes_checked: [], vetoes_fired: [] } },
	{ event_type: 'supervisor_decision', timestamp: at(1.1), data: { next_action: 'INVESTIGATE', action_reasoning: 'High-volume auth failures on web-01; pull surrounding log context first.', tp_confidence: 0.45, iteration: 1 } },
	{ event_type: 'worker_started', timestamp: at(1.4), data: { worker: 'wazuh', action: 'INVESTIGATE' } },
	{ event_type: 'worker_result', timestamp: at(9.2), data: { worker: 'wazuh', ok: true, summary: '214 failed logins from 203.0.113.40, no successful auth', counts: { logs: 214 } } },
	{ event_type: 'supervisor_decision', timestamp: at(10.0), data: { next_action: 'ENRICH', action_reasoning: 'Single external source; reputation check before any conclusion.', tp_confidence: 0.4, iteration: 2 } },
	{ event_type: 'worker_started', timestamp: at(10.3), data: { worker: 'cortex', action: 'ENRICH' } },
	{ event_type: 'worker_result', timestamp: at(21.6), data: { worker: 'cortex', ok: true, summary: 'source IP clean across 4 analyzers', counts: { analyzers: 4 } } },
	{ event_type: 'supervisor_decision', timestamp: at(22.2), data: { next_action: 'CONTEXTUALIZE', action_reasoning: 'Check threat feeds before weighing the clean reputation.', tp_confidence: 0.35, iteration: 3 } },
	{ event_type: 'worker_started', timestamp: at(22.5), data: { worker: 'misp', action: 'CONTEXTUALIZE' } },
	{ event_type: 'worker_result', timestamp: at(33.9), data: { worker: 'misp', ok: true, summary: 'no IOC match in connected feeds', counts: { checked: 3, matches: 0 } } },
	{ event_type: 'worker_started', timestamp: at(41.0), data: { worker: 'authorization_context' } },
	{ event_type: 'worker_result', timestamp: at(41.6), data: { worker: 'authorization_context', ok: true, summary: 'engagement "Q3 external pentest · Redwood Security" covers web-01 until Jul 26', counts: { facts: 2 } } },
	{ event_type: 'supervisor_decision', timestamp: at(42.3), data: { next_action: 'VERDICT', action_reasoning: 'Evidence complete: covered activity, clean reputation, no IOC.', tp_confidence: 0.2, iteration: 4 } },
	{ event_type: 'verdict_rendered', timestamp: at(67.0), data: { decision: 'close', confidence: 0.93, evidence_strength: 'strong', threat_assessment: 'Authorized scanning activity from a declared penetration test window.', key_evidence: ['214 failed logins, zero successes', 'source IP clean across 4 Cortex analyzers, no MISP IOC', 'asset and window covered by declared engagement'], gaps_in_evidence: ['cannot verify the scanner’s full target list'], recommendation: 'Close as covered pentest activity; reopen window guards recurrence.' } },
	{ event_type: 'guard_evaluated', timestamp: at(72.0), data: { stage: 'verdict_guard', decision_in: 'close', decision_out: 'close', effect: 'pass', fired: [] } },
	{ event_type: 'guard_evaluated', timestamp: at(73.4), data: { stage: 'server_floor', decision_in: 'close_fp', decision_out: 'close_fp', effect: 'pass', fired: [] } },
	{ event_type: 'auto_closed', timestamp: at(73.6), data: { path: 'reasoning', reason: 'Activity covered by declared pentest engagement', run_id: 'run-801' } }
].map((e, i) => ({ ...e, id: `a-${i}`, seq: i + 1, run_id: 'run-801', visibility: 'mssp_only' }));

// ---- Film B: guard veto (model proposes close over a revoked grant)
const INV_B = '550e8400-e29b-41d4-a716-446655440802';
const filmB = [
	{ event_type: 'alert_ingested', timestamp: at(0), data: { rule_id: '60122' } },
	{ event_type: 'policy_resolved', timestamp: at(0.5), data: { deterministic_disposition: null } },
	{ event_type: 'supervisor_decision', timestamp: at(1.2), data: { next_action: 'INVESTIGATE', action_reasoning: 'Failures-then-success on a sensitive asset.', tp_confidence: 0.5, iteration: 1 } },
	{ event_type: 'worker_started', timestamp: at(1.5), data: { worker: 'wazuh', action: 'INVESTIGATE' } },
	{ event_type: 'worker_result', timestamp: at(11.3), data: { worker: 'wazuh', ok: true, summary: 'svc-backup: 11 failures then success from 172.16.4.9' } },
	{ event_type: 'worker_started', timestamp: at(37.0), data: { worker: 'authorization_context' } },
	{ event_type: 'worker_result', timestamp: at(37.6), data: { worker: 'authorization_context', ok: true, summary: 'grant for svc-backup on fin-db-02 REVOKED Jul 18 — class: contradicted', counts: { facts: 1 } } },
	{ event_type: 'verdict_rendered', timestamp: at(63.0), data: { decision: 'close', confidence: 0.78, evidence_strength: 'moderate', threat_assessment: 'Pattern matches this vendor’s routine maintenance logins.', key_evidence: ['matches historical vendor login pattern'], gaps_in_evidence: ['revoked grant not weighed against the pattern match'], recommendation: 'Close as routine vendor maintenance.' } },
	{ event_type: 'guard_evaluated', timestamp: at(79.1), data: { stage: 'verdict_guard', decision_in: 'close', decision_out: 'escalate', effect: 'override', fired: ['authz_contradicted'], reasons: ['revoked grant: activity cannot be presumed authorized'] } },
	{ event_type: 'human_review_requested', timestamp: at(79.3), data: { reason: 'guard override: authz_contradicted', verdict_decision: 'escalate', verdict_confidence: 0.78 } }
].map((e, i) => ({ ...e, id: `b-${i}`, seq: i + 1, run_id: 'run-802', visibility: 'mssp_only' }));

const invFixture = (id: string, title: string, status: string, decision: string | null) => ({
	id, title, status, phase: 'verdict',
	created_at: at(0), updated_at: at(80), closed_at: null,
	alert_count: 1, observable_count: 3, malicious_count: 0, suspicious_count: 1, clean_count: 2,
	max_severity: 'high', verdict_decision: decision, thehive_case_id: null, tenant_id: TENANT_ID,
	time_to_triage_seconds: 12, time_to_verdict_seconds: 74, verdict_confidence: 0.93,
	verdict_reasoning: null, threat_actor: null, tags: [], tokens_used: 38200,
	tokens_budget: 200000, disposition: null
});

const eventsResp = (id: string, events: unknown[]) => ({
	investigation_id: id, events, total: (events as unknown[]).length,
	server_now: at(90), next_after_seq: (events as { seq: number }[]).at(-1)?.seq ?? 0, has_more: false
});

// ---- Fleet day: 60 sampled dots across a diurnal day
const dayDots = Array.from({ length: 60 }, (_, i) => {
	const hour = (i * 37) % 24;
	const kind = i % 10 === 0 ? 'human' : i % 3 === 0 ? 'reasoning' : 'ingest_rules';
	return {
		alert_id: `alert-${1000 + i}`,
		investigation_id: `inv-${1000 + i}`,
		first_event_at: new Date(Date.parse('2026-07-24T00:00:00Z') + hour * 3600_000 + (i % 60) * 60_000).toISOString(),
		closed_at: kind === 'human' ? null : at(90),
		path: kind === 'human' ? null : kind,
		outcome: kind === 'human' ? 'human' : 'closed',
		veto: i % 20 === 0
	};
});

const fleetDay = {
	date: '2026-07-24', tz: 'UTC', server_now: at(90),
	window_start: '2026-07-24T00:00:00+00:00', window_end: '2026-07-25T00:00:00+00:00',
	ingested: 1247, closed_ingest_memoized: 296, closed_ingest_rules: 432,
	closed_operational: 16, closed_reasoning: 419, escalated: 84, guard_vetoes: 14,
	still_open: 0, ingest_histogram: [12,8,6,5,7,9,14,32,58,79,82,76,64,58,71,80,74,62,44,31,24,19,15,13],
	dollars_used: 198, tokens_used: 19_400_000, sample_rate: 60 / 1247,
	dots: dayDots,
	recent_vetoes: [
		{ investigation_id: 'inv-1000', at: at(10), stage: 'verdict_guard', fired: ['authz_contradicted'] },
		{ investigation_id: 'inv-1020', at: at(40), stage: 'server_floor', fired: ['active_incident'] },
		{ investigation_id: 'inv-1040', at: at(70), stage: 'worker_floor', fired: ['ioc_present'] }
	]
};

const analyticsSummary = {
	period_start: '2026-07-17T00:00:00Z', period_end: '2026-07-24T00:00:00Z',
	executive_kpis: { auto_close_rate: 0.93, escalation_rate: 0.067, human_override_rate: 0.04, mean_time_to_decision_seconds: 62, total_investigations: 1247, auto_closed_count: 1163, escalated_count: 84, human_reviewed_count: 84, avg_ai_confidence: 0.86, high_confidence_rate: 0.71 },
	ai_behavior: { confidence_distribution: [], decision_trends: [], escalation_breakdown: [], avg_confidence_by_decision: {} },
	human_review: { total_reviews: 84, pending: 2, approved: 61, rejected: 9, info_requested: 8, expired: 4, approval_rate: 0.73, override_rate: 0.11, ai_agreed_count: 70, ai_overridden_count: 9, avg_review_time_seconds: 300 },
	outcomes: { total_closed: 1163, closed_as_false_positive: 1101, closed_as_true_positive: 39, closed_as_suspicious: 23, avg_resolution_time_seconds: 90, p50_resolution_time_seconds: 45, p90_resolution_time_seconds: 240, reopen_rate: 0.01 }
};

async function seekTo(page: Page, frac: number) {
	const scrub = page.getByTestId('replay-transport').locator('input[type="range"]');
	await scrub.evaluate((el, f) => {
		const input = el as HTMLInputElement;
		input.value = String(Number(input.max) * (f as number));
		input.dispatchEvent(new Event('input', { bubbles: true }));
	}, frac);
}

test('demo: reasoning-close replay stills + video', async ({ page }) => {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	await page.route(`**/api/investigations/${INV_A}`, (r) =>
		r.fulfill({ json: invFixture(INV_A, 'SSH brute force — web-01', 'completed', 'close') }));
	await page.route(`**/api/investigations/${INV_A}/events*`, (r) =>
		r.fulfill({ json: eventsResp(INV_A, filmA) }));

	await page.goto(`/investigations/${INV_A}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 15000 });
	// Let the film play through for the video, then take deterministic stills.
	await page.waitForTimeout(14000);
	await seekTo(page, 0.35);
	await page.waitForTimeout(400);
	await page.screenshot({ path: `${OUT}/replay-a-workers.png` });
	await seekTo(page, 0.8);
	await page.waitForTimeout(400);
	await page.screenshot({ path: `${OUT}/replay-a-verdict.png` });
	await seekTo(page, 1);
	await page.waitForTimeout(700);
	await page.screenshot({ path: `${OUT}/replay-a-closed.png` });
});

test('demo: guard-veto replay still', async ({ page }) => {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	await page.route(`**/api/investigations/${INV_B}`, (r) =>
		r.fulfill({ json: invFixture(INV_B, 'RDP failures then success — fin-db-02', 'escalated', 'escalate') }));
	await page.route(`**/api/investigations/${INV_B}/events*`, (r) =>
		r.fulfill({ json: eventsResp(INV_B, filmB) }));

	await page.goto(`/investigations/${INV_B}?view=replay`);
	await expect(page.getByTestId('pipeline-map')).toBeVisible({ timeout: 15000 });
	await page.waitForTimeout(9000);
	await seekTo(page, 1);
	await page.waitForTimeout(700);
	await page.screenshot({ path: `${OUT}/replay-b-veto.png` });
});

test('demo: fleet hero stills + video', async ({ page }) => {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	await page.route('**/api/analytics/summary*', (r) => r.fulfill({ json: analyticsSummary }));
	await page.route('**/api/analytics/fleet-day*', (r) => r.fulfill({ json: fleetDay }));

	await page.goto('/analytics');
	await expect(page.getByTestId('fleet-map')).toBeVisible({ timeout: 15000 });
	await page.waitForTimeout(12000); // half the day plays for the video
	// Freeze mid-morning for a still, then end-of-day.
	const scrub = page.getByTestId('fleet-panel').locator('input[type="range"]');
	await scrub.evaluate((el) => {
		const input = el as HTMLInputElement;
		input.value = String(Number(input.max) * 0.44);
		input.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.waitForTimeout(400);
	await page.getByTestId('fleet-panel').screenshot({ path: `${OUT}/fleet-midday.png` });
	await scrub.evaluate((el) => {
		const input = el as HTMLInputElement;
		input.value = input.max;
		input.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.waitForTimeout(400);
	await page.getByTestId('fleet-panel').screenshot({ path: `${OUT}/fleet-endofday.png` });
});

test('demo: live home dashboard still', async ({ page }) => {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	await page.addInitScript(() => {
		sessionStorage.setItem(`soctalk-fleet-catchup-${new Date().toISOString().slice(0, 10)}`, '1');
	});
	await page.route('**/api/metrics/overview', (r) =>
		r.fulfill({ json: { open_investigations: 3, pending_reviews: 2, avg_time_to_triage_seconds: 300, avg_time_to_verdict_seconds: 1800, investigations_created_today: 412, investigations_closed_today: 384, escalations_today: 25, auto_closed_today: 384, malicious_observables_today: 3, verdict_breakdown: { auto_close: 384, escalate: 25 }, severity_breakdown: { high: 2, medium: 2 } } }));
	await page.route('**/api/metrics/hourly*', (r) => r.fulfill({ json: { metrics: [] } }));
	await page.route('**/api/investigations*', (r) =>
		r.fulfill({ json: { items: [], total: 0, page: 1, page_size: 10, has_more: false } }));
	await page.route('**/api/analytics/fleet-day*', (r) =>
		r.fulfill({ json: { date: '2026-07-24', tz: 'UTC', server_now: new Date().toISOString(), window_start: new Date(Date.now() - 14 * 3600_000).toISOString(), window_end: new Date(Date.now() + 10 * 3600_000).toISOString(), ingested: 412, closed_ingest_memoized: 100, closed_ingest_rules: 180, closed_operational: 6, closed_reasoning: 98, escalated: 25, guard_vetoes: 4, still_open: 3, ingest_histogram: Array(24).fill(17), dollars_used: 61, tokens_used: 6_000_000, sample_rate: 1, dots: [], recent_vetoes: [ { investigation_id: 'inv-9', at: new Date().toISOString(), stage: 'verdict_guard', fired: ['authz_contradicted'] } ] } }));
	await page.route('**/api/analytics/fleet-live*', (r) =>
		r.fulfill({ json: { server_now: new Date().toISOString(), window_start: new Date(Date.now() - 14 * 3600_000).toISOString(), ingested: 412, closed_ingest_memoized: 100, closed_ingest_rules: 180, closed_operational: 6, closed_reasoning: 98, escalated: 25, guard_vetoes: 4, in_flight: 3, last_alert_at: new Date(Date.now() - 42_000).toISOString(), open_by_stage: { sup: 1, verdict: 1, unknown: 1 }, recent_arrivals: [ { alert_id: 'live-a-1', investigation_id: 'live-i-1', first_event_at: new Date(Date.now() - 800).toISOString(), status: 'new' } ] } }));
	await page.goto('/');
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible({ timeout: 10000 });
	await page.waitForTimeout(600);
	await page.getByTestId('fleet-panel').screenshot({ path: `${OUT}/home-live.png` });
});

test('demo: home live with catch-up intro video', async ({ page }) => {
	await mockAuthMe(page, { current_tenant: TENANT_ID, current_tenant_slug: 'acme' });
	// NO sessionStorage preseed: first visit of the day → catch-up cam plays.
	const winStart = Date.now() - 14 * 3600_000;
	const catchDots = Array.from({ length: 50 }, (_, i) => {
		const kind = i % 9 === 0 ? 'human' : i % 3 === 0 ? 'reasoning' : 'ingest_rules';
		return {
			alert_id: `cd-${i}`, investigation_id: `ci-${i}`,
			first_event_at: new Date(winStart + (i / 50) * 13.5 * 3600_000).toISOString(),
			closed_at: kind === 'human' ? null : new Date().toISOString(),
			path: kind === 'human' ? null : kind,
			outcome: kind === 'human' ? 'human' : 'closed', veto: i % 18 === 0
		};
	});
	await page.route('**/api/metrics/overview', (r) =>
		r.fulfill({ json: { open_investigations: 3, pending_reviews: 2, avg_time_to_triage_seconds: 300, avg_time_to_verdict_seconds: 1800, investigations_created_today: 412, investigations_closed_today: 384, escalations_today: 25, auto_closed_today: 384, malicious_observables_today: 3, verdict_breakdown: { auto_close: 384, escalate: 25 }, severity_breakdown: { high: 2 } } }));
	await page.route('**/api/metrics/hourly*', (r) => r.fulfill({ json: { metrics: [] } }));
	await page.route('**/api/investigations*', (r) =>
		r.fulfill({ json: { items: [], total: 0, page: 1, page_size: 10, has_more: false } }));
	await page.route('**/api/analytics/fleet-day*', (r) =>
		r.fulfill({ json: { date: '2026-07-24', tz: 'UTC', server_now: new Date().toISOString(), window_start: new Date(winStart).toISOString(), window_end: new Date(winStart + 24 * 3600_000).toISOString(), ingested: 412, closed_ingest_memoized: 100, closed_ingest_rules: 180, closed_operational: 6, closed_reasoning: 98, escalated: 25, guard_vetoes: 4, still_open: 3, ingest_histogram: Array(24).fill(17), dollars_used: 61, tokens_used: 6_000_000, sample_rate: 412 / 50 > 1 ? 50 / 412 : 1, dots: catchDots, recent_vetoes: [ { investigation_id: 'ci-9', at: new Date().toISOString(), stage: 'verdict_guard', fired: ['authz_contradicted'] } ] } }));
	await page.route('**/api/analytics/fleet-live*', (r) =>
		r.fulfill({ json: { server_now: new Date().toISOString(), window_start: new Date(winStart).toISOString(), ingested: 412, closed_ingest_memoized: 100, closed_ingest_rules: 180, closed_operational: 6, closed_reasoning: 98, escalated: 25, guard_vetoes: 4, in_flight: 3, last_alert_at: new Date(Date.now() - 42_000).toISOString(), open_by_stage: { sup: 1, verdict: 1, unknown: 1 }, recent_arrivals: [ { alert_id: `live-${Date.now()}`, investigation_id: 'live-i-1', first_event_at: new Date(Date.now() - 300).toISOString(), status: 'new' } ] } }));
	await page.goto('/');
	await expect(page.getByTestId('fleet-panel')).toBeVisible({ timeout: 10000 });
	await page.getByTestId('fleet-panel').scrollIntoViewIfNeeded();
	// Catch-up (~4.5s) → live head; keep rolling through two live polls.
	await page.waitForTimeout(19000);
	await expect(page.getByTestId('fleet-live-chip')).toBeVisible();
});
