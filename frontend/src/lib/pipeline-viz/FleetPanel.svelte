<script lang="ts">
	import { browser } from '$app/environment';
	import { onDestroy, onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import SegmentedTabs from '$lib/components/SegmentedTabs.svelte';
	import { localizedGoto } from '$lib/i18n';
	import { formatNumber, formatTime } from '$lib/i18n/format';
	import { m } from '$lib/paraglide/messages';
	import { formatRelativeAge } from '$lib/utils/formatters';
	import FleetMap from './FleetMap.svelte';
	import {
		buildArrivalEntries,
		buildFleetSchedule,
		countsAt,
		LAPSE_MS,
		progressiveExact,
		scheduleTotals,
		type FleetScheduleEntry
	} from './fleetSchedule';
	import { guardReasonsLabel, guardStageLabel } from './guardLabels';
	import { createServerClock } from './serverClock';
	import { createTimeline } from './timeline';
	import type { FleetDay, FleetLive } from './types';

	/** 'live' = present tense on the server clock (tenant home).
	 *  'replay' = the day as an explicit, non-autoplaying recap (analytics). */
	export let defaultMode: 'live' | 'replay' = 'replay';

	const DAY_REFRESH_MS = 60_000;
	const LIVE_POLL_MS = 7_000;
	const CATCHUP_PLAY_MS = 4_500;

	let mode: 'live' | 'replay' = defaultMode;
	/** Within live mode: the once-per-session catch-up intro, then the head. */
	let livePhase: 'catchup' | 'head' = 'head';

	let day: FleetDay | null = null;
	let live: FleetLive | null = null;
	let schedule: FleetScheduleEntry[] = [];
	let arrivalEntries: FleetScheduleEntry[] = [];
	let loading = true;
	let error: string | null = null;
	let dayHandle: ReturnType<typeof setInterval> | null = null;
	let liveHandle: ReturnType<typeof setInterval> | null = null;
	/** Refresh landed while the film was running: hold it — a mid-film day
	 * swap (worse, a DATE flip) reshuffles the story under the cursor. */
	let pendingDay: FleetDay | null = null;
	/** Escape hatch: the user clicked the last-activity badge and asked for
	 * the true (empty) today instead of the fallback day. */
	let pinToday = false;

	const timeline = createTimeline(LAPSE_MS);
	const clock = createServerClock();

	const tzName = () =>
		browser ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'UTC';
	const reducedMotion = () =>
		browser && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
	/** Viewer-tz calendar date (YYYY-MM-DD). NOT toISOString — that is UTC
	 * and wrong near midnight for any non-UTC viewer. */
	const viewerToday = () => new Date().toLocaleDateString('en-CA');

	function dayFrac(d: FleetDay, serverNowIso: string): number {
		const start = Date.parse(d.window_start);
		const end = Date.parse(d.window_end);
		return Math.max(0, Math.min(1, (Date.parse(serverNowIso) - start) / (end - start)));
	}

	function applyDay(fresh: FleetDay) {
		day = fresh;
		schedule = buildFleetSchedule(fresh);
	}

	/** Request generation: a response fetched for a superseded mode or
	 * fallback intent must be discarded, or a slow replay-fallback reply
	 * can overwrite the live surface after a mode switch. */
	let dayReq = 0;

	async function loadDay(initial: boolean) {
		const req = ++dayReq;
		try {
			// Latest-active-day fallback (zero-only rule): today with ANY
			// alerts always wins; an empty today is substituted server-side
			// with the most recent active day, disclosed via the date label.
			// REPLAY-ONLY: the live surface is the present tense —
			// it must never carry a substituted day's title or stats.
			const wantFallback = mode === 'replay' && !pinToday;
			const fresh = await api.analytics.getFleetDay({
				tz: tzName(),
				fallback: wantFallback ? 'latest_active' : undefined
			});
			if (req !== dayReq) return; // superseded by a newer request
			error = null; // a recovered load clears a prior transient error banner
			if (initial || !$timeline.playing) {
				applyDay(fresh);
				pendingDay = null;
			} else {
				pendingDay = fresh;
			}
			if (initial) {
				loading = false;
				if (mode === 'replay') {
					// Recap surface: land on "the day so far" (a fallback day
					// is complete, so the clamp parks at the full film).
					timeline.setRate(1);
					timeline.seek(dayFrac(fresh, fresh.server_now) * LAPSE_MS);
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
			loading = false;
		}
	}

	// Apply a held refresh as soon as the film stops.
	$: if (pendingDay && !$timeline.playing) {
		applyDay(pendingDay);
		pendingDay = null;
	}

	function showToday() {
		// Explicit navigation away from the film: stop it first so the
		// immediate re-apply/seek cannot land mid-play.
		timeline.pause();
		pinToday = true;
		void loadDay(true);
	}
	function showLastActive() {
		timeline.pause();
		pinToday = false;
		void loadDay(true);
	}

	async function pollLive() {
		try {
			live = await api.analytics.getFleetLive({ tz: tzName() });
			clock.sync(live.server_now);
			arrivalEntries = buildArrivalEntries(live.recent_arrivals);
		} catch (e) {
			if (!day) {
				error = e instanceof Error ? e.message : String(e);
				loading = false;
			}
		}
	}

	function catchupKey(): string {
		// Viewer-tz date, matching the day window (UTC here double-played
		// or skipped the catch-up around midnight for non-UTC viewers).
		return `soctalk-fleet-catchup-${viewerToday()}`;
	}

	function maybeStartCatchup() {
		// Once per session per day, never under reduced motion
		// (a ritual replayed on every visit becomes an ignored roadblock).
		// Never on an empty or substituted day: there is nothing of TODAY
		// to catch up on, and auto-playing yesterday uninvited would blur
		// the live/replay line.
		if (!browser || !day || reducedMotion()) return;
		if (day.ingested === 0 || day.date !== viewerToday()) return;
		if (sessionStorage.getItem(catchupKey())) return;
		sessionStorage.setItem(catchupKey(), '1');
		const upto = dayFrac(day, live?.server_now ?? day.server_now) * LAPSE_MS;
		if (upto < 500) return;
		livePhase = 'catchup';
		timeline.seek(0);
		timeline.setDuration(upto);
		timeline.setRate(Math.max(1, upto / CATCHUP_PLAY_MS));
		timeline.play();
	}

	$: if (mode === 'live' && livePhase === 'catchup' && $timeline.ended) {
		livePhase = 'head';
	}

	function switchMode(next: 'live' | 'replay') {
		if (mode === next) return;
		mode = next;
		if (next === 'live') {
			livePhase = 'head';
			clock.start();
			if (!liveHandle) {
				void pollLive();
				liveHandle = setInterval(() => {
					if (document.visibilityState === 'visible') void pollLive();
				}, LIVE_POLL_MS);
			}
		} else {
			timeline.pause();
			timeline.setRate(1);
			timeline.setDuration(LAPSE_MS);
			if (day) timeline.seek(dayFrac(day, live?.server_now ?? day.server_now) * LAPSE_MS);
		}
		// EVERY mode switch refetches under the new mode's intent (replay
		// wants the fallback, live wants the plain present) — bumping the
		// request generation so any in-flight response for the previous
		// mode is discarded rather than landing stale.
		void loadDay(true);
	}

	onMount(() => {
		void loadDay(true).then(() => {
			if (mode === 'live') {
				clock.start();
				void pollLive().then(() => maybeStartCatchup());
				liveHandle = setInterval(() => {
					if (document.visibilityState === 'visible') void pollLive();
				}, LIVE_POLL_MS);
			}
		});
		dayHandle = setInterval(() => {
			if (document.visibilityState === 'visible') void loadDay(false);
		}, DAY_REFRESH_MS);
	});

	onDestroy(() => {
		if (dayHandle) clearInterval(dayHandle);
		if (liveHandle) clearInterval(liveHandle);
		timeline.destroy();
		clock.destroy();
	});

	function drill(e: CustomEvent<{ investigationId: string }>) {
		void localizedGoto(`/investigations/${e.detail.investigationId}?view=replay`);
	}

	// The lapse clock is a synthetic 24h position, not a wall time — the
	// live clock and ages go through the locale-aware shared formatters.
	const lapseClock = (t: number): string => {
		const mins = (t / LAPSE_MS) * 1440;
		return `${String(Math.floor(mins / 60)).padStart(2, '0')}:${String(Math.floor(mins % 60)).padStart(2, '0')}`;
	};

	$: sampleN = day && day.sample_rate > 0 ? Math.max(1, Math.round(1 / day.sample_rate)) : 1;
	$: liveClosed = live
		? live.closed_ingest_memoized +
			live.closed_ingest_rules +
			live.closed_operational +
			live.closed_reasoning
		: 0;
	$: dayClosed = day
		? day.closed_ingest_memoized + day.closed_ingest_rules + day.closed_operational + day.closed_reasoning
		: 0;
	$: showLiveHead = mode === 'live' && livePhase === 'head';
	// Substituted day (today empty, latest active served): the label must
	// move — playing Friday under a "today" heading would be a lie.
	$: dayIsFallback = !!day && day.ingested > 0 && day.date !== viewerToday();
	$: dayEmpty = !!day && day.ingested === 0;
	$: dayLabel = day
		? new Intl.DateTimeFormat(undefined, {
				weekday: 'short',
				month: 'short',
				day: 'numeric'
			}).format(new Date(`${day.date}T12:00:00`))
		: '';
	// Replay and the catch-up cam track the playhead: counters accumulate
	// as dots land (projected onto the exact aggregates so they end on
	// the true totals). Only the live head binds to the live snapshot.
	// Totals are invariant per schedule — keep them out of the per-frame
	// path.
	$: totals = scheduleTotals(schedule);
	$: lapse = day && !showLiveHead ? countsAt(schedule, $timeline.t) : null;
	$: lapseAtEnd = $timeline.t >= LAPSE_MS - 1;
	$: statIngested =
		showLiveHead && live
			? live.ingested
			: lapse && day
				? progressiveExact(lapse.arrived, totals.dots, day.ingested, lapseAtEnd)
				: (day?.ingested ?? 0);
	$: statClosed =
		showLiveHead && live
			? liveClosed
			: lapse
				? progressiveExact(lapse.closed, totals.closed, dayClosed, lapseAtEnd)
				: dayClosed;
	$: statEscalated =
		showLiveHead && live
			? live.escalated
			: lapse && day
				? progressiveExact(lapse.human, totals.human, day.escalated, lapseAtEnd)
				: (day?.escalated ?? 0);
	$: statVetoes =
		showLiveHead && live
			? live.guard_vetoes
			: lapse && day
				? progressiveExact(lapse.vetoes, totals.vetoes, day.guard_vetoes, lapseAtEnd)
				: (day?.guard_vetoes ?? 0);
	// The veto rail reveals each ruling when its DOT lands — the same
	// clock statVetoes ticks on, so a row never appears while the stat
	// still reads 0. Rows whose investigation was sampled out
	// of the dot set (sample_rate < 1 only) fall back to their real
	// guard-decision time; the stat's projection covers them in aggregate.
	const vetoLapseT = (d: FleetDay, at: string): number => {
		const start = Date.parse(d.window_start);
		const span = Math.max(1, Date.parse(d.window_end) - start);
		return ((Date.parse(at) - start) / span) * LAPSE_MS;
	};
	// Earliest land per investigation: attached alerts give one
	// investigation several dots, and the row should appear with the
	// first of them (min, not last-wins).
	$: vetoLandByInv = (() => {
		const map = new Map<string, number>();
		for (const e of schedule) {
			if (!e.dot.veto || !e.dot.investigation_id) continue;
			const prev = map.get(e.dot.investigation_id);
			if (prev === undefined || e.land < prev) map.set(e.dot.investigation_id, e.land);
		}
		return map;
	})();
	$: visibleVetoes = (() => {
		const d = day;
		if (!d) return [];
		if (!lapse) return d.recent_vetoes;
		return d.recent_vetoes.filter(
			(v) => (vetoLandByInv.get(v.investigation_id) ?? vetoLapseT(d, v.at)) <= $timeline.t
		);
	})();
	$: unknownOpen = live?.open_by_stage?.unknown ?? 0;
</script>

<section class="mb-8" data-testid="fleet-panel">
	<div class="flex items-center gap-3 mb-3">
		{#if dayIsFallback}
			<h2 class="h3" data-testid="fleet-date-label">{m.fleet_title_date({ date: dayLabel })}</h2>
			<button
				type="button"
				class="badge variant-soft-warning text-[0.65rem] uppercase tracking-wide"
				title={m.fleet_show_today()}
				aria-label={m.fleet_show_today()}
				on:click={showToday}
				data-testid="fleet-fallback-badge"
			>
				{m.fleet_last_activity()}
			</button>
		{:else}
			<h2 class="h3">{m.fleet_title()}</h2>
		{/if}
		{#if showLiveHead}
			<span class="badge variant-soft-error font-mono text-[0.65rem] live-chip" data-testid="fleet-live-chip">
				<span class="live-dot" />
				{m.replay_live()}
			</span>
		{/if}
		<div class="ml-auto">
			<SegmentedTabs
				value={mode}
				options={[
					{ id: 'live', label: m.fleet_mode_live(), testid: 'fleet-mode-live' },
					{ id: 'replay', label: m.fleet_mode_replay(), testid: 'fleet-mode-replay' }
				]}
				on:change={(e) => switchMode(e.detail.id === 'live' ? 'live' : 'replay')}
			/>
		</div>
	</div>
	{#if loading}
		<div class="flex justify-center p-8">
			<div class="animate-spin w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full" />
		</div>
	{:else if error}
		<aside class="alert variant-soft-error"><p>{error}</p></aside>
	{:else if day && dayEmpty && !showLiveHead}
		<!-- Designed empty state (zero-only rule): pinToday means the user
		     chose the true empty today via the badge; otherwise the fallback
		     already ran and found nothing in 30 days. Quiet, not broken. -->
		<div class="card p-10 text-center" data-testid="fleet-empty">
			<p class="opacity-60">
				{pinToday ? m.fleet_empty_today() : m.fleet_empty_month()}
			</p>
			{#if pinToday}
				<button
					type="button"
					class="btn btn-sm variant-soft-primary mt-4 font-mono"
					on:click={showLastActive}
					data-testid="fleet-show-last-active"
				>
					{m.fleet_show_last_active()}
				</button>
			{/if}
		</div>
	{:else if day}
		<div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
			<div class="xl:col-span-2">
				<div class="card p-3 film-card">
					{#if showLiveHead}
						<FleetMap
							{day}
							schedule={arrivalEntries}
							t={$clock}
							mode="live"
							openByStage={live?.open_by_stage ?? {}}
							liveCounts={live
								? {
										ingested: live.ingested,
										closed: liveClosed,
										reasoning: live.closed_reasoning,
										escalated: live.escalated
									}
								: null}
							on:drill={drill}
						/>
						<div class="flex items-center gap-3 mt-2">
							<span class="text-xs font-mono opacity-70 tabular-nums" data-testid="fleet-live-clock">
								{$clock ? formatTime($clock) : '—'}
							</span>
							<p class="text-[0.68rem] font-mono opacity-50">{m.fleet_live_caption()}</p>
						</div>
					{:else}
						<FleetMap {day} {schedule} t={$timeline.t} on:drill={drill} />
						<div class="flex items-center gap-2 mt-2 transport-row">
							<button
								type="button"
								class="btn btn-sm variant-soft-primary font-mono"
								on:click={() => (mode === 'live' ? undefined : $timeline.playing ? timeline.pause() : timeline.restart())}
								aria-label={$timeline.playing ? m.replay_pause() : m.fleet_replay_day()}
								data-testid="fleet-play"
								disabled={mode === 'live'}
							>
								{$timeline.playing ? '❚❚' : '▶'}
							</button>
							{#if mode === 'replay'}
								<span class="text-[0.7rem] opacity-60">{m.fleet_replay_hint()}</span>
								<input
									type="range"
									class="flex-1 min-w-[8rem] accent-primary-500"
									min="0"
									max={LAPSE_MS}
									step="50"
									value={$timeline.t}
									on:input={(e) => {
										timeline.pause();
										timeline.seek(Number(e.currentTarget.value));
									}}
									aria-label={m.replay_scrub()}
								/>
							{/if}
							<span class="text-xs font-mono opacity-70 tabular-nums">{lapseClock($timeline.t)} / 24h</span>
						</div>
					{/if}
					{#if !showLiveHead && sampleN > 1}
						<p class="text-[0.68rem] font-mono opacity-50 mt-1">
							{m.fleet_sample({ n: sampleN })}
						</p>
					{/if}
					<p class="text-[0.68rem] font-mono opacity-50">{m.fleet_drill_hint()}</p>
				</div>
			</div>

			<div class="space-y-4">
				<div class="card p-4">
					<div class="grid grid-cols-2 gap-4" data-testid="fleet-stats">
						{#if showLiveHead && live}
							<div>
								<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_in_flight()}</span>
								<span class="text-xl font-mono tabular-nums" data-testid="fleet-in-flight">{live.in_flight}</span>
								{#if unknownOpen > 0}
									<span class="text-[0.6rem] opacity-40 block">{m.fleet_stage_unknown({ n: unknownOpen })}</span>
								{/if}
							</div>
							<div>
								<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_last_alert()}</span>
								<span class="text-xl font-mono tabular-nums" data-testid="fleet-last-alert">{formatRelativeAge(live.last_alert_at, $clock)}</span>
							</div>
						{/if}
						<div>
							<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_ingested()}</span>
							<span class="text-xl font-mono tabular-nums">{formatNumber(statIngested)}</span>
						</div>
						<div>
							<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_closed()}</span>
							<span class="text-xl font-mono tabular-nums text-success-500">{formatNumber(statClosed)}</span>
						</div>
						<div>
							<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_human()}</span>
							<span class="text-xl font-mono tabular-nums text-warning-500">{formatNumber(statEscalated)}</span>
						</div>
						<div>
							<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_vetoes()}</span>
							<span class="text-xl font-mono tabular-nums">{statVetoes}</span>
						</div>
						{#if mode === 'replay'}
							<div>
								<span class="text-[0.65rem] uppercase tracking-wider opacity-50 block">{m.fleet_open()}</span>
								<span class="text-xl font-mono tabular-nums">{formatNumber(day.still_open)}</span>
							</div>
							<!-- Model spend deliberately not shown here: cost is
							     MSSP-facing curation state (visibility adjudication),
							     and on scripted-playback demo tenants it reads $0. -->
						{/if}
					</div>
				</div>

				<div class="card p-4" data-testid="fleet-veto-rail">
					<h3 class="h5 mb-2">{m.fleet_vetoes_title()}</h3>
					{#if visibleVetoes.length === 0}
						<p class="text-sm opacity-60">{m.fleet_none_yet()}</p>
					{:else}
						<div class="space-y-2">
							{#each visibleVetoes as veto (veto.investigation_id + veto.at)}
								<button
									type="button"
									class="block w-full text-left text-xs border-b border-surface-500/20 pb-1 hover:opacity-80"
									title="{veto.stage ?? 'guard'}: {veto.fired.join(', ')}"
									on:click={() => void localizedGoto(`/investigations/${veto.investigation_id}?view=replay`)}
								>
									<span class="text-warning-500">{guardStageLabel(veto.stage)}</span>
									<span class="text-error-500 block">{guardReasonsLabel(veto.fired)}</span>
								</button>
							{/each}
						</div>
					{/if}
				</div>
			</div>
		</div>
	{/if}
</section>

<style>
	.live-chip {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
	}
	.live-dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: rgb(var(--color-error-500));
		animation: blink 1.4s steps(2) infinite;
	}
	@keyframes blink {
		50% {
			opacity: 0.25;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.live-dot {
			animation: none;
		}
	}
	/* Transport bar reveals on hover/focus of the film card — the map is
	   the star; controls appear when reached for. Opacity-only (never
	   display:none) so keyboard focus and assistive tech always land on
	   real, interactive controls, and focus-within reveals for tabbing. */
	.film-card .transport-row {
		opacity: 0;
		transition: opacity 150ms ease;
	}
	.film-card:hover .transport-row,
	.film-card:focus-within .transport-row {
		opacity: 1;
	}
	/* No hover on touch devices: keep the controls always visible. */
	@media (hover: none) {
		.film-card .transport-row {
			opacity: 1;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.film-card .transport-row {
			transition: none;
		}
	}
</style>
