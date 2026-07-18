<!--
  MSSP fleet analytics — trend-shaped companion to MsspDashboard.

  Product rule (locked):
    Dashboard tells the MSSP where to act NOW.
    Analytics tells the MSSP whether the service is getting better
    or worse over TIME.

  v1 widgets (no overlap with Dashboard):
    1. Trend strip — alert volume / p95 TTV / p95 TTR / escalation
       rate over a 7/30/90d window. Bucket auto-scales server-side
       (hour ≤30d, day >30d) so 90d isn't hairline noise.
    2. Comparative ranking — top "worsening" tenants by current vs
       previous-period p95 TTV (toggle TTR). Min-sample threshold +
       absolute Δ in seconds (not relative %) so low-volume tenants
       don't dominate.
    3. Activity heatmap — fleet activity (alerts | cases) by
       day-of-week × hour-of-day. Surfaces staffing patterns.

  Lightweight charting: SVG sparklines hand-rolled. No chart lib so
  the bundle stays lean and we avoid the apexcharts hydration cost
  that drags the per-tenant dashboard.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { localizedGoto } from '$lib/i18n';
	import {
		api,
		type MsspTrendsResponse,
		type MsspRankingResponse,
		type MsspHeatmapResponse,
		type MsspTrendBucket
	} from '$lib/api/client';
	import { authSession } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';

	// Deep-link contract: clicking an outlier tenant in the ranking
	// must land on a meaningful Dashboard slice with the same context
	// (= per-tenant dashboard for that tenant). Pin the scope first
	// via assume-tenant, refresh the session store so isMsspScope
	// flips to false, then navigate to / which renders the legacy
	// per-tenant dashboard under tenant pin.
	async function drillIntoTenant(slug: string) {
		try {
			const updated = await api.auth.assumeTenant(slug);
			authSession.update((s) => ({ ...s, user: updated }));
			await localizedGoto('/', { invalidateAll: true });
		} catch (e) {
			console.error('[Analytics] drill-in failed:', e);
		}
	}

	let trends: MsspTrendsResponse | null = null;
	let ranking: MsspRankingResponse | null = null;
	let heatmap: MsspHeatmapResponse | null = null;
	let errors: Record<string, string> = {};
	let loading = true;

	let trendDays: 7 | 30 | 90 = 30;
	let rankingMetric: 'ttv' | 'ttr' = 'ttv';
	let heatmapDimension: 'alerts' | 'cases' = 'alerts';

	async function load(name: string, fn: () => Promise<unknown>) {
		try {
			return await fn();
		} catch (e) {
			// Svelte 4 reactivity: ``errors[name] = X`` doesn't notify
			// the template — we have to reassign the object reference.
			errors = { ...errors, [name]: e instanceof Error ? e.message : String(e) };
			return null;
		}
	}

	async function refresh() {
		loading = true;
		errors = {};
		const [t, r, h] = await Promise.all([
			load('trends', () => api.msspAnalytics.trends(trendDays)),
			// Use the API's ``min_sample`` default (10) — the user-
			// pinned guard rail keeps low-volume tenants out of the
			// "worsening" list. Overriding to 1 here would defeat it.
			load('ranking', () => api.msspAnalytics.ranking(rankingMetric, trendDays)),
			load('heatmap', () => api.msspAnalytics.heatmap(heatmapDimension, trendDays))
		]);
		if (t) trends = t as MsspTrendsResponse;
		if (r) ranking = r as MsspRankingResponse;
		if (h) heatmap = h as MsspHeatmapResponse;
		loading = false;
	}

	onMount(refresh);

	function humanSeconds(s: number | null | undefined): string {
		if (s == null) return '—';
		if (s < 60) return `${Math.round(s)}s`;
		if (s < 3600) return `${Math.round(s / 60)}m`;
		if (s < 86_400) return `${(s / 3600).toFixed(1)}h`;
		return `${(s / 86_400).toFixed(1)}d`;
	}

	function deltaLabel(d: number | null | undefined): string {
		if (d == null) return '—';
		const sign = d > 0 ? '+' : d < 0 ? '−' : '';
		return `${sign}${humanSeconds(Math.abs(d))}`;
	}

	function deltaClass(d: number | null | undefined): string {
		if (d == null) return 'opacity-60';
		if (d > 0) return 'text-error-500'; // worsening
		if (d < 0) return 'text-success-500'; // improving
		return 'opacity-60';
	}

	// Sparkline path generator. Pure pixel-space, no axes.
	function sparkline(
		buckets: MsspTrendBucket[] | undefined,
		key: keyof MsspTrendBucket,
		w = 200,
		h = 36
	): string {
		if (!buckets || buckets.length === 0) return '';
		const vals = buckets.map((b) => Number(b[key] ?? 0));
		const max = Math.max(...vals, 1);
		const min = Math.min(...vals, 0);
		const range = max - min || 1;
		const step = w / Math.max(1, buckets.length - 1);
		return vals
			.map((v, i) => {
				const x = (i * step).toFixed(2);
				const y = (h - ((v - min) / range) * h).toFixed(2);
				return `${i === 0 ? 'M' : 'L'}${x},${y}`;
			})
			.join(' ');
	}

	function totalKpi(buckets: MsspTrendBucket[] | undefined, key: keyof MsspTrendBucket): number {
		if (!buckets) return 0;
		return buckets.reduce((acc, b) => acc + Number(b[key] ?? 0), 0);
	}

	$: escRate = (() => {
		if (!trends) return null;
		const closed = trends.window_closed_total;
		return closed === 0 ? null : trends.window_escalated_total / closed;
	})();

	// Message FUNCTION refs (called at render time) — never evaluate
	// messages at module scope (#52).
	const DOW_LABELS = [
		m.ana_dow_sun,
		m.ana_dow_mon,
		m.ana_dow_tue,
		m.ana_dow_wed,
		m.ana_dow_thu,
		m.ana_dow_fri,
		m.ana_dow_sat
	];

	// Svelte 4's reactive declaration ($:) tracks variable reads in
	// the right-hand expression at compile time. ``$: hm = fn()``
	// where ``fn`` reads ``heatmap`` from closure would NOT register
	// ``heatmap`` as a dep, so ``hm`` was computed once on mount
	// (heatmap null → empty map) and never updated when the fetch
	// resolved. Inlining the build keeps the dep visible.
	$: hm = ((): { max: number; cell: (dow: number, hour: number) => number } => {
		// (named ``byKey`` — a local ``m`` would shadow the paraglide
		// message import used elsewhere in this component)
		const byKey = new Map<string, number>();
		let max = 0;
		for (const c of heatmap?.cells ?? []) {
			byKey.set(`${c.dow}-${c.hour}`, c.count);
			if (c.count > max) max = c.count;
		}
		return {
			max,
			cell: (dow, hour) => byKey.get(`${dow}-${hour}`) ?? 0
		};
	})();

	// Two-stop scheme:
	//   - empty (count=0)          → slate-700 (#334155), one shade
	//                                 lighter than the card so the
	//                                 grid is visible even when
	//                                 sparse.
	//   - any non-zero count       → ramp from rose-300 (#fda4af,
	//                                 light pink) at the low end to
	//                                 rose-500 (#f43f5e, saturated
	//                                 crimson) at max.
	//
	// The earlier slate→rose-500 ramp made count=1 cells nearly
	// indistinguishable from empty — the lightest non-zero color
	// still sat in the dark region of the gradient. Forcing
	// non-zero into the rose family guarantees any activity reads
	// as "warm" at a glance, which is the heatmap's point.
	function heatColor(count: number, max: number): string {
		if (max === 0 || count === 0) return '#334155';
		const ratio = count / max;
		// rose-300 #fda4af (253,164,175) → rose-500 #f43f5e (244,63,94)
		const r = Math.round(253 + (244 - 253) * ratio);
		const g = Math.round(164 + (63 - 164) * ratio);
		const b = Math.round(175 + (94 - 175) * ratio);
		return `rgb(${r}, ${g}, ${b})`;
	}
</script>

<div class="space-y-6 p-6">
	<header class="flex items-center justify-between flex-wrap gap-3">
		<div>
			<h1 class="h2">{m.ana_mssp_title()}</h1>
			<p class="opacity-70 text-sm">
				{m.ana_mssp_subtitle()}
			</p>
		</div>
		<div class="flex items-center gap-2">
			<span class="opacity-70 text-sm">{m.ana_window_label()}</span>
			<select
				class="select select-sm"
				bind:value={trendDays}
				on:change={refresh}
				data-testid="window-select"
			>
				<option value={7}>{m.ana_window_7d()}</option>
				<option value={30}>{m.ana_window_30d()}</option>
				<option value={90}>{m.ana_window_90d()}</option>
			</select>
		</div>
	</header>

	<!-- Trend strip — alert volume + p95 TTV + p95 TTR + escalation rate -->
	<section class="grid grid-cols-1 md:grid-cols-4 gap-4" data-testid="trend-strip">
		<div class="card p-4 space-y-2">
			<div class="text-xs opacity-60 uppercase tracking-wide">{m.ana_alert_volume()}</div>
			<div class="text-2xl font-semibold">{(trends?.window_alert_total ?? 0).toLocaleString()}</div>
			<svg viewBox="0 0 200 36" class="w-full h-9 opacity-80">
				<path d={sparkline(trends?.buckets, 'alert_count')} fill="none" stroke="#f43f5e" stroke-width="1.5" />
			</svg>
		</div>
		<div class="card p-4 space-y-2">
			<div class="text-xs opacity-60 uppercase tracking-wide">{m.ana_p95_ttv_window()}</div>
			<div class="text-2xl font-semibold">{humanSeconds(trends?.window_p95_ttv_seconds)}</div>
			<svg viewBox="0 0 200 36" class="w-full h-9 opacity-80">
				<path d={sparkline(trends?.buckets, 'p95_ttv_seconds')} fill="none" stroke="#fcd34d" stroke-width="1.5" />
			</svg>
		</div>
		<div class="card p-4 space-y-2">
			<div class="text-xs opacity-60 uppercase tracking-wide">{m.ana_p95_ttr_window()}</div>
			<div class="text-2xl font-semibold">{humanSeconds(trends?.window_p95_ttr_seconds)}</div>
			<svg viewBox="0 0 200 36" class="w-full h-9 opacity-80">
				<path d={sparkline(trends?.buckets, 'p95_ttr_seconds')} fill="none" stroke="#94a3b8" stroke-width="1.5" />
			</svg>
		</div>
		<div class="card p-4 space-y-2">
			<div class="text-xs opacity-60 uppercase tracking-wide">{m.ana_mssp_escalation_rate()}</div>
			<div class="text-2xl font-semibold">{escRate == null ? '—' : `${(escRate * 100).toFixed(1)}%`}</div>
			<div class="text-xs opacity-60">
				{m.ana_escalated_of_closed({ escalated: trends?.window_escalated_total ?? 0, closed: trends?.window_closed_total ?? 0 })}
			</div>
		</div>
	</section>

	<!-- Comparative ranking + heatmap, side by side -->
	<section class="grid grid-cols-1 lg:grid-cols-2 gap-4">
		<div class="card p-4" data-testid="panel-ranking">
			<header class="flex items-center justify-between flex-wrap gap-2 mb-3">
				<h3 class="text-sm font-semibold">{m.ana_top_worsening_tenants()}</h3>
				<select
					class="select select-sm w-32"
					bind:value={rankingMetric}
					on:change={refresh}
					data-testid="ranking-metric"
				>
					<option value="ttv">{m.ana_opt_p95_ttv()}</option>
					<option value="ttr">{m.ana_opt_p95_ttr()}</option>
				</select>
			</header>
			<div class="grid grid-cols-2 gap-2 text-xs mb-4">
				<div class="flex items-center justify-between bg-surface-700/40 rounded px-3 py-2">
					<span class="opacity-60">{m.ana_fleet_median()}</span>
					<span class="font-bold">{humanSeconds(ranking?.fleet_median_seconds)}</span>
				</div>
				<div class="flex items-center justify-between bg-surface-700/40 rounded px-3 py-2">
					<span class="opacity-60">{m.ana_min_sample()}</span>
					<span class="font-bold">{ranking?.min_sample ?? '—'}</span>
				</div>
			</div>
			{#if loading}
				<div class="opacity-60 text-sm py-6 text-center">{m.common_loading()}</div>
			{:else if errors.ranking}
				<div class="alert variant-filled-error text-sm">{errors.ranking}</div>
			{:else if !ranking || ranking.rows.length === 0}
				<div class="opacity-40 text-sm py-6 text-center">
					{m.ana_no_tenants_min_sample()}
				</div>
			{:else}
				<div class="space-y-1">
					{#each ranking.rows as r (r.tenant_id)}
						<button
							type="button"
							class="w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded
								   bg-surface-700/30 hover:bg-surface-700/60 transition-colors
								   text-left border-0 cursor-pointer"
							on:click={() => drillIntoTenant(r.slug)}
							title={m.ana_open_tenant_dashboard()}
						>
							<div class="min-w-0 flex-1">
								<div class="font-semibold truncate">{r.display_name || r.slug}</div>
								<div class="text-xs opacity-40 mt-0.5">
									{m.ana_sample_closed({ count: r.sample_current })}
									{#if r.sample_previous > 0}
										<span class="opacity-70">{m.ana_prev_sample({ count: r.sample_previous })}</span>
									{/if}
								</div>
							</div>
							<div class="text-right">
								<div class="font-bold">{humanSeconds(r.current_p95_seconds)}</div>
								<div class="text-xs opacity-40">{m.ana_current_p95()}</div>
							</div>
							<div class="text-right min-w-[4.5rem]">
								<div class="font-bold {deltaClass(r.delta_seconds)}">
									{deltaLabel(r.delta_seconds)}
								</div>
								<div class="text-xs opacity-40">{m.ana_vs_prev()}</div>
							</div>
						</button>
					{/each}
				</div>
			{/if}
		</div>

		<div class="card p-4 space-y-3" data-testid="panel-heatmap">
			<header class="flex items-center justify-between flex-wrap gap-2">
				<h2 class="h4">{m.ana_activity_heatmap()}</h2>
				<div class="flex items-center gap-2">
					<select
						class="select select-sm"
						bind:value={heatmapDimension}
						on:change={refresh}
						data-testid="heatmap-dimension"
					>
						<option value="alerts">{m.ana_opt_alerts()}</option>
						<option value="cases">{m.ana_opt_cases_opened()}</option>
					</select>
				</div>
			</header>
			<p class="opacity-60 text-xs">
				{m.ana_heatmap_hint({ days: trendDays })}
			</p>
			{#if loading}
				<p class="opacity-60 text-sm">{m.common_loading()}</p>
			{:else if errors.heatmap}
				<p class="text-error-500 text-sm">{errors.heatmap}</p>
			{:else if !heatmap || heatmap.cells.length === 0}
				<p class="opacity-60 text-sm">{m.ana_no_activity()}</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="text-xs font-mono" style="border-spacing: 1px; border-collapse: separate;">
						<thead>
							<tr>
								<th></th>
								{#each Array(24) as _, h}
									<th class="font-normal opacity-60 px-1" class:opacity-90={h % 6 === 0}>
										{h % 6 === 0 ? h : ''}
									</th>
								{/each}
							</tr>
						</thead>
						<tbody>
							{#each DOW_LABELS as label, dow}
								<tr>
									<td class="opacity-70 pr-2">{label()}</td>
									{#each Array(24) as _, hour}
										<td
											style="background: {heatColor(hm.cell(dow, hour), hm.max)}; width: 18px; height: 18px;"
											title={m.ana_heatmap_cell_title({ day: label(), hour, count: hm.cell(dow, hour) })}
										></td>
									{/each}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	</section>
</div>
