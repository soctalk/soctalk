<script lang="ts">
	import { createEventDispatcher, onMount } from 'svelte';
	import { m } from '$lib/paraglide/messages';
	import { buildLut, lutPoint, type PathLut } from './pathLut';
	import {
		LAPSE_MS,
		progressiveExact,
		scheduleTotals,
		type FleetScheduleEntry
	} from './fleetSchedule';
	import type { FleetDay } from './types';

	export let day: FleetDay;
	export let schedule: FleetScheduleEntry[] = [];
	/** Playback time in ms. Lapse: 0..LAPSE_MS. Live: server epoch ms. */
	export let t = 0;
	/** 'lapse' replays the day; 'live' renders the present on the server clock. */
	export let mode: 'lapse' | 'live' = 'lapse';
	/** Live only: open investigations by parked stage (from latest replay beat). */
	export let openByStage: Record<string, number> = {};
	/** Live only: exact today-so-far counters for fills/ribbons. */
	export let liveCounts: {
		ingested: number;
		closed: number;
		reasoning: number;
		escalated: number;
	} | null = null;

	const dispatch = createEventDispatcher<{ drill: { investigationId: string } }>();

	// Centerline rails per route; ribbons and glyphs are separate elements.
	const RAILS: Record<string, string> = {
		fast: 'M 4 210 H 92 M92 210 H 198 M204 222 C 204 355, 700 388, 972 390',
		reason:
			'M 4 210 H 92 M92 210 H 198 M212 210 H 418 M474 210 H 662 M738 210 H 838 M872 210 C 910 210, 930 262, 958 300',
		human:
			'M 4 210 H 92 M92 210 H 198 M212 210 H 418 M474 210 H 662 M738 210 H 838 M872 210 C 910 210, 930 158, 958 120',
		unknown: 'M 4 210 H 92 M92 210 H 198'
	};

	let railEls: Record<string, SVGPathElement | null> = {};
	let luts: Record<string, PathLut> = {};
	let ready = false;

	onMount(() => {
		const built: Record<string, PathLut> = {};
		for (const [route, el] of Object.entries(railEls)) {
			if (el) built[route] = buildLut(el, 160);
		}
		luts = built;
		ready = true;
	});

	interface LiveDot {
		entry: FleetScheduleEntry;
		x: number;
		y: number;
		veto: boolean;
	}

	// Single pass per tick (#72 quality pass): active dots and all four
	// counters in one O(n) scan instead of five.
	$: scan = (() => {
		const active: LiveDot[] = [];
		let arrFast = 0;
		let arrMain = 0;
		let doneClosed = 0;
		let doneHuman = 0;
		for (const entry of schedule) {
			if (entry.t > t) continue;
			if (entry.route === 'fast') arrFast++;
			else if (entry.route === 'reason' || entry.route === 'human') arrMain++;
			if (entry.land <= t) {
				if (entry.route === 'fast' || entry.route === 'reason') doneClosed++;
				else if (entry.route === 'human') doneHuman++;
			} else if (ready) {
				const lut = luts[entry.route];
				if (lut) {
					const frac = (t - entry.t) / Math.max(1, entry.land - entry.t);
					const p = lutPoint(lut, frac);
					active.push({
						entry,
						x: p.x,
						y: p.y + entry.jit,
						veto: entry.dot.veto && frac > 0.8
					});
				}
			}
		}
		return { active, arrFast, arrMain, doneClosed, doneHuman };
	})();
	$: activeDots = scan.active;
	$: arrFast = scan.arrFast;
	$: arrMain = scan.arrMain;
	$: doneClosed = scan.doneClosed;
	$: doneHuman = scan.doneHuman;

	// Column labels AND fills share one progressive basis (a
	// label scaled one way over a fill scaled another can visibly
	// disagree under sampling): the landed-dot fraction projected onto
	// the exact day aggregates in lapse mode, the exact today-so-far
	// counters on the live head.
	$: totals = scheduleTotals(schedule);
	$: lapseAtEnd = mode === 'lapse' && t >= LAPSE_MS - 1;
	$: dayClosedExact =
		day.closed_ingest_memoized + day.closed_ingest_rules + day.closed_operational + day.closed_reasoning;
	$: closedLabel = liveCounts
		? liveCounts.closed
		: progressiveExact(doneClosed, totals.closed, dayClosedExact, lapseAtEnd);
	$: humanLabel = liveCounts
		? liveCounts.escalated
		: progressiveExact(doneHuman, totals.human, day.escalated, lapseAtEnd);

	const totalDay = () => Math.max(1, liveCounts?.ingested ?? day.ingested);
	const VESSEL_H = 144;
	$: closeFillH = Math.min(VESSEL_H, (closedLabel / totalDay()) * VESSEL_H);
	$: humanFillH = Math.min(VESSEL_H, (humanLabel / totalDay()) * VESSEL_H);
	const ribWidth = (frac: number) => (frac <= 0 ? 0 : 1.5 + 15 * Math.min(1, frac));
	$: fastFrac = liveCounts
		? Math.max(0, liveCounts.closed - liveCounts.reasoning) / totalDay()
		: arrFast / Math.max(1, schedule.length);
	$: mainFrac = liveCounts
		? (liveCounts.reasoning + liveCounts.escalated) / totalDay()
		: arrMain / Math.max(1, schedule.length);
	$: guardHot = activeDots.some((d) => d.veto);

	// Live stage badges: worker stages collapse onto the supervisor hub at
	// this altitude (the fleet map has no worker satellites); 'unknown' is
	// reported in the rail, never faked onto a node.
	const BADGE_POS: Record<string, { x: number; y: number }> = {
		gate: { x: 244, y: 126 },
		sup: { x: 446, y: 164 },
		verdict: { x: 700, y: 164 },
		guard: { x: 884, y: 122 },
		human: { x: 938, y: 150 }
	};
	$: badges =
		mode === 'live'
			? Object.entries(
					Object.entries(openByStage).reduce<Record<string, number>>((acc, [stage, n]) => {
						const target = ['wazuh', 'cortex', 'misp', 'authz', 'thehive'].includes(stage)
							? 'sup'
							: stage;
						if (target in BADGE_POS) acc[target] = (acc[target] ?? 0) + n;
						return acc;
					}, {})
				).filter(([, n]) => n > 0)
			: [];

	function onDotClick(dot: LiveDot) {
		if (dot.entry.dot.investigation_id) {
			dispatch('drill', { investigationId: dot.entry.dot.investigation_id });
		}
	}
</script>

<div class="map-wrap" data-testid="fleet-map">
	<svg viewBox="0 0 1080 420" role="img" aria-label={m.fleet_title()}>
		<!-- volume ribbons (lapse: sample-derived; live: exact counters) -->
		<path class="rib rib-fast" style={`stroke-width:${ribWidth(fastFrac)}`} d="M204 222 C 204 355, 700 388, 972 390" />
		<path class="rib rib-main" style={`stroke-width:${ribWidth(mainFrac)}`} d="M212 210 H 836" />

		<!-- dot rails (invisible; sampled into LUTs at mount) -->
		{#each Object.entries(RAILS) as [route, d] (route)}
			<path class="rail" {d} bind:this={railEls[route]} />
		{/each}

		<!-- dots: every one is a real sampled alert -->
		{#each activeDots as dot (dot.entry.dot.alert_id)}
			<circle
				class="fdot {dot.veto ? 'veto' : ''} {dot.entry.dot.investigation_id ? 'clickable' : ''}"
				cx={dot.x}
				cy={dot.y}
				r="3.2"
				role="button"
				tabindex="-1"
				aria-label={dot.entry.dot.alert_id}
				on:click={() => onDotClick(dot)}
				on:keydown={(e) => e.key === 'Enter' && onDotClick(dot)}
			/>
		{/each}

		<!-- intake funnel: ingest genuinely coalesces events into alerts -->
		<polygon class="glyph" points="4,168 88,200 88,220 4,252" />
		<text class="glabel" x="8" y="156">{m.replay_node_alert()}</text>

		<!-- policy gate: barrier with a slit -->
		<rect class="gbar" x="198" y="138" width="11" height="62" />
		<rect class="gbar" x="198" y="220" width="11" height="62" />
		<text class="glabel" x="160" y="126">{m.replay_node_gate()}</text>

		<!-- supervisor hub -->
		<circle class="hub" cx="446" cy="210" r="27" />
		<text class="glabel" x="404" y="258">{m.replay_node_sup()}</text>

		<!-- verdict: explicit three-state decision element -->
		<rect class="glyph" x="662" y="178" width="76" height="64" rx="6" />
		<text class="vchip" x="700" y="197" text-anchor="middle">CLOSE</text>
		<text class="vchip" x="700" y="213" text-anchor="middle">ESCALATE</text>
		<text class="vchip" x="700" y="229" text-anchor="middle">MORE INFO</text>
		<text class="glabel" x="672" y="262">{m.replay_node_verdict()}</text>

		<!-- guard: the hard floor -->
		<g class:hot={guardHot}>
			<rect class="gbar heavy" x="842" y="134" width="9" height="66" />
			<rect class="gbar heavy" x="842" y="220" width="9" height="66" />
			<rect class="gbar heavy" x="858" y="134" width="9" height="66" />
			<rect class="gbar heavy" x="858" y="220" width="9" height="66" />
		</g>
		<text class="glabel" x="832" y="122">{m.replay_node_guard()}</text>

		<!-- outcome columns, one shared scale -->
		<rect class="vtrack" x="962" y="28" width="92" height="152" />
		<rect class="vfill warn" x="966" y={176 - humanFillH} width="84" height={humanFillH} />
		<text class="glabel" x="962" y="196">{m.replay_node_human()}</text>
		<text class="cnt warn" x="1054" y="212" text-anchor="end">{humanLabel}</text>

		<rect class="vtrack" x="962" y="240" width="92" height="152" />
		<rect class="vfill good" x="966" y={388 - closeFillH} width="84" height={closeFillH} />
		<text class="glabel" x="962" y="232">{m.replay_node_close()}</text>
		<text class="cnt good" x="1054" y="416" text-anchor="end">{closedLabel}</text>

		<text class="glabel tiny" x="430" y="366">{m.replay_fast_path_label()}</text>

		<!-- live: open investigations parked by stage (honest queue depth) -->
		{#each badges as [stage, count] (stage)}
			<g class="badge-pill" data-stage={stage}>
				<rect x={BADGE_POS[stage].x - 16} y={BADGE_POS[stage].y - 11} width="32" height="16" rx="8" />
				<text x={BADGE_POS[stage].x} y={BADGE_POS[stage].y + 1} text-anchor="middle">{count}</text>
			</g>
		{/each}
	</svg>
</div>

<style>
	.map-wrap {
		overflow-x: auto;
	}
	svg {
		display: block;
		min-width: 720px;
		width: 100%;
		height: auto;
	}
	.rail {
		stroke: rgb(var(--color-surface-500) / 0.15);
		stroke-width: 1;
		fill: none;
	}
	.rib {
		fill: none;
		stroke-linecap: round;
		transition: stroke-width 0.3s linear;
	}
	.rib-fast {
		stroke: rgb(var(--color-success-500) / 0.2);
	}
	.rib-main {
		stroke: rgb(var(--color-primary-500) / 0.15);
	}
	.fdot {
		fill: rgb(var(--color-primary-400));
	}
	.fdot.veto {
		fill: rgb(var(--color-warning-500));
	}
	.fdot.clickable {
		cursor: pointer;
	}
	.glyph,
	.gbar,
	.hub,
	.vtrack {
		fill: rgb(var(--color-surface-700) / 0.6);
		stroke: rgb(var(--color-surface-400) / 0.4);
		stroke-width: 1.4;
	}
	.gbar.heavy {
		fill: rgb(var(--color-surface-600) / 0.8);
		stroke: rgb(var(--color-surface-300) / 0.6);
		stroke-width: 2;
	}
	g.hot .gbar.heavy {
		fill: rgb(var(--color-error-500) / 0.25);
		stroke: rgb(var(--color-error-500));
	}
	.vfill.good {
		fill: rgb(var(--color-success-500) / 0.85);
	}
	.vfill.warn {
		fill: rgb(var(--color-warning-500) / 0.85);
	}
	.glabel {
		fill: rgb(var(--color-surface-400));
		font-family: ui-monospace, 'SF Mono', Menlo, monospace;
		font-size: 10px;
		letter-spacing: 0.12em;
	}
	.glabel.tiny {
		font-size: 8.5px;
	}
	.vchip {
		fill: rgb(var(--color-surface-400));
		font-family: ui-monospace, Menlo, monospace;
		font-size: 8.5px;
		letter-spacing: 0.1em;
	}
	.cnt {
		font-family: ui-monospace, Menlo, monospace;
		font-size: 15px;
		font-variant-numeric: tabular-nums;
	}
	.cnt.good {
		fill: rgb(var(--color-success-400));
	}
	.cnt.warn {
		fill: rgb(var(--color-warning-400));
	}
	.badge-pill rect {
		fill: rgb(var(--color-primary-500) / 0.18);
		stroke: rgb(var(--color-primary-500) / 0.6);
		stroke-width: 1;
	}
	.badge-pill text {
		fill: rgb(var(--color-primary-300));
		font-family: ui-monospace, Menlo, monospace;
		font-size: 10px;
		font-variant-numeric: tabular-nums;
	}
</style>
