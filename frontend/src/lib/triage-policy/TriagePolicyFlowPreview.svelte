<script lang="ts">
	// Read-only projection of a triage-policy definition onto the guard pipeline.
	// The document is the source of truth; this canvas is derived, never edited
	// directly (Windmill/Kestra pattern). Clicking a guardrail node emits
	// `focus` so the editor can scroll to that rule's form. Positions come from
	// dagre (top-down layered layout), so node heights can vary with content.
	import { createEventDispatcher } from 'svelte';
	import { writable } from 'svelte/store';
	import {
		SvelteFlow,
		Background,
		Controls,
		type Node,
		type Edge,
		type NodeTypes
	} from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';
	import dagre from '@dagrejs/dagre';
	import FlowNode from './FlowNode.svelte';
	import { m } from '$lib/paraglide/messages';
	import { conditionToSentence, type TriagePolicyDef } from './schema';

	export let definition: TriagePolicyDef;
	/** Node id the Try-it simulation says would dispose the draft — highlighted. */
	export let firedNodeId: string | null = null;
	/** Compact mode: intake chain merged into one node, subtitles hidden. */
	export let compact = false;

	const dispatch = createEventDispatcher<{ focus: { guardrail: number } }>();

	// FlowNode only declares the `data` prop it uses; the wrapper injects the rest.
	const nodeTypes = { pb: FlowNode } as unknown as NodeTypes;
	const nodes = writable<Node[]>([]);
	const edges = writable<Edge[]>([]);

	// SvelteFlow 0.1.x only fits the view on mount — re-key the component when
	// the projected structure changes so it re-fits (cheap at this graph size).
	let layoutKey = '';

	function matchSummary(def: TriagePolicyDef): string {
		const applies = def.applies_to ?? {};
		const parts: string[] = [];
		if (applies.rule_groups?.length) parts.push(m.tp_match_groups({ v: applies.rule_groups.join(', ') }));
		if (applies.rule_ids?.length) parts.push(m.tp_match_rules({ v: applies.rule_ids.join(', ') }));
		if (applies.authorization_tracks?.length)
			parts.push(m.tp_match_authz_track({ v: applies.authorization_tracks.join(', ') }));
		return parts.join('\n') || m.tp_match_none();
	}

	function outcomeTitle(accent: string): string {
		switch (accent) {
			case 'escalate':
				return m.tp_flow_outcome_escalate();
			case 'needs_more_info':
				return m.tp_flow_outcome_needs_more_info();
			case 'human_review':
				return m.tp_flow_outcome_human_review();
			case 'commit':
				return m.tp_flow_outcome_commit();
			default:
				return m.tp_flow_invalid_target({
					target: accent || m.tp_flow_empty_target()
				});
		}
	}

	// ------------------------------------------------------------ size model
	// dagre needs node dimensions up front; these mirror FlowNode's rendering
	// (max-w-[15rem], text-xs title, 10px subtitle, px-3 py-2).

	const NODE_W = 250;
	const OUTCOME_W = 130;
	const CHARS_PER_LINE = 40;

	function estSize(data: Record<string, unknown>): { width: number; height: number } {
		if (data.kind === 'outcome') return { width: OUTCOME_W, height: 40 };
		let h = 30; // padding + title
		const subtitle = typeof data.subtitle === 'string' ? data.subtitle : '';
		if (subtitle) {
			const lines = subtitle
				.split('\n')
				.reduce((n, l) => n + Math.max(1, Math.ceil(l.length / CHARS_PER_LINE)), 0);
			h += lines * 13 + 4;
		}
		if (data.fired) h += 14;
		return { width: NODE_W, height: h };
	}

	function runLayout(ns: Node[], es: Edge[]): void {
		const g = new dagre.graphlib.Graph();
		g.setGraph({ rankdir: 'TB', nodesep: 50, ranksep: 34, marginx: 8, marginy: 8 });
		g.setDefaultEdgeLabel(() => ({}));
		for (const n of ns) g.setNode(n.id, estSize(n.data as Record<string, unknown>));
		for (const e of es) g.setEdge(e.source, e.target);
		dagre.layout(g);
		for (const n of ns) {
			const p = g.node(n.id);
			const s = estSize(n.data as Record<string, unknown>);
			n.position = { x: p.x - s.width / 2, y: p.y - s.height / 2 };
		}
	}

	// ------------------------------------------------------------- projection

	function rebuild(def: TriagePolicyDef, dense: boolean) {
		const ns: Node[] = [];
		const es: Edge[] = [];
		const outcomesUsed = new Map<string, string>();
		let prev: string | null = null;

		function chainNode(id: string, data: Record<string, unknown>): void {
			if (dense) delete data.subtitle;
			ns.push({
				id,
				type: 'pb',
				position: { x: 0, y: 0 }, // dagre assigns
				data: { hasTarget: prev !== null, hasNext: false, fired: id === firedNodeId, ...data },
				draggable: false,
				connectable: false
			});
			if (prev !== null) {
				const p = ns.find((n) => n.id === prev);
				if (p) (p.data as Record<string, unknown>).hasNext = true;
				es.push({ id: `${prev}->${id}`, source: prev, target: id, type: 'smoothstep' });
			}
			prev = id;
		}

		function outcome(accent: string): string {
			let id = outcomesUsed.get(accent);
			if (!id) {
				id = `outcome-${accent}`;
				outcomesUsed.set(accent, id);
				ns.push({
					id,
					type: 'pb',
					position: { x: 0, y: 0 },
					// A mid-edit JSON `to` can be any string — never crash the projection.
					data: {
						title: outcomeTitle(accent),
						kind: 'outcome',
						accent
					},
					draggable: false,
					connectable: false
				});
			}
			return id;
		}

		function fires(from: string, accent: string, label: string) {
			es.push({
				id: `${from}->outcome-${accent}`,
				source: from,
				sourceHandle: 'fires',
				target: outcome(accent),
				label: dense ? undefined : label,
				type: 'smoothstep',
				animated: true
			});
		}

		if (dense) {
			// the intake chain never varies per-rule — collapse it to one node
			chainNode('alert', { title: m.tp_flow_dense_intake(), kind: 'verdict' });
		} else {
			chainNode('alert', {
				title: m.tp_flow_alert_matches_policy(),
				subtitle: matchSummary(def),
				kind: 'alert'
			});
			const steps = def.required_steps ?? [];
			const legal = def.legal_actions ?? {};
			if (steps.length || legal.triage?.length) {
				const lines: string[] = [];
				if (steps.length) lines.push(m.tp_flow_must_run_first({ steps: steps.join(', ') }));
				if (legal.triage?.length)
					lines.push(m.tp_flow_allowed_actions({ actions: legal.triage.join(', ') }));
				chainNode('triage', { title: m.tp_flow_triage_phase(), subtitle: lines.join('\n'), kind: 'phase' });
			}
			if (legal.decide?.length) {
				chainNode('decide', {
					title: m.tp_flow_decide_phase(),
					subtitle: m.tp_flow_allowed_actions({ actions: legal.decide.join(', ') }),
					kind: 'phase'
				});
			}
			chainNode('verdict', {
				title: m.tp_flow_llm_drafts_verdict(),
				subtitle: m.tp_flow_llm_drafts_verdict_subtitle(),
				kind: 'verdict'
			});
		}

		chainNode('floor', {
			title: m.tp_flow_safety_floor_title(),
			subtitle: m.tp_flow_safety_floor_subtitle(),
			kind: 'floor',
			hasFires: true
		});
		fires('floor', 'escalate', m.tp_flow_fires());

		(def.guardrails ?? []).forEach((g, i) => {
			chainNode(`guardrail-${i}`, {
				title: m.tp_flow_guardrail_title({ n: i + 1, effect: g.effect }),
				subtitle: m.tp_flow_when({ condition: conditionToSentence(g.when) }),
				kind: 'guardrail',
				hasFires: true
			});
			fires(
				`guardrail-${i}`,
				g.to,
				g.effect === 'interrupt'
					? m.tp_flow_interrupt()
					: m.tp_flow_raise_to({ target: g.to })
			);
		});

		const signoff = def.close_signoff_data_classes ?? [];
		if (signoff.length) {
			chainNode('signoff', {
				title: m.tp_flow_close_signoff_title(),
				subtitle: m.tp_flow_close_signoff_subtitle({ classes: signoff.join('/') }),
				kind: 'signoff',
				hasFires: true
			});
			fires('signoff', 'human_review', m.tp_flow_interrupt());
		}

		chainNode('commit', {
			title: m.tp_flow_commit_title(),
			subtitle: m.tp_flow_no_guardrail_fired(),
			kind: 'terminal'
		});

		runLayout(ns, es);
		nodes.set(ns);
		edges.set(es);
		layoutKey = (dense ? 'c|' : 'f|') + ns.map((n) => n.id).join('|');
	}

	$: {
		firedNodeId; // re-project when the simulated firing node changes too
		rebuild(definition, compact);
	}

	function onNodeClick(e: CustomEvent<{ node: Node }>) {
		const m = /^guardrail-(\d+)$/.exec(e.detail.node.id);
		if (m) dispatch('focus', { guardrail: Number(m[1]) });
	}
</script>

<div class="h-full w-full pb-flow">
	{#key layoutKey}
	<SvelteFlow
		{nodes}
		{edges}
		{nodeTypes}
		fitView
		minZoom={0.25}
		nodesDraggable={false}
		nodesConnectable={false}
		elementsSelectable={true}
		proOptions={{ hideAttribution: false }}
		on:nodeclick={onNodeClick}
	>
		<Background />
		<Controls showLock={false} />
	</SvelteFlow>
	{/key}
</div>

<style>
	.pb-flow :global(.svelte-flow) {
		background: transparent;
	}
	.pb-flow :global(.svelte-flow__edge-textbg) {
		fill: rgb(var(--color-surface-800) / 1);
	}
	.pb-flow :global(.svelte-flow__edge-text) {
		fill: rgb(var(--color-surface-200) / 1);
		font-size: 9px;
	}
	/* Theme the zoom/pan controls for the dark UI — the library default is a
	   white box with black icons that clashes with the surface theme. */
	.pb-flow :global(.svelte-flow__controls) {
		box-shadow: none;
	}
	.pb-flow :global(.svelte-flow__controls-button) {
		background: rgb(var(--color-surface-700) / 1);
		border-bottom: 1px solid rgb(var(--color-surface-500) / 0.25);
		color: rgb(var(--color-surface-100) / 1);
	}
	.pb-flow :global(.svelte-flow__controls-button:hover) {
		background: rgb(var(--color-surface-600) / 1);
	}
	.pb-flow :global(.svelte-flow__controls-button svg) {
		fill: rgb(var(--color-surface-100) / 1);
	}
	.pb-flow :global(.svelte-flow__attribution) {
		background: transparent;
		color: rgb(var(--color-surface-400) / 0.6);
	}
</style>
