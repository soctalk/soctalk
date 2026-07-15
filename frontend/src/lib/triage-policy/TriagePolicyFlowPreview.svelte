<script lang="ts">
	// Read-only projection of a playbook definition onto the guard pipeline.
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
		const m = def.applies_to ?? {};
		const parts: string[] = [];
		if (m.rule_groups?.length) parts.push(`groups: ${m.rule_groups.join(', ')}`);
		if (m.rule_ids?.length) parts.push(`rules: ${m.rule_ids.join(', ')}`);
		if (m.authorization_tracks?.length) parts.push(`authz track: ${m.authorization_tracks.join(', ')}`);
		return parts.join('\n') || 'no matchers yet — matches nothing';
	}

	const OUTCOME_META: Record<string, { title: string }> = {
		escalate: { title: 'Escalate' },
		needs_more_info: { title: 'Needs more info' },
		human_review: { title: 'Human review' },
		commit: { title: 'Decision commits' }
	};

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
					data: { title: OUTCOME_META[accent].title, kind: 'outcome', accent },
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
			chainNode('alert', { title: 'Intake → LLM verdict draft', kind: 'verdict' });
		} else {
			chainNode('alert', {
				title: 'Alert matches playbook',
				subtitle: matchSummary(def),
				kind: 'alert'
			});
			const steps = def.required_steps ?? [];
			const legal = def.legal_actions ?? {};
			if (steps.length || legal.triage?.length) {
				const lines: string[] = [];
				if (steps.length) lines.push(`must run first: ${steps.join(', ')}`);
				if (legal.triage?.length) lines.push(`allowed actions: ${legal.triage.join(', ')}`);
				chainNode('triage', { title: 'Triage phase', subtitle: lines.join('\n'), kind: 'phase' });
			}
			if (legal.decide?.length) {
				chainNode('decide', {
					title: 'Decide phase',
					subtitle: `allowed actions: ${legal.decide.join(', ')}`,
					kind: 'phase'
				});
			}
			chainNode('verdict', {
				title: 'LLM drafts a verdict',
				subtitle: 'close · needs_more_info · escalate\n(proposes — the guard disposes)',
				kind: 'verdict'
			});
		}

		chainNode('floor', {
			title: 'Safety floor — always on',
			subtitle: 'IOC present or contradicted authorization\ncaps any close at escalate (not editable)',
			kind: 'floor',
			hasFires: true
		});
		fires('floor', 'escalate', 'fires');

		(def.guardrails ?? []).forEach((g, i) => {
			chainNode(`guardrail-${i}`, {
				title: `Guardrail ${i + 1} — ${g.effect}`,
				subtitle: `when ${conditionToSentence(g.when)}`,
				kind: 'guardrail',
				hasFires: true
			});
			fires(`guardrail-${i}`, g.to, g.effect === 'interrupt' ? 'interrupt' : `raise to ${g.to}`);
		});

		const signoff = def.close_signoff_data_classes ?? [];
		if (signoff.length) {
			chainNode('signoff', {
				title: 'Close sign-off',
				subtitle: `a close on a ${signoff.join('/')} asset\nwaits for a human`,
				kind: 'signoff',
				hasFires: true
			});
			fires('signoff', 'human_review', 'interrupt');
		}

		chainNode('commit', {
			title: 'Decision commits as drafted',
			subtitle: 'no guardrail fired',
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
</style>
