<script lang="ts">
	// Read-only diagram of a response playbook: the disposition envelope fans out
	// to on_escalate / on_close actions; gated actions route through a human
	// approval node before executing, tier-0 actions execute directly. The
	// document is the source of truth — this canvas is derived.
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
	import ResponseFlowNode from './ResponseFlowNode.svelte';
	import { CAP_BY_NAME, whenToSentence, type ResponsePlaybookDef } from './schema';

	export let definition: ResponsePlaybookDef;

	const nodeTypes = { rp: ResponseFlowNode } as unknown as NodeTypes;
	const nodes = writable<Node[]>([]);
	const edges = writable<Edge[]>([]);
	let layoutKey = '';

	const NODE_W = 260;
	const CHARS_PER_LINE = 42;

	function estSize(data: Record<string, unknown>): { width: number; height: number } {
		let h = 30;
		const st = typeof data.subtitle === 'string' ? data.subtitle : '';
		if (st) {
			const lines = st
				.split('\n')
				.reduce((n, l) => n + Math.max(1, Math.ceil(l.length / CHARS_PER_LINE)), 0);
			h += lines * 13 + 4;
		}
		return { width: NODE_W, height: h };
	}

	function runLayout(ns: Node[], es: Edge[]): void {
		const g = new dagre.graphlib.Graph();
		g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 40, marginx: 8, marginy: 8 });
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

	function matchSummary(def: ResponsePlaybookDef): string {
		const m = def.applies_to ?? {};
		const parts: string[] = [];
		if (m.rule_groups?.length) parts.push(`groups: ${m.rule_groups.join(', ')}`);
		if (m.rule_ids?.length) parts.push(`rules: ${m.rule_ids.join(', ')}`);
		if (m.mitre_techniques?.length) parts.push(`ATT&CK: ${m.mitre_techniques.join(', ')}`);
		if (m.mitre_tactics?.length) parts.push(`tactics: ${m.mitre_tactics.join(', ')}`);
		return parts.join('\n') || 'matches every alert';
	}

	function rebuild(def: ResponsePlaybookDef) {
		const ns: Node[] = [];
		const es: Edge[] = [];

		ns.push({
			id: 'env',
			type: 'rp',
			position: { x: 0, y: 0 },
			data: { title: 'Effective disposition', subtitle: matchSummary(def), kind: 'envelope', hasNext: true },
			draggable: false,
			connectable: false
		});

		let approvalAdded = false;
		function ensureApproval(): string {
			if (!approvalAdded) {
				ns.push({
					id: 'approval',
					type: 'rp',
					position: { x: 0, y: 0 },
					data: {
						title: 'Human approval',
						subtitle: 'gated actions wait for an\nanalyst before they execute',
						kind: 'approval'
					},
					draggable: false,
					connectable: false
				});
				approvalAdded = true;
			}
			return 'approval';
		}

		function branch(which: 'escalate' | 'close', title: string, actions: unknown[]) {
			if (!actions.length) return;
			const bid = `phase-${which}`;
			ns.push({
				id: bid,
				type: 'rp',
				position: { x: 0, y: 0 },
				data: { title, kind: which, hasTarget: true, hasNext: true },
				draggable: false,
				connectable: false
			});
			es.push({ id: `env->${bid}`, source: 'env', target: bid, type: 'smoothstep' });
			(actions as Record<string, unknown>[]).forEach((a, i) => {
				const cap = String(a.capability ?? '');
				const meta = CAP_BY_NAME[cap];
				const gated = meta ? !meta.autonomous : false;
				const aid = `${which}-${i}`;
				const sub: string[] = [];
				if (a.when) sub.push(`when ${whenToSentence(a.when)}`);
				sub.push(gated ? 'routes to approval' : 'fires automatically');
				ns.push({
					id: aid,
					type: 'rp',
					position: { x: 0, y: 0 },
					data: {
						title: meta?.label ?? cap,
						subtitle: sub.join('\n'),
						kind: gated ? 'gated' : 'auto',
						badge: gated ? 'gated' : 'autonomous',
						hasTarget: true,
						hasFires: gated
					},
					draggable: false,
					connectable: false
				});
				es.push({ id: `${bid}->${aid}`, source: bid, target: aid, type: 'smoothstep' });
				if (gated) {
					const ap = ensureApproval();
					es.push({
						id: `${aid}->${ap}`,
						source: aid,
						sourceHandle: 'fires',
						target: ap,
						type: 'smoothstep',
						animated: true,
						label: 'approve'
					});
				}
			});
		}

		branch('escalate', 'On escalate', def.response?.on_escalate ?? []);
		branch('close', 'On close', def.response?.on_close ?? []);

		if (ns.length === 1) {
			ns[0].data.hasNext = false;
			ns.push({
				id: 'empty',
				type: 'rp',
				position: { x: 0, y: 0 },
				data: { title: 'No actions yet', subtitle: 'add an action to see the flow', kind: 'execute', hasTarget: true },
				draggable: false,
				connectable: false
			});
			es.push({ id: 'env->empty', source: 'env', target: 'empty', type: 'smoothstep' });
		}

		runLayout(ns, es);
		nodes.set(ns);
		edges.set(es);
		layoutKey = ns.map((n) => n.id).join('|');
	}

	$: rebuild(definition);
</script>

<div class="h-full w-full rp-flow">
	{#key layoutKey}
		<SvelteFlow
			{nodes}
			{edges}
			{nodeTypes}
			fitView
			minZoom={0.25}
			nodesDraggable={false}
			nodesConnectable={false}
			elementsSelectable={false}
			proOptions={{ hideAttribution: false }}
		>
			<Background />
			<Controls showLock={false} />
		</SvelteFlow>
	{/key}
</div>

<style>
	.rp-flow :global(.svelte-flow) {
		background: transparent;
	}
	.rp-flow :global(.svelte-flow__edge-textbg) {
		fill: rgb(var(--color-surface-800) / 1);
	}
	.rp-flow :global(.svelte-flow__edge-text) {
		fill: rgb(var(--color-surface-200) / 1);
		font-size: 9px;
	}
	/* Theme the zoom/pan controls for the dark UI — the library default is a
	   white box with black icons, which clashes with the surface theme. */
	.rp-flow :global(.svelte-flow__controls) {
		box-shadow: none;
	}
	.rp-flow :global(.svelte-flow__controls-button) {
		background: rgb(var(--color-surface-700) / 1);
		border-bottom: 1px solid rgb(var(--color-surface-500) / 0.25);
		color: rgb(var(--color-surface-100) / 1);
	}
	.rp-flow :global(.svelte-flow__controls-button:hover) {
		background: rgb(var(--color-surface-600) / 1);
	}
	.rp-flow :global(.svelte-flow__controls-button svg) {
		fill: rgb(var(--color-surface-100) / 1);
	}
	.rp-flow :global(.svelte-flow__attribution) {
		background: transparent;
		color: rgb(var(--color-surface-400) / 0.6);
	}
</style>
