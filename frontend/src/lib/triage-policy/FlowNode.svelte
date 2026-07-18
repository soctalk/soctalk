<script lang="ts">
	import { Handle, Position } from '@xyflow/svelte';
	import { m } from '$lib/paraglide/messages';

	export let data: {
		title: string;
		subtitle?: string;
		kind:
			| 'alert'
			| 'phase'
			| 'verdict'
			| 'floor'
			| 'guardrail'
			| 'signoff'
			| 'outcome'
			| 'terminal';
		/** Outcome accent: escalate | needs_more_info | human_review | commit */
		accent?: string;
		/** Right-side "fires" output toward an outcome node. */
		hasFires?: boolean;
		/** Chain continues below. */
		hasNext?: boolean;
		/** Chain input above. */
		hasTarget?: boolean;
		/** The Try-it simulation says this node disposes the draft. */
		fired?: boolean;
	};

	const KIND_CLASSES: Record<string, string> = {
		alert: 'border-primary-500 bg-primary-500/10',
		phase: 'border-surface-400 bg-surface-500/10',
		verdict: 'border-secondary-500 bg-secondary-500/10',
		floor: 'border-error-500/60 bg-error-500/5 border-dashed',
		guardrail: 'border-warning-500 bg-warning-500/10',
		signoff: 'border-tertiary-500 bg-tertiary-500/10',
		outcome: '',
		terminal: 'border-success-500 bg-success-500/10'
	};

	const ACCENT_CLASSES: Record<string, string> = {
		escalate: 'border-error-500 bg-error-500/15',
		needs_more_info: 'border-warning-500 bg-warning-500/15',
		human_review: 'border-tertiary-500 bg-tertiary-500/15',
		commit: 'border-success-500 bg-success-500/15'
	};

	$: cls =
		data.kind === 'outcome'
			? ACCENT_CLASSES[data.accent ?? ''] ?? 'border-surface-400'
			: KIND_CLASSES[data.kind];
</script>

<div
	class="rounded-lg border-2 px-3 py-2 max-w-[15rem] text-left {cls} {data.fired
		? 'ring-2 ring-warning-400 shadow-lg shadow-warning-500/20'
		: ''}"
>
	{#if data.fired}
		<div class="text-[9px] font-bold uppercase tracking-wide text-warning-500">
			{m.tp_flow_would_fire()}
		</div>
	{/if}
	{#if data.hasTarget}
		<Handle type="target" position={Position.Top} class="!bg-surface-400" />
	{/if}
	{#if data.kind === 'outcome'}
		<Handle type="target" position={Position.Left} class="!bg-surface-400" />
	{/if}
	<div class="text-xs font-semibold leading-tight">{data.title}</div>
	{#if data.subtitle}
		<div class="text-[10px] opacity-70 mt-0.5 leading-snug whitespace-pre-line">
			{data.subtitle}
		</div>
	{/if}
	{#if data.hasNext}
		<Handle type="source" position={Position.Bottom} class="!bg-surface-400" />
	{/if}
	{#if data.hasFires}
		<Handle id="fires" type="source" position={Position.Right} class="!bg-warning-500" />
	{/if}
</div>
