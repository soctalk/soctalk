<script lang="ts">
	import { Handle, Position } from '@xyflow/svelte';
	import { m } from '$lib/paraglide/messages';

	export let data: {
		title: string;
		subtitle?: string;
		kind: 'envelope' | 'escalate' | 'close' | 'auto' | 'gated' | 'approval' | 'execute';
		badge?: string;
		hasTarget?: boolean;
		hasNext?: boolean;
		hasFires?: boolean;
	};

	const KIND_CLASSES: Record<string, string> = {
		envelope: 'border-primary-500 bg-primary-500/10',
		escalate: 'border-error-500 bg-error-500/10',
		close: 'border-success-500 bg-success-500/10',
		auto: 'border-secondary-500 bg-secondary-500/10',
		gated: 'border-warning-500 bg-warning-500/10 border-dashed',
		approval: 'border-tertiary-500 bg-tertiary-500/15',
		execute: 'border-surface-400 bg-surface-500/10'
	};

	const BADGE_CLASSES: Record<string, string> = {
		autonomous: 'variant-soft-secondary',
		gated: 'variant-soft-warning'
	};
</script>

<div class="rounded-lg border-2 px-3 py-2 max-w-[16rem] text-left {KIND_CLASSES[data.kind]}">
	{#if data.hasTarget}
		<Handle type="target" position={Position.Top} class="!bg-surface-400" />
	{/if}
	{#if data.kind === 'approval' || data.kind === 'execute'}
		<Handle type="target" position={Position.Left} class="!bg-surface-400" />
	{/if}
	<div class="flex items-center gap-2">
		<div class="text-xs font-semibold leading-tight flex-1">{data.title}</div>
		{#if data.badge}
			<span class="badge {BADGE_CLASSES[data.badge] ?? 'variant-soft'} text-[9px] uppercase"
				>{data.badge === 'gated' ? m.badge_gated() : m.badge_autonomous()}</span
			>
		{/if}
	</div>
	{#if data.subtitle}
		<div class="text-[10px] opacity-70 mt-0.5 leading-snug whitespace-pre-line">{data.subtitle}</div>
	{/if}
	{#if data.hasNext}
		<Handle type="source" position={Position.Bottom} class="!bg-surface-400" />
	{/if}
	{#if data.hasFires}
		<Handle id="fires" type="source" position={Position.Right} class="!bg-warning-500" />
	{/if}
</div>
