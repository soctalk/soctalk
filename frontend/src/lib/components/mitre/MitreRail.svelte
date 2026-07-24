<!--
  MitreRail — the ATT&CK evidence rail (issue #71).

  Every tactic of the pinned ATT&CK version is always rendered, in
  canonical matrix order, so position stays learnable; mapped tactics are
  highlighted. Binary encoding only (mapped / not) — severity and counts
  live elsewhere by design. Count badges appear only when the caller opts
  in (investigation-level union view).

  Tactic labels are MITRE's canonical English domain terms and are
  deliberately not localized.
-->
<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { TACTIC_ORDER, tacticAbbrev } from '$lib/mitre/attack';

	/** TA id → technique (or contributing-alert) count. Presence = mapped. */
	export let tacticCounts: Map<string, number>;
	export let showCounts = false;

	const dispatch = createEventDispatcher<{ select: string }>();
</script>

<div class="flex gap-1" role="group">
	{#each TACTIC_ORDER as tactic (tactic.id)}
		{@const count = tacticCounts.get(tactic.id)}
		{#if count !== undefined}
			<button
				type="button"
				class="relative flex-1 min-w-0 h-8 rounded text-[10px] font-semibold tracking-tight
					bg-primary-500 text-white hover:bg-primary-600 transition-colors"
				title={tactic.name}
				on:click={() => dispatch('select', tactic.id)}
			>
				{tacticAbbrev(tactic.id)}
				{#if showCounts}
					<span
						class="absolute -top-2 -right-1 badge-icon variant-filled text-[10px] w-4 h-4"
					>
						{count}
					</span>
				{/if}
			</button>
		{:else}
			<div
				class="flex-1 min-w-0 h-8 rounded text-[10px] font-medium tracking-tight
					bg-surface-500/20 text-surface-400-500-token opacity-60
					flex items-center justify-center"
				title={tactic.name}
			>
				{tacticAbbrev(tactic.id)}
			</div>
		{/if}
	{/each}
</div>
