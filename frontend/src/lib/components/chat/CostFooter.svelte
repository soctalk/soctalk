<script lang="ts">
	import type { ConversationRow, UsageView } from '$lib/stores/chat';

	export let conv: ConversationRow | null;
	export let usage: UsageView | null;

	$: convDollars = usage?.conv_total_dollars ?? conv?.total_dollars ?? 0;
	$: budget = conv?.budget_dollars ?? 1.0;
	$: pct = budget > 0 ? Math.min(100, (convDollars / budget) * 100) : 0;
	$: model = conv?.model_name ?? '—';
	$: nearLimit = pct >= 80;
</script>

<footer class="px-3 py-2 text-xs opacity-70 border-t border-surface-500/20 flex items-center justify-between gap-2">
	<div class="flex items-center gap-2 min-w-0">
		<span class="whitespace-nowrap">conv</span>
		<span class="font-mono" class:text-warning-500={nearLimit}>
			${convDollars.toFixed(3)} / ${budget.toFixed(2)}
		</span>
		<div class="w-16 h-1 rounded bg-surface-500/30 overflow-hidden">
			<div
				class="h-full transition-all"
				class:bg-warning-500={nearLimit}
				class:bg-primary-500={!nearLimit}
				style="width: {pct}%"
			></div>
		</div>
	</div>
	<span class="font-mono truncate" title={model}>{model}</span>
</footer>
