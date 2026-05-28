<script lang="ts">
	export let text: string;
	export let timestamp: string | null = null;
</script>

<div class="flex flex-col items-end">
	<div class="bg-primary-500/15 rounded-lg px-3 py-2 max-w-[85%] whitespace-pre-wrap text-sm">
		{text}
	</div>
	{#if timestamp}
		<span class="text-xs opacity-40 mt-1">
			{new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
		</span>
	{/if}
</div>
