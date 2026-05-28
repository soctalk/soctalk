<script lang="ts">
	export let text: string;
	export let timestamp: string | null = null;
	export let streaming = false;
</script>

<div class="flex flex-col items-start">
	<div class="bg-surface-500/15 rounded-lg px-3 py-2 max-w-[95%] whitespace-pre-wrap text-sm">
		{text}
		{#if streaming}
			<span class="inline-block w-2 h-3 bg-primary-500 align-middle ml-1 animate-pulse"></span>
		{/if}
	</div>
	{#if timestamp}
		<span class="text-xs opacity-40 mt-1">
			{new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
		</span>
	{/if}
</div>
