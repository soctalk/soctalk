<!--
  ChatPanel — the dock/panel embedded on the investigation detail page
  and reused full-bleed on /chat. Owns one chat store instance.

  Props:
    investigationId  string | null  — pre-load conversation for this case
    height           string         — CSS height (defaults to 100%)
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { createChatStore } from '$lib/stores/chat';
	import Composer from './Composer.svelte';
	import CostFooter from './CostFooter.svelte';
	import MessageList from './MessageList.svelte';

	export let investigationId: string | null = null;
	export let height = '100%';

	const chat = createChatStore();
	const { state } = chat;

	onMount(async () => {
		await chat.open(investigationId);
	});

	onDestroy(() => chat.close());

	async function handleSend(event: CustomEvent<{ text: string }>) {
		await chat.send(event.detail.text);
	}

	async function handleConfirm(event: CustomEvent<{ messageId: string }>) {
		await chat.confirmAction(event.detail.messageId);
	}

	function handleStop() {
		chat.stop();
	}
</script>

<div class="card variant-soft chat-panel flex flex-col" style="height: {height}">
	<header class="flex items-center justify-between p-3 border-b border-surface-500/20">
		<div class="flex items-center gap-2 text-sm">
			<svg
				xmlns="http://www.w3.org/2000/svg"
				class="h-4 w-4 text-primary-500"
				fill="none"
				viewBox="0 0 24 24"
				stroke="currentColor"
			>
				<path
					stroke-linecap="round"
					stroke-linejoin="round"
					stroke-width="2"
					d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
				/>
			</svg>
			<span class="font-semibold">Ask AI</span>
			{#if $state.conversation?.investigation_id}
				<span class="badge variant-soft-tertiary text-xs">
					Case {$state.conversation.investigation_id.slice(0, 8)}
				</span>
			{/if}
		</div>
		{#if $state.streaming}
			<button class="btn btn-sm variant-soft-error" on:click={handleStop} type="button">
				Stop
			</button>
		{/if}
	</header>

	{#if $state.error}
		<div class="alert variant-soft-error m-3 p-2 text-sm">
			{$state.error}
		</div>
	{/if}

	<MessageList
		messages={$state.messages}
		pending={$state.pending}
		on:confirm={handleConfirm}
	/>

	<Composer
		disabled={$state.streaming || !$state.conversation}
		on:send={handleSend}
	/>

	{#if $state.usage || $state.conversation}
		<CostFooter
			conv={$state.conversation}
			usage={$state.usage}
		/>
	{/if}
</div>

<style>
	.chat-panel {
		display: flex;
		flex-direction: column;
		min-height: 0;
		overflow: hidden;
	}
</style>
