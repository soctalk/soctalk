<!--
  ChatPanel — the dock/panel embedded on the investigation detail page
  and reused full-bleed on /chat. Owns one chat store instance.

  Props:
    conversationId   string | null  — load this exact conversation by id.
                                      Takes precedence over investigationId
                                      (the /chat list uses this).
    investigationId  string | null  — pre-load any active conversation for
                                      this case (or create one).
    height           string         — CSS height (defaults to 100%)
-->
<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createEventDispatcher, onDestroy, onMount } from 'svelte';
	import { createChatStore } from '$lib/stores/chat';
	import Composer from './Composer.svelte';
	import MessageList from './MessageList.svelte';

	export let conversationId: string | null = null;
	export let investigationId: string | null = null;
	export let height = '100%';

	const chat = createChatStore();
	const { state } = chat;
	// Lets the parent (/chat page) refresh its conversation list after
	// a turn — picks up mutations like set_fleet_focus changing the
	// row's focused_tenant_slug so the list badge updates.
	const dispatch = createEventDispatcher<{ turnend: void }>();

	onMount(async () => {
		// conversationId beats investigationId: the /chat list passes a
		// specific id when the user clicks a row. The dock on the
		// investigation page omits it and lets ``open()`` find/create
		// the active conversation for that case.
		if (conversationId) {
			await chat.openExisting(conversationId);
		} else {
			await chat.open(investigationId);
		}
	});

	onDestroy(() => chat.close());

	async function handleSend(event: CustomEvent<{ text: string }>) {
		await chat.send(event.detail.text);
		dispatch('turnend');
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
			<span class="font-semibold">{m.cp_ask_ai()}</span>
			{#if $state.conversation?.investigation_id}
				<span class="badge variant-soft-tertiary text-xs">
					Case {$state.conversation.investigation_id.slice(0, 8)}
				</span>
			{:else if $state.conversation?.scope === 'mssp_fleet' && $state.conversation?.focused_tenant_slug}
				<span class="badge variant-filled-secondary text-xs">
					Focused on {$state.conversation.focused_tenant_slug}
				</span>
			{:else if $state.conversation?.scope === 'mssp_fleet'}
				<span class="badge variant-soft-secondary text-xs">{m.cp_fleet()}</span>
			{/if}
		</div>
		{#if $state.streaming}
			<button class="btn btn-sm variant-soft-error" on:click={handleStop} type="button">
				{m.cp_stop()}
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
		scope={$state.conversation?.scope ?? 'tenant'}
		on:send={handleSend}
	/>
</div>

<style>
	.chat-panel {
		display: flex;
		flex-direction: column;
		min-height: 0;
		overflow: hidden;
	}
</style>
