<!--
  Renders persisted messages + the in-flight pending assistant message.
  Auto-scrolls to bottom when new content arrives.
-->
<script lang="ts">
	import { afterUpdate, createEventDispatcher } from 'svelte';
	import type { MessageRow, PendingAssistant, ProposedActionView } from '$lib/stores/chat';
	import AssistantMessage from './AssistantMessage.svelte';
	import ProposedActionCard from './ProposedActionCard.svelte';
	import ToolCallBadge from './ToolCallBadge.svelte';
	import UserMessage from './UserMessage.svelte';

	export let messages: MessageRow[] = [];
	export let pending: PendingAssistant | null = null;

	const dispatch = createEventDispatcher<{ confirm: { messageId: string } }>();

	let scrollEl: HTMLDivElement;

	afterUpdate(() => {
		if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
	});

	function isText(content: Record<string, unknown>): string {
		return typeof content.text === 'string' ? content.text : '';
	}

	function asProposedAction(content: Record<string, unknown>): ProposedActionView {
		return content as unknown as ProposedActionView;
	}

	function isToolContent(content: Record<string, unknown>): boolean {
		return typeof content.name === 'string';
	}

	function toolArgs(content: Record<string, unknown>): Record<string, unknown> {
		return (content.args as Record<string, unknown>) ?? {};
	}

	function isTruncated(content: Record<string, unknown>): boolean {
		const r = content.result;
		if (!r || typeof r !== 'object') return false;
		return !!(r as { truncated?: boolean }).truncated;
	}
</script>

<div bind:this={scrollEl} class="message-list flex-1 overflow-y-auto p-3 space-y-3">
	{#each messages as msg (msg.id)}
		{#if msg.role === 'user'}
			<UserMessage text={isText(msg.content)} timestamp={msg.created_at} />
		{:else if msg.role === 'assistant'}
			<AssistantMessage text={isText(msg.content)} timestamp={msg.created_at} />
		{:else if msg.role === 'tool' && isToolContent(msg.content)}
			<ToolCallBadge
				name={String(msg.content.name ?? 'tool')}
				args={toolArgs(msg.content)}
				result={msg.content.result}
				truncated={isTruncated(msg.content)}
			/>
		{:else if msg.role === 'action'}
			<ProposedActionCard
				action={asProposedAction(msg.content)}
				messageId={msg.id}
				on:confirm={(e) => dispatch('confirm', e.detail)}
			/>
		{:else if msg.role === 'system'}
			<div class="text-xs opacity-60 italic">
				{isText(msg.content)}
			</div>
		{/if}
	{/each}

	{#if pending}
		<div class="space-y-2">
			{#each pending.toolCalls as tc (tc.call_id)}
				<ToolCallBadge
					name={tc.name}
					args={tc.args}
					result={tc.result}
					truncated={!!tc.truncated}
				/>
			{/each}
			{#if pending.text}
				<AssistantMessage text={pending.text} timestamp={null} streaming={pending.streaming} />
			{:else if pending.streaming}
				<div class="text-xs opacity-60 italic">Thinking…</div>
			{/if}
			{#each pending.proposedActions as pa, i (i)}
				<ProposedActionCard action={pa} messageId={null} disabled />
			{/each}
		</div>
	{/if}

	{#if messages.length === 0 && !pending}
		<div class="text-xs opacity-60 italic text-center py-4">
			Ask anything about this investigation — try
			<code class="text-primary-500">"why did this escalate?"</code>
			or <code class="text-primary-500">"any related alerts in the last hour?"</code>
		</div>
	{/if}
</div>

<style>
	.message-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
</style>
