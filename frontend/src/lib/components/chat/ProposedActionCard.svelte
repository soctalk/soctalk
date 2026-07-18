<!--
  Renders a proposed action with Confirm/Dismiss buttons. Confirm
  dispatches an event the parent handles by POSTing to
  /api/chat/conversations/{id}/messages/{msg}/confirm.

  Dismiss is local-only; the agent's suggestion just doesn't get
  acted on. We don't write anything back to the server for dismiss
  in Phase 2 (revisit if analysts want a "dismissed" audit).
-->
<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { m } from '$lib/paraglide/messages';
	import type { ProposedActionView } from '$lib/stores/chat';

	export let action: ProposedActionView;
	export let messageId: string | null = null;
	export let disabled = false;

	const dispatch = createEventDispatcher<{ confirm: { messageId: string } }>();
	let dismissed = false;
	let busy = false;

	$: confirmed = !!action.confirmed_at;
	$: actionLabel = labelForAction(action.action);

	// Localized display label for a proposed-action code (call-time, #52).
	function labelForAction(a: string): string {
		switch (a) {
			case 'approve_review':
				return m.cp_approve_escalate();
			case 'reject_review':
				return m.cp_reject_close();
			case 'expire_review':
				return m.cp_expire_review();
			default:
				return a;
		}
	}

	async function handleConfirm() {
		if (!messageId || busy) return;
		busy = true;
		dispatch('confirm', { messageId });
		setTimeout(() => (busy = false), 1500);
	}
</script>

{#if !dismissed}
	<div class="card variant-soft-warning p-3 space-y-2 max-w-full">
		<div class="flex items-center gap-2 text-sm font-semibold">
			<svg
				xmlns="http://www.w3.org/2000/svg"
				class="h-4 w-4"
				fill="none"
				viewBox="0 0 24 24"
				stroke="currentColor"
			>
				<path
					stroke-linecap="round"
					stroke-linejoin="round"
					stroke-width="2"
					d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
				/>
			</svg>
			{m.cp_proposed_action()}
		</div>
		<div class="text-sm">
			<span class="font-semibold">{actionLabel}</span>
			{#if action.target.title}
				— {action.target.title}
			{/if}
		</div>
		<div class="text-xs opacity-80 whitespace-pre-wrap">{action.reason}</div>
		{#if action.confidence !== null && action.confidence !== undefined}
			<div class="text-xs opacity-60">
				{m.cp_confidence({ pct: Math.round(action.confidence * 100) })}
			</div>
		{/if}
		{#if action.evidence && action.evidence.length > 0}
			<div class="text-xs opacity-70">
				{m.cp_evidence()}
				{#each action.evidence as ev, i}
					<span class="font-mono">{ev.kind}:{ev.id.slice(0, 8)}</span>{#if i < action.evidence.length - 1},
					{/if}
				{/each}
			</div>
		{/if}
		{#if confirmed}
			<div class="text-xs text-success-500">
				{m.cp_confirmed_at({ ts: new Date(action.confirmed_at ?? '').toLocaleString() })}
			</div>
		{:else}
			<div class="flex gap-2 pt-1">
				<button
					type="button"
					class="btn btn-sm variant-soft"
					on:click={() => (dismissed = true)}
					{disabled}
				>
					{m.cp_dismiss()}
				</button>
				<button
					type="button"
					class="btn btn-sm variant-filled-success"
					on:click={handleConfirm}
					disabled={disabled || !messageId || busy}
				>
					{busy ? m.cp_confirming() : m.cp_confirm()}
				</button>
			</div>
		{/if}
	</div>
{/if}
