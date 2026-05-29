<!--
  Global /chat — two-pane layout. Left: conversation list. Right: active panel.

  Single "+ New" button. The backend picks the right scope from the
  caller's role: MSSP-level → fleet-scope (the agent narrows via
  set_fleet_focus mid-chat), customer/tenant-bound → tenant-scope.
  Conversation rows show the focused tenant slug when the fleet agent
  has set one, otherwise the scope badge ("Fleet" / "Tenant" / case).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';

	interface ConversationRow {
		id: string;
		title: string | null;
		tenant_id: string | null;
		scope: 'tenant' | 'mssp_fleet';
		focused_tenant_id: string | null;
		focused_tenant_slug: string | null;
		investigation_id: string | null;
		model_name: string;
		status: string;
		total_dollars: number;
		created_at: string;
		last_message_at: string | null;
	}

	let conversations: ConversationRow[] = [];
	let activeId: string | null = null;
	let loading = false;
	let error: string | null = null;

	async function loadList() {
		loading = true;
		error = null;
		try {
			const res = await fetch('/api/chat/conversations?limit=50', {
				credentials: 'same-origin'
			});
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const data = await res.json();
			conversations = data.items;
		} catch (e) {
			error = e instanceof Error ? e.message : 'failed to load conversations';
		} finally {
			loading = false;
		}
	}

	async function newConversation() {
		try {
			// No scope sent: the backend defaults to fleet for MSSP roles
			// and tenant for customer roles. Single button, single intent.
			const res = await fetch('/api/chat/conversations', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({})
			});
			if (!res.ok) {
				const body = await res.text().catch(() => '');
				throw new Error(body || `HTTP ${res.status}`);
			}
			const conv = await res.json();
			activeId = conv.id;
			await loadList();
		} catch (e) {
			error = e instanceof Error ? e.message : 'failed to start conversation';
		}
	}

	onMount(loadList);
</script>

<svelte:head>
	<title>Chat - SocTalk</title>
</svelte:head>

<div class="chat-page flex gap-4">
	<aside class="conv-list">
		<div class="flex items-center justify-between mb-3">
			<h2 class="text-base font-semibold">Conversations</h2>
			<button
				class="btn btn-sm variant-filled-primary"
				on:click={newConversation}
				title="Start a new chat"
			>
				+ New
			</button>
		</div>

		{#if error}
			<div class="alert variant-soft-error text-xs p-2">{error}</div>
		{/if}

		{#if loading && conversations.length === 0}
			<div class="text-xs opacity-60">Loading…</div>
		{:else if conversations.length === 0}
			<div class="text-xs opacity-60">No conversations yet.</div>
		{:else}
			<ul class="space-y-1">
				{#each conversations as c (c.id)}
					<li>
						<button
							type="button"
							class="conv-item w-full text-left p-2 rounded text-sm"
							class:active={c.id === activeId}
							on:click={() => (activeId = c.id)}
						>
							<div class="font-medium truncate">{c.title ?? '(untitled)'}</div>
							<div class="text-xs opacity-60 flex items-center gap-2 flex-wrap">
								{#if c.investigation_id}
									<span class="badge variant-soft-tertiary text-xs">
										case:{c.investigation_id.slice(0, 6)}
									</span>
								{:else if c.scope === 'mssp_fleet' && c.focused_tenant_slug}
									<span class="badge variant-filled-secondary text-xs">
										{c.focused_tenant_slug}
									</span>
								{:else if c.scope === 'mssp_fleet'}
									<span class="badge variant-soft-secondary text-xs">Fleet</span>
								{:else}
									<span class="badge variant-soft-tertiary text-xs">Tenant</span>
								{/if}
								<span>{new Date(c.created_at).toLocaleDateString()}</span>
							</div>
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</aside>

	<div class="chat-pane flex-1">
		{#if activeId}
			{#key activeId}
				<ChatPanel
					conversationId={activeId}
					investigationId={null}
					on:turnend={loadList}
				/>
			{/key}
		{:else}
			<div class="card variant-soft p-8 text-center h-full flex items-center justify-center">
				<div>
					<div class="text-lg font-semibold mb-2">Select or start a conversation</div>
					<div class="text-sm opacity-60">
						The AI SOC Analyst can summarise cases, dig through alerts and the audit
						log, and propose actions on pending reviews.
					</div>
				</div>
			</div>
		{/if}
	</div>
</div>

<style>
	.chat-page {
		height: calc(100vh - 6rem);
	}
	.conv-list {
		width: 280px;
		flex-shrink: 0;
		overflow-y: auto;
	}
	.chat-pane {
		min-width: 0;
		min-height: 0;
	}
	.conv-item {
		background: transparent;
		border: 1px solid transparent;
	}
	.conv-item:hover {
		background: rgba(255, 255, 255, 0.04);
	}
	.conv-item.active {
		background: rgba(99, 102, 241, 0.15);
		border-color: rgba(99, 102, 241, 0.5);
	}
</style>
