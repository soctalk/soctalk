<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type AuditEvent } from '$lib/api/client';
	import { formatEventType } from '$lib/utils/formatters';
	import { m } from '$lib/paraglide/messages';
	import { localizeHref } from '$lib/i18n';

	let events: AuditEvent[] = [];
	let loading = true;
	let error: string | null = null;
	let page = 1;
	let total = 0;
	let hasMore = false;

	// Filters
	let eventTypeFilter = '';
	let eventTypes: string[] = [];

	onMount(async () => {
		try {
			const types = await api.audit.getEventTypes();
			eventTypes = types.event_types;
		} catch (e) {
			if (import.meta.env.DEV) console.error('Failed to load event types:', e);
		}
		await loadEvents();
	});

	async function loadEvents() {
		loading = true;
		error = null;
		try {
			const result = await api.audit.list({
				page,
				page_size: 50,
				event_type: eventTypeFilter || undefined
			});
			events = result.items;
			total = result.total;
			hasMore = result.has_more;
		} catch (e) {
			error = e instanceof Error ? e.message : m.audit_load_failed();
		} finally {
			loading = false;
		}
	}

	function getEventBadgeClass(eventType: string): string {
		if (eventType.startsWith('investigation.')) return 'variant-soft-primary';
		if (eventType.startsWith('human.')) return 'variant-soft-warning';
		if (eventType.startsWith('verdict.')) return 'variant-soft-secondary';
		if (eventType.startsWith('thehive.')) return 'variant-soft-success';
		if (eventType.startsWith('enrichment.')) return 'variant-soft-tertiary';
		return 'variant-soft';
	}
</script>

<svelte:head>
	<title>{m.nav_audit_log()} - SocTalk</title>
</svelte:head>

<div class="flex items-center justify-between mb-4">
	<h1 class="h2">{m.nav_audit_log()}</h1>
	<button class="btn variant-soft" on:click={loadEvents} disabled={loading}>
		{#if loading}
			<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
		{/if}
		{m.audit_refresh()}
	</button>
</div>

<!-- Filters -->
<div class="flex flex-wrap gap-4 mb-4">
	<select class="select" bind:value={eventTypeFilter} on:change={() => { page = 1; loadEvents(); }}>
		<option value="">{m.audit_all_event_types()}</option>
		{#each eventTypes as type}
			<option value={type}>{formatEventType(type)}</option>
		{/each}
	</select>
</div>

{#if loading}
	<div class="flex items-center justify-center h-64">
		<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
	</div>
{:else if error}
	<div class="alert variant-filled-error">
		<span>{m.audit_error({ error })}</span>
	</div>
{:else}
	<div class="table-container">
		<table class="table table-hover table-compact">
			<thead>
				<tr>
					<th>{m.audit_th_timestamp()}</th>
					<th>{m.audit_th_event_type()}</th>
					<th>{m.audit_th_investigation()}</th>
					<th>{m.audit_th_version()}</th>
					<th>{m.audit_th_data()}</th>
				</tr>
			</thead>
			<tbody>
				{#each events as event}
					<tr>
						<td class="text-xs opacity-60 whitespace-nowrap">
							{new Date(event.timestamp).toLocaleString()}
						</td>
						<td>
							<span class="badge {getEventBadgeClass(event.event_type)} text-xs">
								{formatEventType(event.event_type)}
							</span>
						</td>
						<td class="font-mono text-xs">
							<a href={localizeHref(`/investigations/${event.aggregate_id}`)} class="anchor">
								{event.aggregate_id.slice(0, 8)}...
							</a>
						</td>
						<td class="text-center">{event.version}</td>
						<td>
							<details class="text-sm">
								<summary class="cursor-pointer opacity-60 hover:opacity-100">
									{m.audit_view_data()}
								</summary>
								<pre class="text-xs mt-2 p-2 bg-surface-700 rounded overflow-auto max-h-40">
{JSON.stringify(event.data, null, 2)}
								</pre>
							</details>
						</td>
					</tr>
				{/each}
				{#if events.length === 0}
					<tr>
						<td colspan="5" class="text-center opacity-60 py-8">
							{m.audit_no_events()}
						</td>
					</tr>
				{/if}
			</tbody>
		</table>
	</div>

	<!-- Pagination -->
	{#if total > 50}
		<div class="flex justify-between items-center mt-4">
			<span class="text-sm opacity-60">
				{m.audit_showing({ from: (page - 1) * 50 + 1, to: Math.min(page * 50, total), total })}
			</span>
			<div class="flex gap-2">
				<button
					class="btn btn-sm variant-soft"
					disabled={page <= 1}
					on:click={() => { page--; loadEvents(); }}
				>
					{m.audit_previous()}
				</button>
				<button
					class="btn btn-sm variant-soft"
					disabled={!hasMore}
					on:click={() => { page++; loadEvents(); }}
				>
					{m.audit_next()}
				</button>
			</div>
		</div>
	{/if}
{/if}
