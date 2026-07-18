	<script lang="ts">
		import { onMount } from 'svelte';
		import { api, type InvestigationSummary } from '$lib/api/client';
		import { authSession, isMsspScope } from '$lib/stores';
		import { formatStatus, formatPhase, formatSeverity, formatDecision } from '$lib/utils/formatters';
	import { m } from '$lib/paraglide/messages';
	import { localizeHref } from '$lib/i18n';

		// Show the per-row Tenant column only when the session is in
		// cross-tenant view — i.e. an MSSP user with no current_tenant
		// pin. Tenant-bound or assume-tenant'd sessions hide it because
		// every row belongs to the same tenant.
		$: showTenantColumn = $isMsspScope && !$authSession.user?.current_tenant;

		let investigations: InvestigationSummary[] = [];
		let loading = true;
		let error: string | null = null;
		let page = 1;
		let total = 0;
	let hasMore = false;

	// Filters
	let statusFilter = '';
	let phaseFilter = '';

	onMount(() => loadInvestigations());

	async function loadInvestigations() {
		loading = true;
		error = null;
		try {
			const result = await api.investigations.list({
				page,
				page_size: 20,
				status: statusFilter || undefined,
				phase: phaseFilter || undefined
			});
			investigations = result.items;
			total = result.total;
			hasMore = result.has_more;
		} catch (e) {
			error = e instanceof Error ? e.message : m.inv_load_failed();
		} finally {
			loading = false;
		}
	}

	function getStatusBadge(status: string): string {
		switch (status) {
			case 'pending': return 'variant-soft-warning';
			case 'in_progress': return 'variant-soft-primary';
			case 'paused': return 'variant-soft-tertiary';
			case 'closed':
			case 'auto_closed':
				return 'variant-soft-success';
			case 'escalated':
			case 'rejected':
				return 'variant-soft-error';
			case 'cancelled':
				return 'variant-soft';
			default: return 'variant-soft';
		}
	}

	function getSeverityBadge(severity: string | null): string {
		switch (severity?.toLowerCase()) {
			case 'critical': return 'variant-filled-error';
			case 'high': return 'variant-filled-warning';
			case 'medium': return 'variant-filled-secondary';
			case 'low': return 'variant-filled-tertiary';
			default: return 'variant-soft';
		}
	}
</script>

<svelte:head>
	<title>{m.nav_investigations()} - SocTalk</title>
</svelte:head>

<div class="flex items-center justify-between mb-4">
	<h1 class="h2">{m.inv_title()}</h1>
	<button class="btn variant-soft" on:click={loadInvestigations} disabled={loading}>
		{#if loading}
			<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
		{/if}
		{m.inv_refresh()}
	</button>
</div>

<!-- Filters -->
<div class="flex flex-wrap gap-4 mb-4">
	<select class="select" bind:value={statusFilter} on:change={() => { page = 1; loadInvestigations(); }}>
		<option value="">{m.inv_all_statuses()}</option>
		<option value="pending">{formatStatus('pending')}</option>
		<option value="in_progress">{formatStatus('in_progress')}</option>
		<option value="paused">{formatStatus('paused')}</option>
		<option value="escalated">{formatStatus('escalated')}</option>
		<option value="auto_closed">{formatStatus('auto_closed')}</option>
		<option value="closed">{formatStatus('closed')}</option>
		<option value="rejected">{formatStatus('rejected')}</option>
		<option value="cancelled">{formatStatus('cancelled')}</option>
	</select>
	<select class="select" bind:value={phaseFilter} on:change={() => { page = 1; loadInvestigations(); }}>
		<option value="">{m.inv_all_phases()}</option>
		<option value="triage">{formatPhase('triage')}</option>
		<option value="enrichment">{formatPhase('enrichment')}</option>
		<option value="analysis">{formatPhase('analysis')}</option>
		<option value="verdict">{formatPhase('verdict')}</option>
		<option value="human_review">{formatPhase('human_review')}</option>
		<option value="closed">{formatPhase('closed')}</option>
	</select>
</div>

{#if loading}
	<div class="flex items-center justify-center h-64">
		<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
	</div>
{:else if error}
	<div class="alert variant-filled-error">
		<span>{m.inv_error({ error })}</span>
	</div>
{:else}
	<div class="table-container">
		<table class="table table-hover">
			<thead>
				<tr>
					{#if showTenantColumn}
						<th>{m.inv_col_tenant()}</th>
					{/if}
					<th>{m.inv_col_title()}</th>
					<th>{m.inv_col_status()}</th>
					<th>{m.inv_col_phase()}</th>
					<th>{m.inv_col_severity()}</th>
					<th>{m.inv_col_alerts()}</th>
					<th>{m.inv_col_malicious()}</th>
					<th>{m.inv_col_verdict()}</th>
					<th>{m.inv_col_created()}</th>
					<th>{m.inv_col_actions()}</th>
				</tr>
			</thead>
			<tbody>
				{#each investigations as inv}
					<tr>
						{#if showTenantColumn}
							<td class="text-xs">
								{#if inv.tenant_display_name || inv.tenant_slug}
									<span class="badge variant-soft-primary">
										{inv.tenant_display_name || inv.tenant_slug}
									</span>
								{:else}
									<span class="opacity-40">-</span>
								{/if}
							</td>
						{/if}
						<td class="max-w-xs truncate">
							<a href={localizeHref(`/investigations/${inv.id}`)} class="anchor">
								{inv.title || m.inv_untitled()}
							</a>
						</td>
						<td><span class="badge {getStatusBadge(inv.status)}">{formatStatus(inv.status)}</span></td>
						<td><span class="badge variant-soft">{formatPhase(inv.phase)}</span></td>
						<td>
							{#if inv.max_severity}
								<span class="badge {getSeverityBadge(inv.max_severity)}">{formatSeverity(inv.max_severity)}</span>
							{:else}
								<span class="opacity-40">-</span>
							{/if}
						</td>
						<td>{inv.alert_count}</td>
						<td class="text-error-500">{inv.malicious_count}</td>
						<td>
							{#if inv.verdict_decision}
								<span class="badge {inv.verdict_decision === 'escalate' ? 'variant-filled-error' :
								                    inv.verdict_decision === 'needs_more_info' || inv.verdict_decision === 'suspicious' ? 'variant-filled-warning' :
								                    inv.verdict_decision === 'close' || inv.verdict_decision === 'auto_close' ? 'variant-filled-success' :
								                    'variant-soft'}">
									{formatDecision(inv.verdict_decision)}
								</span>
							{:else}
								<span class="opacity-40">-</span>
							{/if}
						</td>
						<td class="text-xs opacity-60">
							{new Date(inv.created_at).toLocaleString()}
						</td>
						<td>
							<a href={localizeHref(`/investigations/${inv.id}`)} class="btn btn-sm variant-soft">{m.inv_view()}</a>
						</td>
					</tr>
				{/each}
				{#if investigations.length === 0}
					<tr>
						<td colspan={showTenantColumn ? 10 : 9} class="text-center opacity-60 py-8">
							{m.inv_empty()}
						</td>
					</tr>
				{/if}
			</tbody>
		</table>
	</div>

	<!-- Pagination -->
	{#if total > 20}
		<div class="flex justify-between items-center mt-4">
			<span class="text-sm opacity-60">
				{m.inv_showing_range({ from: (page - 1) * 20 + 1, to: Math.min(page * 20, total), total })}
			</span>
			<div class="flex gap-2">
				<button
					class="btn btn-sm variant-soft"
					disabled={page <= 1}
					on:click={() => { page--; loadInvestigations(); }}
				>
					{m.inv_previous()}
				</button>
				<button
					class="btn btn-sm variant-soft"
					disabled={!hasMore}
					on:click={() => { page++; loadInvestigations(); }}
				>
					{m.inv_next()}
				</button>
			</div>
		</div>
	{/if}
{/if}
