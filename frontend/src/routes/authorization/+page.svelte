<script lang="ts">
	import { page } from '$app/stores';
	import { api, type AuthorizationFact, type TenantEngagement } from '$lib/api/client';
	import {
		currentTenantId,
		canManageAuthorization,
		canViewEngagements,
		canAuthorizeEngagements
	} from '$lib/stores';
	import { m } from '$lib/paraglide/messages';
	import AuthorizationFactForm from '$lib/components/authz/AuthorizationFactForm.svelte';
	import EngagementForm from '$lib/components/authz/EngagementForm.svelte';
	import { engagementStatus, engagementStatusVariant, factSummary } from '$lib/authz/display';

	// Mirrors the tenant-side area (/my-authorization): standing FACTS plus time-boxed
	// ENGAGEMENTS, here declared on a customer tenant's behalf. Both are per-tenant, so
	// both tabs need a tenant pinned in the switcher.
	let tab: 'facts' | 'engagements' =
		$page.url.searchParams.get('tab') === 'engagements' ? 'engagements' : 'facts';

	let facts: AuthorizationFact[] = [];
	let loading = false;
	let error: string | null = null;

	let editorOpen = false;
	let editorSaving = false;
	let editorError: string | null = null;

	$: tenantId = $currentTenantId;
	$: if (tenantId) load(tenantId);

	// ---- engagements ----
	let engagements: TenantEngagement[] = [];
	let engLoading = false;
	let engFormOpen = false;
	let engSaving = false;
	let engError: string | null = null;
	let engSeed: TenantEngagement | null = null;

	function engStatusLabel(st: 'scheduled' | 'active' | 'expired' | 'revoked'): string {
		return st === 'active'
			? m.authz_eng_status_active()
			: st === 'scheduled'
				? m.authz_eng_status_scheduled()
				: st === 'expired'
					? m.authz_eng_status_expired()
					: m.authz_eng_status_revoked();
	}

	async function loadEngagements(tid: string) {
		engLoading = true;
		error = null;
		try {
			engagements = await api.engagements.list(tid, true);
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_eng_load_failed();
		} finally {
			engLoading = false;
		}
	}

	// Refetch whenever the tab or the pinned tenant changes — an MSSP user switching
	// tenants must never keep looking at the previous customer's engagements.
	$: if (tab === 'engagements' && tenantId) loadEngagements(tenantId);

	function openEngForm(seed?: TenantEngagement) {
		engError = null;
		engSeed = seed ?? null;
		engFormOpen = true;
	}

	async function declare(body: Record<string, unknown>) {
		if (!tenantId) return;
		engSaving = true;
		engError = null;
		try {
			await api.engagements.declare(tenantId, body as never);
			engFormOpen = false;
			await loadEngagements(tenantId);
		} catch (e) {
			engError = e instanceof Error ? e.message : m.adm_eng_declare_failed();
		} finally {
			engSaving = false;
		}
	}

	async function revokeEngagement(e: TenantEngagement) {
		if (!tenantId) return;
		const reason = window.prompt(m.adm_revoke_engagement_prompt({ name: e.name }), '');
		if (reason === null) return;
		try {
			await api.engagements.revoke(tenantId, e.id, reason || null);
			await loadEngagements(tenantId);
		} catch (err) {
			error = err instanceof Error ? err.message : m.adm_revoke_failed();
		}
	}

	async function load(tid: string) {
		loading = true;
		error = null;
		try {
			const res = await api.authorizationFacts.list(tid);
			facts = res.facts;
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_facts_load_failed();
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editorError = null;
		editorOpen = true;
	}

	async function save(fact: Record<string, unknown>) {
		if (!tenantId) return;
		editorSaving = true;
		editorError = null;
		try {
			await api.authorizationFacts.create(tenantId, fact);
			editorOpen = false;
			await load(tenantId);
		} catch (e) {
			editorError = e instanceof Error ? e.message : m.adm_create_failed();
		} finally {
			editorSaving = false;
		}
	}

	async function revoke(f: AuthorizationFact) {
		if (!tenantId) return;
		const reason = window.prompt(m.adm_revoke_fact_prompt({ id: f.id }), '');
		if (reason === null) return; // cancelled
		try {
			await api.authorizationFacts.revoke(tenantId, f.id, reason || null);
			await load(tenantId);
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_revoke_failed();
		}
	}

	async function review(f: AuthorizationFact, decision: 'approve' | 'reject') {
		if (!tenantId) return;
		try {
			await api.authorizationFacts.review(tenantId, f.id, decision);
			await load(tenantId);
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_review_failed();
		}
	}
</script>

<div class="p-6">
	<div class="flex items-center justify-between mb-4">
		<div>
			<h1 class="text-2xl font-semibold">
				{tab === 'engagements' ? m.adm_engagements_tab() : m.adm_facts_title()}
			</h1>
			{#if tab === 'facts'}
				<p class="text-sm text-gray-400">
					{m.adm_facts_intro()}
				</p>
			{/if}
		</div>
		{#if tab === 'facts' && $canManageAuthorization}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
				on:click={openCreate}
				disabled={!tenantId}
				title={tenantId ? undefined : m.adm_select_tenant()}
			>
				{m.adm_new_fact()}
			</button>
		{:else if tab === 'engagements' && $canAuthorizeEngagements}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
				on:click={() => openEngForm()}
				disabled={!tenantId}
				title={tenantId ? undefined : m.adm_select_tenant()}
			>
				{m.adm_declare_engagement()}
			</button>
		{/if}
	</div>

	{#if $canViewEngagements}
		<div class="flex gap-1 border-b border-surface-500/20 text-sm mb-4">
			<button
				class="px-3 py-2 -mb-px border-b-2 {tab === 'facts'
					? 'border-blue-600 font-medium'
					: 'border-transparent opacity-70'}"
				on:click={() => (tab = 'facts')}
			>
				{m.adm_facts_title()}
			</button>
			<button
				class="px-3 py-2 -mb-px border-b-2 {tab === 'engagements'
					? 'border-blue-600 font-medium'
					: 'border-transparent opacity-70'}"
				on:click={() => (tab = 'engagements')}
			>
				{m.adm_engagements_tab()}
			</button>
		</div>
	{/if}

	{#if tab === 'engagements'}
		{#if !tenantId}
			<p class="text-gray-400">{m.adm_select_tenant()}</p>
		{:else}
			{#if engFormOpen && $canAuthorizeEngagements}
				<!-- Keyed on the seed so clicking "clone" on another row while the form is
				     already open remounts it with that row's scope, instead of keeping the
				     first seed's values (the props only initialize the fields once). -->
				{#key engSeed}
					<div class="mb-4">
						<EngagementForm
							saving={engSaving}
							error={engError}
							seed={engSeed}
							on:submit={(e) => declare(e.detail)}
							on:cancel={() => (engFormOpen = false)}
						/>
					</div>
				{/key}
			{/if}

			{#if engLoading}
				<div class="opacity-60 text-sm">{m.common_loading()}</div>
			{:else if engagements.length === 0}
				<div class="opacity-60 text-sm">{m.adm_eng_empty()}</div>
			{:else}
				<div class="space-y-2">
					{#each engagements as e (e.id)}
						{@const st = engagementStatus(e)}
						<div class="card p-3 rounded border flex items-center justify-between gap-3">
							<div class="min-w-0">
								<div class="flex items-center gap-2 flex-wrap">
									<span class="font-semibold truncate">{e.name}</span>
									<span class="badge variant-soft text-xs">{e.kind}</span>
									<span class="badge {engagementStatusVariant(st)} text-xs">{engStatusLabel(st)}</span>
									{#if e.out_of_scope_count}
										<span class="badge variant-soft-warning text-xs">
											{m.authz_eng_out_of_scope({ count: e.out_of_scope_count })}
										</span>
									{/if}
								</div>
								<div class="text-xs opacity-70 mt-0.5">
									{e.starts_at} → {e.ends_at}
									{#if e.scope_source_ips?.length}· {e.scope_source_ips.join(', ')}{/if}
									{#if e.scope_techniques?.length}· {e.scope_techniques.join(', ')}{/if}
								</div>
							</div>
							<div class="flex gap-3 shrink-0">
								{#if $canAuthorizeEngagements}
									<button class="text-sm opacity-70 hover:opacity-100" on:click={() => openEngForm(e)}>
										{m.authz_eng_clone()}
									</button>
								{/if}
								{#if $canAuthorizeEngagements && st !== 'revoked'}
									<button class="text-red-400 hover:underline text-sm" on:click={() => revokeEngagement(e)}>
										{m.adm_revoke()}
									</button>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		{/if}
	{:else if !tenantId}
		<p class="text-gray-400">{m.adm_select_tenant()}</p>
	{:else if loading}
		<p class="text-gray-400">{m.common_loading()}</p>
	{:else if error}
		<p class="text-red-400">{error}</p>
	{:else if facts.length === 0}
		<p class="text-gray-400">{m.adm_facts_empty()}</p>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
					<tr>
						<th class="px-3 py-2">{m.adm_th_id()}</th>
						<th class="px-3 py-2">{m.adm_th_kind()}</th>
						<th class="px-3 py-2">{m.adm_th_track()}</th>
						<th class="px-3 py-2">{m.adm_th_scope()}</th>
						<th class="px-3 py-2">{m.adm_th_source()}</th>
						<th class="px-3 py-2">{m.adm_th_trust()}</th>
						<th class="px-3 py-2">{m.adm_th_review()}</th>
						<th class="px-3 py-2">{m.adm_th_valid_until()}</th>
						<th class="px-3 py-2">{m.adm_th_provenance()}</th>
						<th class="px-3 py-2"></th>
					</tr>
				</thead>
				<tbody>
					{#each facts as f (f.id)}
						<tr class="border-t">
							<td class="px-3 py-2 font-mono">{f.id}</td>
							<td class="px-3 py-2">{f.kind}</td>
							<td class="px-3 py-2">{f.track}</td>
							<td class="px-3 py-2">{factSummary(f)}</td>
							<td class="px-3 py-2">{f.source_type}</td>
							<td class="px-3 py-2">{f.trust}</td>
							<td class="px-3 py-2">
								{#if f.review_status === 'pending'}
									<span class="text-xs px-2 py-0.5 rounded bg-amber-200 text-amber-900"
										>{m.adm_status_awaiting_review()}</span
									>
								{:else if f.review_status === 'rejected'}
									<span class="text-xs px-2 py-0.5 rounded bg-red-200 text-red-900">{m.adm_status_rejected()}</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">{m.adm_status_approved()}</span>
								{/if}
							</td>
							<td class="px-3 py-2">{f.valid_until ?? '—'}</td>
							<td class="px-3 py-2 text-gray-400">
								{f.provenance?.api_caller ?? f.created_by ?? '—'}
							</td>
							<td class="px-3 py-2 text-right whitespace-nowrap">
								{#if $canManageAuthorization && f.review_status === 'pending'}
									<button class="text-green-400 hover:underline mr-2" on:click={() => review(f, 'approve')}>
										{m.adm_approve()}
									</button>
									<button class="text-red-400 hover:underline" on:click={() => review(f, 'reject')}>
										{m.adm_reject()}
									</button>
								{:else if $canManageAuthorization}
									<button class="text-red-400 hover:underline" on:click={() => revoke(f)}>
										{m.adm_revoke()}
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	{#if editorOpen}
		<!-- Scroll on the overlay, center via an inner min-h-full wrapper. Centering
		     directly on the scroll container clips a too-tall panel at BOTH ends and
		     the overflow above the top edge can never be scrolled back into view. -->
		<div class="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
			<div class="flex min-h-full items-center justify-center p-4">
				<div class="card w-full max-w-2xl p-5">
					<h2 class="h4 mb-3">{m.adm_modal_new_fact_title()}</h2>
					<AuthorizationFactForm
						mode="mssp"
						saving={editorSaving}
						error={editorError}
						on:submit={(e) => save(e.detail)}
						on:cancel={() => (editorOpen = false)}
					/>
				</div>
			</div>
		</div>
	{/if}
</div>
