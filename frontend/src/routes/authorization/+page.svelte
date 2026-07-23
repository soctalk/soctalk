<script lang="ts">
	import { api, type AuthorizationFact } from '$lib/api/client';
	import { currentTenantId, canManageAuthorization } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';

	let facts: AuthorizationFact[] = [];
	let loading = false;
	let error: string | null = null;

	let editorOpen = false;
	let editorText = '';
	let editorSaving = false;
	let editorError: string | null = null;

	$: tenantId = $currentTenantId;
	$: if (tenantId) load(tenantId);

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

	function scopeText(f: AuthorizationFact): string {
		const s = f.scope ?? {};
		const parts = [s.subject, s.target, s.action].filter(Boolean);
		return parts.length ? parts.join(' · ') : '—';
	}

	function openCreate() {
		editorError = null;
		editorText = JSON.stringify(
			{
				kind: 'grant',
				id: 'CHG-1001',
				track: 'account',
				grant_class: 'change_ticket',
				scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' },
				valid_until: '2026-12-31T00:00:00Z'
			},
			null,
			2
		);
		editorOpen = true;
	}

	async function save() {
		if (!tenantId) return;
		editorSaving = true;
		editorError = null;
		let parsed: Record<string, unknown>;
		try {
			parsed = JSON.parse(editorText);
		} catch {
			editorError = m.adm_not_valid_json();
			editorSaving = false;
			return;
		}
		try {
			await api.authorizationFacts.create(tenantId, parsed);
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
			<h1 class="text-2xl font-semibold">{m.adm_facts_title()}</h1>
			<p class="text-sm text-gray-400">
				{m.adm_facts_intro()}
			</p>
		</div>
		{#if $canManageAuthorization}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
				on:click={openCreate}
				disabled={!tenantId}
			>
				{m.adm_new_fact()}
			</button>
		{/if}
	</div>

	{#if !tenantId}
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
							<td class="px-3 py-2">{scopeText(f)}</td>
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
		<div class="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
			<div class="card w-full max-w-2xl p-4">
				<h2 class="text-lg font-semibold mb-2">{m.adm_modal_new_fact_title()}</h2>
				<p class="text-xs opacity-60 mb-2">
					{m.adm_modal_new_fact_hint()}
				</p>
				<textarea
					class="w-full h-72 font-mono text-xs border border-surface-500 rounded p-2 bg-surface-800 text-surface-50"
					bind:value={editorText}
				></textarea>
				{#if editorError}<p class="text-red-400 text-sm mt-1">{editorError}</p>{/if}
				<div class="flex justify-end gap-2 mt-3">
					<button class="px-3 py-2 text-sm" on:click={() => (editorOpen = false)}>{m.common_cancel()}</button>
					<button
						class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
						on:click={save}
						disabled={editorSaving}
					>
						{editorSaving ? m.common_saving() : m.adm_create()}
					</button>
				</div>
			</div>
		</div>
	{/if}
</div>
