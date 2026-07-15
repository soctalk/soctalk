<script lang="ts">
	import { api, type AuthorizationFact } from '$lib/api/client';
	import { currentTenantId } from '$lib/stores';

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
			error = e instanceof Error ? e.message : 'Failed to load authorization facts';
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
			editorError = 'Not valid JSON';
			editorSaving = false;
			return;
		}
		try {
			await api.authorizationFacts.create(tenantId, parsed);
			editorOpen = false;
			await load(tenantId);
		} catch (e) {
			editorError = e instanceof Error ? e.message : 'Create failed';
		} finally {
			editorSaving = false;
		}
	}

	async function revoke(f: AuthorizationFact) {
		if (!tenantId) return;
		const reason = window.prompt(`Revoke fact "${f.id}"? Optional reason:`, '');
		if (reason === null) return; // cancelled
		try {
			await api.authorizationFacts.revoke(tenantId, f.id, reason || null);
			await load(tenantId);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Revoke failed';
		}
	}
</script>

<div class="p-6">
	<div class="flex items-center justify-between mb-4">
		<div>
			<h1 class="text-2xl font-semibold">Authorization facts</h1>
			<p class="text-sm text-gray-500">
				Org-state the triage engine reasons over. Facts arrive from connectors (the ingest API),
				SIEM-derived routine, or analyst answers. Revoking is a soft delete; the audit row survives.
			</p>
		</div>
		<button
			class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
			on:click={openCreate}
			disabled={!tenantId}
		>
			+ New fact
		</button>
	</div>

	{#if !tenantId}
		<p class="text-gray-500">Select a tenant to view its authorization facts.</p>
	{:else if loading}
		<p class="text-gray-500">Loading…</p>
	{:else if error}
		<p class="text-red-600">{error}</p>
	{:else if facts.length === 0}
		<p class="text-gray-500">No authorization facts for this tenant yet.</p>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 text-left text-gray-600">
					<tr>
						<th class="px-3 py-2">ID</th>
						<th class="px-3 py-2">Kind</th>
						<th class="px-3 py-2">Track</th>
						<th class="px-3 py-2">Scope</th>
						<th class="px-3 py-2">Source</th>
						<th class="px-3 py-2">Trust</th>
						<th class="px-3 py-2">Valid until</th>
						<th class="px-3 py-2">Provenance</th>
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
							<td class="px-3 py-2">{f.valid_until ?? '—'}</td>
							<td class="px-3 py-2 text-gray-500">
								{f.provenance?.api_caller ?? f.created_by ?? '—'}
							</td>
							<td class="px-3 py-2 text-right">
								<button class="text-red-600 hover:underline" on:click={() => revoke(f)}>
									Revoke
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	{#if editorOpen}
		<div class="fixed inset-0 bg-black/40 flex items-center justify-center p-4">
			<div class="bg-white rounded shadow-lg w-full max-w-2xl p-4">
				<h2 class="text-lg font-semibold mb-2">New authorization fact</h2>
				<p class="text-xs text-gray-500 mb-2">
					A typed AuthorizationFact (grant / prohibition / change_freeze / entity_context). Stored as
					analyst_asserted (trust 60).
				</p>
				<textarea
					class="w-full h-72 font-mono text-xs border rounded p-2"
					bind:value={editorText}
				></textarea>
				{#if editorError}<p class="text-red-600 text-sm mt-1">{editorError}</p>{/if}
				<div class="flex justify-end gap-2 mt-3">
					<button class="px-3 py-2 text-sm" on:click={() => (editorOpen = false)}>Cancel</button>
					<button
						class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
						on:click={save}
						disabled={editorSaving}
					>
						{editorSaving ? 'Saving…' : 'Create'}
					</button>
				</div>
			</div>
		</div>
	{/if}
</div>
