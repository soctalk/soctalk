<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type AuthorizationFact } from '$lib/api/client';
	import { canAssertTenantAuthorization } from '$lib/stores';

	let facts: AuthorizationFact[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;
	let factText = '';

	const EXAMPLE = JSON.stringify(
		{
			kind: 'grant',
			id: 'ignored-server-generates-one',
			track: 'account',
			grant_class: 'standing_baseline',
			scope: { subject: 'svc-deploy', target: 'db-01', action: 'sudo-exec' }
		},
		null,
		2
	);

	async function load() {
		loading = true;
		error = null;
		try {
			const res = await api.tenantAuthzFacts.list();
			facts = res.facts;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load facts';
		} finally {
			loading = false;
		}
	}

	function openForm() {
		factText = EXAMPLE;
		formOpen = true;
	}

	async function assert() {
		let parsed: Record<string, unknown>;
		try {
			parsed = JSON.parse(factText);
		} catch {
			error = 'Invalid JSON.';
			return;
		}
		saving = true;
		error = null;
		try {
			await api.tenantAuthzFacts.assert(parsed);
			formOpen = false;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Assertion failed';
		} finally {
			saving = false;
		}
	}

	function scopeText(f: AuthorizationFact): string {
		const s = f.scope;
		if (!s) return '—';
		return [s.subject, s.target, s.action].filter(Boolean).join(' · ') || '—';
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">Authorization facts</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">
				Tell the SOC what activity in your environment is authorized — an approved change,
				a service account's routine work. Anything you assert is reviewed by an analyst before
				it can affect triage, and it can never close an alert that carries a threat indicator.
			</p>
		</div>
		{#if $canAssertTenantAuthorization}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
				on:click={openForm}
			>
				+ Assert fact
			</button>
		{/if}
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if formOpen && $canAssertTenantAuthorization}
		<div class="card p-4 rounded border space-y-2">
			<p class="text-sm opacity-70">
				Paste an authorization fact (JSON). It's submitted at low trust and lands
				<span class="font-medium">awaiting review</span> until an analyst approves it.
			</p>
			<textarea
				class="w-full border rounded p-2 font-mono text-xs h-56"
				bind:value={factText}
			></textarea>
			<div class="flex justify-end gap-2">
				<button class="px-3 py-2 text-sm" on:click={() => (formOpen = false)}>Cancel</button>
				<button class="px-3 py-2 rounded bg-blue-600 text-white text-sm" on:click={assert} disabled={saving}>
					{saving ? 'Submitting…' : 'Submit for review'}
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="opacity-60 text-sm">Loading…</div>
	{:else if facts.length === 0}
		<div class="opacity-60 text-sm">No authorization facts for your organization yet.</div>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
					<tr>
						<th class="px-3 py-2">ID</th>
						<th class="px-3 py-2">Kind</th>
						<th class="px-3 py-2">Scope</th>
						<th class="px-3 py-2">Source</th>
						<th class="px-3 py-2">Status</th>
					</tr>
				</thead>
				<tbody>
					{#each facts as f (f.id)}
						<tr class="border-t">
							<td class="px-3 py-2 font-mono truncate max-w-[16rem]">{f.id}</td>
							<td class="px-3 py-2">{f.kind}</td>
							<td class="px-3 py-2">{scopeText(f)}</td>
							<td class="px-3 py-2">{f.source_type}</td>
							<td class="px-3 py-2">
								{#if f.review_status === 'pending'}
									<span class="text-xs px-2 py-0.5 rounded bg-amber-200 text-amber-900">awaiting review</span>
								{:else if f.review_status === 'rejected'}
									<span class="text-xs px-2 py-0.5 rounded bg-red-200 text-red-900">rejected</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">approved</span>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
