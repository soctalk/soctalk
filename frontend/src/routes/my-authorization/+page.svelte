<script lang="ts">
	import { page } from '$app/stores';
	import {
		api,
		type AuthorizationFact,
		type TenantEngagement
	} from '$lib/api/client';
	import {
		canAssertTenantAuthorization,
		canDeclareTenantEngagement
	} from '$lib/stores';

	// Two kinds of authorization for your environment: standing FACTS (an approved change, a
	// service account's routine work) and time-boxed ENGAGEMENTS (an authorized pentest/red-team
	// window). Both tell the SOC what activity is authorized; they differ only in how the SOC uses
	// them — facts inform the AI's reasoning; an engagement deconflicts by window+scope.
	let tab: 'facts' | 'engagements' =
		$page.url.searchParams.get('tab') === 'engagements' ? 'engagements' : 'facts';

	let error: string | null = null;

	// ---- facts ----
	let facts: AuthorizationFact[] = [];
	let factsLoading = true;
	let factsLoaded = false;
	let factFormOpen = false;
	let savingFact = false;
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

	async function loadFacts() {
		factsLoading = true;
		factsLoaded = true;
		try {
			facts = (await api.tenantAuthzFacts.list()).facts;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load facts';
		} finally {
			factsLoading = false;
		}
	}

	function openFactForm() {
		factText = EXAMPLE;
		factFormOpen = true;
	}

	async function assertFact() {
		let parsed: Record<string, unknown>;
		try {
			parsed = JSON.parse(factText);
		} catch {
			error = 'Invalid JSON.';
			return;
		}
		savingFact = true;
		error = null;
		try {
			await api.tenantAuthzFacts.assert(parsed);
			factFormOpen = false;
			await loadFacts();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Assertion failed';
		} finally {
			savingFact = false;
		}
	}

	function scopeText(f: AuthorizationFact): string {
		const s = f.scope;
		if (!s) return '—';
		return [s.subject, s.target, s.action].filter(Boolean).join(' · ') || '—';
	}

	// ---- engagements ----
	let engagements: TenantEngagement[] = [];
	let engLoading = true;
	let engLoaded = false;
	let engFormOpen = false;
	let savingEng = false;
	let name = '';
	let kind = 'pentest';
	let startsAt = '';
	let endsAt = '';
	let sourceIps = '';
	let hosts = '';

	function csv(s: string): string[] {
		return s
			.split(',')
			.map((v) => v.trim())
			.filter((v) => v.length > 0);
	}

	async function loadEngagements() {
		engLoading = true;
		engLoaded = true;
		try {
			engagements = await api.tenantEngagements.list(true);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load engagements';
		} finally {
			engLoading = false;
		}
	}

	async function declare() {
		savingEng = true;
		error = null;
		try {
			await api.tenantEngagements.declare({
				name,
				kind,
				starts_at: new Date(startsAt).toISOString(),
				ends_at: new Date(endsAt).toISOString(),
				scope_source_ips: csv(sourceIps),
				scope_hosts: csv(hosts),
				scope_techniques: []
			});
			engFormOpen = false;
			name = '';
			sourceIps = '';
			hosts = '';
			await loadEngagements();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to declare engagement';
		} finally {
			savingEng = false;
		}
	}

	async function revoke(e: TenantEngagement) {
		const reason = window.prompt(`Revoke engagement "${e.name}"? Optional reason:`, '');
		if (reason === null) return;
		try {
			await api.tenantEngagements.revoke(e.id, reason || null);
			await loadEngagements();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Revoke failed';
		}
	}

	// Lazy per-tab load: only fetch a tab's data the first time it's shown (avoids a wasted
	// request for the inactive tab).
	$: if (tab === 'facts' && !factsLoaded) loadFacts();
	$: if (tab === 'engagements' && !engLoaded) loadEngagements();
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div>
		<h1 class="text-2xl font-semibold">Authorization</h1>
		<p class="text-sm opacity-70 mt-1 max-w-2xl">
			Tell the SOC what activity in your environment is authorized. Authorization comes in two
			forms: standing <span class="font-medium">facts</span> (an approved change, a service
			account's routine work) and time-boxed <span class="font-medium">engagements</span> (an
			authorized pentest or red-team window). An engagement is simply a bounded authorization of
			attack-shaped activity.
		</p>
	</div>

	<div class="flex gap-1 border-b border-surface-500/20 text-sm">
		<button
			class="px-3 py-2 -mb-px border-b-2 {tab === 'facts'
				? 'border-blue-600 font-medium'
				: 'border-transparent opacity-70'}"
			on:click={() => (tab = 'facts')}
		>
			Authorization facts
		</button>
		<button
			class="px-3 py-2 -mb-px border-b-2 {tab === 'engagements'
				? 'border-blue-600 font-medium'
				: 'border-transparent opacity-70'}"
			on:click={() => (tab = 'engagements')}
		>
			Engagements
		</button>
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if tab === 'facts'}
		<div class="flex items-start justify-between gap-4">
			<p class="text-sm opacity-70 max-w-2xl">
				Anything you assert is reviewed by an analyst before it can affect triage, and it can never
				close an alert that carries a threat indicator.
			</p>
			{#if $canAssertTenantAuthorization}
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
					on:click={openFactForm}
				>
					+ Assert fact
				</button>
			{/if}
		</div>

		{#if factFormOpen && $canAssertTenantAuthorization}
			<div class="card p-4 rounded border space-y-2">
				<p class="text-sm opacity-70">
					Paste an authorization fact (JSON). It's submitted at low trust and lands
					<span class="font-medium">awaiting review</span> until an analyst approves it.
				</p>
				<textarea class="w-full border rounded p-2 font-mono text-xs h-56" bind:value={factText}></textarea>
				<div class="flex justify-end gap-2">
					<button class="px-3 py-2 text-sm" on:click={() => (factFormOpen = false)}>Cancel</button>
					<button class="px-3 py-2 rounded bg-blue-600 text-white text-sm" on:click={assertFact} disabled={savingFact}>
						{savingFact ? 'Submitting…' : 'Submit for review'}
					</button>
				</div>
			</div>
		{/if}

		{#if factsLoading}
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
	{:else}
		<div class="flex items-start justify-between gap-4">
			<p class="text-sm opacity-70 max-w-2xl">
				Declare authorized offensive activity against your own environment — a pentest or red-team
				window and its scope — so the SOC deconflicts it. A declared engagement adds context; it
				never suppresses detections, and activity outside its scope still escalates.
			</p>
			{#if $canDeclareTenantEngagement}
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
					on:click={() => (engFormOpen = !engFormOpen)}
				>
					+ Declare engagement
				</button>
			{/if}
		</div>

		{#if engFormOpen && $canDeclareTenantEngagement}
			<form class="card p-4 rounded border space-y-3" on:submit|preventDefault={declare}>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
					<label class="flex flex-col gap-1">
						<span class="opacity-70">Name</span>
						<input class="border rounded px-2 py-1" bind:value={name} required placeholder="Q3 external pentest" />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">Kind</span>
						<select class="border rounded px-2 py-1" bind:value={kind}>
							<option value="pentest">pentest</option>
							<option value="red_team">red_team</option>
							<option value="vuln_scan">vuln_scan</option>
						</select>
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">Starts</span>
						<input class="border rounded px-2 py-1" type="datetime-local" bind:value={startsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">Ends</span>
						<input class="border rounded px-2 py-1" type="datetime-local" bind:value={endsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">Source IPs / CIDRs (comma-separated)</span>
						<input class="border rounded px-2 py-1 font-mono" bind:value={sourceIps} placeholder="203.0.113.0/24" />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">In-scope hosts (comma-separated)</span>
						<input class="border rounded px-2 py-1 font-mono" bind:value={hosts} placeholder="web-01, db-01" />
					</label>
				</div>
				<div class="flex justify-end gap-2">
					<button type="button" class="px-3 py-2 text-sm" on:click={() => (engFormOpen = false)}>Cancel</button>
					<button type="submit" class="px-3 py-2 rounded bg-blue-600 text-white text-sm" disabled={savingEng}>
						{savingEng ? 'Declaring…' : 'Declare'}
					</button>
				</div>
			</form>
		{/if}

		{#if engLoading}
			<div class="opacity-60 text-sm">Loading…</div>
		{:else if engagements.length === 0}
			<div class="opacity-60 text-sm">No engagements declared for this tenant yet.</div>
		{:else}
			<div class="space-y-2">
				{#each engagements as e (e.id)}
					<div class="card p-3 rounded border flex items-center justify-between gap-3">
						<div class="min-w-0">
							<div class="flex items-center gap-2">
								<span class="font-semibold truncate">{e.name}</span>
								<span class="text-xs px-2 py-0.5 rounded bg-gray-200 dark:bg-gray-700">{e.kind}</span>
								<span
									class="text-xs px-2 py-0.5 rounded {e.status === 'active'
										? 'bg-green-200 text-green-900'
										: 'bg-gray-200 text-gray-700'}">{e.status}</span
								>
							</div>
							<div class="text-xs opacity-70 mt-0.5">
								{e.starts_at} → {e.ends_at}
								{#if e.scope_source_ips?.length}· {e.scope_source_ips.join(', ')}{/if}
							</div>
						</div>
						{#if $canDeclareTenantEngagement && e.status !== 'revoked'}
							<button class="text-red-600 hover:underline text-sm shrink-0" on:click={() => revoke(e)}>
								Revoke
							</button>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>
