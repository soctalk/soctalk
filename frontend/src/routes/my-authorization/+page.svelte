<script lang="ts">
	import { page } from '$app/stores';
	import {
		api,
		type AuthorizationFact,
		type TenantEngagement
	} from '$lib/api/client';
	import {
		authSession,
		canAssertTenantAuthorization,
		canDeclareTenantEngagement,
		isMsspUser
	} from '$lib/stores';
	import { m } from '$lib/paraglide/messages';
	import { localizedGoto } from '$lib/i18n';

	// Tenant-side (/api/tenant/*) area. An MSSP-side user who reaches it by
	// URL is denied by the audience wall, so bounce them to the MSSP-side
	// authorization review rather than surface a raw permission error.
	$: if ($authSession.user && $isMsspUser) {
		localizedGoto('/authorization');
	}

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
			error = e instanceof Error ? e.message : m.adm_my_facts_load_failed();
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
			error = m.adm_invalid_json();
			return;
		}
		savingFact = true;
		error = null;
		try {
			await api.tenantAuthzFacts.assert(parsed);
			factFormOpen = false;
			await loadFacts();
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_assert_failed();
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
			error = e instanceof Error ? e.message : m.adm_eng_load_failed();
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
			error = e instanceof Error ? e.message : m.adm_eng_declare_failed();
		} finally {
			savingEng = false;
		}
	}

	async function revoke(e: TenantEngagement) {
		const reason = window.prompt(m.adm_revoke_engagement_prompt({ name: e.name }), '');
		if (reason === null) return;
		try {
			await api.tenantEngagements.revoke(e.id, reason || null);
			await loadEngagements();
		} catch (err) {
			error = err instanceof Error ? err.message : m.adm_revoke_failed();
		}
	}

	// Lazy per-tab load: only fetch a tab's data the first time it's shown (avoids a wasted
	// request for the inactive tab).
	$: if (tab === 'facts' && !factsLoaded) loadFacts();
	$: if (tab === 'engagements' && !engLoaded) loadEngagements();
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div>
		<h1 class="text-2xl font-semibold">{m.nav_authorization()}</h1>
		<p class="text-sm opacity-70 mt-1 max-w-2xl">
			{m.adm_authz_intro_1()} <span class="font-medium">{m.adm_authz_intro_facts()}</span>
			{m.adm_authz_intro_2()} <span class="font-medium">{m.adm_authz_intro_engagements()}</span>
			{m.adm_authz_intro_3()}
		</p>
	</div>

	<div class="flex gap-1 border-b border-surface-500/20 text-sm">
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

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if tab === 'facts'}
		<div class="flex items-start justify-between gap-4">
			<p class="text-sm opacity-70 max-w-2xl">
				{m.adm_my_facts_intro()}
			</p>
			{#if $canAssertTenantAuthorization}
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
					on:click={openFactForm}
				>
					{m.adm_assert_fact()}
				</button>
			{/if}
		</div>

		{#if factFormOpen && $canAssertTenantAuthorization}
			<div class="card p-4 rounded border space-y-2">
				<p class="text-sm opacity-70">
					{m.adm_fact_form_hint_1()}
					<span class="font-medium">{m.adm_status_awaiting_review()}</span>
					{m.adm_fact_form_hint_2()}
				</p>
				<textarea class="w-full border rounded p-2 font-mono text-xs h-56" bind:value={factText}></textarea>
				<div class="flex justify-end gap-2">
					<button class="px-3 py-2 text-sm" on:click={() => (factFormOpen = false)}>{m.common_cancel()}</button>
					<button class="px-3 py-2 rounded bg-blue-600 text-white text-sm" on:click={assertFact} disabled={savingFact}>
						{savingFact ? m.adm_submitting() : m.adm_submit_for_review()}
					</button>
				</div>
			</div>
		{/if}

		{#if factsLoading}
			<div class="opacity-60 text-sm">{m.common_loading()}</div>
		{:else if facts.length === 0}
			<div class="opacity-60 text-sm">{m.adm_my_facts_empty()}</div>
		{:else}
			<div class="overflow-x-auto border rounded">
				<table class="min-w-full text-sm">
					<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
						<tr>
							<th class="px-3 py-2">{m.adm_th_id()}</th>
							<th class="px-3 py-2">{m.adm_th_kind()}</th>
							<th class="px-3 py-2">{m.adm_th_scope()}</th>
							<th class="px-3 py-2">{m.adm_th_source()}</th>
							<th class="px-3 py-2">{m.adm_th_status()}</th>
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
										<span class="text-xs px-2 py-0.5 rounded bg-amber-200 text-amber-900">{m.adm_status_awaiting_review()}</span>
									{:else if f.review_status === 'rejected'}
										<span class="text-xs px-2 py-0.5 rounded bg-red-200 text-red-900">{m.adm_status_rejected()}</span>
									{:else}
										<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">{m.adm_status_approved()}</span>
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
				{m.adm_eng_intro()}
			</p>
			{#if $canDeclareTenantEngagement}
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
					on:click={() => (engFormOpen = !engFormOpen)}
				>
					{m.adm_declare_engagement()}
				</button>
			{/if}
		</div>

		{#if engFormOpen && $canDeclareTenantEngagement}
			<form class="card p-4 rounded border space-y-3" on:submit|preventDefault={declare}>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_name()}</span>
						<input class="border rounded px-2 py-1" bind:value={name} required placeholder={m.adm_placeholder_engagement_name()} />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_kind()}</span>
						<select class="border rounded px-2 py-1" bind:value={kind}>
							<option value="pentest">pentest</option>
							<option value="red_team">red_team</option>
							<option value="vuln_scan">vuln_scan</option>
						</select>
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_starts()}</span>
						<input class="border rounded px-2 py-1" type="datetime-local" bind:value={startsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_ends()}</span>
						<input class="border rounded px-2 py-1" type="datetime-local" bind:value={endsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_source_ips()}</span>
						<input class="border rounded px-2 py-1 font-mono" bind:value={sourceIps} placeholder="203.0.113.0/24" />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_hosts()}</span>
						<input class="border rounded px-2 py-1 font-mono" bind:value={hosts} placeholder="web-01, db-01" />
					</label>
				</div>
				<div class="flex justify-end gap-2">
					<button type="button" class="px-3 py-2 text-sm" on:click={() => (engFormOpen = false)}>{m.common_cancel()}</button>
					<button type="submit" class="px-3 py-2 rounded bg-blue-600 text-white text-sm" disabled={savingEng}>
						{savingEng ? m.adm_declaring() : m.adm_declare()}
					</button>
				</div>
			</form>
		{/if}

		{#if engLoading}
			<div class="opacity-60 text-sm">{m.common_loading()}</div>
		{:else if engagements.length === 0}
			<div class="opacity-60 text-sm">{m.adm_eng_empty()}</div>
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
								{m.adm_revoke()}
							</button>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>
