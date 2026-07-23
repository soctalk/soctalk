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
	import AuthorizationFactForm from '$lib/components/authz/AuthorizationFactForm.svelte';
	import { engagementStatus, engagementStatusVariant, factSummary } from '$lib/authz/display';

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

	async function assertFact(fact: Record<string, unknown>) {
		savingFact = true;
		error = null;
		try {
			await api.tenantAuthzFacts.assert(fact);
			factFormOpen = false;
			await loadFacts();
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_assert_failed();
		} finally {
			savingFact = false;
		}
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
	let techniques = '';
	let engError: string | null = null;

	function csv(s: string): string[] {
		return s
			.split(',')
			.map((v) => v.trim())
			.filter((v) => v.length > 0);
	}

	// IPv4/IPv6/CIDR shape check. The server does authoritative validation; this
	// mirrors it closely enough to catch obvious mistakes before the round-trip
	// (rejects out-of-range octets and CIDR bits; accepts IPv4-mapped IPv6).
	function looksLikeIp(v: string): boolean {
		const slash = v.indexOf('/');
		const addr = slash >= 0 ? v.slice(0, slash) : v;
		const cidr = slash >= 0 ? v.slice(slash + 1) : undefined;
		const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
		if (v4) {
			if (!v4.slice(1).every((o) => Number(o) <= 255)) return false;
			return cidr === undefined || (/^\d+$/.test(cidr) && Number(cidr) <= 32);
		}
		if (addr.includes(':') && /^[0-9a-fA-F:.]+$/.test(addr)) {
			return cidr === undefined || (/^\d+$/.test(cidr) && Number(cidr) <= 128);
		}
		return false;
	}

	// Mirror the server-side declare validation (campaign.py) so users get inline
	// feedback instead of a raw 400.
	function validateEngagement(): string | null {
		if (!name.trim()) return m.authz_err_eng_name();
		const start = new Date(startsAt).getTime();
		const end = new Date(endsAt).getTime();
		if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return m.authz_err_eng_window();
		if (end - start > 90 * 24 * 60 * 60 * 1000) return m.authz_err_eng_max_days();
		const ips = csv(sourceIps);
		if (!ips.length || !ips.every(looksLikeIp)) return m.authz_err_eng_source_ip();
		const techs = csv(techniques).map((t) => t.toUpperCase());
		if (!csv(hosts).length && !techs.length) return m.authz_err_eng_target();
		if (techs.length && !techs.every((t) => /^T\d{4}(\.\d{3})?$/.test(t)))
			return m.authz_err_eng_technique();
		return null;
	}

	function engStatusLabel(st: 'scheduled' | 'active' | 'expired' | 'revoked'): string {
		return st === 'active'
			? m.authz_eng_status_active()
			: st === 'scheduled'
				? m.authz_eng_status_scheduled()
				: st === 'expired'
					? m.authz_eng_status_expired()
					: m.authz_eng_status_revoked();
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

	function openEngForm(clone?: TenantEngagement) {
		engError = null;
		// Always reset the window; carry scope/name/kind only when cloning.
		startsAt = '';
		endsAt = '';
		name = clone?.name ?? '';
		kind = clone?.kind ?? 'pentest';
		sourceIps = (clone?.scope_source_ips ?? []).join(', ');
		hosts = (clone?.scope_hosts ?? []).join(', ');
		techniques = (clone?.scope_techniques ?? []).join(', ');
		engFormOpen = true;
	}

	async function declare() {
		engError = validateEngagement();
		if (engError) return;
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
				scope_techniques: csv(techniques).map((t) => t.toUpperCase())
			});
			engFormOpen = false;
			name = '';
			sourceIps = '';
			hosts = '';
			techniques = '';
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
					on:click={() => (factFormOpen = true)}
				>
					{m.adm_assert_fact()}
				</button>
			{/if}
		</div>

		{#if factFormOpen && $canAssertTenantAuthorization}
			<div class="card p-4 rounded border">
				<AuthorizationFactForm
					mode="tenant"
					saving={savingFact}
					{error}
					on:submit={(e) => assertFact(e.detail)}
					on:cancel={() => (factFormOpen = false)}
				/>
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
								<td class="px-3 py-2">{factSummary(f)}</td>
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
					on:click={() => openEngForm()}
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
						<input class="input" bind:value={name} required placeholder={m.adm_placeholder_engagement_name()} />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_kind()}</span>
						<select class="select" bind:value={kind}>
							<option value="pentest">pentest</option>
							<option value="red_team">red_team</option>
							<option value="vuln_scan">vuln_scan</option>
						</select>
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_starts()}</span>
						<input class="input" type="datetime-local" bind:value={startsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_ends()}</span>
						<input class="input" type="datetime-local" bind:value={endsAt} required />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_source_ips()}</span>
						<input class="input font-mono" bind:value={sourceIps} placeholder="203.0.113.0/24" />
					</label>
					<label class="flex flex-col gap-1">
						<span class="opacity-70">{m.adm_field_hosts()}</span>
						<input class="input font-mono" bind:value={hosts} placeholder="web-01, db-01" />
					</label>
					<label class="flex flex-col gap-1 sm:col-span-2">
						<span class="opacity-70">{m.authz_field_techniques()}</span>
						<input class="input font-mono" bind:value={techniques} placeholder="T1078, T1110.001" />
					</label>
				</div>
				{#if engError}
					<div class="alert variant-filled-error text-sm"><span>{engError}</span></div>
				{/if}
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
					{@const st = engagementStatus(e)}
					<div class="card p-3 rounded border flex items-center justify-between gap-3">
						<div class="min-w-0">
							<div class="flex items-center gap-2 flex-wrap">
								<span class="font-semibold truncate">{e.name}</span>
								<span class="badge variant-soft text-xs">{e.kind}</span>
								<span class="badge {engagementStatusVariant(st)} text-xs">{engStatusLabel(st)}</span>
								{#if e.out_of_scope_count}
									<span class="badge variant-soft-warning text-xs">{m.authz_eng_out_of_scope({ count: e.out_of_scope_count })}</span>
								{/if}
							</div>
							<div class="text-xs opacity-70 mt-0.5">
								{e.starts_at} → {e.ends_at}
								{#if e.scope_source_ips?.length}· {e.scope_source_ips.join(', ')}{/if}
								{#if e.scope_techniques?.length}· {e.scope_techniques.join(', ')}{/if}
							</div>
						</div>
						<div class="flex gap-3 shrink-0">
							{#if $canDeclareTenantEngagement}
								<button class="text-sm opacity-70 hover:opacity-100" on:click={() => openEngForm(e)}>{m.authz_eng_clone()}</button>
							{/if}
							{#if $canDeclareTenantEngagement && st !== 'revoked'}
								<button class="text-red-400 hover:underline text-sm" on:click={() => revoke(e)}>{m.adm_revoke()}</button>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>
