<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantEngagement } from '$lib/api/client';
	import { canDeclareTenantEngagement } from '$lib/stores';

	let engagements: TenantEngagement[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;

	// declare form
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

	async function load() {
		loading = true;
		error = null;
		try {
			engagements = await api.tenantEngagements.list(true);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load engagements';
		} finally {
			loading = false;
		}
	}

	async function declare() {
		saving = true;
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
			formOpen = false;
			name = '';
			sourceIps = '';
			hosts = '';
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to declare engagement';
		} finally {
			saving = false;
		}
	}

	async function revoke(e: TenantEngagement) {
		const reason = window.prompt(`Revoke engagement "${e.name}"? Optional reason:`, '');
		if (reason === null) return;
		try {
			await api.tenantEngagements.revoke(e.id, reason || null);
			await load();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Revoke failed';
		}
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">Authorized engagements</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">
				Declare authorized offensive activity against your own environment — a pentest or
				red-team window and its scope — so the SOC deconflicts it. A declared engagement adds
				context; it never suppresses detections, and activity outside its scope still escalates.
			</p>
		</div>
		{#if $canDeclareTenantEngagement}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
				on:click={() => (formOpen = !formOpen)}
			>
				+ Declare engagement
			</button>
		{/if}
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if formOpen && $canDeclareTenantEngagement}
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
				<button type="button" class="px-3 py-2 text-sm" on:click={() => (formOpen = false)}>Cancel</button>
				<button type="submit" class="px-3 py-2 rounded bg-blue-600 text-white text-sm" disabled={saving}>
					{saving ? 'Declaring…' : 'Declare'}
				</button>
			</div>
		</form>
	{/if}

	{#if loading}
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
</div>
