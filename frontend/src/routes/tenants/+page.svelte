<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/client';
	import { tenantsApi, tenantStateBadge, type Tenant } from '$lib/api/tenants';
	import { addToast, authSession, isMsspScope } from '$lib/stores';

	async function scopeTo(slug: string) {
		try {
			const updated = await api.auth.assumeTenant(slug);
			authSession.update((s) => ({ ...s, user: updated }));
			goto('/');
		} catch (e) {
			addToast({
				type: 'error',
				title: 'Scope',
				message: e instanceof Error ? e.message : 'Failed to switch tenant scope',
			});
		}
	}

	let tenants: Tenant[] = [];
	let loading = true;
	let error: string | null = null;
	let loadedFor: string | null = null;

	// Auth lands asynchronously; reactively load when an MSSP user is
	// actually present, redirect only when we know the user is non-MSSP.
	$: if ($authSession.user) {
		if (!$isMsspScope) {
			goto('/');
		} else if (loadedFor !== $authSession.user.user_id) {
			loadedFor = $authSession.user.user_id;
			void load();
		}
	}

	onMount(() => {});

	async function load() {
		loading = true;
		error = null;
		try {
			tenants = await tenantsApi.list();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load tenants';
			addToast({ type: 'error', title: 'Tenants', message: error });
		} finally {
			loading = false;
		}
	}

	function fmtDate(ts: string): string {
		try {
			return new Date(ts).toLocaleString();
		} catch {
			return ts;
		}
	}
</script>

<div class="space-y-4">
	<div class="flex items-center justify-between">
		<h1 class="h2">Tenants</h1>
		<button class="btn variant-filled-primary" on:click={() => goto('/tenants/new')}>
			+ New Tenant
		</button>
	</div>

	{#if loading}
		<div class="card p-6 flex items-center gap-3">
			<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
			<span>Loading tenants…</span>
		</div>
	{:else if error}
		<div class="card p-6 text-error-500">{error}</div>
	{:else if tenants.length === 0}
		<div class="card p-6 opacity-70">
			No tenants yet. Click <strong>+ New Tenant</strong> to onboard one.
		</div>
	{:else}
		<div class="card overflow-hidden">
			<table class="table table-hover">
				<thead>
					<tr>
						<th>Display Name</th>
						<th>Slug</th>
						<th>Profile</th>
						<th>State</th>
						<th>Created</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each tenants as t (t.id)}
						{@const ready = ['active', 'degraded', 'suspended'].includes(t.state)}
						<tr>
							<td class="font-medium">
								<a class="anchor" href={`/tenants/${t.id}`}>{t.display_name}</a>
							</td>
							<td><code class="text-xs">{t.slug}</code></td>
							<td>{t.profile ?? '—'}</td>
							<td>
								<span class="badge {tenantStateBadge(t.state)}">{t.state}</span>
							</td>
							<td class="text-sm opacity-70">{fmtDate(t.created_at)}</td>
							<td>
								<button
									type="button"
									class="btn btn-sm variant-soft-primary"
									title={ready
										? 'Pin session to this tenant — SOC pages will scope to them'
										: `Tenant is ${t.state} — wait for it to reach \'active\' before pinning. Per-tenant SOC data isn\'t available yet.`}
									disabled={!ready}
									on:click={() => scopeTo(t.slug)}
								>
									Open SOC
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
