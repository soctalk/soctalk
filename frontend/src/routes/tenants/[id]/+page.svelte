<script lang="ts">
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import {
		tenantsApi,
		tenantStateBadge,
		type Tenant,
		type LifecycleEvent
	} from '$lib/api/tenants';
	import { addToast, authSession, isMsspScope } from '$lib/stores';

	let tenant: Tenant | null = null;
	let events: LifecycleEvent[] = [];
	let loading = true;
	let error: string | null = null;
	let loadedFor: string | null = null;

	$: id = $page.params.id;

	$: if ($authSession.user && id) {
		if (!$isMsspScope) {
			goto('/');
		} else if (loadedFor !== id) {
			loadedFor = id;
			void load();
		}
	}

	async function load() {
		loading = true;
		error = null;
		try {
			[tenant, events] = await Promise.all([
				tenantsApi.get(id),
				tenantsApi.events(id, 50)
			]);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load tenant';
		} finally {
			loading = false;
		}
	}

	async function act(fn: () => Promise<unknown>, label: string) {
		try {
			await fn();
			addToast({ type: 'success', title: 'Tenant', message: `${label} ok` });
			await load();
		} catch (e) {
			addToast({
				type: 'error',
				title: label,
				message: e instanceof Error ? e.message : String(e)
			});
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
	<div class="flex items-center gap-3">
		<button class="btn btn-sm variant-ghost-surface" on:click={() => goto('/tenants')}>
			← Tenants
		</button>
	</div>

	{#if loading}
		<div class="card p-6 flex items-center gap-3">
			<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
			<span>Loading…</span>
		</div>
	{:else if error}
		<div class="card p-6 text-error-500">{error}</div>
	{:else if tenant}
		<div class="flex items-baseline justify-between">
			<div>
				<h1 class="h2">{tenant.display_name}</h1>
				<p class="text-sm opacity-70 font-mono">{tenant.slug}</p>
			</div>
			<span class="badge {tenantStateBadge(tenant.state)} text-base">{tenant.state}</span>
		</div>

		<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
			<div class="card p-4">
				<h3 class="h4 mb-4">Identity</h3>
				<dl class="space-y-2 text-sm">
					<div class="flex justify-between">
						<dt class="opacity-60">ID</dt>
						<dd class="font-mono text-xs">{tenant.id}</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">Profile</dt>
						<dd>{tenant.profile ?? '—'}</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">Created</dt>
						<dd>{fmtDate(tenant.created_at)}</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">State changed</dt>
						<dd>{fmtDate(tenant.state_changed_at)}</dd>
					</div>
				</dl>
			</div>

			<div class="card p-4 lg:col-span-2">
				<h3 class="h4 mb-4">Actions</h3>
				<div class="flex flex-wrap gap-2">
					<button
						class="btn btn-sm variant-filled-warning"
						disabled={tenant.state !== 'active'}
						on:click={() => act(() => tenantsApi.suspend(id), 'suspend')}
					>
						Suspend
					</button>
					<button
						class="btn btn-sm variant-filled-success"
						disabled={tenant.state !== 'suspended'}
						on:click={() => act(() => tenantsApi.resume(id), 'resume')}
					>
						Resume
					</button>
					<button
						class="btn btn-sm variant-filled-secondary"
						disabled={!['pending', 'degraded'].includes(tenant.state)}
						on:click={() => act(() => tenantsApi.retry(id), 'retry provisioning')}
					>
						Retry Provisioning
					</button>
					<button
						class="btn btn-sm variant-filled-error"
						disabled={['decommissioning', 'archived', 'purged'].includes(tenant.state)}
						on:click={() => act(() => tenantsApi.decommission(id), 'decommission')}
					>
						Decommission
					</button>
				</div>
			</div>
		</div>

		<div class="card p-4">
			<h3 class="h4 mb-4">Lifecycle Events</h3>
			{#if events.length === 0}
				<p class="opacity-70 text-sm">No events yet.</p>
			{:else}
				<table class="table table-compact">
					<thead>
						<tr>
							<th>Time</th>
							<th>Event</th>
							<th>From</th>
							<th>To</th>
						</tr>
					</thead>
					<tbody>
						{#each events as e (e.id)}
							<tr>
								<td class="text-xs opacity-70">{fmtDate(e.timestamp)}</td>
								<td><code class="text-xs">{e.event_type}</code></td>
								<td>{e.from_state ?? '—'}</td>
								<td>{e.to_state ?? '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	{/if}
</div>
