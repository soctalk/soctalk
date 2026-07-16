<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantUser, type TenantUserCreated } from '$lib/api/client';
	import { canManageTenantUsers } from '$lib/stores';

	let users: TenantUser[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;

	let email = '';
	let role = 'tenant_analyst';
	let displayName = '';
	let justCreated: TenantUserCreated | null = null;

	const ROLES = [
		{ value: 'tenant_analyst', label: 'Analyst — operate the SOC (triage, review, decide, chat)' },
		{ value: 'tenant_manager', label: 'Manager — analyst + authorize risk (engagements, facts)' },
		{ value: 'customer_viewer', label: 'Viewer — read-only stakeholder' },
		{ value: 'tenant_admin', label: 'Admin — manager + configure + manage users' }
	];

	function roleLabel(v: string): string {
		return ROLES.find((r) => r.value === v)?.label.split(' — ')[0] ?? v;
	}

	async function load() {
		loading = true;
		error = null;
		try {
			users = await api.tenantUsers.list();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	function openForm() {
		email = '';
		role = 'tenant_analyst';
		displayName = '';
		justCreated = null;
		formOpen = true;
	}

	async function create() {
		saving = true;
		error = null;
		try {
			justCreated = await api.tenantUsers.create(email, role, displayName || undefined);
			formOpen = false;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create user';
		} finally {
			saving = false;
		}
	}

	async function deactivate(u: TenantUser) {
		if (!confirm(`Deactivate ${u.email}? They will no longer be able to sign in.`)) return;
		error = null;
		try {
			await api.tenantUsers.deactivate(u.id);
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to deactivate';
		}
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">Users</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">
				Provision logins for your organization and set what each person can do. An analyst runs
				the SOC; a viewer only watches; a manager authorizes risk; an admin configures the system
				and manages users.
			</p>
		</div>
		{#if $canManageTenantUsers}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
				on:click={openForm}
			>
				+ Add user
			</button>
		{/if}
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if justCreated}
		<div class="rounded border border-green-300 bg-green-50 dark:bg-green-900/20 px-3 py-2 text-sm space-y-1">
			<p class="font-medium text-green-800 dark:text-green-300">
				Created {justCreated.email} ({roleLabel(justCreated.role)}).
			</p>
			<p>
				One-time temporary password — copy it now, it won't be shown again. They'll be asked to
				change it on first sign-in:
			</p>
			<code class="block bg-white dark:bg-gray-800 border rounded px-2 py-1 font-mono">{justCreated.temporary_password}</code>
		</div>
	{/if}

	{#if formOpen && $canManageTenantUsers}
		<div class="card p-4 rounded border space-y-3">
			<label class="block text-sm">
				<span class="opacity-70">Email</span>
				<input class="w-full border rounded p-2 mt-1" type="email" bind:value={email} placeholder="analyst@your-org.com" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">Display name (optional)</span>
				<input class="w-full border rounded p-2 mt-1" bind:value={displayName} placeholder="Jordan Rivera" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">Role</span>
				<select class="w-full border rounded p-2 mt-1" bind:value={role}>
					{#each ROLES as r (r.value)}
						<option value={r.value}>{r.label}</option>
					{/each}
				</select>
			</label>
			<div class="flex justify-end gap-2">
				<button class="px-3 py-2 text-sm" on:click={() => (formOpen = false)}>Cancel</button>
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm"
					on:click={create}
					disabled={saving || !email}
				>
					{saving ? 'Creating…' : 'Create user'}
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="opacity-60 text-sm">Loading…</div>
	{:else if users.length === 0}
		<div class="opacity-60 text-sm">No users yet.</div>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
					<tr>
						<th class="px-3 py-2">Email</th>
						<th class="px-3 py-2">Name</th>
						<th class="px-3 py-2">Role</th>
						<th class="px-3 py-2">Status</th>
						<th class="px-3 py-2"></th>
					</tr>
				</thead>
				<tbody>
					{#each users as u (u.id)}
						<tr class="border-t" class:opacity-50={!u.active}>
							<td class="px-3 py-2 font-mono">{u.email}</td>
							<td class="px-3 py-2">{u.display_name ?? '—'}</td>
							<td class="px-3 py-2">{roleLabel(u.role)}</td>
							<td class="px-3 py-2">
								{#if u.active}
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">active</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-700">deactivated</span>
								{/if}
							</td>
							<td class="px-3 py-2 text-right">
								{#if $canManageTenantUsers && u.active}
									<button class="text-xs text-red-700 hover:underline" on:click={() => deactivate(u)}>
										Deactivate
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
