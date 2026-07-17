<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantUser, type TenantUserCreated } from '$lib/api/client';
	import { canManageUsers } from '$lib/stores';

	let users: TenantUser[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;

	let email = '';
	let role = 'analyst';
	let displayName = '';
	let justCreated: TenantUserCreated | null = null;

	const ROLES = [
		{ value: 'analyst', label: 'Analyst — triage, review verdicts, decide, chat (cross-tenant)' },
		{ value: 'mssp_manager', label: 'Manager — analyst + authorize risk (engagements, facts)' },
		{ value: 'mssp_admin', label: 'Admin — manager + configure the system + manage users' },
		{ value: 'platform_admin', label: 'Platform admin — full super-admin (platform_admin only)' }
	];

	function roleLabel(v: string): string {
		return ROLES.find((r) => r.value === v)?.label.split(' — ')[0] ?? v;
	}

	async function load() {
		loading = true;
		error = null;
		try {
			users = await api.msspUsers.list();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	function openForm() {
		email = '';
		role = 'analyst';
		displayName = '';
		justCreated = null;
		formOpen = true;
	}

	async function create() {
		saving = true;
		error = null;
		try {
			justCreated = await api.msspUsers.create(email, role, displayName || undefined);
			formOpen = false;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create user';
		} finally {
			saving = false;
		}
	}

	async function changeRole(u: TenantUser, newRole: string) {
		if (newRole === u.role) return;
		error = null;
		try {
			await api.msspUsers.update(u.id, { role: newRole });
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to change role';
			await load(); // reset the select
		}
	}

	async function setActive(u: TenantUser, active: boolean) {
		error = null;
		try {
			if (active) await api.msspUsers.update(u.id, { active: true });
			else {
				if (!confirm(`Deactivate ${u.email}? They will be signed out and cannot log in.`)) return;
				await api.msspUsers.deactivate(u.id);
			}
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Update failed';
		}
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">Staff users</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">
				Provision MSSP staff logins and set what each person can do. An analyst works the queue
				across customers; a manager authorizes risk; an admin configures the system and manages
				users.
			</p>
		</div>
		{#if $canManageUsers}
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
			<p>One-time temporary password — copy it now, it won't be shown again:</p>
			<code class="block bg-white dark:bg-gray-800 border rounded px-2 py-1 font-mono">{justCreated.temporary_password}</code>
		</div>
	{/if}

	{#if formOpen && $canManageUsers}
		<div class="card p-4 rounded border space-y-3">
			<label class="block text-sm">
				<span class="opacity-70">Email</span>
				<input class="w-full border rounded p-2 mt-1" type="email" bind:value={email} placeholder="analyst@your-mssp.example" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">Display name (optional)</span>
				<input class="w-full border rounded p-2 mt-1" bind:value={displayName} />
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
				<button class="px-3 py-2 rounded bg-blue-600 text-white text-sm" on:click={create} disabled={saving || !email}>
					{saving ? 'Creating…' : 'Create user'}
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="opacity-60 text-sm">Loading…</div>
	{:else if users.length === 0}
		<div class="opacity-60 text-sm">No staff users yet.</div>
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
							<td class="px-3 py-2">
								{#if $canManageUsers && u.active}
									<select class="border rounded p-1 text-xs" value={u.role} on:change={(e) => changeRole(u, e.currentTarget.value)}>
										{#each ROLES as r (r.value)}
											<option value={r.value}>{roleLabel(r.value)}</option>
										{/each}
									</select>
								{:else}
									{roleLabel(u.role)}
								{/if}
							</td>
							<td class="px-3 py-2">
								{#if u.active}
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">active</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-700">deactivated</span>
								{/if}
							</td>
							<td class="px-3 py-2 text-right">
								{#if $canManageUsers}
									{#if u.active}
										<button class="text-xs text-red-700 hover:underline" on:click={() => setActive(u, false)}>Deactivate</button>
									{:else}
										<button class="text-xs text-blue-700 hover:underline" on:click={() => setActive(u, true)}>Reactivate</button>
									{/if}
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
