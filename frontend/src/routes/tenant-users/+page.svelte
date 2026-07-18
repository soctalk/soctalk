<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantUser, type TenantUserCreated } from '$lib/api/client';
	import { canManageTenantUsers } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';

	let users: TenantUser[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;

	let email = '';
	let role = 'tenant_analyst';
	let displayName = '';
	let justCreated: TenantUserCreated | null = null;

	// `label`/`short` hold message FUNCTIONS (called at render time) — never
	// evaluate messages at module scope (#52).
	const ROLES = [
		{ value: 'tenant_analyst', label: m.adm_role_analyst_full, short: m.adm_role_analyst },
		{ value: 'tenant_manager', label: m.adm_role_manager_full, short: m.adm_role_manager },
		{ value: 'customer_viewer', label: m.adm_role_viewer_full, short: m.adm_role_viewer },
		{ value: 'tenant_admin', label: m.adm_role_admin_full, short: m.adm_role_admin }
	];

	function roleLabel(v: string): string {
		return ROLES.find((r) => r.value === v)?.short() ?? v;
	}

	async function load() {
		loading = true;
		error = null;
		try {
			users = await api.tenantUsers.list();
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_users_load_failed();
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
			error = e instanceof Error ? e.message : m.adm_user_create_failed();
		} finally {
			saving = false;
		}
	}

	async function deactivate(u: TenantUser) {
		if (!confirm(m.adm_deactivate_confirm({ email: u.email }))) return;
		error = null;
		try {
			await api.tenantUsers.deactivate(u.id);
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : m.adm_deactivate_failed();
		}
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">{m.nav_users()}</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">
				{m.adm_users_intro()}
			</p>
		</div>
		{#if $canManageTenantUsers}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
				on:click={openForm}
			>
				{m.adm_add_user()}
			</button>
		{/if}
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if justCreated}
		<div class="rounded border border-green-300 bg-green-50 dark:bg-green-900/20 px-3 py-2 text-sm space-y-1">
			<p class="font-medium text-green-800 dark:text-green-300">
				{m.adm_user_created({ email: justCreated.email, role: roleLabel(justCreated.role) })}
			</p>
			<p>
				{m.adm_temp_password_hint()}
			</p>
			<code class="block bg-white dark:bg-gray-800 border rounded px-2 py-1 font-mono">{justCreated.temporary_password}</code>
		</div>
	{/if}

	{#if formOpen && $canManageTenantUsers}
		<div class="card p-4 rounded border space-y-3">
			<label class="block text-sm">
				<span class="opacity-70">{m.adm_field_email()}</span>
				<input class="w-full border rounded p-2 mt-1" type="email" bind:value={email} placeholder="analyst@your-org.com" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">{m.adm_field_display_name()}</span>
				<input class="w-full border rounded p-2 mt-1" bind:value={displayName} placeholder="Jordan Rivera" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">{m.adm_field_role()}</span>
				<select class="w-full border rounded p-2 mt-1" bind:value={role}>
					{#each ROLES as r (r.value)}
						<option value={r.value}>{r.label()}</option>
					{/each}
				</select>
			</label>
			<div class="flex justify-end gap-2">
				<button class="px-3 py-2 text-sm" on:click={() => (formOpen = false)}>{m.common_cancel()}</button>
				<button
					class="px-3 py-2 rounded bg-blue-600 text-white text-sm"
					on:click={create}
					disabled={saving || !email}
				>
					{saving ? m.adm_creating() : m.adm_create_user()}
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="opacity-60 text-sm">{m.common_loading()}</div>
	{:else if users.length === 0}
		<div class="opacity-60 text-sm">{m.adm_users_empty()}</div>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
					<tr>
						<th class="px-3 py-2">{m.adm_field_email()}</th>
						<th class="px-3 py-2">{m.adm_field_name()}</th>
						<th class="px-3 py-2">{m.adm_field_role()}</th>
						<th class="px-3 py-2">{m.adm_th_status()}</th>
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
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">{m.adm_status_active()}</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-700">{m.adm_status_deactivated()}</span>
								{/if}
							</td>
							<td class="px-3 py-2 text-right">
								{#if $canManageTenantUsers && u.active}
									<button class="text-xs text-red-700 hover:underline" on:click={() => deactivate(u)}>
										{m.adm_deactivate()}
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
