<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantUser, type TenantUserCreated } from '$lib/api/client';
	import { canManageUsers } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';

	let users: TenantUser[] = [];
	let loading = true;
	let error: string | null = null;
	let formOpen = false;
	let saving = false;

	let email = '';
	let role = 'analyst';
	let displayName = '';
	let justCreated: TenantUserCreated | null = null;

	// Codes only; short label + full description resolve via messages at call time (#52).
	const ROLES = [
		{ value: 'analyst', label: m.su_role_analyst, desc: m.su_role_analyst_desc },
		{ value: 'mssp_manager', label: m.su_role_manager, desc: m.su_role_manager_desc },
		{ value: 'mssp_admin', label: m.su_role_admin, desc: m.su_role_admin_desc },
		{ value: 'platform_admin', label: m.su_role_platform, desc: m.su_role_platform_desc }
	] as const;

	function roleLabel(v: string): string {
		return ROLES.find((r) => r.value === v)?.label() ?? v;
	}
	function roleOption(v: string): string {
		const r = ROLES.find((x) => x.value === v);
		return r ? `${r.label()} — ${r.desc()}` : v;
	}

	async function load() {
		loading = true;
		error = null;
		try {
			users = await api.msspUsers.list();
		} catch (e) {
			error = e instanceof Error ? e.message : m.su_load_failed();
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
			error = e instanceof Error ? e.message : m.su_create_failed();
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
			error = e instanceof Error ? e.message : m.su_role_change_failed();
			await load(); // reset the select
		}
	}

	async function setActive(u: TenantUser, active: boolean) {
		error = null;
		try {
			if (active) await api.msspUsers.update(u.id, { active: true });
			else {
				if (!confirm(m.su_confirm_deactivate({ email: u.email }))) return;
				await api.msspUsers.deactivate(u.id);
			}
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : m.su_update_failed();
		}
	}

	onMount(load);
</script>

<div class="max-w-4xl mx-auto p-4 space-y-4">
	<div class="flex items-start justify-between gap-4">
		<div>
			<h1 class="text-2xl font-semibold">{m.su_title()}</h1>
			<p class="text-sm opacity-70 mt-1 max-w-2xl">{m.su_intro()}</p>
		</div>
		{#if $canManageUsers}
			<button
				class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700 shrink-0"
				on:click={openForm}
			>
				{m.su_add_user()}
			</button>
		{/if}
	</div>

	{#if error}
		<div class="rounded bg-red-100 text-red-800 px-3 py-2 text-sm">{error}</div>
	{/if}

	{#if justCreated}
		<div class="rounded border border-green-300 bg-green-50 dark:bg-green-900/20 px-3 py-2 text-sm space-y-1">
			<p class="font-medium text-green-800 dark:text-green-300">
				{m.su_created({ email: justCreated.email, role: roleLabel(justCreated.role) })}
			</p>
			<p>{m.su_temp_password_hint()}</p>
			<code class="block bg-white dark:bg-gray-800 border rounded px-2 py-1 font-mono">{justCreated.temporary_password}</code>
		</div>
	{/if}

	{#if formOpen && $canManageUsers}
		<div class="card p-4 rounded border space-y-3">
			<label class="block text-sm">
				<span class="opacity-70">{m.su_email()}</span>
				<input class="input mt-1" type="email" bind:value={email} placeholder="analyst@your-mssp.example" />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">{m.su_display_name()}</span>
				<input class="input mt-1" bind:value={displayName} />
			</label>
			<label class="block text-sm">
				<span class="opacity-70">{m.su_role()}</span>
				<select class="select mt-1" bind:value={role}>
					{#each ROLES as r (r.value)}
						<option value={r.value}>{roleOption(r.value)}</option>
					{/each}
				</select>
			</label>
			<div class="flex justify-end gap-2">
				<button class="px-3 py-2 text-sm" on:click={() => (formOpen = false)}>{m.common_cancel()}</button>
				<button class="px-3 py-2 rounded bg-blue-600 text-white text-sm" on:click={create} disabled={saving || !email}>
					{saving ? m.su_creating() : m.su_create_user()}
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="opacity-60 text-sm">{m.common_loading()}</div>
	{:else if users.length === 0}
		<div class="opacity-60 text-sm">{m.su_empty()}</div>
	{:else}
		<div class="overflow-x-auto border rounded">
			<table class="min-w-full text-sm">
				<thead class="bg-gray-50 dark:bg-gray-800 text-left text-gray-600 dark:text-gray-300">
					<tr>
						<th class="px-3 py-2">{m.su_email()}</th>
						<th class="px-3 py-2">{m.su_name()}</th>
						<th class="px-3 py-2">{m.su_role()}</th>
						<th class="px-3 py-2">{m.su_status()}</th>
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
									<select class="select select-sm w-auto text-xs" value={u.role} on:change={(e) => changeRole(u, e.currentTarget.value)}>
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
									<span class="text-xs px-2 py-0.5 rounded bg-green-100 text-green-800">{m.su_active()}</span>
								{:else}
									<span class="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-700">{m.su_deactivated()}</span>
								{/if}
							</td>
							<td class="px-3 py-2 text-right">
								{#if $canManageUsers}
									{#if u.active}
										<button class="text-xs text-red-400 hover:underline" on:click={() => setActive(u, false)}>{m.adm_deactivate()}</button>
									{:else}
										<button class="text-xs text-blue-400 hover:underline" on:click={() => setActive(u, true)}>{m.adm_reactivate()}</button>
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
