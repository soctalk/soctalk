<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Host, type Platform, type ProbeResult } from '$lib/api';
	import SchemaForm from '$lib/components/SchemaForm.svelte';

	// connectivity/credential probe state, keyed by host name
	let probing: Record<string, boolean> = {};
	let probeRes: Record<string, ProbeResult> = {};

	async function probe(name: string) {
		probing = { ...probing, [name]: true };
		probeRes = { ...probeRes, [name]: undefined as unknown as ProbeResult };
		try {
			probeRes = { ...probeRes, [name]: await api.probeHost(name) };
		} catch (e) {
			probeRes = { ...probeRes, [name]: { ok: false, message: e instanceof Error ? e.message : String(e) } };
		} finally {
			probing = { ...probing, [name]: false };
		}
	}

	let hosts: Host[] = [];
	let platforms: Platform[] = [];
	let loading = true;
	let error = '';

	// editor state
	let editing = false;
	let editName = '';
	let editPlatform = '';
	let editConfig: Record<string, unknown> = {};
	let editEnv: Record<string, string> = {};
	let saveError = '';

	$: platform = platforms.find((p) => p.name === editPlatform);
	$: credEnv = platform?.credential_env ?? [];

	onMount(refresh);

	async function refresh() {
		loading = true;
		try {
			[hosts, platforms] = await Promise.all([api.listHosts(), api.listPlatforms()]);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	function newHost() {
		editing = true;
		editName = '';
		editPlatform = platforms.find((p) => p.available)?.name ?? '';
		editConfig = {};
		editEnv = {};
		saveError = '';
	}
	function editHost(h: Host) {
		editing = true;
		editName = h.name;
		editPlatform = h.platform;
		editConfig = { ...h.config };
		editEnv = { ...(h.env ?? {}) };
		saveError = '';
	}
	async function save() {
		saveError = '';
		if (!editName.trim()) {
			saveError = 'name is required';
			return;
		}
		// Only send credential keys that have a value (or the unchanged placeholder).
		const env: Record<string, string> = {};
		for (const k of credEnv) if (editEnv[k]) env[k] = editEnv[k];
		try {
			await api.putHost(editName.trim(), {
				name: editName.trim(),
				platform: editPlatform,
				config: editConfig,
				env,
			});
			editing = false;
			await refresh();
		} catch (e) {
			saveError = e instanceof Error ? e.message : String(e);
		}
	}
	async function remove(h: Host) {
		await api.deleteHost(h.name);
		await refresh();
	}

	function summarize(h: Host): string {
		return Object.entries(h.config)
			.filter((e) => e[1] !== '' && e[1] != null)
			.map((e) => {
				const v = e[1];
				return `${e[0]}=${Array.isArray(v) ? v.length + ' keys' : v}`;
			})
			.join(' · ');
	}
</script>

<div class="flex items-center justify-between mb-1">
	<h1 class="text-lg font-semibold">Hosts</h1>
	<button class="btn-primary !py-2" data-testid="new-host" on:click={newHost}>+ New host</button>
</div>
<p class="text-sm text-slate-400 mb-6">
	A host holds the address and credentials for one place you can create virtual machines, such as a
	cloud account, a hypervisor, or a server. Save it once, then choose it whenever you provision a
	machine on that <a class="text-accent-400" href="/platforms">platform</a>.
</p>

{#if editing}
	<section class="card mb-6" data-testid="host-editor">
		<div class="grid grid-cols-2 gap-3 mb-3">
			<div>
				<label class="field-label" for="host-name">host name</label>
				<input id="host-name" class="field-input" data-testid="host-name" bind:value={editName} placeholder="nuc-qemu" />
			</div>
			<div>
				<label class="field-label" for="host-platform">platform</label>
				<select id="host-platform" class="field-input" data-testid="host-platform" bind:value={editPlatform}>
					{#each platforms as p}
						<option value={p.name} disabled={!p.available}>{p.name}{p.available ? '' : ' (unavailable)'}</option>
					{/each}
				</select>
			</div>
		</div>
		<h3 class="text-xs uppercase tracking-wide text-slate-500 mb-2">{editPlatform} config</h3>
		<SchemaForm schema={platform?.config_schema} bind:value={editConfig} testidPrefix="hostcfg" exclude={['tailnet']} />
		<p class="text-xs text-slate-600 mt-1">tailnet is set by the run's Network, not the host.</p>
		{#if credEnv.length > 0}
			<h3 class="text-xs uppercase tracking-wide text-slate-500 mt-4 mb-2">credentials <span class="normal-case text-slate-600">· secret, stored with this host</span></h3>
			<div class="grid grid-cols-2 gap-3">
				{#each credEnv as k}
					<div>
						<label class="field-label" for={'cred-' + k}>{k}</label>
						<input
							id={'cred-' + k}
							class="field-input font-mono text-xs"
							type="password"
							data-testid={'hostenv-' + k}
							bind:value={editEnv[k]}
							placeholder={editEnv[k] === '__set__' ? '•••••• (unchanged)' : ''}
							on:focus={() => { if (editEnv[k] === '__set__') editEnv[k] = ''; }}
						/>
					</div>
				{/each}
			</div>
		{/if}
		<div class="mt-4 flex items-center gap-3">
			<button class="btn-primary" data-testid="save-host" on:click={save}>Save host</button>
			<button class="btn-ghost" on:click={() => (editing = false)}>Cancel</button>
			{#if saveError}<span class="text-sm text-red-400" data-testid="host-save-error">{saveError}</span>{/if}
		</div>
	</section>
{/if}

{#if loading}
	<p class="text-slate-400">Loading…</p>
{:else if error}
	<p class="text-red-400">{error}</p>
{:else if hosts.length === 0}
	<p class="text-slate-500">No hosts yet. Add one to launch a run.</p>
{:else}
	<div class="grid gap-2" data-testid="host-list">
		{#each hosts as h (h.name)}
			<div class="card !p-3" data-testid={"host-" + h.name}>
				<div class="flex items-center gap-3">
					<span class="font-semibold">{h.name}</span>
					<span class="text-xs px-2 py-0.5 rounded-full bg-surface-600 text-slate-300">{h.platform}</span>
					<span class="flex-1"></span>
					<button class="btn-ghost !py-1 shrink-0" data-testid={"test-host-" + h.name} disabled={probing[h.name]} on:click={() => probe(h.name)}>
						{probing[h.name] ? 'Testing…' : 'Test'}
					</button>
					<button class="btn-ghost !py-1 shrink-0" data-testid={"edit-host-" + h.name} on:click={() => editHost(h)}>Edit</button>
					<button class="btn-ghost !py-1 shrink-0 text-red-400" data-testid={"delete-host-" + h.name} on:click={() => remove(h)}>Delete</button>
				</div>
				<div class="text-xs text-slate-500 mt-1.5 break-all">{summarize(h)}</div>
				{#if probeRes[h.name]}
					<div class="mt-2 text-xs flex items-start gap-2 {probeRes[h.name].ok ? 'text-emerald-400' : 'text-red-400'}" data-testid={"probe-result-" + h.name}>
						<span>{probeRes[h.name].ok ? '✓' : '✕'}</span>
						<span class="font-mono break-all">{probeRes[h.name].message}</span>
					</div>
				{/if}
			</div>
		{/each}
	</div>
{/if}
