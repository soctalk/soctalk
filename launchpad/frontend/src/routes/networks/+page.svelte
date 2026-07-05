<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Network, type ProbeResult } from '$lib/api';

	let networks: Network[] = [];
	let loading = true;
	let error = '';

	// connectivity probe state, keyed by network name
	let probing: Record<string, boolean> = {};
	let probeRes: Record<string, ProbeResult> = {};

	async function probe(name: string) {
		probing = { ...probing, [name]: true };
		probeRes = { ...probeRes, [name]: undefined as unknown as ProbeResult };
		try {
			probeRes = { ...probeRes, [name]: await api.probeNetwork(name) };
		} catch (e) {
			probeRes = { ...probeRes, [name]: { ok: false, message: e instanceof Error ? e.message : String(e) } };
		} finally {
			probing = { ...probing, [name]: false };
		}
	}

	let editing = false;
	let editName = '';
	let editTailnet = '';
	let editKey = '';
	let saveError = '';

	onMount(refresh);
	async function refresh() {
		loading = true;
		try {
			networks = await api.listNetworks();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}
	function newNet() {
		editing = true;
		editName = '';
		editTailnet = '';
		editKey = '';
		saveError = '';
	}
	function editNet(n: Network) {
		editing = true;
		editName = n.name;
		editTailnet = n.tailnet;
		editKey = n.api_key === '__set__' ? '__set__' : '';
		saveError = '';
	}
	async function save() {
		saveError = '';
		if (!editName.trim() || !editTailnet.trim()) {
			saveError = 'name and tailnet are required';
			return;
		}
		try {
			await api.putNetwork(editName.trim(), {
				name: editName.trim(),
				kind: 'tailscale',
				tailnet: editTailnet.trim(),
				api_key: editKey,
			});
			editing = false;
			await refresh();
		} catch (e) {
			saveError = e instanceof Error ? e.message : String(e);
		}
	}
	async function remove(n: Network) {
		await api.deleteNetwork(n.name);
		await refresh();
	}
</script>

<div class="flex items-center justify-between mb-1">
	<h1 class="text-lg font-semibold">Networks</h1>
	<button class="btn-primary !py-2" data-testid="new-network" on:click={newNet}>+ New network</button>
</div>
<p class="text-sm text-slate-400 mb-6">
	A network is the private overlay that machines join so they can reach each other wherever they run.
	Store its name and access key here once, and every machine you attach shares the same secure,
	routable address space.
</p>

{#if editing}
	<section class="card mb-6" data-testid="network-editor">
		<div class="grid grid-cols-2 gap-3">
			<div>
				<label class="field-label" for="net-name">network name</label>
				<input id="net-name" class="field-input" data-testid="net-name" bind:value={editName} placeholder="tail6397c" />
			</div>
			<div>
				<label class="field-label" for="net-tailnet">tailnet</label>
				<input id="net-tailnet" class="field-input" data-testid="net-tailnet" bind:value={editTailnet} placeholder="tailxxxx.ts.net" />
			</div>
			<div class="col-span-2">
				<label class="field-label" for="net-key">Tailscale API key <span class="text-slate-600">· secret</span></label>
				<input
					id="net-key"
					class="field-input font-mono text-xs"
					type="password"
					data-testid="net-key"
					bind:value={editKey}
					placeholder={editKey === '__set__' ? '•••••• (unchanged, type to replace)' : 'tskey-api-…'}
					on:focus={() => { if (editKey === '__set__') editKey = ''; }}
				/>
			</div>
		</div>
		<div class="mt-4 flex items-center gap-3">
			<button class="btn-primary" data-testid="save-network" on:click={save}>Save network</button>
			<button class="btn-ghost" on:click={() => (editing = false)}>Cancel</button>
			{#if saveError}<span class="text-sm text-red-400" data-testid="net-save-error">{saveError}</span>{/if}
		</div>
	</section>
{/if}

{#if loading}
	<p class="text-slate-400">Loading…</p>
{:else if error}
	<p class="text-red-400">{error}</p>
{:else if networks.length === 0}
	<p class="text-slate-500">No networks yet. Add one to launch a run.</p>
{:else}
	<div class="grid gap-2" data-testid="network-list">
		{#each networks as n (n.name)}
			<div class="card !p-3 flex items-center gap-4" data-testid={'network-' + n.name}>
				<span class="font-semibold">{n.name}</span>
				<span class="text-xs px-2 py-0.5 rounded-full bg-surface-600 text-slate-300">{n.kind}</span>
				<span class="text-xs text-slate-500 font-mono">{n.tailnet}</span>
				<span class="text-xs {n.api_key === '__set__' ? 'text-emerald-400' : 'text-amber-400'}"
					>{n.api_key === '__set__' ? 'key set' : 'no key'}</span
				>
				<span class="flex-1"></span>
				<button class="btn-ghost !py-1" data-testid={'test-network-' + n.name} disabled={probing[n.name]} on:click={() => probe(n.name)}>
					{probing[n.name] ? 'Testing…' : 'Test'}
				</button>
				<button class="btn-ghost !py-1" on:click={() => editNet(n)}>Edit</button>
				<button class="btn-ghost !py-1 text-red-400" on:click={() => remove(n)}>Delete</button>
			</div>
			{#if probeRes[n.name]}
				<div class="mt-2 text-xs flex items-center gap-2 {probeRes[n.name].ok ? 'text-emerald-400' : 'text-red-400'}" data-testid={'probe-result-' + n.name}>
					<span>{probeRes[n.name].ok ? '✓' : '✕'}</span>
					<span class="font-mono break-all">{probeRes[n.name].message}</span>
				</div>
			{/if}
		{/each}
	</div>
{/if}
