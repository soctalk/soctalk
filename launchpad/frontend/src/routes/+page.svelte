<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { api, type Host, type Network, type RunSnapshot } from '$lib/api';

	let hosts: Host[] = [];
	let networks: Network[] = [];
	let runs: RunSnapshot[] = [];
	let loaded = false;

	// placement: MSSP + N tenants, each assigned to a host by name.
	let msspHost = '';
	let tenants: { slug: string; host: string }[] = [{ slug: 'acme', host: '' }];
	let network = '';

	// install config (advanced)
	let adminEmail = 'admin@launchpad.demo';
	let adminPassword = 'LaunchpadDemo123!';
	let displayName = 'Launchpad Pilot MSSP';
	let llmProvider = 'anthropic';
	let llmKey = 'sk-launchpad-smoke-placeholder';

	let launching = false;
	let launchError = '';

	onMount(async () => {
		try {
			[hosts, networks, runs] = await Promise.all([
				api.listHosts(),
				api.listNetworks(),
				api.listRuns(),
			]);
			if (hosts.length) {
				msspHost = hosts[0].name;
				tenants = tenants.map((t) => ({ ...t, host: hosts[0].name }));
			}
			if (networks.length) network = networks[0].name;
		} catch {
			/* ignore */
		} finally {
			loaded = true;
		}
	});

	const hostByName = (n: string) => hosts.find((h) => h.name === n);
	const platformOf = (n: string) => hostByName(n)?.platform ?? '';

	function addTenant() {
		tenants = [...tenants, { slug: `tenant${tenants.length + 1}`, host: msspHost }];
	}
	function removeTenant(i: number) {
		tenants = tenants.filter((_, idx) => idx !== i);
	}

	$: preview =
		hosts.length && msspHost && network
			? `mssp on ${msspHost} (${platformOf(msspHost)})` +
				tenants.map((t) => ` · ${t.slug} on ${t.host} (${platformOf(t.host)})`).join('') +
				` · net ${network}`
			: 'add a host + network, then place your VMs';

	$: formReady =
		hosts.length > 0 && networks.length > 0 && !!msspHost && !!network && tenants.every((t) => t.slug && t.host);

	async function launch() {
		launching = true;
		launchError = '';
		// Reference-based run request. The server resolves hosts and network into
		// the full config and injects secrets, so nothing sensitive leaves the browser.
		const req = {
			run_id: `web-${Date.now()}`,
			network,
			mssp_host: msspHost,
			tenants: tenants.map((t) => ({ slug: t.slug, host: t.host })),
			install: {
				mssp_admin_email: adminEmail,
				mssp_admin_password: adminPassword,
				mssp_display_name: displayName,
				llm_provider: llmProvider,
				llm_api_key: llmKey,
			},
		};
		try {
			const { run_id } = await api.startRun(req);
			await goto(`/runs/${run_id}`);
		} catch (e) {
			launchError = e instanceof Error ? e.message : String(e);
			launching = false;
		}
	}
</script>

<div class="grid gap-8">
	<section class="card">
		<h2 class="text-lg font-semibold mb-1">New run</h2>
		<p class="text-sm text-slate-400 mb-5">
			Assign each machine to any saved <a class="text-accent-400" href="/hosts">host</a>. Machines in
			a single deployment can run on different platforms, so a control node can live on one hypervisor
			while workloads run in a cloud account.
		</p>

		{#if loaded && (hosts.length === 0 || networks.length === 0)}
			<div class="text-sm text-slate-400">
				{#if hosts.length === 0}<a class="text-accent-400" href="/hosts">Add a host</a>{/if}
				{#if hosts.length === 0 && networks.length === 0} and {/if}
				{#if networks.length === 0}<a class="text-accent-400" href="/networks">add a network</a>{/if}
				to get started.
			</div>
		{:else if loaded}
			<!-- placement table -->
			<div class="grid gap-2" data-testid="placement">
				<div class="grid grid-cols-[120px_1fr_110px] gap-3 text-xs uppercase tracking-wide text-slate-500 px-1">
					<span>VM</span><span>Host</span><span>Platform</span>
				</div>
				<div class="grid grid-cols-[120px_1fr_110px] gap-3 items-center">
					<span class="font-semibold text-sm">mssp</span>
					<select class="field-input" data-testid="mssp-host" bind:value={msspHost}>
						{#each hosts as h}<option value={h.name}>{h.name}</option>{/each}
					</select>
					<span class="text-xs text-slate-400 font-mono">{platformOf(msspHost)}</span>
				</div>
				{#each tenants as t, i}
					<div class="grid grid-cols-[120px_1fr_110px] gap-3 items-center">
						<input
							class="field-input !py-1 text-sm"
							data-testid={"tenant-slug-" + i}
							bind:value={t.slug}
							placeholder="slug"
						/>
						<select class="field-input" data-testid={"tenant-host-" + i} bind:value={t.host}>
							{#each hosts as h}<option value={h.name}>{h.name}</option>{/each}
						</select>
						<div class="flex items-center gap-2">
							<span class="text-xs text-slate-400 font-mono">{platformOf(t.host)}</span>
							{#if tenants.length > 1}
								<button class="text-slate-500 hover:text-red-400 text-sm" on:click={() => removeTenant(i)}>✕</button>
							{/if}
						</div>
					</div>
				{/each}
				<button class="text-xs text-accent-400 text-left mt-1" data-testid="add-tenant" on:click={addTenant}
					>+ add tenant</button
				>
			</div>

			<div class="mt-4">
				<label class="field-label" for="network">network</label>
				<select id="network" class="field-input" data-testid="network" bind:value={network}>
					{#each networks as n}<option value={n.name}>{n.name} · {n.tailnet}</option>{/each}
				</select>
			</div>

			<details class="mt-4">
				<summary class="text-sm text-slate-400 cursor-pointer select-none">Install settings</summary>
				<div class="grid grid-cols-3 gap-3 mt-3">
					<div>
						<label class="field-label" for="adm-email">admin email</label>
						<input id="adm-email" class="field-input" data-testid="admin-email" bind:value={adminEmail} />
					</div>
					<div>
						<label class="field-label" for="adm-pass">admin password</label>
						<input id="adm-pass" class="field-input" data-testid="admin-password" bind:value={adminPassword} />
					</div>
					<div>
						<label class="field-label" for="disp">MSSP display name</label>
						<input id="disp" class="field-input" bind:value={displayName} />
					</div>
					<div>
						<label class="field-label" for="llmp">LLM provider</label>
						<input id="llmp" class="field-input" bind:value={llmProvider} />
					</div>
					<div>
						<label class="field-label" for="llmk">LLM API key</label>
						<input id="llmk" class="field-input" data-testid="llm-key" bind:value={llmKey} />
					</div>
				</div>
			</details>

			<div class="mt-5 flex items-center gap-4">
				<button class="btn-primary" data-testid="launch" disabled={launching || !formReady} on:click={launch}>
					{launching ? 'Launching…' : 'Launch'}
				</button>
				<span class="text-xs text-slate-500 truncate" data-testid="preview-ribbon">{preview}</span>
			</div>
			{#if launchError}<p class="mt-3 text-sm text-red-400" data-testid="launch-error">{launchError}</p>{/if}
		{/if}
	</section>

	{#if runs.length > 0}
		<section>
			<h3 class="text-sm uppercase tracking-wide text-slate-400 mb-3">Recent runs</h3>
			<div class="grid gap-2" data-testid="recent-runs">
				{#each runs as run}
					<a href={`/runs/${run.id}`} class="card !p-3 flex items-center gap-4 hover:border-accent-500">
						<span
							class="text-xs px-2 py-0.5 rounded-full {run.status === 'complete'
								? 'bg-emerald-900 text-emerald-300'
								: run.status === 'failed'
									? 'bg-red-900 text-red-300'
									: 'bg-surface-600 text-slate-300'}">{run.status}</span
						>
						<span class="font-mono text-sm">{run.id}</span>
						<span class="text-xs text-slate-500 ml-auto">{run.phase}</span>
					</a>
				{/each}
			</div>
		</section>
	{/if}
</div>
