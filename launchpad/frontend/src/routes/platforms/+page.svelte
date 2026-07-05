<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Platform } from '$lib/api';

	let platforms: Platform[] = [];
	let loading = true;
	let error = '';

	onMount(async () => {
		try {
			platforms = await api.listPlatforms();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	});
</script>

<h1 class="text-lg font-semibold mb-1">Platforms</h1>
<p class="text-sm text-slate-400 mb-6">
	Platforms are the kinds of infrastructure you can provision on, including public clouds,
	hypervisors, and container runtimes. Each one shown here is installed and available. To use a
	platform, create a <a class="text-accent-400" href="/hosts">host</a> that points at your account or
	server.
</p>

{#if loading}
	<p class="text-slate-400">Loading platforms…</p>
{:else if error}
	<p class="text-red-400" data-testid="platforms-error">{error}</p>
{:else}
	<div class="grid gap-3" data-testid="platform-list">
		{#each platforms as p (p.name)}
			<div class="card" data-testid={"platform-" + p.name}>
				<div class="flex items-center gap-3 mb-2">
					<span class="font-semibold">{p.name}</span>
					<span class="text-xs text-slate-500">v{p.version}</span>
					{#if p.available}
						<span class="text-xs px-2 py-0.5 rounded-full bg-emerald-900 text-emerald-300"
							>available</span
						>
					{:else}
						<span class="text-xs px-2 py-0.5 rounded-full bg-red-900 text-red-300">unavailable</span>
					{/if}
				</div>
				{#if p.error}
					<p class="text-xs text-red-400 mb-2">{p.error}</p>
				{/if}
			</div>
		{/each}
	</div>
{/if}
