<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import { initToken } from '$lib/api';
	initToken();
</script>

<script lang="ts" context="module">
	const NAV = [
		{ href: '/', label: 'Runs' },
		{ href: '/hosts', label: 'Hosts' },
		{ href: '/networks', label: 'Networks' },
		{ href: '/platforms', label: 'Platforms' },
	];
</script>

<div class="min-h-screen">
	<header class="border-b border-surface-700 px-6 py-3 flex items-center gap-6">
		<a href="/" class="flex items-center gap-2.5 tracking-tight" data-testid="wordmark">
			<!-- Official SocTalk logo (bubble.png from soctalk.ai) -->
			<img src="/bubble.png" alt="SocTalk" class="h-7 w-auto" />
			<span class="text-lg"><span class="font-bold">SocTalk</span> <span class="text-slate-400">Launchpad</span></span>
		</a>
		<nav class="flex gap-1 text-sm">
			{#each NAV as n}
				<a
					href={n.href}
					class="px-3 py-1.5 rounded-xl hover:bg-surface-700 {$page.url.pathname === n.href
						? 'bg-surface-700 text-white'
						: 'text-slate-400'}"
					data-testid={"nav-" + n.label.toLowerCase()}>{n.label}</a
				>
			{/each}
		</nav>
	</header>
	<main class="max-w-5xl mx-auto px-6 py-8">
		<slot />
	</main>
</div>
