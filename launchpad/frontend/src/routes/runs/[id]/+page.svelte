<script lang="ts">
	import { page } from '$app/stores';
	import { onDestroy, onMount } from 'svelte';
	import {
		api,
		openEventStream,
		type JournalEvent,
		type RunSnapshot,
	} from '$lib/api';

	// `[id]` is always present for this route; assert so the API helpers,
	// which take a required string, type-check under strict svelte-check.
	const runId = $page.params.id as string;

	let snap: RunSnapshot | null = null;
	let events: JournalEvent[] = [];
	let feedEl: HTMLDivElement | null = null;
	let closeStream: (() => void) | null = null;
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	const PHASES = ['initializing', 'planning', 'provisioning', 'installing', 'complete'];

	$: phaseIdx = snap ? PHASES.indexOf(snap.phase) : -1;
	$: installCfg = (snap?.config?.install ?? {}) as Record<string, string>;

	async function refresh() {
		try {
			snap = await api.getRun(runId);
		} catch {
			/* transient */
		}
	}

	onMount(async () => {
		await refresh();
		closeStream = openEventStream(runId, 0, (ev) => {
			events = [...events.slice(-800), ev];
			queueMicrotask(() => {
				if (feedEl) feedEl.scrollTop = feedEl.scrollHeight;
			});
		});
		pollTimer = setInterval(refresh, 3000);
	});
	onDestroy(() => {
		closeStream?.();
		if (pollTimer) clearInterval(pollTimer);
	});

	async function confirmGate(gid: string) {
		await api.resolveGate(runId, gid);
		await refresh();
	}
	async function cancelRun() {
		await api.cancel(runId);
		await refresh();
	}
	async function downRun() {
		await api.down(runId);
		await refresh();
	}

	function fmtTime(t: string): string {
		return new Date(t).toLocaleTimeString();
	}
</script>

{#if snap}
	<div class="grid gap-6">
		<!-- header -->
		<div class="flex items-center gap-4">
			<h2 class="font-mono text-lg">{snap.id}</h2>
			<span
				class="text-xs px-2.5 py-1 rounded-full font-medium"
				data-testid="run-status"
				data-status={snap.status}
				class:bg-emerald-900={snap.status === 'complete'}
				class:text-emerald-300={snap.status === 'complete'}
				class:bg-red-900={snap.status === 'failed'}
				class:text-red-300={snap.status === 'failed'}
				class:bg-surface-600={snap.status === 'running'}
			>
				{snap.status}
			</span>
			<span class="text-sm text-slate-400" data-testid="run-phase">{snap.phase}</span>
			<div class="ml-auto flex gap-2">
				{#if snap.status === 'running'}
					<button class="btn-ghost" data-testid="cancel" on:click={cancelRun}>Cancel</button>
				{:else if snap.status === 'complete' || snap.status === 'failed'}
					<button class="btn-ghost" data-testid="down" on:click={downRun}>Tear down</button>
				{/if}
			</div>
		</div>

		{#if snap.error}
			<div class="card border-red-800 text-red-300 text-sm" data-testid="run-error">
				{snap.error}
			</div>
		{/if}

		<!-- phase timeline -->
		<div class="flex items-center gap-1" data-testid="phase-timeline">
			{#each PHASES as p, i}
				<div class="flex items-center gap-1 {i > 0 ? 'flex-1' : ''}">
					{#if i > 0}
						<div class="h-px flex-1 {i <= phaseIdx ? 'bg-accent-500' : 'bg-surface-600'}"></div>
					{/if}
					<span
						class="text-xs px-2 py-1 rounded-md whitespace-nowrap
						{i < phaseIdx || snap.phase === 'complete'
							? 'text-accent-400'
							: i === phaseIdx
								? 'bg-accent-500 text-white'
								: 'text-slate-500'}"
					>
						{p}
					</span>
				</div>
			{/each}
		</div>

		<!-- VM cards -->
		<div class="grid grid-cols-2 gap-4" data-testid="vm-cards">
			{#each snap.vms as vm}
				<div class="card" data-testid={`vm-card-${vm.key}`}>
					<div class="flex items-center gap-2 mb-2">
						<span class="font-semibold">{vm.key}</span>
						<span class="text-xs text-slate-500 uppercase">{vm.role}</span>
					</div>
					<dl class="text-sm grid grid-cols-[90px_1fr] gap-y-1">
						<dt class="text-slate-500">hostname</dt>
						<dd class="font-mono text-xs pt-0.5">{vm.hostname ?? 'not assigned'}</dd>
						<dt class="text-slate-500">tailnet IP</dt>
						<dd class="font-mono" data-testid={`vm-ip-${vm.key}`}>{vm.ipv4 || 'waiting…'}</dd>
					</dl>
				</div>
			{/each}
		</div>

		<!-- access panel (money shot) -->
		{#if snap.status === 'complete'}
			<section class="card border-emerald-800" data-testid="access-panel">
				<h3 class="font-semibold text-emerald-300 mb-3">Your pilot is ready</h3>
				{#each snap.vms.filter((v) => v.role === 'mssp') as vm}
					<div class="grid grid-cols-[110px_1fr] gap-y-2 text-sm">
						<span class="text-slate-500">MSSP UI</span>
						<a class="text-accent-400 font-mono" href={vm.url} target="_blank" data-testid="mssp-url"
							>{vm.url}</a
						>
						<span class="text-slate-500">login</span>
						<span class="font-mono" data-testid="mssp-login">{installCfg.mssp_admin_email}</span>
						<span class="text-slate-500">password</span>
						<span class="font-mono">{installCfg.mssp_admin_password}</span>
						<span class="text-slate-500">SSH</span>
						<span class="font-mono text-xs pt-0.5">ssh ops@{vm.ipv4}</span>
					</div>
				{/each}
			</section>
		{/if}

		<!-- event feed -->
		<section>
			<h3 class="text-sm uppercase tracking-wide text-slate-400 mb-2">Events</h3>
			<div
				bind:this={feedEl}
				class="card !p-3 h-80 overflow-y-auto font-mono text-xs leading-relaxed"
				data-testid="event-feed"
			>
				{#each events as ev (ev.seq)}
					<div class="flex gap-2">
						<span class="text-slate-600 shrink-0">{fmtTime(ev.time)}</span>
						{#if ev.vm_key}<span class="text-accent-400 shrink-0">[{ev.vm_key}]</span>{/if}
						<span
							class={ev.ev === 'error' || ev.level === 'error'
								? 'text-red-400'
								: ev.level === 'warn'
									? 'text-amber-400'
									: ev.ev === 'phase'
										? 'text-emerald-400'
										: 'text-slate-300'}
						>
							{#if ev.ev === 'phase'}phase → {ev.phase}
							{:else if ev.ev === 'error'}{ev.error?.message}
							{:else if ev.ev === 'vm_progress'}{ev.step} {ev.percent}%: {ev.message}
							{:else if ev.ev === 'vm_ready'}ready at {ev.ipv4}
							{:else}{ev.message ?? ev.ev}{/if}
						</span>
					</div>
				{/each}
			</div>
		</section>
	</div>

	<!-- gate modal -->
	{#if snap.gates && snap.gates.length > 0}
		<div class="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
			<div class="card max-w-lg w-full" data-testid="gate-modal">
				{#each snap.gates as gate}
					<h3 class="font-semibold mb-2">Action required</h3>
					<p class="text-sm text-slate-300 mb-4">{gate.instructions}</p>
					<button
						class="btn-primary"
						data-testid="gate-confirm"
						on:click={() => confirmGate(gate.id)}
					>
						Confirm and continue
					</button>
				{/each}
			</div>
		</div>
	{/if}
{:else}
	<p class="text-slate-400">Loading run…</p>
{/if}
