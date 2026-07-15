<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Playbook, type AuthoredPlaybook } from '$lib/api/client';
	import { currentTenantId } from '$lib/stores';

	let playbooks: Playbook[] = [];
	let loading = true;
	let error: string | null = null;
	let expanded = new Set<string>();

	// --- authored (per-tenant, shadow/draft) ---
	let authored: AuthoredPlaybook[] = [];
	let authoredLoading = false;
	let authoredError: string | null = null;
	let editorOpen = false;
	let editorMode: 'create' | 'edit' = 'create';
	let editorPid = '';
	let editorText = '';
	let editorSaving = false;
	let editorError: string | null = null;

	$: tenantId = $currentTenantId;
	$: if (tenantId) loadAuthored(tenantId);

	async function loadAuthored(tid: string) {
		authoredLoading = true;
		authoredError = null;
		try {
			authored = await api.playbooks.listAuthored(tid);
		} catch (e) {
			authoredError = e instanceof Error ? e.message : 'Failed to load authored playbooks';
		} finally {
			authoredLoading = false;
		}
	}

	function openCreate() {
		editorMode = 'create';
		editorPid = '';
		editorError = null;
		editorText = JSON.stringify(
			{ id: 'my-playbook', priority: 70, applies_to: { rule_groups: [] }, guardrails: [] },
			null,
			2
		);
		editorOpen = true;
	}

	function openEdit(pb: AuthoredPlaybook) {
		editorMode = 'edit';
		editorPid = pb.playbook_id;
		editorError = null;
		editorText = JSON.stringify(pb.definition, null, 2);
		editorOpen = true;
	}

	async function save() {
		if (!tenantId) return;
		let def: Record<string, unknown>;
		try {
			def = JSON.parse(editorText);
		} catch {
			editorError = 'Invalid JSON.';
			return;
		}
		editorSaving = true;
		editorError = null;
		try {
			if (editorMode === 'create') await api.playbooks.createAuthored(tenantId, def);
			else await api.playbooks.updateAuthored(tenantId, editorPid, def);
			editorOpen = false;
			await loadAuthored(tenantId);
		} catch (e) {
			editorError = e instanceof Error ? e.message : 'Save failed.';
		} finally {
			editorSaving = false;
		}
	}

	async function retire(pid: string) {
		if (!tenantId || !confirm(`Retire playbook "${pid}"? This removes it from the tenant.`))
			return;
		try {
			await api.playbooks.retireAuthored(tenantId, pid);
			await loadAuthored(tenantId);
		} catch (e) {
			authoredError = e instanceof Error ? e.message : 'Retire failed.';
		}
	}

	async function exportYaml(pid: string) {
		if (!tenantId) return;
		try {
			const res = await api.playbooks.exportAuthored(tenantId, pid);
			const blob = new Blob([res.yaml], { type: 'text/yaml' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `${pid}.yaml`;
			a.click();
			URL.revokeObjectURL(url);
		} catch (e) {
			authoredError = e instanceof Error ? e.message : 'Export failed.';
		}
	}

	onMount(loadPlaybooks);

	async function loadPlaybooks() {
		loading = true;
		error = null;
		try {
			playbooks = await api.playbooks.list();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load playbooks';
		} finally {
			loading = false;
		}
	}

	function toggle(id: string) {
		expanded.has(id) ? expanded.delete(id) : expanded.add(id);
		expanded = expanded;
	}

	function statusBadge(status: string): string {
		return status === 'active' ? 'variant-filled-success' : 'variant-soft-warning';
	}

	function sourceBadge(source: string): string {
		return source === 'built-in' ? 'variant-soft' : 'variant-soft-primary';
	}

	function matchSummary(pb: Playbook): string {
		const parts: string[] = [];
		const m = pb.applies_to;
		if (m.rule_groups.length) parts.push(`groups: ${m.rule_groups.join(', ')}`);
		if (m.rule_ids.length) parts.push(`rules: ${m.rule_ids.join(', ')}`);
		if (m.authorization_tracks.length) parts.push(`authz: ${m.authorization_tracks.join(', ')}`);
		return parts.join('  ·  ') || '—';
	}

	$: activeCount = playbooks.filter((p) => p.status === 'active').length;
	$: shadowCount = playbooks.filter((p) => p.status === 'shadow').length;
</script>

<svelte:head>
	<title>Playbooks - SocTalk</title>
</svelte:head>

<div class="flex items-center justify-between mb-2">
	<h1 class="h2">Playbooks</h1>
	<button class="btn variant-soft btn-sm" on:click={loadPlaybooks} disabled={loading}>
		{#if loading}
			<span
				class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"
			></span>
		{/if}
		Refresh
	</button>
</div>
<p class="opacity-60 text-sm mb-6">
	Deterministic guardrails over the AI triage loop — the LLM proposes, a playbook disposes.
	Shows the compiled-in (built-in) playbooks that govern triage; these are vetted code and
	read-only here.
</p>

{#if loading}
	<div class="flex items-center justify-center h-64">
		<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
	</div>
{:else if error}
	<div class="alert variant-filled-error"><span>Error: {error}</span></div>
{:else if playbooks.length === 0}
	<div class="card p-8 text-center opacity-60">No playbooks configured.</div>
{:else}
	<div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
		<div class="card p-3">
			<h4 class="text-xs opacity-60 uppercase tracking-wide">Total</h4>
			<p class="text-2xl font-bold">{playbooks.length}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60 uppercase tracking-wide">Active</h4>
			<p class="text-2xl font-bold text-success-500">{activeCount}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60 uppercase tracking-wide">Shadow</h4>
			<p class="text-2xl font-bold text-warning-500">{shadowCount}</p>
		</div>
	</div>

	<div class="grid gap-3">
		{#each playbooks as pb (pb.id)}
			{@const isOpen = expanded.has(pb.id)}
			<div class="card">
				<button
					class="w-full p-4 text-left hover:bg-surface-500/5 transition-colors"
					on:click={() => toggle(pb.id)}
				>
					<div class="flex flex-col lg:flex-row lg:items-center gap-3">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-5 w-5 opacity-60 transition-transform flex-shrink-0 {isOpen
								? 'rotate-90'
								: ''}"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M9 5l7 7-7 7"
							/>
						</svg>
						<div class="flex-1 min-w-0">
							<div class="flex items-center gap-2 flex-wrap">
								<span class="font-semibold font-mono truncate">{pb.id}</span>
								<span class="badge {statusBadge(pb.status)} text-xs">{pb.status}</span>
								<span class="badge {sourceBadge(pb.source)} text-xs">{pb.source}</span>
							</div>
							<div class="text-xs opacity-60 mt-1 truncate">{matchSummary(pb)}</div>
						</div>
						<div class="flex items-center gap-3 text-xs opacity-60 flex-shrink-0">
							<span>v{pb.version}</span>
							<span>priority {pb.priority}</span>
						</div>
					</div>
				</button>

				{#if isOpen}
					<div class="border-t border-surface-500/20 p-4 space-y-4 text-sm">
						{#if pb.deterministic_disposition}
							<div>
								<span class="opacity-60">Deterministic disposition:</span>
								<span class="badge variant-soft-error text-xs ml-1"
									>{pb.deterministic_disposition}</span
								>
								<span class="opacity-60 text-xs"
									>&nbsp;— closes without an LLM look unless a security veto fires</span
								>
							</div>
						{/if}

						{#if pb.required_steps.length}
							<div>
								<span class="opacity-60">Required steps before verdict:</span>
								{#each pb.required_steps as s}
									<span class="badge variant-soft text-xs ml-1 font-mono">{s}</span>
								{/each}
							</div>
						{/if}

						{#if pb.decision_modules.length}
							<div>
								<span class="opacity-60">Decision modules:</span>
								{#each pb.decision_modules as d}
									<span class="badge variant-soft text-xs ml-1 font-mono">{d}</span>
								{/each}
							</div>
						{/if}

						{#if Object.keys(pb.legal_actions).length}
							<div>
								<span class="opacity-60">Legal actions per phase:</span>
								<div class="mt-1 space-y-1">
									{#each Object.entries(pb.legal_actions) as [phase, actions]}
										<div class="flex gap-2 items-baseline flex-wrap">
											<span class="font-mono text-xs opacity-70 w-16">{phase}</span>
											{#each actions as a}
												<span class="badge variant-soft text-xs font-mono">{a}</span>
											{/each}
										</div>
									{/each}
								</div>
							</div>
						{/if}

						{#if pb.close_signoff_data_classes.length}
							<div>
								<span class="opacity-60">Close requires human sign-off for data classes:</span>
								{#each pb.close_signoff_data_classes as c}
									<span class="badge variant-soft-warning text-xs ml-1">{c}</span>
								{/each}
							</div>
						{/if}

						{#if pb.guardrails.length}
							<div>
								<span class="opacity-60">Guardrails:</span>
								<div class="mt-1 space-y-2">
									{#each pb.guardrails as g}
										<div class="card variant-soft p-3">
											<div class="flex items-center gap-2 flex-wrap">
												<span class="badge variant-filled-warning text-xs">{g.effect} → {g.to}</span>
												<span class="text-xs opacity-80">{g.reason}</span>
											</div>
											<pre
												class="text-xs mt-2 overflow-x-auto opacity-70">{JSON.stringify(
													g.when,
													null,
													2
												)}</pre>
										</div>
									{/each}
								</div>
							</div>
						{/if}

						{#if !pb.required_steps.length && !pb.decision_modules.length && !pb.guardrails.length && !pb.deterministic_disposition && !Object.keys(pb.legal_actions).length && !pb.close_signoff_data_classes.length}
							<p class="opacity-60">Matching only — no gates or dispositions configured.</p>
						{/if}
					</div>
				{/if}
			</div>
		{/each}
	</div>
{/if}

<!-- Authored playbooks (per-tenant, shadow/draft) -->
<div class="mt-10">
	<div class="flex items-center justify-between mb-2">
		<h2 class="h3">Authored playbooks</h2>
		{#if tenantId}
			<div class="flex gap-2">
				<a class="btn btn-sm variant-filled-primary" href="/playbooks/editor">+ New playbook</a>
				<button class="btn btn-sm variant-soft" on:click={openCreate} title="Raw JSON editor">
					JSON
				</button>
			</div>
		{/if}
	</div>

	{#if !tenantId}
		<div class="card p-6 opacity-60 text-sm">
			Pin a tenant (from Tenants) to author shadow playbooks for it.
		</div>
	{:else}
		<p class="opacity-60 text-sm mb-3">
			Shadow/draft playbooks for this tenant, validated server-side. Authored playbooks never
			govern triage directly — export to YAML and roll out via the worker to activate.
		</p>
		{#if authoredError}
			<div class="alert variant-filled-error mb-3"><span>{authoredError}</span></div>
		{/if}
		{#if authoredLoading}
			<div class="card p-6 text-center opacity-60 text-sm">Loading…</div>
		{:else if authored.length === 0}
			<div class="card p-6 opacity-60 text-sm">No authored playbooks yet.</div>
		{:else}
			<div class="grid gap-2">
				{#each authored as pb (pb.playbook_id)}
					<div class="card p-4 flex items-center justify-between gap-3">
						<div class="flex items-center gap-2 min-w-0">
							<span class="font-mono font-semibold truncate">{pb.playbook_id}</span>
							<span class="badge variant-soft-warning text-xs">{pb.status}</span>
							<span class="badge variant-soft text-xs">rev {pb.revision}</span>
						</div>
						<div class="flex items-center gap-2 flex-shrink-0">
							<a
								class="btn btn-sm variant-filled-primary"
								href="/playbooks/editor?id={encodeURIComponent(pb.playbook_id)}"
							>
								Edit
							</a>
							<button class="btn btn-sm variant-soft" on:click={() => openEdit(pb)} title="Raw JSON editor">
								JSON
							</button>
							<button class="btn btn-sm variant-soft" on:click={() => exportYaml(pb.playbook_id)}>
								Export
							</button>
							<button
								class="btn btn-sm variant-soft-error"
								on:click={() => retire(pb.playbook_id)}
							>
								Delete
							</button>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>

{#if editorOpen}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="card p-6 max-w-2xl w-full space-y-4">
			<h3 class="h4">
				{editorMode === 'create' ? 'New playbook' : `Edit ${editorPid}`}
			</h3>
			<p class="text-xs opacity-60">
				Definition (JSON). Validated server-side: shadow-only, priority ≥ 60, no
				deterministic_disposition, id must not collide with a built-in, sandboxed guardrail
				conditions.
			</p>
			<textarea class="textarea font-mono text-xs h-80" bind:value={editorText}></textarea>
			{#if editorError}
				<div class="alert variant-filled-error text-sm"><span>{editorError}</span></div>
			{/if}
			<div class="flex justify-end gap-2">
				<button class="btn variant-soft" on:click={() => (editorOpen = false)} disabled={editorSaving}>
					Cancel
				</button>
				<button class="btn variant-filled-primary" on:click={save} disabled={editorSaving}>
					{editorSaving ? 'Saving…' : 'Save'}
				</button>
			</div>
		</div>
	</div>
{/if}
