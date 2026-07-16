<script lang="ts">
	import { api, type AuthoredResponsePlaybook } from '$lib/api/client';
	import { currentTenantId, canManageTriagePolicies } from '$lib/stores';

	// Reuses the admin-tier config-management gate (the API gates response-playbook
	// mutations with the same MSSP_ADMIN role as triage policies).
	$: canManage = $canManageTriagePolicies;

	let authored: AuthoredResponsePlaybook[] = [];
	let loading = false;
	let error: string | null = null;
	let note: string | null = null;

	let editorOpen = false;
	let editorMode: 'create' | 'edit' = 'create';
	let editorPid = '';
	let editorText = '';
	let editorSaving = false;
	let editorError: string | null = null;

	$: tenantId = $currentTenantId;
	$: if (tenantId) load(tenantId);

	async function load(tid: string) {
		loading = true;
		error = null;
		try {
			authored = await api.responsePlaybooks.listAuthored(tid);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load response playbooks';
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editorMode = 'create';
		editorPid = '';
		editorError = null;
		editorText = JSON.stringify(
			{
				id: 'my-response-playbook',
				version: 1,
				applies_to: { rule_groups: [] },
				response: {
					on_escalate: [
						{ capability: 'annotate_investigation', params: { body: 'escalation acknowledged' } }
					]
				}
			},
			null,
			2
		);
		editorOpen = true;
	}

	function openEdit(pb: AuthoredResponsePlaybook) {
		editorMode = 'edit';
		editorPid = pb.response_playbook_id;
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
			if (editorMode === 'create') await api.responsePlaybooks.createAuthored(tenantId, def);
			else await api.responsePlaybooks.updateAuthored(tenantId, editorPid, def);
			editorOpen = false;
			await load(tenantId);
		} catch (e) {
			editorError = e instanceof Error ? e.message : 'Save failed.';
		} finally {
			editorSaving = false;
		}
	}

	async function retire(pid: string) {
		if (!tenantId || !confirm(`Delete response playbook "${pid}"? This removes it from the tenant.`))
			return;
		try {
			await api.responsePlaybooks.retireAuthored(tenantId, pid);
			await load(tenantId);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Delete failed.';
		}
	}

	async function exportYaml(pid: string) {
		if (!tenantId) return;
		try {
			const res = await api.responsePlaybooks.exportAuthored(tenantId, pid);
			const blob = new Blob([res.yaml], { type: 'text/yaml' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `${pid}.yaml`;
			a.click();
			URL.revokeObjectURL(url);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Export failed.';
		}
	}

	async function setActive(pid: string, active: boolean) {
		if (!tenantId) return;
		error = null;
		try {
			if (active) await api.responsePlaybooks.activateAuthored(tenantId, pid);
			else await api.responsePlaybooks.deactivateAuthored(tenantId, pid);
			// Unlike triage policies, activation is LIVE — L1 dispatches from the DB,
			// so there is no worker rollout to wait for.
			note = active
				? `"${pid}" is now active — it governs response dispatch immediately.`
				: `"${pid}" returned to shadow — audited only, no longer dispatched.`;
			await load(tenantId);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Activation change failed.';
		}
	}

	function statusBadge(s: string): string {
		return s === 'active'
			? 'variant-filled-success'
			: s === 'shadow'
				? 'variant-soft-warning'
				: 'variant-soft';
	}

	function actionSummary(pb: AuthoredResponsePlaybook): string {
		const r = (pb.definition?.response ?? {}) as Record<string, unknown>;
		const caps = (phase: string): string[] =>
			(((r[phase] as unknown[]) ?? []) as Record<string, unknown>[]).map((a) =>
				String(a.capability ?? '?')
			);
		const parts: string[] = [];
		const esc = caps('on_escalate');
		const cls = caps('on_close');
		if (esc.length) parts.push(`escalate → ${esc.join(', ')}`);
		if (cls.length) parts.push(`close → ${cls.join(', ')}`);
		return parts.join('  ·  ') || '—';
	}
</script>

<svelte:head>
	<title>Response Playbooks - SocTalk</title>
</svelte:head>

<div class="flex items-center justify-between mb-2">
	<h1 class="h2">Response Playbooks</h1>
	{#if tenantId && canManage}
		<button class="btn btn-sm variant-filled-primary" on:click={openCreate}>+ New response playbook</button>
	{/if}
</div>
<p class="opacity-60 text-sm mb-6">
	Procedural response dispatched after the triage disposition is final — the playbook names vetted
	capabilities per disposition. Tier-0 actions (annotate, notify) fire autonomously; higher-tier
	actions route to a human-approved proposal. Activate one to dispatch live; deactivate returns it
	to shadow (audited only).
</p>

{#if !tenantId}
	<div class="card p-6 opacity-60 text-sm">
		Pin a tenant (from Tenants) to author response playbooks for it.
	</div>
{:else}
	{#if error}
		<div class="alert variant-filled-error mb-3"><span>{error}</span></div>
	{/if}
	{#if note}
		<div class="alert variant-soft-primary mb-3 text-sm"><span>{note}</span></div>
	{/if}
	{#if loading}
		<div class="card p-6 text-center opacity-60 text-sm">Loading…</div>
	{:else if authored.length === 0}
		<div class="card p-6 opacity-60 text-sm">No response playbooks yet.</div>
	{:else}
		<div class="grid gap-2">
			{#each authored as pb (pb.response_playbook_id)}
				<div class="card p-4 flex items-center justify-between gap-3">
					<div class="flex flex-col min-w-0 gap-1">
						<div class="flex items-center gap-2 min-w-0">
							<span class="font-mono font-semibold truncate">{pb.response_playbook_id}</span>
							<span class="badge {statusBadge(pb.status)} text-xs">{pb.status}</span>
							<span class="badge variant-soft text-xs">rev {pb.revision}</span>
						</div>
						<div class="text-xs opacity-60 truncate">{actionSummary(pb)}</div>
					</div>
					<div class="flex items-center gap-2 flex-shrink-0">
						<button class="btn btn-sm variant-soft" on:click={() => exportYaml(pb.response_playbook_id)}>
							Export
						</button>
						{#if canManage}
							{#if pb.status === 'active'}
								<button
									class="btn btn-sm variant-soft"
									on:click={() => setActive(pb.response_playbook_id, false)}
								>
									Deactivate
								</button>
							{:else}
								<button
									class="btn btn-sm variant-filled-success"
									on:click={() => setActive(pb.response_playbook_id, true)}
								>
									Activate
								</button>
							{/if}
							<button class="btn btn-sm variant-filled-primary" on:click={() => openEdit(pb)}>
								Edit
							</button>
							<button
								class="btn btn-sm variant-soft-error"
								on:click={() => retire(pb.response_playbook_id)}
							>
								Delete
							</button>
						{/if}
					</div>
				</div>
			{/each}
		</div>
	{/if}
{/if}

{#if editorOpen}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="card p-6 max-w-2xl w-full space-y-4">
			<h3 class="h4">
				{editorMode === 'create' ? 'New response playbook' : `Edit ${editorPid}`}
			</h3>
			<p class="text-xs opacity-60">
				Definition (JSON). Validated server-side: fail-closed, vetted capability names only,
				on_close restricted to annotation-tier actions. New/edited playbooks land as shadow —
				activate to dispatch live.
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
