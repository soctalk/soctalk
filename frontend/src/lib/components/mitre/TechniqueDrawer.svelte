<!--
  TechniqueDrawer — in-product technique panel (issue #71).

  Opens from a chip or rail stop. Shows the MITRE description, tactic
  breadcrumb, sub-technique parentage, source-rule provenance, and the
  pivot: other RLS-visible alerts sharing this technique, linking to
  their investigations. Replaces the industry-default link-out to
  attack.mitre.org (the external link stays as a secondary affordance).
-->
<script lang="ts">
	import { createEventDispatcher, onMount } from 'svelte';
	import { api, type InvestigationAlert, type TechniqueAlerts } from '$lib/api/client';
	import { ATTACK_VERSION, tacticName, type ResolvedTechnique } from '$lib/mitre/attack';
	import { formatSeverity } from '$lib/utils/formatters';
	import { localizeHref } from '$lib/i18n';
	import { m } from '$lib/paraglide/messages';

	export let technique: ResolvedTechnique;
	/** Member alerts of the current investigation that carry this technique
	 * — the provenance ("which rule said so"). */
	export let sourceAlerts: InvestigationAlert[] = [];
	/** Current investigation id — related alerts from the same one are
	 * labeled instead of linked. */
	export let investigationId: string | null = null;

	const dispatch = createEventDispatcher<{ close: void }>();

	let related: TechniqueAlerts | null = null;
	let relatedError = false;
	let relatedLoading = true;

	onMount(async () => {
		try {
			related = await api.mitre.alertsByTechnique(technique.id, {
				excludeInvestigationId: investigationId ?? undefined
			});
		} catch {
			relatedError = true;
		} finally {
			relatedLoading = false;
		}
	});

	function severityBadge(severity: string | null): string {
		switch (severity) {
			case 'critical':
				return 'variant-filled-error';
			case 'high':
				return 'variant-filled-warning';
			case 'medium':
				return 'variant-filled-secondary';
			case 'low':
				return 'variant-filled-tertiary';
			default:
				return 'variant-soft';
		}
	}

	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') dispatch('close');
	}

	// Exclusion happens server-side (exclude_investigation_id), so the
	// page and `total` agree; no client-side re-filtering.
	$: otherAlerts = related?.alerts ?? [];
</script>

<svelte:window on:keydown={onKeydown} />

<div class="fixed inset-0 z-50">
	<button
		class="absolute inset-0 bg-black/50 cursor-default"
		on:click={() => dispatch('close')}
		aria-label={m.common_close()}
		tabindex="-1"
	></button>
	<aside
		class="card absolute right-0 top-0 h-full w-full max-w-md rounded-none overflow-y-auto p-6 space-y-4"
		role="dialog"
		aria-modal="true"
		aria-label={technique.name}
	>
		<!-- Header -->
		<div class="flex items-start justify-between gap-2">
			<div>
				<div class="text-xs opacity-60 mb-1">
					{technique.tactics.map(tacticName).join(' · ') || m.mitre_card_title()}
					{#if technique.parentId}
						&nbsp;›&nbsp;{technique.parentId}
						{technique.parentName ?? ''}
					{/if}
				</div>
				<h3 class="h4">
					{technique.name}
					<span class="font-mono text-sm opacity-60">({technique.id})</span>
				</h3>
			</div>
			<button
				class="btn-icon btn-icon-sm variant-soft"
				on:click={() => dispatch('close')}
				title={m.common_close()}
				aria-label={m.common_close()}
			>
				<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>

		{#if technique.deprecated}
			<div class="alert variant-soft-warning text-sm p-2">{m.mitre_deprecated_technique()}</div>
		{/if}
		{#if !technique.known}
			<div class="alert variant-soft-warning text-sm p-2">
				{m.mitre_unknown_technique({ version: ATTACK_VERSION })}
			</div>
		{/if}

		{#if technique.desc}
			<p class="text-sm opacity-80">{technique.desc}</p>
		{/if}

		<!-- Provenance -->
		<dl class="space-y-2 text-sm">
			{#if sourceAlerts.length > 0}
				<div>
					<dt class="opacity-60">{m.mitre_source_rules()}</dt>
					{#each sourceAlerts as alert (alert.id)}
						<dd class="mt-1 flex items-center gap-2">
							{#if alert.rule_id}
								<span class="font-mono text-xs">{alert.rule_id}</span>
							{/if}
							<span class="truncate">{alert.description ?? ''}</span>
						</dd>
					{/each}
				</div>
			{/if}
			<div class="flex justify-between">
				<dt class="opacity-60">{m.mitre_mapping()}</dt>
				<dd>{m.mitre_mapping_rule_metadata()}</dd>
			</div>
			<div class="flex justify-between">
				<dt class="opacity-60">{m.mitre_attack_version()}</dt>
				<dd>v{ATTACK_VERSION}</dd>
			</div>
		</dl>

		<!-- Pivot: other alerts sharing this technique -->
		<div class="border-t border-surface-500/30 pt-4">
			<h4 class="font-semibold text-sm mb-2">
				{m.mitre_other_alerts()}
				{#if related}
					<span class="badge variant-soft ml-1">{related.total}</span>
				{/if}
			</h4>

			{#if relatedLoading}
				<div class="flex justify-center py-4">
					<div class="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-500"></div>
				</div>
			{:else if relatedError}
				<p class="text-sm text-error-500">{m.mitre_related_load_failed()}</p>
			{:else if otherAlerts.length === 0}
				<p class="text-sm opacity-60">{m.mitre_no_related()}</p>
			{:else}
				<ul class="space-y-2">
					{#each otherAlerts as alert (alert.id)}
						<li class="bg-surface-500/10 rounded p-2 text-sm">
							<div class="flex items-center gap-2 mb-1">
								{#if alert.severity}
									<span class="badge {severityBadge(alert.severity)} text-xs">
										{formatSeverity(alert.severity)}
									</span>
								{/if}
								{#if alert.rule_id}
									<span class="font-mono text-xs opacity-60">{alert.rule_id}</span>
								{/if}
								{#if alert.tenant_display_name}
									<span class="badge variant-ghost text-xs">{alert.tenant_display_name}</span>
								{/if}
							</div>
							<p class="truncate">{alert.description ?? alert.id}</p>
							{#if alert.investigation_id && alert.investigation_id !== investigationId}
								<a
									class="anchor text-xs"
									href={localizeHref(`/investigations/${alert.investigation_id}`)}
								>
									{alert.investigation_title ?? alert.investigation_id}
								</a>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</div>

		<a
			class="anchor text-xs opacity-60"
			href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
			target="_blank"
			rel="noreferrer"
		>
			{m.mitre_view_on_site()}
		</a>
	</aside>
</div>
