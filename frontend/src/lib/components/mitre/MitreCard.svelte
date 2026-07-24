<!--
  MitreCard — MITRE ATT&CK context card for the investigation detail page
  (issue #71). Composes the evidence rail (union of member alerts'
  tactics), technique chips in "Tactic via Technique (Txxxx)" grammar,
  and the technique drawer. Renders nothing when no alert carries a
  MITRE mapping.
-->
<script lang="ts">
	import type { InvestigationAlert } from '$lib/api/client';
	import {
		ATTACK_VERSION,
		resolveMitre,
		tacticName,
		type ResolvedTechnique
	} from '$lib/mitre/attack';
	import { m } from '$lib/paraglide/messages';
	import MitreRail from './MitreRail.svelte';
	import TechniqueDrawer from './TechniqueDrawer.svelte';

	export let alerts: InvestigationAlert[];
	export let investigationId: string | null = null;

	let selected: ResolvedTechnique | null = null;

	$: resolved = resolveMitre(alerts.map((a) => a.mitre));
	$: hasMitre = resolved.techniques.length > 0 || resolved.tacticCounts.size > 0;
	// Count badges only make sense as "contributing alerts per tactic",
	// so they are investigation-level only (>1 mapped alert).
	$: mappedAlerts = alerts.filter(
		(a) => (a.mitre?.ids?.length ?? 0) > 0 || (a.mitre?.tactics?.length ?? 0) > 0
	);
	$: showCounts = mappedAlerts.length > 1;
	$: railCounts = showCounts ? alertCountsPerTactic(mappedAlerts) : resolved.tacticCounts;

	function alertCountsPerTactic(list: InvestigationAlert[]): Map<string, number> {
		const counts = new Map<string, number>();
		for (const alert of list) {
			for (const [ta] of resolveMitre([alert.mitre]).tacticCounts) {
				counts.set(ta, (counts.get(ta) ?? 0) + 1);
			}
		}
		return counts;
	}

	function chipLabel(t: ResolvedTechnique): string {
		if (t.tactics.length === 1) {
			return m.mitre_chip_via({ tactic: tacticName(t.tactics[0]), technique: t.name });
		}
		return t.name;
	}

	function openTechnique(t: ResolvedTechnique) {
		selected = t;
	}

	function openTactic(tacticId: string) {
		const first = resolved.techniques.find((t) => t.tactics.includes(tacticId));
		if (first) selected = first;
	}

	function sourceAlertsFor(t: ResolvedTechnique): InvestigationAlert[] {
		return alerts.filter((a) => a.mitre?.ids?.includes(t.id));
	}
</script>

{#if hasMitre}
	<div class="card p-4 mb-6">
		<div class="flex items-baseline justify-between flex-wrap gap-2 mb-1">
			<h3 class="h4">{m.mitre_card_title()}</h3>
			<span class="text-xs opacity-60">{m.mitre_from_rule_meta({ version: ATTACK_VERSION })}</span>
		</div>
		<div class="flex items-baseline justify-between flex-wrap gap-2 mb-2">
			<span class="text-xs font-semibold uppercase tracking-wide opacity-60">
				{showCounts ? m.mitre_rule_mappings_across() : m.mitre_mapped_tactics()}
			</span>
			{#if showCounts}
				<span class="text-xs opacity-50">{m.mitre_not_narrative()}</span>
			{/if}
		</div>

		<MitreRail tacticCounts={railCounts} {showCounts} on:select={(e) => openTactic(e.detail)} />

		{#if resolved.techniques.length > 0}
			<div class="flex flex-wrap gap-2 mt-3">
				{#each resolved.techniques as technique (technique.id)}
					<button
						type="button"
						class="chip variant-soft-primary"
						class:opacity-60={!technique.known}
						on:click={() => openTechnique(technique)}
					>
						<span class="w-1.5 h-1.5 rounded-full bg-primary-500"></span>
						<span>{chipLabel(technique)}</span>
						<span class="font-mono opacity-60">({technique.id})</span>
					</button>
				{/each}
			</div>
		{/if}

		{#if resolved.unmatchedTactics.length > 0}
			<p class="text-xs opacity-50 mt-2">
				{m.mitre_unmatched_tactics({ names: resolved.unmatchedTactics.join(', ') })}
			</p>
		{/if}
	</div>
{/if}

{#if selected}
	<TechniqueDrawer
		technique={selected}
		sourceAlerts={sourceAlertsFor(selected)}
		{investigationId}
		on:close={() => (selected = null)}
	/>
{/if}
