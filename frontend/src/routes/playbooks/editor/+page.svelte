<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/client';
	import { currentTenantId } from '$lib/stores';
	import ConditionBuilder from '$lib/playbook/ConditionBuilder.svelte';
	import PlaybookFlowPreview from '$lib/playbook/PlaybookFlowPreview.svelte';
	import {
		AUTHORIZATION_TRACKS,
		FILE_PRIORITY_FLOOR,
		GUARDRAIL_TARGETS,
		KNOWN_DECISION_MODULES,
		KNOWN_STEP_NODES,
		MAX_GUARDRAILS,
		STATE_CONTRACT,
		SUPERVISOR_ACTIONS,
		conditionToGroup,
		emptyGroup,
		emptyRule,
		groupToCondition,
		simulateGuard,
		validateDefinition,
		type GuardrailDef,
		type PlaybookDef,
		type RuleGroup
	} from '$lib/playbook/schema';

	// ---------------------------------------------------------------- state

	$: tenantId = $currentTenantId;
	$: editId = $page.url.searchParams.get('id');
	$: mode = editId ? 'edit' : ('create' as 'edit' | 'create');

	let loaded = false;
	let loadError: string | null = null;

	let pid = 'my-playbook';
	let priority = 70;
	let version = 1;
	let lifecycleStatus: 'draft' | 'shadow' = 'shadow';

	let ruleGroupsText = '';
	let ruleIdsText = '';
	let tracks: Record<string, boolean> = { account: false, fim: false };

	let stepChecked: Record<string, boolean> = Object.fromEntries(
		KNOWN_STEP_NODES.map((s) => [s, false])
	);
	let moduleChecked: Record<string, boolean> = Object.fromEntries(
		KNOWN_DECISION_MODULES.map((m) => [m, false])
	);

	let constrainTriage = false;
	let constrainDecide = false;
	let triageActions: Record<string, boolean> = Object.fromEntries(
		SUPERVISOR_ACTIONS.map((a) => [a, a !== 'CLOSE'])
	);
	let decideActions: Record<string, boolean> = Object.fromEntries(
		SUPERVISOR_ACTIONS.map((a) => [a, a !== 'CLOSE'])
	);

	let signoffText = '';

	interface GuardrailState {
		effect: 'override' | 'interrupt';
		to: 'escalate' | 'needs_more_info' | 'human_review';
		reason: string;
		/** null = the condition isn't representable in the builder → JSON mode. */
		builder: RuleGroup | null;
		rawWhen: string;
		/** Blocking problem (invalid JSON) — disables save. */
		rawError: string | null;
		/** Informational note (e.g. not representable visually) — never blocks. */
		rawNotice: string | null;
	}
	let guardrails: GuardrailState[] = [];

	let showJson = false;
	let jsonText = '';
	let jsonError: string | null = null;
	let flowCompact = false;

	let saving = false;
	let saveError: string | null = null;

	// ------------------------------------------------------------- document

	function csv(text: string): string[] {
		return text
			.split(',')
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
	}

	function guardrailWhen(g: GuardrailState): Record<string, unknown> {
		if (g.builder !== null) {
			return groupToCondition(g.builder) ?? {};
		}
		try {
			return JSON.parse(g.rawWhen);
		} catch {
			return {};
		}
	}

	function buildDefinition(..._deps: unknown[]): PlaybookDef {
		const def: PlaybookDef = { id: pid, priority: Number(priority) };
		if (version !== 1) def.version = version;
		const applies: PlaybookDef['applies_to'] = {};
		if (csv(ruleGroupsText).length) applies.rule_groups = csv(ruleGroupsText);
		if (csv(ruleIdsText).length) applies.rule_ids = csv(ruleIdsText);
		const activeTracks = AUTHORIZATION_TRACKS.filter((t) => tracks[t]);
		if (activeTracks.length) applies.authorization_tracks = activeTracks;
		if (Object.keys(applies).length) def.applies_to = applies;
		const steps = KNOWN_STEP_NODES.filter((s) => stepChecked[s]);
		if (steps.length) def.required_steps = steps;
		const modules = KNOWN_DECISION_MODULES.filter((m) => moduleChecked[m]);
		if (modules.length) def.decision_modules = modules;
		const legal: Record<string, string[]> = {};
		if (constrainTriage) legal.triage = SUPERVISOR_ACTIONS.filter((a) => triageActions[a]);
		if (constrainDecide) legal.decide = SUPERVISOR_ACTIONS.filter((a) => decideActions[a]);
		if (Object.keys(legal).length) def.legal_actions = legal;
		if (csv(signoffText).length) def.close_signoff_data_classes = csv(signoffText);
		if (guardrails.length) {
			def.guardrails = guardrails.map(
				(g): GuardrailDef => ({
					when: guardrailWhen(g),
					effect: g.effect,
					to: g.to,
					reason: g.reason
				})
			);
		}
		return def;
	}

	$: definition = buildDefinition(
		pid,
		priority,
		version,
		ruleGroupsText,
		ruleIdsText,
		tracks,
		stepChecked,
		moduleChecked,
		constrainTriage,
		constrainDecide,
		triageActions,
		decideActions,
		signoffText,
		guardrails
	);

	$: validationErrors = [
		...guardrails.flatMap((g, i) => (g.rawError ? [`guardrail ${i + 1}: ${g.rawError}`] : [])),
		...validateDefinition(definition as unknown as Record<string, unknown>)
	];

	function loadDefinition(def: Record<string, unknown>) {
		pid = String(def.id ?? '');
		priority = Number(def.priority ?? 70);
		version = Number(def.version ?? 1);
		const applies = (def.applies_to ?? {}) as Record<string, string[]>;
		ruleGroupsText = (applies.rule_groups ?? []).join(', ');
		ruleIdsText = (applies.rule_ids ?? []).join(', ');
		tracks = Object.fromEntries(
			AUTHORIZATION_TRACKS.map((t) => [t, (applies.authorization_tracks ?? []).includes(t)])
		);
		stepChecked = Object.fromEntries(
			KNOWN_STEP_NODES.map((s) => [s, ((def.required_steps as string[]) ?? []).includes(s)])
		);
		moduleChecked = Object.fromEntries(
			KNOWN_DECISION_MODULES.map((m) => [m, ((def.decision_modules as string[]) ?? []).includes(m)])
		);
		const legal = (def.legal_actions ?? {}) as Record<string, string[]>;
		constrainTriage = Array.isArray(legal.triage);
		constrainDecide = Array.isArray(legal.decide);
		triageActions = Object.fromEntries(
			SUPERVISOR_ACTIONS.map((a) => [a, (legal.triage ?? []).includes(a)])
		);
		decideActions = Object.fromEntries(
			SUPERVISOR_ACTIONS.map((a) => [a, (legal.decide ?? []).includes(a)])
		);
		signoffText = ((def.close_signoff_data_classes as string[]) ?? []).join(', ');
		guardrails = (((def.guardrails as GuardrailDef[]) ?? []) || []).map((g) => ({
			effect: g.effect,
			to: g.to,
			reason: g.reason,
			builder: conditionToGroup(g.when),
			rawWhen: JSON.stringify(g.when, null, 2),
			rawError: null,
			rawNotice:
				conditionToGroup(g.when) === null
					? 'this condition uses shapes the visual builder cannot show — editing as JSON'
					: null
		}));
	}

	onMount(() => {
		if (!editId) loaded = true;
	});

	let loadStarted = false;
	$: if (editId && tenantId && !loadStarted) {
		loadStarted = true;
		loadExisting(tenantId, editId);
	}

	async function loadExisting(tid: string, id: string) {
		try {
			// listAuthored + find: there is no single-get endpoint yet.
			const all = await api.playbooks.listAuthored(tid);
			const row = all.find((p) => p.playbook_id === id);
			if (!row) throw new Error(`playbook '${id}' not found for this tenant`);
			lifecycleStatus = row.status === 'draft' ? 'draft' : 'shadow';
			loadDefinition(row.definition);
			loaded = true;
		} catch (e) {
			loadError = e instanceof Error ? e.message : 'Failed to load playbook';
		}
	}

	// ------------------------------------------------------------ guardrails

	function addGuardrail() {
		const g = emptyGroup();
		g.children = [emptyRule()];
		guardrails = [
			...guardrails,
			{
				effect: 'override',
				to: 'escalate',
				reason: '',
				builder: g,
				rawWhen: '',
				rawError: null,
				rawNotice: null
			}
		];
	}

	function removeGuardrail(i: number) {
		guardrails = guardrails.filter((_, idx) => idx !== i);
	}

	function moveGuardrail(i: number, delta: number) {
		const j = i + delta;
		if (j < 0 || j >= guardrails.length) return;
		const next = [...guardrails];
		[next[i], next[j]] = [next[j], next[i]];
		guardrails = next;
	}

	function onEffectChange(g: GuardrailState) {
		// keep the pair legal: interrupt → human_review; override → a disposition
		if (g.effect === 'interrupt') g.to = 'human_review';
		else if (g.to === 'human_review') g.to = 'escalate';
		guardrails = guardrails;
	}

	function toJsonMode(g: GuardrailState) {
		g.rawWhen = JSON.stringify(g.builder ? (groupToCondition(g.builder) ?? {}) : {}, null, 2);
		g.builder = null;
		guardrails = guardrails;
	}

	function toBuilderMode(g: GuardrailState) {
		try {
			const parsed = JSON.parse(g.rawWhen);
			const group = conditionToGroup(parsed);
			if (group === null) {
				g.rawNotice =
					'this condition uses shapes the visual builder cannot show (e.g. ! / !!) — keep editing it as JSON';
				guardrails = guardrails;
				return;
			}
			g.builder = group;
			g.rawError = null;
			g.rawNotice = null;
		} catch {
			g.rawError = 'invalid JSON';
		}
		guardrails = guardrails;
	}

	function onRawWhenChange(g: GuardrailState, text: string) {
		g.rawWhen = text;
		try {
			JSON.parse(text);
			g.rawError = null;
		} catch {
			g.rawError = 'invalid JSON';
		}
		guardrails = guardrails;
	}

	// ---------------------------------------------------------- JSON document

	function openJson() {
		jsonText = JSON.stringify(definition, null, 2);
		jsonError = null;
		showJson = true;
	}

	function applyJson() {
		try {
			const parsed = JSON.parse(jsonText);
			loadDefinition(parsed);
			jsonError = null;
			showJson = false;
		} catch (e) {
			jsonError = e instanceof Error ? e.message : 'Invalid JSON';
		}
	}

	// ------------------------------------------------------------- test panel

	let sim = {
		verdict: 'close',
		confidence: 0.8,
		authzClass: 'absent',
		ioc: false,
		activeIncident: false,
		dataClass: '',
		environment: '',
		criticality: ''
	};

	$: simCtx = {
		authz: {
			class: sim.authzClass,
			in_scope: sim.authzClass === 'covered',
			sanctioned_or_routine: sim.authzClass === 'covered',
			actor_genuine: true,
			policy_allowed: sim.authzClass !== 'contradicted'
		},
		verdict: sim.verdict,
		verdict_confidence: sim.confidence,
		asset: {
			data_classification: sim.dataClass || null,
			environment: sim.environment || null,
			criticality: sim.criticality || null
		},
		enrichment: { ioc: sim.ioc },
		correlation: { active_incident: sim.activeIncident }
	};

	$: simResult = simulateGuard(definition, simCtx);

	$: firedNodeId =
		simResult.stage === 'guardrail'
			? `guardrail-${simResult.index}`
			: simResult.stage; // 'floor' | 'signoff' | 'commit' match the node ids

	const SIM_BADGE: Record<string, string> = {
		close: 'variant-filled-success',
		needs_more_info: 'variant-filled-warning',
		escalate: 'variant-filled-error',
		human_review: 'variant-filled-tertiary'
	};

	// ------------------------------------------------------------------- save

	async function save() {
		if (!tenantId) return;
		saving = true;
		saveError = null;
		try {
			const doc = definition as unknown as Record<string, unknown>;
			if (mode === 'create') await api.playbooks.createAuthored(tenantId, doc, lifecycleStatus);
			else await api.playbooks.updateAuthored(tenantId, editId!, doc, lifecycleStatus);
			goto('/playbooks');
		} catch (e) {
			saveError = e instanceof Error ? e.message : 'Save failed.';
		} finally {
			saving = false;
		}
	}

	function focusGuardrail(e: CustomEvent<{ guardrail: number }>) {
		document
			.getElementById(`guardrail-card-${e.detail.guardrail}`)
			?.scrollIntoView({ behavior: 'smooth', block: 'center' });
	}
</script>

<svelte:head>
	<title>{mode === 'edit' ? `Edit ${editId}` : 'New playbook'} - SocTalk</title>
</svelte:head>

<div class="flex items-center justify-between mb-1">
	<h1 class="h2">{mode === 'edit' ? `Edit playbook` : 'New playbook'}</h1>
	<div class="flex gap-2">
		<button class="btn btn-sm variant-soft" on:click={openJson}>View as JSON</button>
		<a class="btn btn-sm variant-soft" href="/playbooks">Cancel</a>
		<button
			class="btn btn-sm variant-filled-primary"
			on:click={save}
			disabled={saving || !tenantId || validationErrors.length > 0}
		>
			{saving ? 'Saving…' : mode === 'create' ? 'Create (shadow)' : 'Save revision'}
		</button>
	</div>
</div>
<p class="opacity-60 text-sm mb-4">
	Authored playbooks run in shadow: matched and evaluated for audit, enforcing nothing, until
	promoted. The safety floor (IOC / contradicted-authorization vetoes) always applies and cannot
	be weakened here — guardrails can only raise suspicion, never suppress it.
</p>

{#if !tenantId}
	<div class="card p-6 opacity-60 text-sm">Pin a tenant (from Tenants) to author playbooks.</div>
{:else if loadError}
	<div class="alert variant-filled-error"><span>{loadError}</span></div>
{:else if !loaded}
	<div class="flex items-center justify-center h-40">
		<div class="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-500"></div>
	</div>
{:else}
	<div class="grid grid-cols-1 xl:grid-cols-5 gap-4 items-start">
		<!-- ------------------------------------------------ form column -->
		<div class="xl:col-span-3 space-y-4">
			<section class="card p-4 space-y-3">
				<h3 class="h4">Identity</h3>
				<div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
					<label class="label text-sm sm:col-span-2">
						<span class="opacity-70">Playbook id (slug)</span>
						<input
							class="input font-mono"
							bind:value={pid}
							disabled={mode === 'edit'}
							placeholder="my-playbook"
						/>
					</label>
					<label class="label text-sm">
						<span class="opacity-70">Priority (≥ {FILE_PRIORITY_FLOOR}, lower wins)</span>
						<input class="input" type="number" min={FILE_PRIORITY_FLOOR} bind:value={priority} />
					</label>
				</div>
				<label class="flex items-center gap-2 text-sm">
					<input class="checkbox" type="checkbox" checked={lifecycleStatus === 'draft'}
						on:change={(e) => (lifecycleStatus = e.currentTarget.checked ? 'draft' : 'shadow')} />
					<span>Keep as draft (not yet shadow-evaluated against live runs)</span>
				</label>
			</section>

			<section class="card p-4 space-y-3">
				<h3 class="h4">Which alerts does it own?</h3>
				<p class="text-xs opacity-60">
					Criteria are OR'd — the playbook applies when any one matches.
				</p>
				<label class="label text-sm">
					<span class="opacity-70">Wazuh rule groups (comma-separated)</span>
					<input class="input" bind:value={ruleGroupsText} placeholder="sudo, su" />
				</label>
				<label class="label text-sm">
					<span class="opacity-70">Rule ids (comma-separated)</span>
					<input class="input" bind:value={ruleIdsText} placeholder="5402, 5501" />
				</label>
				<div class="text-sm">
					<span class="opacity-70">Authorization activity tracks</span>
					<div class="flex gap-4 mt-1">
						{#each AUTHORIZATION_TRACKS as t}
							<label class="flex items-center gap-2">
								<input class="checkbox" type="checkbox" bind:checked={tracks[t]} />
								<span class="font-mono text-xs">{t}</span>
							</label>
						{/each}
					</div>
				</div>
			</section>

			<section class="card p-4 space-y-3">
				<h3 class="h4">Investigation requirements</h3>
				<div class="text-sm">
					<span class="opacity-70">Steps that must run before a verdict is legal</span>
					{#each KNOWN_STEP_NODES as s}
						<label class="flex items-center gap-2 mt-1">
							<input class="checkbox" type="checkbox" bind:checked={stepChecked[s]} />
							<span class="font-mono text-xs">{s}</span>
						</label>
					{/each}
				</div>
				<div class="text-sm">
					<span class="opacity-70">Deterministic decision modules to consult</span>
					{#each KNOWN_DECISION_MODULES as m}
						<label class="flex items-center gap-2 mt-1">
							<input class="checkbox" type="checkbox" bind:checked={moduleChecked[m]} />
							<span class="font-mono text-xs">{m}</span>
						</label>
					{/each}
				</div>
				<div class="text-sm space-y-2">
					<span class="opacity-70">Allowed supervisor actions per phase (unchecked phase = unconstrained)</span>
					{#each ['triage', 'decide'] as phase}
						<div class="flex flex-wrap items-center gap-3">
							<label class="flex items-center gap-2 w-20">
								<input
									class="checkbox"
									type="checkbox"
									checked={phase === 'triage' ? constrainTriage : constrainDecide}
									on:change={(e) => {
										if (phase === 'triage') constrainTriage = e.currentTarget.checked;
										else constrainDecide = e.currentTarget.checked;
									}}
								/>
								<span class="font-mono text-xs">{phase}</span>
							</label>
							{#if phase === 'triage' ? constrainTriage : constrainDecide}
								{#each SUPERVISOR_ACTIONS as a}
									<label class="flex items-center gap-1">
										<input
											class="checkbox"
											type="checkbox"
											checked={phase === 'triage' ? triageActions[a] : decideActions[a]}
											on:change={(e) => {
												if (phase === 'triage') {
													triageActions[a] = e.currentTarget.checked;
													triageActions = triageActions;
												} else {
													decideActions[a] = e.currentTarget.checked;
													decideActions = decideActions;
												}
											}}
										/>
										<span class="font-mono text-[10px]">{a}</span>
									</label>
								{/each}
							{/if}
						</div>
					{/each}
				</div>
			</section>

			<section class="card p-4 space-y-3">
				<h3 class="h4">Close sign-off</h3>
				<label class="label text-sm">
					<span class="opacity-70">
						A committing close on an asset with one of these data classifications waits for a
						human (comma-separated)
					</span>
					<input class="input" bind:value={signoffText} placeholder="pci, phi" />
				</label>
			</section>

			<section class="card p-4 space-y-3">
				<div class="flex items-center justify-between">
					<h3 class="h4">Guardrails</h3>
					<button
						class="btn btn-sm variant-soft"
						on:click={addGuardrail}
						disabled={guardrails.length >= MAX_GUARDRAILS}
					>
						+ Add guardrail
					</button>
				</div>
				<p class="text-xs opacity-60">
					Evaluated after the safety floor, in order — the first matching rule wins. Overrides can
					only raise a decision (close → needs_more_info → escalate); interrupts hold the draft for
					human review.
				</p>

				{#each guardrails as g, i}
					<div class="card variant-soft p-3 space-y-2" id="guardrail-card-{i}">
						<div class="flex items-center gap-2">
							<span class="badge variant-filled text-xs">{i + 1}</span>
							<select class="select w-auto !py-1 text-xs" bind:value={g.effect} on:change={() => onEffectChange(g)}>
								<option value="override">override the decision</option>
								<option value="interrupt">interrupt for human review</option>
							</select>
							{#if g.effect === 'override'}
								<span class="text-xs opacity-60">raise to</span>
								<select class="select w-auto !py-1 text-xs" bind:value={g.to}>
									{#each GUARDRAIL_TARGETS.filter((t) => t !== 'human_review') as t}
										<option value={t}>{t}</option>
									{/each}
								</select>
							{:else}
								<span class="badge variant-soft-tertiary text-xs">→ human_review</span>
							{/if}
							<div class="flex-1"></div>
							<button class="btn-icon btn-icon-sm variant-soft" title="Move up" on:click={() => moveGuardrail(i, -1)} disabled={i === 0}>↑</button>
							<button class="btn-icon btn-icon-sm variant-soft" title="Move down" on:click={() => moveGuardrail(i, 1)} disabled={i === guardrails.length - 1}>↓</button>
							<button class="btn-icon btn-icon-sm variant-soft-error" title="Remove" on:click={() => removeGuardrail(i)}>✕</button>
						</div>

						<div class="pl-1">
							{#if g.builder !== null}
								<ConditionBuilder bind:group={g.builder} on:change={() => (guardrails = guardrails)} />
								<button class="anchor text-xs mt-1" on:click={() => toJsonMode(g)}>
									edit condition as JSON
								</button>
							{:else}
								<textarea
									class="textarea font-mono text-xs h-28"
									value={g.rawWhen}
									on:input={(e) => onRawWhenChange(g, e.currentTarget.value)}
								></textarea>
								{#if g.rawError}
									<div class="text-xs text-error-500">{g.rawError}</div>
								{/if}
								{#if g.rawNotice}
									<div class="text-xs text-warning-500">{g.rawNotice}</div>
								{/if}
								<button class="anchor text-xs mt-1" on:click={() => toBuilderMode(g)}>
									back to visual builder
								</button>
							{/if}
						</div>

						<label class="label text-sm">
							<span class="opacity-70 text-xs">Reason shown to the analyst when this fires</span>
							<input class="input !py-1 text-sm" bind:value={g.reason}
								placeholder="why this rule raises / interrupts" maxlength="512" />
						</label>
					</div>
				{/each}
				{#if guardrails.length === 0}
					<div class="text-sm opacity-50 text-center py-2">No guardrails yet.</div>
				{/if}
			</section>

			{#if validationErrors.length}
				<div class="alert variant-soft-error text-sm">
					<div>
						<p class="font-semibold mb-1">Fix before saving:</p>
						<ul class="list-disc ml-5 space-y-0.5">
							{#each validationErrors as e}
								<li>{e}</li>
							{/each}
						</ul>
					</div>
				</div>
			{/if}
			{#if saveError}
				<div class="alert variant-filled-error text-sm"><span>{saveError}</span></div>
			{/if}
		</div>

		<!-- --------------------------------------------- preview column -->
		<div
			class="xl:col-span-2 space-y-4 xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)] xl:overflow-y-auto"
		>
			<section class="card p-2">
				<div class="flex items-center justify-between px-2 pt-1">
					<h3 class="h4">Decision flow</h3>
					<label class="flex items-center gap-2 text-xs opacity-70">
						<input class="checkbox checkbox-sm" type="checkbox" bind:checked={flowCompact} />
						compact
					</label>
				</div>
				<p class="text-xs opacity-60 px-2 pb-1">
					Projection of this document onto the triage pipeline — click a guardrail to jump to it.
				</p>
				<div class="h-[32rem]">
					<PlaybookFlowPreview
						{definition}
						{firedNodeId}
						compact={flowCompact}
						on:focus={focusGuardrail}
					/>
				</div>
			</section>

			<section class="card p-4 space-y-2">
				<h3 class="h4">Try it</h3>
				<p class="text-xs opacity-60">
					Set a sample verdict context and see what this playbook would do.
				</p>
				<div class="grid grid-cols-2 gap-2 text-sm">
					<label class="label">
						<span class="opacity-70 text-xs">LLM draft verdict</span>
						<select class="select !py-1" bind:value={sim.verdict}>
							<option value="close">close</option>
							<option value="needs_more_info">needs_more_info</option>
							<option value="escalate">escalate</option>
						</select>
					</label>
					<label class="label">
						<span class="opacity-70 text-xs">Confidence</span>
						<input class="input !py-1" type="number" min="0" max="1" step="0.05" bind:value={sim.confidence} />
					</label>
					<label class="label">
						<span class="opacity-70 text-xs">Authorization class</span>
						<select class="select !py-1" bind:value={sim.authzClass}>
							<option value="covered">covered</option>
							<option value="contradicted">contradicted</option>
							<option value="absent">absent</option>
						</select>
					</label>
					<label class="label">
						<span class="opacity-70 text-xs">Asset data classification</span>
						<input class="input !py-1" bind:value={sim.dataClass} placeholder="pci" />
					</label>
					<label class="label">
						<span class="opacity-70 text-xs">Asset criticality</span>
						<select class="select !py-1" bind:value={sim.criticality}>
							<option value="">unknown</option>
							<option value="critical">critical</option>
							<option value="high">high</option>
							<option value="medium">medium</option>
							<option value="low">low</option>
						</select>
					</label>
					<label class="label">
						<span class="opacity-70 text-xs">Asset environment</span>
						<input class="input !py-1" bind:value={sim.environment} placeholder="production" />
					</label>
					<label class="flex items-center gap-2">
						<input class="checkbox" type="checkbox" bind:checked={sim.ioc} />
						<span class="text-xs">malicious indicator (IOC)</span>
					</label>
					<label class="flex items-center gap-2">
						<input class="checkbox" type="checkbox" bind:checked={sim.activeIncident} />
						<span class="text-xs">active incident</span>
					</label>
				</div>
				<div class="card variant-soft p-3 text-sm space-y-1">
					<div class="flex items-center gap-2">
						<span class="opacity-60 text-xs">outcome</span>
						<span class="badge {SIM_BADGE[simResult.finalDecision] ?? 'variant-soft'} text-xs">
							{simResult.finalDecision}
						</span>
						{#if simResult.stage === 'guardrail'}
							<span class="text-xs opacity-70">
								guardrail {(simResult.index ?? 0) + 1} fired ({simResult.effect})
							</span>
						{:else if simResult.stage === 'floor'}
							<span class="text-xs opacity-70">safety floor (not this playbook)</span>
						{:else if simResult.stage === 'signoff'}
							<span class="text-xs opacity-70">close sign-off interrupt</span>
						{/if}
					</div>
					<p class="text-xs opacity-70">{simResult.reason}</p>
				</div>
				<p class="text-[10px] opacity-40">
					Contract fields simulated: {STATE_CONTRACT.length}. The worker's guard remains the
					authority — this preview mirrors it for authoring feedback only.
				</p>
			</section>
		</div>
	</div>
{/if}

{#if showJson}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="card p-6 max-w-2xl w-full space-y-3">
			<h3 class="h4">Playbook document</h3>
			<p class="text-xs opacity-60">
				The form and this JSON are the same document. Edit here and apply, or copy it out — the
				YAML export uses the identical structure.
			</p>
			<textarea class="textarea font-mono text-xs h-80" bind:value={jsonText}></textarea>
			{#if jsonError}
				<div class="alert variant-filled-error text-sm"><span>{jsonError}</span></div>
			{/if}
			<div class="flex justify-end gap-2">
				<button class="btn variant-soft" on:click={() => (showJson = false)}>Close</button>
				<button class="btn variant-filled-primary" on:click={applyJson}>Apply to form</button>
			</div>
		</div>
	</div>
{/if}
