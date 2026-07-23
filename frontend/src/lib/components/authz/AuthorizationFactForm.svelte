<script lang="ts">
	// Guided, kind/track-aware editor for an AuthorizationFact. Replaces the raw
	// JSON textarea on both the MSSP create and tenant assert surfaces. The
	// payload builder mirrors the server-side model validators 1:1 so illegal
	// combinations are impossible to submit (rather than bouncing on a 422).
	//
	// `mode`:
	//   'mssp'   — analyst-authored; requires a client-supplied `id`.
	//   'tenant' — self-service assertion; `id` is server-generated, so we send
	//              a throwaway placeholder the server overwrites.
	// source_type / trust are ALWAYS stamped server-side and never sent here.
	import { createEventDispatcher } from 'svelte';
	import { m } from '$lib/paraglide/messages';
	import { factSummary } from '$lib/authz/display';

	export let mode: 'mssp' | 'tenant' = 'mssp';
	export let saving = false;
	export let error: string | null = null;

	const dispatch = createEventDispatcher<{ submit: Record<string, unknown>; cancel: void }>();

	type Kind = 'grant' | 'prohibition' | 'change_freeze' | 'entity_context';
	type Track = 'account' | 'fim';

	let kind: Kind = 'grant';
	let track: Track = 'account';
	let factId = '';

	// scope
	let subject = '';
	let target = '';
	let action = '';
	let changeType = 'any';
	let validFrom = '';
	let validUntil = '';

	// grant
	let grantClass: 'change_ticket' | 'standing_baseline' | 'routine_observation' = 'change_ticket';
	let cabRequired = false;
	let cabApproved = true;
	let emergency = false;
	let freezeException = false;
	let seenCount = '';
	let ioc = false;

	// prohibition
	let forbidAction = '';
	let forbidAccountType = '';
	let forbidChangeType = '';
	let appliesEnv = '';
	let appliesCriticality = '';
	let appliesDataClass = '';
	let appliesConfigClass = '';
	let priority: 'high' | 'medium' | 'low' = 'high';
	let waiverPresent = false;
	let breakGlassException = false;

	// change_freeze
	let freezeStart = '';
	let freezeEnd = '';
	let freezeEnvs = '';
	let freezeConfigClasses = '';
	let allowedExceptionIds = '';

	// entity_context
	let entityType: 'asset' | 'account' | 'watched_path' | 'org' = 'asset';
	let entityName = '';
	let environment = '';
	let criticality = '';
	let dataClassification = '';
	let entityConfigClass = '';
	let ownerOrg = '';
	let custodianAccount = '';
	let approver = '';
	let serviceOwner = '';
	let accountType = '';
	let privileged = false;
	let onCall = false;
	let breakGlass = false;
	let compromiseStatus = '';
	let linkedOrgs = '';

	// advanced JSON escape hatch
	let jsonMode = false;
	let jsonText = '';

	const KINDS: { k: Kind; label: string; desc: string; icon: string; color: string }[] = [
		{ k: 'grant', label: m.authz_kind_grant(), desc: m.authz_kind_grant_desc(), icon: '✓', color: 'success' },
		{ k: 'prohibition', label: m.authz_kind_prohibition(), desc: m.authz_kind_prohibition_desc(), icon: '⃠', color: 'error' },
		{ k: 'change_freeze', label: m.authz_kind_freeze(), desc: m.authz_kind_freeze_desc(), icon: '❄', color: 'warning' },
		{ k: 'entity_context', label: m.authz_kind_entity(), desc: m.authz_kind_entity_desc(), icon: '◆', color: 'tertiary' }
	];

	function csv(s: string): string[] {
		return s.split(',').map((v) => v.trim()).filter((v) => v.length > 0);
	}
	function toIso(local: string): string | undefined {
		if (!local) return undefined;
		const d = new Date(local);
		return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
	}

	// Build the wire payload with ONLY the fields legal for the current
	// kind/track/grant_class, and enforce the same required-field rules the
	// server does. Returns {fact} or {error} — never a partial payload.
	function buildFact(): { fact?: Record<string, unknown>; error?: string } {
		const id = mode === 'mssp' ? factId.trim() : `draft-${crypto.randomUUID()}`;
		if (mode === 'mssp' && !id) return { error: m.authz_err_id_required() };

		const scope: Record<string, unknown> = {};
		if (track === 'account') {
			if (subject.trim()) scope.subject = subject.trim();
			if (target.trim()) scope.target = target.trim();
			if (action.trim()) scope.action = action.trim();
		} else {
			if (target.trim()) scope.target = target.trim();
			if (changeType) scope.change_type = changeType;
		}

		const base: Record<string, unknown> = { id, kind, track, scope };
		if (validFrom) base.valid_from = toIso(validFrom);
		if (validUntil) base.valid_until = toIso(validUntil);

		if (kind === 'grant') {
			base.grant_class = grantClass;
			if (grantClass === 'change_ticket') {
				if (!validUntil) return { error: m.authz_err_ticket_needs_until() };
				base.cab_required = cabRequired;
				base.cab_approved = cabApproved;
				base.emergency = emergency;
				base.freeze_exception = freezeException;
			} else if (grantClass === 'routine_observation') {
				const n = parseInt(seenCount, 10);
				if (Number.isNaN(n)) return { error: m.authz_err_routine_needs_seen() };
				base.seen_count = n;
				base.ioc = ioc;
			}
			// standing_baseline carries no extra fields (status stays approved)
			return { fact: base };
		}

		if (kind === 'prohibition') {
			const applies: Record<string, unknown> = {};
			if (track === 'account') {
				if (!forbidAction.trim()) return { error: m.authz_err_prohibition_needs_action() };
				base.forbid_action = forbidAction.trim();
				if (forbidAccountType) base.forbid_account_type = forbidAccountType;
				if (csv(appliesEnv).length) applies.env = csv(appliesEnv);
				if (csv(appliesCriticality).length) applies.criticality = csv(appliesCriticality);
				if (csv(appliesDataClass).length) applies.data_class = csv(appliesDataClass);
			} else {
				if (csv(forbidChangeType).length) base.forbid_change_type = csv(forbidChangeType);
				if (csv(appliesConfigClass).length) applies.config_class = csv(appliesConfigClass);
			}
			if (Object.keys(applies).length) base.applies_to = applies;
			base.priority = priority;
			base.waiver_present = waiverPresent;
			base.break_glass_exception = breakGlassException;
			return { fact: base };
		}

		if (kind === 'change_freeze') {
			const start = toIso(freezeStart);
			const end = toIso(freezeEnd);
			if (!start || !end) return { error: m.authz_err_freeze_needs_window() };
			base.start = start;
			base.end = end;
			const fs: Record<string, unknown> = {};
			if (track === 'account') {
				if (!csv(freezeEnvs).length) return { error: m.authz_err_freeze_account_envs() };
				fs.envs = csv(freezeEnvs);
			} else {
				if (!csv(freezeConfigClasses).length) return { error: m.authz_err_freeze_fim_config() };
				fs.config_classes = csv(freezeConfigClasses);
			}
			base.freeze_scope = fs;
			if (csv(allowedExceptionIds).length) base.allowed_exception_ids = csv(allowedExceptionIds);
			return { fact: base };
		}

		// entity_context
		if (!entityName.trim()) return { error: m.authz_err_entity_needs_name() };
		base.entity_type = entityType;
		base.name = entityName.trim();
		if (environment.trim()) base.environment = environment.trim();
		if (criticality.trim()) base.criticality = criticality.trim();
		if (dataClassification.trim()) base.data_classification = dataClassification.trim();
		if (ownerOrg.trim()) base.owner_org = ownerOrg.trim();
		if (custodianAccount.trim()) base.custodian_account = custodianAccount.trim();
		if (compromiseStatus) base.compromise_status = compromiseStatus;
		if (entityType === 'account') {
			if (accountType) base.account_type = accountType;
			if (privileged) base.privileged = true;
			if (onCall) base.on_call = true;
			if (breakGlass) base.break_glass = true;
			if (serviceOwner.trim()) base.service_owner = serviceOwner.trim();
		}
		if (entityType === 'org' && csv(linkedOrgs).length) base.linked_orgs = csv(linkedOrgs);
		if (entityType === 'watched_path') {
			if (entityConfigClass.trim()) base.config_class = entityConfigClass.trim();
			if (approver.trim()) base.approver = approver.trim();
		}
		return { fact: base };
	}

	// Live preview. Deps are passed as args (ignored) so Svelte's legacy
	// reactivity re-runs on any field change — it does not track vars read only
	// inside the called buildFact().
	function trackDeps(..._deps: unknown[]): string | null {
		const built = buildFact();
		if (built.error || !built.fact) return null;
		try {
			return factSummary(built.fact as never);
		} catch {
			return null;
		}
	}

	$: preview = trackDeps(
		kind, track, factId, subject, target, action, changeType, validFrom, validUntil,
		grantClass, cabRequired, cabApproved, emergency, freezeException, seenCount, ioc,
		forbidAction, forbidAccountType, forbidChangeType, appliesEnv, appliesCriticality,
		appliesDataClass, appliesConfigClass, priority, waiverPresent, breakGlassException,
		freezeStart, freezeEnd, freezeEnvs, freezeConfigClasses, allowedExceptionIds,
		entityType, entityName, environment, criticality, dataClassification, entityConfigClass,
		ownerOrg, custodianAccount, approver, serviceOwner, accountType, privileged, onCall,
		breakGlass, compromiseStatus, linkedOrgs
	);

	function toggleJson() {
		if (!jsonMode) {
			const built = buildFact();
			jsonText = JSON.stringify(built.fact ?? {}, null, 2);
		}
		jsonMode = !jsonMode;
		error = null;
	}

	function submit() {
		error = null;
		if (jsonMode) {
			let parsed: Record<string, unknown>;
			try {
				parsed = JSON.parse(jsonText);
			} catch {
				error = m.authz_err_bad_json();
				return;
			}
			// Server stamps these regardless — strip any hand-edited values so the
			// JSON path keeps the same guarantee as guided mode (and can't 422 on them).
			for (const k of ['source_type', 'trust', 'tenant', 'review_status']) delete parsed[k];
			if (mode === 'mssp' && !String(parsed.id ?? '').trim()) {
				error = m.authz_err_id_required();
				return;
			}
			if (mode === 'tenant') parsed.id = `draft-${crypto.randomUUID()}`;
			dispatch('submit', parsed);
			return;
		}
		const built = buildFact();
		if (built.error || !built.fact) {
			error = built.error ?? m.authz_err_generic();
			return;
		}
		dispatch('submit', built.fact);
	}
</script>

<div class="space-y-4">
	{#if preview}
		<div class="alert variant-soft-primary text-sm">
			<span><strong class="uppercase text-xs opacity-70 mr-2">{m.authz_reads_as()}</strong>{preview}</span>
		</div>
	{/if}

	<!-- Kind picker -->
	<div>
		<span class="text-xs font-semibold opacity-70">{m.authz_kind_label()}</span>
		<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">
			{#each KINDS as kc (kc.k)}
				<button
					type="button"
					class="card p-3 text-left flex gap-3 items-start {kind === kc.k ? 'variant-soft-primary' : 'variant-soft'}"
					on:click={() => (kind = kc.k)}
				>
					<span class="badge-icon variant-soft-{kc.color} shrink-0">{kc.icon}</span>
					<span>
						<span class="font-semibold text-sm block">{kc.label}</span>
						<span class="text-xs opacity-60">{kc.desc}</span>
					</span>
				</button>
			{/each}
		</div>
	</div>

	<!-- Track -->
	<label class="flex flex-col gap-1">
		<span class="text-xs font-semibold opacity-70">{m.authz_track_label()}</span>
		<select class="select" bind:value={track}>
			<option value="account">{m.authz_track_account()}</option>
			<option value="fim">{m.authz_track_fim()}</option>
		</select>
	</label>

	{#if mode === 'mssp'}
		<label class="flex flex-col gap-1">
			<span class="text-xs font-semibold opacity-70">{m.authz_field_id()}</span>
			<input class="input font-mono" bind:value={factId} placeholder="CHG-1001" />
		</label>
	{/if}

	{#if !jsonMode}
		<!-- Scope -->
		<div class="card variant-soft p-3 space-y-3">
			<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_scope_label()}</span>
			{#if track === 'account'}
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_subject()}</span><input class="input" bind:value={subject} placeholder="svc-deploy" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_target_host()}</span><input class="input" bind:value={target} placeholder="db-01" /></label>
				</div>
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_action()}</span><input class="input" bind:value={action} placeholder="sudo-exec" /></label>
			{:else}
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_target_path()}</span><input class="input font-mono" bind:value={target} placeholder="/etc/sudoers*" /></label>
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_change_type()}</span>
					<select class="select" bind:value={changeType}><option>any</option><option>modify</option><option>add</option><option>delete</option></select>
				</label>
			{/if}
		</div>

		<!-- GRANT -->
		{#if kind === 'grant'}
			<div class="card variant-soft p-3 space-y-3">
				<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_grant_label()}</span>
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_grant_class()}</span>
					<select class="select" bind:value={grantClass}>
						<option value="change_ticket">{m.authz_grantclass_ticket()}</option>
						<option value="standing_baseline">{m.authz_grantclass_baseline()}</option>
						<option value="routine_observation">{m.authz_grantclass_routine()}</option>
					</select>
				</label>
				{#if grantClass === 'change_ticket'}
					<div class="flex flex-wrap gap-4 text-sm">
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={cabRequired} />{m.authz_field_cab_required()}</label>
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={cabApproved} />{m.authz_field_cab_approved()}</label>
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={emergency} />{m.authz_field_emergency()}</label>
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={freezeException} />{m.authz_field_freeze_exception()}</label>
					</div>
				{:else if grantClass === 'routine_observation'}
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_seen_count()}</span><input class="input" type="number" min="0" bind:value={seenCount} /></label>
						<label class="flex items-center gap-2 mt-6 text-sm"><input type="checkbox" class="checkbox" bind:checked={ioc} />{m.authz_field_ioc()}</label>
					</div>
				{/if}
			</div>
		{/if}

		<!-- PROHIBITION -->
		{#if kind === 'prohibition'}
			<div class="card variant-soft p-3 space-y-3">
				<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_prohibition_label()}</span>
				{#if track === 'account'}
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_forbid_action()}</span><input class="input" bind:value={forbidAction} placeholder="interactive-shell" /></label>
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_forbid_account_type()}</span>
							<select class="select" bind:value={forbidAccountType}><option value="">{m.authz_any()}</option><option value="service">service</option><option value="human">human</option></select>
						</label>
					</div>
					<div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_applies_env()}</span><input class="input" bind:value={appliesEnv} placeholder="prod, staging" /></label>
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_applies_criticality()}</span><input class="input" bind:value={appliesCriticality} placeholder="high" /></label>
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_applies_data_class()}</span><input class="input" bind:value={appliesDataClass} placeholder="pci" /></label>
					</div>
				{:else}
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_forbid_change_type()}</span><input class="input font-mono" bind:value={forbidChangeType} placeholder="modify, delete" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_applies_config_class()}</span><input class="input" bind:value={appliesConfigClass} placeholder="kernel, sudoers" /></label>
				{/if}
				<div class="flex flex-wrap gap-4 text-sm items-center">
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_priority()}</span>
						<select class="select select-sm" bind:value={priority}><option>high</option><option>medium</option><option>low</option></select>
					</label>
					<label class="flex items-center gap-2 mt-4"><input type="checkbox" class="checkbox" bind:checked={waiverPresent} />{m.authz_field_waiver()}</label>
					<label class="flex items-center gap-2 mt-4"><input type="checkbox" class="checkbox" bind:checked={breakGlassException} />{m.authz_field_break_glass_exc()}</label>
				</div>
			</div>
		{/if}

		<!-- CHANGE FREEZE -->
		{#if kind === 'change_freeze'}
			<div class="card variant-soft p-3 space-y-3">
				<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_freeze_label()}</span>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_start()}</span><input class="input" type="datetime-local" bind:value={freezeStart} /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_end()}</span><input class="input" type="datetime-local" bind:value={freezeEnd} /></label>
				</div>
				{#if track === 'account'}
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_freeze_envs()}</span><input class="input" bind:value={freezeEnvs} placeholder="prod" /></label>
				{:else}
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_freeze_config()}</span><input class="input" bind:value={freezeConfigClasses} placeholder="kernel, sudoers" /></label>
				{/if}
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_exceptions()}</span><input class="input font-mono" bind:value={allowedExceptionIds} placeholder="CHG-1001, CHG-1044" /></label>
			</div>
		{/if}

		<!-- ENTITY CONTEXT -->
		{#if kind === 'entity_context'}
			<div class="card variant-soft p-3 space-y-3">
				<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_entity_label()}</span>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_entity_type()}</span>
						<select class="select" bind:value={entityType}><option>asset</option><option>account</option><option>watched_path</option><option>org</option></select>
					</label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_entity_name()}</span><input class="input" bind:value={entityName} placeholder="db-01" /></label>
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_environment()}</span><input class="input" bind:value={environment} placeholder="prod" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_criticality()}</span><input class="input" bind:value={criticality} placeholder="high" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_data_class()}</span><input class="input" bind:value={dataClassification} placeholder="pci" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_owner_org()}</span><input class="input" bind:value={ownerOrg} placeholder="Payments" /></label>
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_compromise()}</span>
						<select class="select" bind:value={compromiseStatus}><option value="">{m.authz_unset()}</option><option>clean</option><option>suspected</option><option>compromised</option><option>contained</option></select>
					</label>
				</div>
				{#if entityType === 'account'}
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 border-t border-surface-500/30 pt-3">
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_account_type()}</span>
							<select class="select" bind:value={accountType}><option value="">{m.authz_unset()}</option><option>service</option><option>human</option></select>
						</label>
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_service_owner()}</span><input class="input" bind:value={serviceOwner} /></label>
					</div>
					<div class="flex flex-wrap gap-4 text-sm">
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={privileged} />{m.authz_field_privileged()}</label>
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={onCall} />{m.authz_field_on_call()}</label>
						<label class="flex items-center gap-2"><input type="checkbox" class="checkbox" bind:checked={breakGlass} />{m.authz_field_break_glass()}</label>
					</div>
				{:else if entityType === 'org'}
					<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_linked_orgs()}</span><input class="input" bind:value={linkedOrgs} placeholder="acme-eu, acme-us" /></label>
				{:else if entityType === 'watched_path'}
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_config_class()}</span><input class="input" bind:value={entityConfigClass} placeholder="sudoers" /></label>
						<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_approver()}</span><input class="input" bind:value={approver} /></label>
					</div>
				{/if}
			</div>
		{/if}

		<!-- Validity -->
		<div class="card variant-soft p-3 space-y-3">
			<span class="text-xs font-semibold opacity-70 uppercase">{m.authz_validity_label()}</span>
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_valid_from()}</span><input class="input" type="date" bind:value={validFrom} /></label>
				<label class="flex flex-col gap-1"><span class="text-xs opacity-70">{m.authz_field_valid_until()}{#if kind === 'grant' && grantClass === 'change_ticket'} <span class="text-error-400">*</span>{/if}</span><input class="input" type="date" bind:value={validUntil} /></label>
			</div>
			<p class="text-xs opacity-60">{mode === 'mssp' ? m.authz_source_note_mssp() : m.authz_source_note_tenant()}</p>
		</div>
	{:else}
		<textarea class="textarea font-mono text-xs h-96" bind:value={jsonText}></textarea>
	{/if}

	{#if error}
		<div class="alert variant-filled-error text-sm"><span>{error}</span></div>
	{/if}

	<div class="flex justify-between items-center gap-2">
		<button type="button" class="btn btn-sm variant-soft" on:click={toggleJson}>
			{jsonMode ? m.authz_form_view() : m.authz_json_view()}
		</button>
		<div class="flex gap-2">
			<button type="button" class="btn variant-soft" on:click={() => dispatch('cancel')} disabled={saving}>{m.common_cancel()}</button>
			<button type="button" class="btn variant-filled-primary" on:click={submit} disabled={saving}>
				{saving ? m.common_saving() : mode === 'mssp' ? m.authz_create() : m.authz_assert()}
			</button>
		</div>
	</div>
</div>
