<script lang="ts">
	import { onMount } from 'svelte';
	import {
		tenantsApi,
		type TenantLlmRead,
		type TenantLlmUpdate,
		type TenantLlmTierRead,
		type TenantLlmTierWrite,
		type LlmDecodingMode
	} from '$lib/api/tenants';
	import { addToast } from '$lib/stores';

	// MSSP-side LLM configuration panel for the tenant detail page. Shows the
	// masked config (GET .../llm — the plaintext key is NEVER returned, only
	// has_api_key + an api_key_preview tail) and offers an in-place edit form
	// that PATCHes only the fields the operator actually changed. A blank
	// "Replace API key" field means "leave unchanged" — the api_key field is
	// OMITTED from the payload entirely. Clearing the key (DELETE .../llm/api-key)
	// requires an inline confirm step.
	//
	// SECURITY: the key value must never reach toasts, console logs, or any
	// non-password input — only the masked preview from the server is rendered.
	export let tenantId: string;

	let read: TenantLlmRead | null = null;
	let readError: string | null = null;
	let loadingRead = true;

	let collapsed = false;
	let editing = false;
	let saving = false;

	// Inline confirm step for the destructive clear-key action.
	let confirmingClear = false;
	let clearing = false;

	interface LlmForm {
		provider: string;
		base_url: string;
		model: string;
		// Per-tier overrides — '' in the form means "no override" (the tier
		// falls back to the primary model).
		fast_model: string;
		reasoning_model: string;
		// Tenant-global default sampling for the router/supervisor tier. Kept as
		// strings so an emptied input can be validated before coercion.
		temperature: string;
		max_tokens: string;
		api_key: string;
	}

	let formData: LlmForm = {
		provider: 'openai-compatible',
		base_url: '',
		model: '',
		fast_model: '',
		reasoning_model: '',
		temperature: '',
		max_tokens: '',
		api_key: ''
	};
	let formError: string | null = null;

	// --- Per-tier "model chain" editor (issue #12 / #4) -----------------
	// A hybrid tenant routes the fast (router) and/or reasoning (verdict)
	// tier to a DEDICATED backend — its own provider/base_url/model/engine/
	// decoding + optional own key — instead of the primary provider. When a
	// tier has a dedicated backend it supersedes the simple fast/thinking
	// model override above (the tier's own model wins at render time).
	const TIER_KEYS = ['fast', 'reasoning'] as const;
	type TierKey = (typeof TIER_KEYS)[number];
	const TIER_LABELS: Record<TierKey, string> = {
		fast: 'Fast / router',
		reasoning: 'Reasoning / verdict'
	};
	const DECODING_MODES: LlmDecodingMode[] = [
		'auto',
		'none',
		'tool_use',
		'json_schema_strict',
		'json_object',
		'guided_json',
		'guided_grammar'
	];

	interface TierForm {
		enabled: boolean;
		provider: 'openai-compatible' | 'anthropic';
		base_url: string;
		model: string;
		engine: '' | 'frontier' | 'openai_compatible' | 'vllm' | 'sglang';
		decoding_mode: '' | LlmDecodingMode;
		// Whether a key is already stored for this tier (from the sanitized read).
		has_api_key: boolean;
		// New key input — blank = keep the stored key (keep/replace/clear).
		api_key: string;
		// Explicit "reuse the primary credential" — clears the tier's own key.
		clear_key: boolean;
	}

	function blankTier(): TierForm {
		return {
			enabled: false,
			provider: 'openai-compatible',
			base_url: '',
			model: '',
			engine: '',
			decoding_mode: '',
			has_api_key: false,
			api_key: '',
			clear_key: false
		};
	}

	let tierForms: Record<TierKey, TierForm> = {
		fast: blankTier(),
		reasoning: blankTier()
	};

	function seedTier(r: TenantLlmTierRead | undefined): TierForm {
		if (!r) return blankTier();
		return {
			enabled: true,
			provider: (r.provider as TierForm['provider']) ?? 'openai-compatible',
			base_url: r.base_url ?? '',
			model: r.model ?? '',
			engine: (r.engine as TierForm['engine']) ?? '',
			decoding_mode: (r.decoding_mode as LlmDecodingMode) ?? '',
			has_api_key: r.has_api_key,
			api_key: '',
			clear_key: false
		};
	}

	// A tier's backend differs from the stored read (structural OR key touched).
	function tierDiffers(f: TierForm, r: TenantLlmTierRead | undefined): boolean {
		if (!r) return true; // newly enabled
		return (
			f.provider !== r.provider ||
			f.base_url.trim() !== (r.base_url ?? '') ||
			f.model.trim() !== (r.model ?? '') ||
			(f.engine || null) !== (r.engine ?? null) ||
			(f.decoding_mode || null) !== (r.decoding_mode ?? null) ||
			!!f.api_key.trim() ||
			f.clear_key
		);
	}

	// Build the tiers half of the PATCH: ``undefined`` = omit (unchanged),
	// ``{}`` = clear back to single-provider, a map = replace (backend merges
	// per-tier keys via keep/replace/clear).
	function buildTiers(): Record<string, TenantLlmTierWrite> | undefined {
		const readTiers = read?.tiers ?? null;
		const readEnabled = readTiers ? Object.keys(readTiers) : [];
		const enabled = TIER_KEYS.filter((k) => tierForms[k].enabled);
		let changed =
			enabled.length !== readEnabled.length || enabled.some((k) => !readEnabled.includes(k));
		for (const k of enabled) {
			if (tierDiffers(tierForms[k], readTiers?.[k])) changed = true;
		}
		if (!changed) return undefined;
		if (enabled.length === 0) return readTiers ? {} : undefined;
		const out: Record<string, TenantLlmTierWrite> = {};
		for (const k of enabled) {
			const f = tierForms[k];
			const t: TenantLlmTierWrite = {
				provider: f.provider,
				base_url: f.base_url.trim(),
				model: f.model.trim()
			};
			if (f.engine) t.engine = f.engine;
			if (f.decoding_mode) t.decoding_mode = f.decoding_mode;
			// Key: a typed value replaces; an explicit clear sends ''; otherwise
			// omit so the backend carries the stored key forward. Trim so a
			// whitespace-only entry is treated as "no new key" (keep), matching
			// the backend's whitespace = clear/keep handling rather than sending
			// blanks that silently clear a same-provider tier's own key.
			const newKey = f.api_key.trim();
			if (newKey) t.api_key_plain = newKey;
			else if (f.clear_key) t.api_key_plain = '';
			out[k] = t;
		}
		return out;
	}

	async function loadRead(): Promise<void> {
		loadingRead = true;
		readError = null;
		try {
			read = await tenantsApi.getLlm(tenantId);
		} catch (e) {
			readError = e instanceof Error ? e.message : 'Failed to load LLM configuration';
		} finally {
			loadingRead = false;
		}
	}

	function toggleCollapsed(): void {
		collapsed = !collapsed;
	}

	function startEdit(): void {
		// Seed the form from the masked read. The key field stays blank — a blank
		// key means "leave unchanged" so we never round-trip a placeholder.
		formData = {
			provider: read?.provider ?? 'openai-compatible',
			base_url: read?.base_url ?? '',
			model: read?.model ?? '',
			// null (no override) seeds as '' — emptying a previously-set input
			// later diffs as a clear ('' sent), while staying empty is unchanged.
			fast_model: read?.fast_model ?? '',
			reasoning_model: read?.reasoning_model ?? '',
			temperature: read != null ? String(read.temperature) : '',
			max_tokens: read != null ? String(read.max_tokens) : '',
			api_key: ''
		};
		// Seed the per-tier chain editor from the sanitized read.tiers map.
		tierForms = {
			fast: seedTier(read?.tiers?.fast),
			reasoning: seedTier(read?.tiers?.reasoning)
		};
		formError = null;
		editing = true;
	}

	function cancelEdit(): void {
		editing = false;
		formData = { ...formData, api_key: '' };
		formError = null;
	}

	async function save(): Promise<void> {
		formError = null;
		const baseUrl = formData.base_url.trim();
		if (baseUrl && !/^https?:\/\//.test(baseUrl)) {
			formError = 'Base URL must start with http:// or https://';
			return;
		}
		// Tenant-global sampling bounds (mirror the backend + chart schema). Both
		// fields are required — they always carry a value (the read seeds the
		// current setting), so a blank is an explicit clear with no meaning; treat
		// it as an error rather than silently no-op'ing the edit.
		const tempStr = formData.temperature.trim();
		if (tempStr === '') {
			formError = 'Temperature is required (0–2)';
			return;
		}
		const t = Number(tempStr);
		if (!Number.isFinite(t) || t < 0 || t > 2) {
			formError = 'Temperature must be a number between 0 and 2';
			return;
		}
		const maxTokStr = formData.max_tokens.trim();
		if (maxTokStr === '') {
			formError = 'Max tokens is required (1–8192)';
			return;
		}
		const m = Number(maxTokStr);
		if (!Number.isInteger(m) || m < 1 || m > 8192) {
			formError = 'Max tokens must be a whole number between 1 and 8192';
			return;
		}
		// Validate each enabled tier before building the payload — surface the
		// error inline rather than round-tripping to a backend 422 toast.
		for (const k of TIER_KEYS) {
			const f = tierForms[k];
			if (!f.enabled) continue;
			if (!/^https?:\/\//.test(f.base_url.trim())) {
				formError = `${TIER_LABELS[k]} tier: base URL must start with http:// or https://`;
				return;
			}
			if (!f.model.trim()) {
				formError = `${TIER_LABELS[k]} tier: model is required`;
				return;
			}
			// A tier on a different provider than the primary must carry its own
			// key (the tenant mounts only the primary credential). Catch it here
			// with an actionable message; the backend enforces it too (422).
			const primary = formData.provider;
			const crossProvider = f.provider !== primary;
			const willHaveKey = f.api_key.trim() ? true : f.clear_key ? false : f.has_api_key;
			if (crossProvider && !willHaveKey) {
				formError = `${TIER_LABELS[k]} tier is on a different provider (${f.provider}) than the primary (${primary}) and needs its own API key`;
				return;
			}
		}
		saving = true;
		try {
			// Changed-fields-only patch: compare against the current read and only
			// send what the operator actually edited. A blank api_key is OMITTED
			// (never sent) so the stored secret is preserved.
			const payload: TenantLlmUpdate = {};
			if (read && formData.provider !== read.provider) {
				payload.provider = formData.provider as TenantLlmUpdate['provider'];
			}
			if (read && baseUrl !== read.base_url) payload.base_url = baseUrl;
			if (read && formData.model !== read.model) payload.model = formData.model;
			// Tri-state per-tier overrides: compare against ``read.x ?? ''`` so an
			// empty input over a null read is "unchanged" (omitted), not a
			// spurious clear. A real clear (input emptied over a set override)
			// sends '' so the backend NULLs the column; a set sends the trimmed
			// value.
			const fastModel = formData.fast_model.trim();
			if (read && fastModel !== (read.fast_model ?? '')) payload.fast_model = fastModel;
			const reasoningModel = formData.reasoning_model.trim();
			if (read && reasoningModel !== (read.reasoning_model ?? '')) {
				payload.reasoning_model = reasoningModel;
			}
			// Tenant-global sampling — send only when changed from the read.
			if (read && tempStr !== '' && Number(tempStr) !== read.temperature) {
				payload.temperature = Number(tempStr);
			}
			if (read && maxTokStr !== '' && Number(maxTokStr) !== read.max_tokens) {
				payload.max_tokens = Number(maxTokStr);
			}
			if (formData.api_key) payload.api_key = formData.api_key;

			// Per-tier chain: undefined = omit (unchanged), {} = clear, map = replace.
			const tiersPayload = buildTiers();
			if (tiersPayload !== undefined) payload.tiers = tiersPayload;

			if (Object.keys(payload).length === 0) {
				// Nothing changed — close the form without a no-op PATCH.
				editing = false;
				return;
			}

			read = await tenantsApi.updateLlm(tenantId, payload);
			editing = false;
			formData = { ...formData, api_key: '' };
			addToast({
				type: 'success',
				title: 'LLM configuration',
				message: 'Configuration updated'
			});
		} catch (e) {
			addToast({
				type: 'error',
				title: 'LLM configuration',
				message: e instanceof Error ? e.message : String(e)
			});
		} finally {
			saving = false;
		}
	}

	async function clearKey(): Promise<void> {
		clearing = true;
		try {
			await tenantsApi.clearLlmKey(tenantId);
			confirmingClear = false;
			addToast({
				type: 'success',
				title: 'LLM configuration',
				message: 'Tenant API key cleared — using MSSP shared install key'
			});
			await loadRead(); // re-fetch the masked state (has_api_key now false)
		} catch (e) {
			addToast({
				type: 'error',
				title: 'LLM configuration',
				message: e instanceof Error ? e.message : String(e)
			});
		} finally {
			clearing = false;
		}
	}

	onMount(() => {
		void loadRead();
	});
</script>

<div class="card p-4" data-testid="llm-config-panel">
	<div class="flex items-center justify-between mb-4">
		<button
			class="h4 flex items-center gap-2"
			data-testid="llm-collapse-toggle"
			on:click={toggleCollapsed}
			aria-expanded={!collapsed}
		>
			<span class="opacity-60">{collapsed ? '▸' : '▾'}</span>
			LLM Configuration
		</button>
		{#if !collapsed && !editing && !loadingRead}
			<button class="btn btn-sm variant-soft-primary" data-testid="llm-edit" on:click={startEdit}>
				Edit
			</button>
		{/if}
	</div>

	{#if !collapsed}
		{#if loadingRead}
			<div class="flex items-center gap-3 text-sm opacity-70">
				<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
				<span>Loading…</span>
			</div>
		{:else if readError}
			<div class="text-error-500 text-sm" data-testid="llm-error">{readError}</div>
		{:else if editing}
			<!-- In-place edit form — changed-fields-only PATCH; blank key = keep. -->
			<form class="space-y-4" on:submit|preventDefault={save} data-testid="llm-edit-form">
				<label class="label">
					<span class="text-sm">Provider</span>
					<select name="provider" class="select" bind:value={formData.provider}>
						<option value="openai-compatible">OpenAI-compatible</option>
						<option value="anthropic">Anthropic</option>
					</select>
				</label>
				<label class="label">
					<span class="text-sm">Base URL</span>
					<input
						name="base_url"
						class="input"
						bind:value={formData.base_url}
						placeholder="https://api.openai.com/v1"
					/>
				</label>
				{#if formError}
					<div class="text-error-500 text-sm" data-testid="llm-form-error">{formError}</div>
				{/if}
				<label class="label">
					<span class="text-sm">Model</span>
					<input name="model" class="input" bind:value={formData.model} placeholder="gpt-4o" />
				</label>
				<label class="label">
					<span class="text-sm">Fast model</span>
					<input
						name="fast_model"
						class="input"
						bind:value={formData.fast_model}
						placeholder="leave blank to use the primary model"
					/>
					<span class="text-xs opacity-60">leave blank to use the primary model</span>
				</label>
				<label class="label">
					<span class="text-sm">Thinking model</span>
					<input
						name="reasoning_model"
						class="input"
						bind:value={formData.reasoning_model}
						placeholder="leave blank to use the primary model"
					/>
					<span class="text-xs opacity-60">leave blank to use the primary model</span>
				</label>
				<div class="grid grid-cols-1 md:grid-cols-2 gap-3" data-testid="llm-sampling">
					<label class="label">
						<span class="text-sm">Temperature</span>
						<input
							name="temperature"
							class="input"
							type="text"
							inputmode="decimal"
							bind:value={formData.temperature}
							placeholder="0.0"
						/>
						<span class="text-xs opacity-60">router sampling, 0–2</span>
					</label>
					<label class="label">
						<span class="text-sm">Max tokens</span>
						<input
							name="max_tokens"
							class="input"
							type="text"
							inputmode="numeric"
							bind:value={formData.max_tokens}
							placeholder="4096"
						/>
						<span class="text-xs opacity-60">router output cap, 1–8192</span>
					</label>
				</div>
				<label class="label">
					<span class="text-sm">Replace API key</span>
					<input
						name="api_key"
						type="password"
						class="input"
						placeholder="leave blank to keep"
						autocomplete="off"
						bind:value={formData.api_key}
					/>
				</label>

				<!-- Per-tier "model chain" editor: route the fast (router) and/or
				     reasoning (verdict) tier to a dedicated backend. -->
				<div class="pt-3 border-t border-surface-500/20" data-testid="llm-chain-editor">
					<div class="text-sm font-semibold">Model chain (advanced)</div>
					<p class="text-xs opacity-60 mb-3">
						Route a tier to a dedicated backend — e.g. a cheap self-hosted router
						feeding a frontier reasoning model. A dedicated backend supersedes the
						matching model override above.
					</p>
					{#each TIER_KEYS as tk}
						<div class="mb-3 rounded border border-surface-500/20 p-3" data-testid={`llm-tier-${tk}`}>
							<label class="flex items-center gap-2">
								<input
									type="checkbox"
									class="checkbox"
									data-testid={`llm-tier-${tk}-enabled`}
									bind:checked={tierForms[tk].enabled}
								/>
								<span class="text-sm font-medium">{TIER_LABELS[tk]}</span>
								<span class="text-xs opacity-60">dedicated backend</span>
							</label>
							{#if tierForms[tk].enabled}
								<div class="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
									<label class="label">
										<span class="text-xs">Provider</span>
										<select
											class="select select-sm"
											data-testid={`llm-tier-${tk}-provider`}
											bind:value={tierForms[tk].provider}
										>
											<option value="openai-compatible">OpenAI-compatible</option>
											<option value="anthropic">Anthropic</option>
										</select>
									</label>
									<label class="label">
										<span class="text-xs">Engine</span>
										<select
											class="select select-sm"
											data-testid={`llm-tier-${tk}-engine`}
											bind:value={tierForms[tk].engine}
										>
											<option value="">auto</option>
											<option value="frontier">frontier</option>
											<option value="openai_compatible">openai_compatible</option>
											<option value="vllm">vllm</option>
											<option value="sglang">sglang</option>
										</select>
									</label>
									<label class="label md:col-span-2">
										<span class="text-xs">Base URL</span>
										<input
											class="input"
											data-testid={`llm-tier-${tk}-base-url`}
											bind:value={tierForms[tk].base_url}
											placeholder="http://sglang.internal:8000/v1"
										/>
									</label>
									<label class="label">
										<span class="text-xs">Model</span>
										<input
											class="input"
											data-testid={`llm-tier-${tk}-model`}
											bind:value={tierForms[tk].model}
											placeholder="qwen3-32b"
										/>
									</label>
									<label class="label">
										<span class="text-xs">Decoding mode</span>
										<select
											class="select select-sm"
											data-testid={`llm-tier-${tk}-decoding`}
											bind:value={tierForms[tk].decoding_mode}
										>
											<option value="">auto (resolver picks)</option>
											{#each DECODING_MODES as dm}
												<option value={dm}>{dm}</option>
											{/each}
										</select>
									</label>
									<label class="label md:col-span-2">
										<span class="text-xs">
											{tierForms[tk].has_api_key ? 'Replace tier API key' : 'Tier API key'}
										</span>
										<input
											type="password"
											class="input"
											data-testid={`llm-tier-${tk}-api-key`}
											autocomplete="off"
											placeholder={tierForms[tk].has_api_key
												? 'leave blank to keep'
												: 'blank = reuse the primary credential'}
											bind:value={tierForms[tk].api_key}
											disabled={tierForms[tk].clear_key}
										/>
										{#if tierForms[tk].has_api_key}
											<label class="flex items-center gap-2 mt-1">
												<input
													type="checkbox"
													class="checkbox"
													data-testid={`llm-tier-${tk}-clear-key`}
													bind:checked={tierForms[tk].clear_key}
												/>
												<span class="text-xs opacity-70">
													Clear the tier key — reuse the primary credential
												</span>
											</label>
										{/if}
									</label>
								</div>
							{/if}
						</div>
					{/each}
				</div>
				<div class="flex gap-2">
					<button
						type="submit"
						class="btn btn-sm variant-filled-primary"
						data-testid="llm-save"
						disabled={saving}
					>
						{#if saving}
							<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
						{/if}
						Save
					</button>
					<button
						type="button"
						class="btn btn-sm variant-ghost-surface"
						data-testid="llm-cancel"
						on:click={cancelEdit}
						disabled={saving}
					>
						Cancel
					</button>
				</div>
			</form>
		{:else if read}
			<!-- Read view — masked; only the server-provided key preview is shown. -->
			<dl class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-sm">
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Provider</dt>
					<dd data-testid="llm-provider">{read.provider || '—'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Base URL</dt>
					<dd class="font-mono text-xs text-right break-all" data-testid="llm-base-url">
						{read.base_url || '—'}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Model</dt>
					<dd class="font-mono text-xs" data-testid="llm-model">{read.model || '—'}</dd>
				</div>
				<!-- Per-tier overrides — when unset (null) the effective model is the
				     primary one, rendered as "default (<model>)" so the operator
				     always sees what will actually be used. -->
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Fast model</dt>
					<dd class="font-mono text-xs" data-testid="llm-fast-model">
						{read.fast_model ?? `default (${read.model})`}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Thinking model</dt>
					<dd class="font-mono text-xs" data-testid="llm-reasoning-model">
						{read.reasoning_model ?? `default (${read.model})`}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Temperature</dt>
					<dd class="font-mono text-xs" data-testid="llm-temperature">{read.temperature}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">Max tokens</dt>
					<dd class="font-mono text-xs" data-testid="llm-max-tokens">{read.max_tokens}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">API key</dt>
					<dd data-testid="llm-api-key-state">
						{#if read.has_api_key}
							<span class="font-mono text-xs" data-testid="llm-api-key-preview">
								{read.api_key_preview}
							</span>
						{:else}
							<span class="opacity-70" data-testid="llm-shared-key-note">
								using MSSP shared install key
							</span>
						{/if}
					</dd>
				</div>
			</dl>

			{#if read.tiers}
				<!-- Per-tier "model chain" read view — one row per dedicated backend. -->
				<div class="mt-4 pt-3 border-t border-surface-500/20" data-testid="llm-chain-view">
					<div class="text-sm font-semibold mb-2">Model chain</div>
					<div class="space-y-2">
						{#each TIER_KEYS as tk}
							{#if read.tiers[tk]}
								<div class="rounded border border-surface-500/20 p-2 text-xs" data-testid={`llm-chain-${tk}`}>
									<div class="font-medium opacity-80">{TIER_LABELS[tk]}</div>
									<div class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1 mt-1 font-mono">
										<div><span class="opacity-60">provider</span> {read.tiers[tk].provider ?? '—'}</div>
										<div><span class="opacity-60">engine</span> {read.tiers[tk].engine ?? 'auto'}</div>
										<div class="md:col-span-2 break-all"><span class="opacity-60">base</span> {read.tiers[tk].base_url ?? '—'}</div>
										<div><span class="opacity-60">model</span> {read.tiers[tk].model ?? '—'}</div>
										<div><span class="opacity-60">decoding</span> {read.tiers[tk].decoding_mode ?? 'auto'}</div>
										<div class="md:col-span-2">
											<span class="opacity-60">key</span>
											{read.tiers[tk].has_api_key ? 'own key' : 'reuses primary'}
										</div>
									</div>
								</div>
							{/if}
						{/each}
					</div>
				</div>
			{/if}

			{#if read.has_api_key}
				<div class="mt-3">
					{#if confirmingClear}
						<div class="flex items-center gap-2" data-testid="llm-clear-key-confirm-row">
							<span class="text-sm">
								Clear the tenant API key and fall back to the MSSP shared install key?
							</span>
							<button
								class="btn btn-sm variant-filled-error"
								data-testid="llm-clear-key-confirm"
								on:click={clearKey}
								disabled={clearing}
							>
								{#if clearing}
									<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
								{/if}
								Confirm clear
							</button>
							<button
								class="btn btn-sm variant-ghost-surface"
								data-testid="llm-clear-key-cancel"
								on:click={() => (confirmingClear = false)}
								disabled={clearing}
							>
								Cancel
							</button>
						</div>
					{:else}
						<button
							class="btn btn-sm variant-soft-error"
							data-testid="llm-clear-key"
							on:click={() => (confirmingClear = true)}
						>
							Clear API key
						</button>
					{/if}
				</div>
			{/if}

			<!-- Rollout semantics so operators know what to expect after Save. -->
			<p class="mt-4 pt-3 border-t border-surface-500/20 text-xs opacity-70" data-testid="llm-rollout-note">
				Provider, endpoint or model changes (including fast/thinking model overrides) roll out
				via a re-render of the tenant release; key-only changes apply within seconds.
			</p>
		{/if}
	{/if}
</div>
