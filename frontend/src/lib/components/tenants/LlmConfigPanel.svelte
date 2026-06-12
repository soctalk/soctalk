<script lang="ts">
	import { onMount } from 'svelte';
	import { tenantsApi, type TenantLlmRead, type TenantLlmUpdate } from '$lib/api/tenants';
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
		api_key: string;
	}

	let formData: LlmForm = {
		provider: 'openai-compatible',
		base_url: '',
		model: '',
		fast_model: '',
		reasoning_model: '',
		api_key: ''
	};
	let formError: string | null = null;

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
			api_key: ''
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
			if (formData.api_key) payload.api_key = formData.api_key;

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
