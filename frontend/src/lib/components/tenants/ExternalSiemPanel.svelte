<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import {
		tenantsApi,
		type ExternalSiemRead,
		type ExternalSiemUpdate,
		type AdapterStatus,
		type IngestSettings
	} from '$lib/api/tenants';
	import { addToast } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';

	// Profile-agnostic External SIEM panel for the tenant detail page. Shows the
	// masked connection (GET .../external-siem), polls live adapter ingest status
	// (GET .../adapter-status, server-side proxied), and offers an in-place edit
	// form that PATCHes both credential pairs.
	//
	// Polling lifecycle: an interval fires every POLL_MS, but the fetch is SKIPPED
	// (paused) while the panel is collapsed OR the page/tab is hidden
	// (document.visibilityState). The interval is cleared on unmount so navigating
	// away stops polling entirely. Expanding the panel or the tab regaining focus
	// triggers an immediate catch-up poll.
	export let tenantId: string;

	const POLL_MS = 10_000;

	let read: ExternalSiemRead | null = null;
	let readError: string | null = null;
	let loadingRead = true;

	let status: AdapterStatus | null = null;
	let statusError: string | null = null;

	let collapsed = false;
	let editing = false;
	let saving = false;

	interface SiemForm {
		indexer_url: string;
		indexer_username: string;
		indexer_password: string;
		api_url: string;
		api_username: string;
		api_password: string;
		api_token: string;
		verify_ssl: boolean;
		// Ingest settings; ``ingest_start`` drives ``initial_ts`` ('now' |
		// '' for a full backfill | a custom UTC instant). Editing the start
		// point never rewinds an established adapter checkpoint.
		ingest_start: 'now' | 'all' | 'custom';
		ingest_initial_ts: string;
		exclude_manager_agent: boolean;
		agent_prefix: string;
		min_severity: string;
	}

	function blankForm(): SiemForm {
		return {
			indexer_url: '',
			indexer_username: '',
			indexer_password: '',
			api_url: '',
			api_username: '',
			api_password: '',
			api_token: '',
			verify_ssl: true,
			ingest_start: 'all',
			ingest_initial_ts: '',
			exclude_manager_agent: false,
			agent_prefix: '',
			min_severity: ''
		};
	}

	function toIngest(f: SiemForm): IngestSettings {
		const initial_ts =
			f.ingest_start === 'now' ? 'now' : f.ingest_start === 'custom' ? f.ingest_initial_ts.trim() : null;
		const sev = f.min_severity.trim();
		return {
			exclude_manager_agent: f.exclude_manager_agent,
			initial_ts: initial_ts || null,
			agent_prefix: f.agent_prefix.trim() || null,
			min_severity: sev === '' ? null : Number(sev)
		};
	}

	let formData: SiemForm = blankForm();

	let pollTimer: ReturnType<typeof setInterval> | null = null;

	async function loadRead(): Promise<void> {
		loadingRead = true;
		readError = null;
		try {
			read = await tenantsApi.getExternalSiem(tenantId);
		} catch (e) {
			readError = e instanceof Error ? e.message : m.ten_siem_load_failed();
		} finally {
			loadingRead = false;
		}
	}

	async function pollStatus(): Promise<void> {
		// Pause (skip the network call) when collapsed or the page is hidden.
		if (collapsed) return;
		if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
		try {
			status = await tenantsApi.getAdapterStatus(tenantId);
			statusError = null;
		} catch (e) {
			statusError = e instanceof Error ? e.message : 'status unavailable';
		}
	}

	function startPolling(): void {
		if (pollTimer !== null) return;
		void pollStatus(); // immediate first poll
		pollTimer = setInterval(() => void pollStatus(), POLL_MS);
	}

	function stopPolling(): void {
		if (pollTimer !== null) {
			clearInterval(pollTimer);
			pollTimer = null;
		}
	}

	function onVisibilityChange(): void {
		if (typeof document === 'undefined') return;
		if (document.visibilityState === 'visible' && !collapsed) {
			void pollStatus(); // resume promptly on tab focus
		}
	}

	function toggleCollapsed(): void {
		collapsed = !collapsed;
		if (!collapsed) void pollStatus(); // resume promptly on expand
	}

	function startEdit(): void {
		// Seed the form from the masked read. Secret fields stay blank — a blank
		// secret means "leave unchanged" so we never round-trip a placeholder.
		formData = {
			indexer_url: read?.indexer_url ?? '',
			indexer_username: read?.indexer_username ?? '',
			indexer_password: '',
			api_url: read?.api_url ?? '',
			api_username: read?.api_username ?? '',
			api_password: '',
			api_token: '',
			verify_ssl: read?.verify_ssl ?? true,
			// Seed the ingest block from the stored settings, showing the
			// effective manager-agent choice so the checkbox reflects what the
			// adapter actually does when the column is unset.
			ingest_start: read?.ingest?.initial_ts ? 'custom' : 'all',
			ingest_initial_ts: read?.ingest?.initial_ts ?? '',
			exclude_manager_agent: read?.ingest?.effective_exclude_manager_agent ?? false,
			agent_prefix: read?.ingest?.agent_prefix ?? '',
			min_severity: read?.ingest?.min_severity == null ? '' : String(read.ingest.min_severity)
		};
		editing = true;
	}

	function cancelEdit(): void {
		editing = false;
	}

	async function save(): Promise<void> {
		saving = true;
		try {
			const payload: ExternalSiemUpdate = {
				indexer_url: formData.indexer_url || null,
				indexer_username: formData.indexer_username || null,
				api_url: formData.api_url || null,
				api_username: formData.api_username || null,
				verify_ssl: formData.verify_ssl,
				ingest: toIngest(formData)
			};
			// Only send a secret when the operator typed a new value; a blank field
			// leaves the stored credential untouched (the read never echoes it).
			if (formData.indexer_password) payload.indexer_password = formData.indexer_password;
			if (formData.api_password) payload.api_password = formData.api_password;
			if (formData.api_token) payload.api_token = formData.api_token;

			read = await tenantsApi.updateExternalSiem(tenantId, payload);
			editing = false;
			addToast({
				type: 'success',
				title: m.ten_siem_title(),
				message: m.ten_siem_connection_updated()
			});
			void pollStatus(); // the adapter just rolled — refresh status
		} catch (e) {
			addToast({
				type: 'error',
				title: m.ten_siem_title(),
				message: e instanceof Error ? e.message : String(e)
			});
		} finally {
			saving = false;
		}
	}

	function fmtTs(ts: string | null | undefined): string {
		if (!ts) return '—';
		const d = new Date(ts);
		return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
	}

	// Derived display for the live ingest line. ``reachable: false`` (soft-fail
	// from the proxy) renders the error; otherwise last_ingest_error || 'OK'.
	$: reachable = status ? status.reachable !== false : null;
	$: ingestText =
		status === null
			? '—'
			: status.reachable === false
				? m.ten_siem_unreachable_error({ error: status.error ?? m.ten_unknown() })
				: (status.last_ingest_error ?? m.ten_ok());

	onMount(() => {
		void loadRead();
		startPolling();
		if (typeof document !== 'undefined') {
			document.addEventListener('visibilitychange', onVisibilityChange);
		}
	});

	onDestroy(() => {
		stopPolling();
		if (typeof document !== 'undefined') {
			document.removeEventListener('visibilitychange', onVisibilityChange);
		}
	});
</script>

<div class="card p-4" data-testid="external-siem-panel">
	<div class="flex items-center justify-between mb-4">
		<button
			class="h4 flex items-center gap-2"
			data-testid="siem-collapse-toggle"
			on:click={toggleCollapsed}
			aria-expanded={!collapsed}
		>
			<span class="opacity-60">{collapsed ? '▸' : '▾'}</span>
			{m.ten_siem_title()}
		</button>
		{#if !collapsed && !editing && !loadingRead}
			<button class="btn btn-sm variant-soft-primary" data-testid="siem-edit" on:click={startEdit}>
				{m.common_edit()}
			</button>
		{/if}
	</div>

	{#if !collapsed}
		{#if loadingRead}
			<div class="flex items-center gap-3 text-sm opacity-70">
				<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
				<span>{m.common_loading()}</span>
			</div>
		{:else if readError}
			<div class="text-error-500 text-sm" data-testid="siem-error">{readError}</div>
		{:else if editing}
			<!-- In-place edit form — both credential pairs, mirrors the wizard step. -->
			<form
				class="space-y-4"
				on:submit|preventDefault={save}
				data-testid="siem-edit-form"
			>
				<div class="space-y-2">
					<div class="text-sm font-medium">{m.ten_siem_indexer_section()}</div>
					<label class="label">
						<span class="text-sm">{m.ten_siem_indexer_url()}</span>
						<input
							name="indexer_url"
							class="input"
							bind:value={formData.indexer_url}
							placeholder="https://indexer.example.com:9200"
						/>
					</label>
					<div class="grid grid-cols-2 gap-3">
						<label class="label">
							<span class="text-sm">{m.ten_siem_indexer_username()}</span>
							<input name="indexer_username" class="input" bind:value={formData.indexer_username} />
						</label>
						<label class="label">
							<span class="text-sm">{m.ten_siem_indexer_password()}</span>
							<input
								name="indexer_password"
								type="password"
								class="input"
								placeholder={m.ten_leave_blank_to_keep()}
								bind:value={formData.indexer_password}
							/>
						</label>
					</div>
				</div>
				<div class="space-y-2">
					<div class="text-sm font-medium">{m.ten_siem_api_section()}</div>
					<label class="label">
						<span class="text-sm">{m.ten_siem_api_url()}</span>
						<input
							name="api_url"
							class="input"
							bind:value={formData.api_url}
							placeholder="https://wazuh.example.com:55000"
						/>
					</label>
					<div class="grid grid-cols-2 gap-3">
						<label class="label">
							<span class="text-sm">{m.ten_siem_api_username()}</span>
							<input name="api_username" class="input" bind:value={formData.api_username} />
						</label>
						<label class="label">
							<span class="text-sm">{m.ten_siem_api_password()}</span>
							<input
								name="api_password"
								type="password"
								class="input"
								placeholder={m.ten_leave_blank_to_keep()}
								bind:value={formData.api_password}
							/>
						</label>
					</div>
					<label class="label">
						<span class="text-sm">{m.ten_siem_api_token_optional()}</span>
						<input
							name="api_token"
							type="password"
							class="input"
							placeholder={m.ten_leave_blank_to_keep()}
							bind:value={formData.api_token}
						/>
					</label>
				</div>
				<label class="flex items-center gap-2">
					<input
						name="verify_ssl"
						type="checkbox"
						class="checkbox"
						bind:checked={formData.verify_ssl}
					/>
					<span class="text-sm">{m.ten_siem_verify_tls_label()}</span>
				</label>
				<div class="space-y-2 pt-2 border-t border-surface-500/20" data-testid="siem-ingest-edit">
					<div class="text-sm font-medium">{m.ten_siem_ingest_section()}</div>
					<label class="label">
						<span class="text-sm">{m.ten_siem_ingest_start()}</span>
						<select name="ingest_start" class="select" bind:value={formData.ingest_start}>
							<option value="all">{m.ten_siem_ingest_start_all()}</option>
							<option value="now">{m.ten_siem_ingest_start_now()}</option>
							<option value="custom">{m.ten_siem_ingest_start_custom()}</option>
						</select>
						<small class="opacity-60">{m.ten_siem_ingest_start_hint()}</small>
					</label>
					{#if formData.ingest_start === 'custom'}
						<label class="label">
							<span class="text-sm">{m.ten_siem_ingest_start_custom()}</span>
							<input
								name="ingest_initial_ts"
								type="text"
								class="input font-mono"
								placeholder="2026-01-31T00:00:00Z"
								bind:value={formData.ingest_initial_ts}
							/>
						</label>
					{/if}
					<label class="flex items-center gap-2">
						<input
							name="exclude_manager_agent"
							type="checkbox"
							class="checkbox"
							bind:checked={formData.exclude_manager_agent}
						/>
						<span class="text-sm">{m.ten_siem_ingest_exclude_manager()}</span>
					</label>
					<small class="opacity-60">{m.ten_siem_ingest_exclude_manager_hint()}</small>
					<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
						<label class="label">
							<span class="text-sm">{m.ten_siem_ingest_agent_prefix()}</span>
							<input name="agent_prefix" type="text" class="input" bind:value={formData.agent_prefix} />
						</label>
						<label class="label">
							<span class="text-sm">{m.ten_siem_ingest_min_severity()}</span>
							<input
								name="min_severity"
								type="number"
								min="0"
								max="15"
								class="input"
								bind:value={formData.min_severity}
							/>
							<small class="opacity-60">{m.ten_siem_ingest_min_severity_hint()}</small>
						</label>
					</div>
				</div>
				<div class="flex gap-2">
					<button
						type="submit"
						class="btn btn-sm variant-filled-primary"
						data-testid="siem-save"
						disabled={saving}
					>
						{#if saving}
							<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
						{/if}
						{m.common_save()}
					</button>
					<button
						type="button"
						class="btn btn-sm variant-ghost-surface"
						data-testid="siem-cancel"
						on:click={cancelEdit}
						disabled={saving}
					>
						{m.common_cancel()}
					</button>
				</div>
			</form>
		{:else if read}
			<!-- Read view -->
			<dl class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-sm">
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_indexer_url()}</dt>
					<dd class="font-mono text-xs text-right break-all" data-testid="siem-indexer-url">
						{read.indexer_url ?? '—'}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_indexer_username()}</dt>
					<dd data-testid="siem-indexer-username">{read.indexer_username ?? '—'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_api_url()}</dt>
					<dd class="font-mono text-xs text-right break-all" data-testid="siem-api-url">
						{read.api_url ?? '—'}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_api_username()}</dt>
					<dd data-testid="siem-api-username">{read.api_username ?? '—'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_verify_tls()}</dt>
					<dd data-testid="siem-verify-ssl">{read.verify_ssl ? '✔' : '✘'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_indexer_password()}</dt>
					<dd data-testid="siem-has-indexer-password">{read.has_indexer_password ? '✔' : '✘'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_api_password()}</dt>
					<dd data-testid="siem-has-api-password">{read.has_api_password ? '✔' : '✘'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_api_token()}</dt>
					<dd data-testid="siem-has-api-token">{read.has_api_token ? '✔' : '✘'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_ingest_start()}</dt>
					<dd class="font-mono text-xs" data-testid="siem-ingest-start">
						{read.ingest?.initial_ts ?? m.ten_siem_ingest_start_all()}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_ingest_manager_alerts()}</dt>
					<dd data-testid="siem-ingest-manager-alerts">
						{read.ingest?.effective_exclude_manager_agent ? '✘' : '✔'}
						{#if read.ingest?.exclude_manager_agent == null}
							<span class="opacity-60">({m.ten_siem_ingest_default()})</span>
						{/if}
					</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_ingest_agent_prefix()}</dt>
					<dd class="font-mono text-xs" data-testid="siem-ingest-agent-prefix">{read.ingest?.agent_prefix ?? '—'}</dd>
				</div>
				<div class="flex justify-between gap-3">
					<dt class="opacity-60">{m.ten_siem_ingest_min_severity()}</dt>
					<dd data-testid="siem-ingest-min-severity">
						{read.ingest?.effective_min_severity ?? '—'}
						{#if read.ingest?.min_severity == null}
							<span class="opacity-60">({m.ten_siem_ingest_default()})</span>
						{/if}
					</dd>
				</div>
			</dl>

			<!-- Live adapter ingest status (polled). -->
			<div class="mt-4 pt-4 border-t border-surface-500/20">
				<div class="flex items-center justify-between mb-2">
					<h4 class="font-medium text-sm">{m.ten_siem_adapter_status()}</h4>
					<span
						class="badge {reachable === false
							? 'variant-filled-error'
							: reachable
								? 'variant-filled-success'
								: 'variant-filled-surface'}"
						data-testid="adapter-reachable"
					>
						{reachable === null ? m.ten_siem_polling() : reachable ? m.ten_siem_reachable() : m.ten_siem_unreachable()}
					</span>
				</div>
				<dl class="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-2 text-sm">
					<div class="flex justify-between gap-3">
						<dt class="opacity-60">{m.ten_siem_last_alert()}</dt>
						<dd class="text-right" data-testid="adapter-last-alert-ts">
							{status && status.reachable !== false ? fmtTs(status.last_alert_ts) : '—'}
						</dd>
					</div>
					<div class="flex justify-between gap-3">
						<dt class="opacity-60">{m.ten_siem_alerts_forwarded()}</dt>
						<dd data-testid="adapter-alerts-forwarded">
							{status && status.reachable !== false ? (status.alerts_forwarded ?? 0) : '—'}
						</dd>
					</div>
					<div class="flex justify-between gap-3">
						<dt class="opacity-60">{m.ten_siem_last_ingest_error()}</dt>
						<dd class="text-right break-all" data-testid="adapter-last-ingest-error">{ingestText}</dd>
					</div>
				</dl>
			</div>
		{/if}
	{/if}
</div>
