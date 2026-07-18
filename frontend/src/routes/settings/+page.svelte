<script lang="ts">
	import { onMount } from 'svelte';
	import { addToast } from '$lib/stores';
	import { api, type Settings, type SettingsUpdate } from '$lib/api/client';
	import { canEditSettings } from '$lib/stores';
	import { SlideToggle } from '@skeletonlabs/skeleton';
	import { m } from '$lib/paraglide/messages';
	import { localizeHref } from '$lib/i18n';

	let loading = true;
	let saving = false;
	let syncing = false;
	let readonly = false;
	let sources: Record<string, 'env' | 'db'> = {};
	let anthropic_api_key_configured = false;
	let openai_api_key_configured = false;
	let llm_keys_conflict = false;
	let wazuh_credentials_configured = false;
	let cortex_api_key_configured = false;
	let thehive_api_key_configured = false;
	let misp_api_key_configured = false;
	let slack_webhook_configured = false;

	// Local form state for LLM settings
	let llm_provider: 'anthropic' | 'openai' = 'anthropic';
	let llm_fast_model = '';
	let llm_reasoning_model = '';
	let llm_temperature = '0.0';
	let llm_max_tokens = '4096';
	let llm_anthropic_base_url = '';
	let llm_openai_base_url = '';
	let llm_openai_organization = '';

	// Local form state for integrations
	// Wazuh
	let wazuh_enabled = false;
	let wazuh_url = '';
	let wazuh_verify_ssl = true;

	// Cortex
	let cortex_enabled = false;
	let cortex_url = '';
	let cortex_verify_ssl = true;

	// TheHive
	let thehive_enabled = false;
	let thehive_url = '';
	let thehive_organisation = '';
	let thehive_verify_ssl = true;

	// MISP
	let misp_enabled = false;
	let misp_url = '';
	let misp_verify_ssl = true;

	// Slack
	let slack_enabled = false;
	let slack_channel = '';
	let slack_notify_on_escalation = true;
	let slack_notify_on_verdict = true;

	function applySettings(serverSettings: Settings): void {
		readonly = serverSettings.readonly;
		sources = serverSettings.sources ?? {};
		anthropic_api_key_configured = serverSettings.anthropic_api_key_configured;
		openai_api_key_configured = serverSettings.openai_api_key_configured;
		llm_keys_conflict = serverSettings.llm_keys_conflict;
		wazuh_credentials_configured = serverSettings.wazuh_credentials_configured;
		cortex_api_key_configured = serverSettings.cortex_api_key_configured;
		thehive_api_key_configured = serverSettings.thehive_api_key_configured;
		misp_api_key_configured = serverSettings.misp_api_key_configured;
		slack_webhook_configured = serverSettings.slack_webhook_configured;

		// LLM
		llm_provider = serverSettings.llm_provider;
		llm_fast_model = serverSettings.llm_fast_model || '';
		llm_reasoning_model = serverSettings.llm_reasoning_model || '';
		llm_temperature = String(serverSettings.llm_temperature ?? 0.0);
		llm_max_tokens = String(serverSettings.llm_max_tokens ?? 4096);
		llm_anthropic_base_url = serverSettings.llm_anthropic_base_url || '';
		llm_openai_base_url = serverSettings.llm_openai_base_url || '';
		llm_openai_organization = serverSettings.llm_openai_organization || '';

		// Wazuh
		wazuh_enabled = serverSettings.wazuh_enabled;
		wazuh_url = serverSettings.wazuh_url || '';
		wazuh_verify_ssl = serverSettings.wazuh_verify_ssl;

		// Cortex
		cortex_enabled = serverSettings.cortex_enabled;
		cortex_url = serverSettings.cortex_url || '';
		cortex_verify_ssl = serverSettings.cortex_verify_ssl;

		// TheHive
		thehive_enabled = serverSettings.thehive_enabled;
		thehive_url = serverSettings.thehive_url || '';
		thehive_organisation = serverSettings.thehive_organisation || '';
		thehive_verify_ssl = serverSettings.thehive_verify_ssl;

		// MISP
		misp_enabled = serverSettings.misp_enabled;
		misp_url = serverSettings.misp_url || '';
		misp_verify_ssl = serverSettings.misp_verify_ssl;

		// Slack
		slack_enabled = serverSettings.slack_enabled;
		slack_channel = serverSettings.slack_channel || '';
		slack_notify_on_escalation = serverSettings.slack_notify_on_escalation;
		slack_notify_on_verdict = serverSettings.slack_notify_on_verdict;
	}

	function getIntegrationSource(prefix: string): 'env' | 'db' | null {
		const keys = Object.keys(sources).filter((key) => key.startsWith(prefix));
		if (keys.length === 0) return null;
		return keys.some((key) => sources[key] === 'db') ? 'db' : 'env';
	}

	onMount(async () => {
		try {
			const serverSettings = await api.settings.get();
			applySettings(serverSettings);
		} catch (e) {
			addToast({
				type: 'error',
				title: m.adm_toast_load_failed_title(),
				message: e instanceof Error ? e.message : m.adm_toast_load_failed_msg()
			});
		} finally {
			loading = false;
		}
	});

	async function saveSettings() {
		saving = true;
		try {
			if (readonly) return;

			const parsedTemperature = Number(llm_temperature);
			const parsedMaxTokens = Number(llm_max_tokens);
			const safeTemperature = Number.isFinite(parsedTemperature)
				? Math.min(2, Math.max(0, parsedTemperature))
				: 0.0;
			const safeMaxTokens = Number.isFinite(parsedMaxTokens) && Math.trunc(parsedMaxTokens) >= 1
				? Math.trunc(parsedMaxTokens)
				: 4096;

			const updates: SettingsUpdate = {
				// LLM
				llm_provider,
				llm_fast_model,
				llm_reasoning_model,
				llm_temperature: safeTemperature,
				llm_max_tokens: safeMaxTokens,
				llm_anthropic_base_url: llm_anthropic_base_url || null,
				llm_openai_base_url: llm_openai_base_url || null,
				llm_openai_organization: llm_openai_organization || null,

				// Wazuh
				wazuh_enabled,
				wazuh_url: wazuh_url || null,
				wazuh_verify_ssl,

				// Cortex
				cortex_enabled,
				cortex_url: cortex_url || null,
				cortex_verify_ssl,

				// TheHive
				thehive_enabled,
				thehive_url: thehive_url || null,
				thehive_organisation: thehive_organisation || null,
				thehive_verify_ssl,

				// MISP
				misp_enabled,
				misp_url: misp_url || null,
				misp_verify_ssl,

				// Slack
				slack_enabled,
				slack_channel: slack_channel || null,
				slack_notify_on_escalation,
				slack_notify_on_verdict
			};

			await api.settings.update(updates);

			addToast({
				type: 'success',
				title: m.adm_toast_saved_title(),
				message: m.adm_toast_saved_msg()
			});
		} catch (e) {
			addToast({
				type: 'error',
				title: m.adm_toast_save_failed_title(),
				message: e instanceof Error ? e.message : m.adm_toast_save_failed_msg()
			});
		} finally {
			saving = false;
		}
	}

	async function resetSettings() {
		syncing = true;
		try {
			if (readonly) return;

			const defaultSettings = await api.settings.reset();
			applySettings(defaultSettings);

			addToast({
				type: 'info',
				title: m.adm_toast_reset_title(),
				message: m.adm_toast_reset_msg()
			});
		} catch (e) {
			addToast({
				type: 'error',
				title: m.adm_toast_reset_failed_title(),
				message: e instanceof Error ? e.message : m.adm_toast_reset_failed_msg()
			});
		} finally {
			syncing = false;
		}
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<h1 class="h2">{m.nav_settings()}</h1>
			{#if readonly}
				<span class="badge variant-soft text-xs">{m.adm_readonly()}</span>
			{:else if !$canEditSettings}
				<span class="badge variant-soft text-xs">{m.adm_viewonly()}</span>
			{/if}
		</div>
		<div class="flex items-center gap-3">
			<a
				href={localizeHref('/settings/llm')}
				class="anchor text-sm"
				title={m.adm_byo_llm_title()}
				>{m.adm_byo_llm_link()}</a
			>
			<div class="flex gap-2">
			<button
				type="button"
				class="btn variant-ghost-surface"
				on:click={resetSettings}
				disabled={syncing || saving || readonly || !$canEditSettings}
				>
					{#if syncing}
						<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
					{/if}
					{m.adm_reset_to_defaults()}
				</button>
			<button
				type="button"
				class="btn variant-filled-primary"
				on:click={saveSettings}
				disabled={saving || syncing || readonly || !$canEditSettings}
				>
					{#if saving}
						<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
					{/if}
					{m.adm_save_changes()}
				</button>
			</div>
		</div>
	</div>

	{#if loading}
		<div class="card p-8 text-center">
			<p class="opacity-60">{m.adm_loading_settings()}</p>
		</div>
	{:else}
		<!-- LLM Settings -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_llm()}</h3>
						{#if getIntegrationSource('llm_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('llm_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_llm_section_hint()}</p>
				</div>
			</div>

			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<div>
					<label class="label">
						<span class="font-medium">{m.adm_field_provider()}</span>
						<select class="select" bind:value={llm_provider} disabled={readonly || !$canEditSettings}>
							<option value="anthropic">{m.adm_provider_anthropic()}</option>
							<option value="openai">{m.adm_provider_openai_compatible()}</option>
						</select>
					</label>
				</div>

				<div class="md:col-span-2 text-sm opacity-70">
					{#if llm_keys_conflict}
						<span class="text-error-500">{m.adm_llm_keys_conflict()}</span>
					{:else if llm_provider === 'anthropic'}
						{anthropic_api_key_configured ? m.adm_api_key_configured() : m.adm_api_key_missing({ env: 'ANTHROPIC_API_KEY' })}
					{:else}
						{openai_api_key_configured ? m.adm_api_key_configured() : m.adm_api_key_missing({ env: 'OPENAI_API_KEY' })}
					{/if}
				</div>

				<div>
					<label class="label">
						<span class="font-medium">{m.adm_field_fast_model()}</span>
						<input
							type="text"
							class="input"
							placeholder="claude-sonnet-4-6"
							bind:value={llm_fast_model}
							disabled={readonly || !$canEditSettings}
						/>
					</label>
				</div>
				<div>
					<label class="label">
						<span class="font-medium">{m.adm_field_reasoning_model()}</span>
						<input
							type="text"
							class="input"
							placeholder="claude-sonnet-4-6"
							bind:value={llm_reasoning_model}
							disabled={readonly || !$canEditSettings}
						/>
					</label>
				</div>
				<div>
					<label class="label">
						<span class="font-medium">{m.adm_field_temperature()}</span>
						<input
							type="number"
							class="input"
							step="0.1"
							min="0"
							max="2"
							bind:value={llm_temperature}
							disabled={readonly || !$canEditSettings}
						/>
					</label>
				</div>
				<div>
					<label class="label">
						<span class="font-medium">{m.adm_field_max_tokens()}</span>
						<input
							type="number"
							class="input"
							step="1"
							min="1"
							bind:value={llm_max_tokens}
							disabled={readonly || !$canEditSettings}
						/>
					</label>
				</div>

				{#if llm_provider === 'anthropic'}
					<div class="md:col-span-2">
						<label class="label">
							<span class="font-medium">{m.adm_field_anthropic_base_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://api.anthropic.com"
								bind:value={llm_anthropic_base_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
				{:else}
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_openai_base_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://api.openai.com/v1"
								bind:value={llm_openai_base_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_organization()}</span>
							<input
								type="text"
								class="input"
								placeholder="org_..."
								bind:value={llm_openai_organization}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
				{/if}

				<div class="md:col-span-2 text-sm opacity-60">
					{m.adm_llm_restart_hint()}
				</div>
			</div>
		</div>

		<!-- Wazuh SIEM Integration -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_wazuh()}</h3>
						{#if getIntegrationSource('wazuh_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('wazuh_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_wazuh_desc()}</p>
				</div>
				<SlideToggle name="wazuh_enabled" bind:checked={wazuh_enabled} disabled={readonly || !$canEditSettings} />
			</div>

			{#if wazuh_enabled}
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_api_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://wazuh.example.com:55000"
								bind:value={wazuh_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div class="md:col-span-2 text-sm opacity-70">
						{wazuh_credentials_configured ? m.adm_credentials_configured() : m.adm_credentials_missing()}
					</div>
					<div class="flex items-center">
						<SlideToggle name="wazuh_verify_ssl" bind:checked={wazuh_verify_ssl} disabled={readonly || !$canEditSettings}>
							{m.adm_verify_ssl()}
						</SlideToggle>
					</div>
				</div>
			{/if}
		</div>

		<!-- Cortex Integration -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_cortex()}</h3>
						{#if getIntegrationSource('cortex_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('cortex_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_cortex_desc()}</p>
				</div>
				<SlideToggle name="cortex_enabled" bind:checked={cortex_enabled} disabled={readonly || !$canEditSettings} />
			</div>

			{#if cortex_enabled}
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_api_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://cortex.example.com:9001"
								bind:value={cortex_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div class="md:col-span-2 text-sm opacity-70">
						{cortex_api_key_configured ? m.adm_api_key_configured() : m.adm_api_key_missing({ env: 'CORTEX_API_KEY' })}
					</div>
					<div class="flex items-center">
						<SlideToggle name="cortex_verify_ssl" bind:checked={cortex_verify_ssl} disabled={readonly || !$canEditSettings}>
							{m.adm_verify_ssl()}
						</SlideToggle>
					</div>
				</div>
			{/if}
		</div>

		<!-- TheHive Integration -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_thehive()}</h3>
						{#if getIntegrationSource('thehive_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('thehive_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_thehive_desc()}</p>
				</div>
				<SlideToggle name="thehive_enabled" bind:checked={thehive_enabled} disabled={readonly || !$canEditSettings} />
			</div>

			{#if thehive_enabled}
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_api_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://thehive.example.com:9000"
								bind:value={thehive_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_organisation()}</span>
							<input
								type="text"
								class="input"
								placeholder="default"
								bind:value={thehive_organisation}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div class="md:col-span-2 text-sm opacity-70">
						{thehive_api_key_configured ? m.adm_api_key_configured() : m.adm_api_key_missing_thehive()}
					</div>
					<div class="flex items-center">
						<SlideToggle name="thehive_verify_ssl" bind:checked={thehive_verify_ssl} disabled={readonly || !$canEditSettings}>
							{m.adm_verify_ssl()}
						</SlideToggle>
					</div>
				</div>
			{/if}
		</div>

		<!-- MISP Integration -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_misp()}</h3>
						{#if getIntegrationSource('misp_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('misp_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_misp_desc()}</p>
				</div>
				<SlideToggle name="misp_enabled" bind:checked={misp_enabled} disabled={readonly || !$canEditSettings} />
			</div>

			{#if misp_enabled}
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_api_url()}</span>
							<input
								type="url"
								class="input"
								placeholder="https://misp.example.com"
								bind:value={misp_url}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div class="md:col-span-2 text-sm opacity-70">
						{misp_api_key_configured ? m.adm_api_key_configured() : m.adm_api_key_missing({ env: 'MISP_API_KEY' })}
					</div>
					<div class="flex items-center">
						<SlideToggle name="misp_verify_ssl" bind:checked={misp_verify_ssl} disabled={readonly || !$canEditSettings}>
							{m.adm_verify_ssl()}
						</SlideToggle>
					</div>
				</div>
			{/if}
		</div>

		<!-- Slack Integration -->
		<div class="card p-6 space-y-4">
			<div class="flex items-center justify-between border-b border-surface-500/30 pb-2">
				<div>
					<div class="flex items-center gap-2">
						<h3 class="h4">{m.adm_section_slack()}</h3>
						{#if getIntegrationSource('slack_') === 'env'}
							<span class="badge variant-soft text-xs">{m.adm_badge_env()}</span>
						{:else if getIntegrationSource('slack_') === 'db'}
							<span class="badge variant-filled-warning text-xs">{m.adm_badge_override()}</span>
						{/if}
					</div>
					<p class="text-sm opacity-60">{m.adm_slack_desc()}</p>
				</div>
				<SlideToggle name="slack_enabled" bind:checked={slack_enabled} disabled={readonly || !$canEditSettings} />
			</div>

			{#if slack_enabled}
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="label">
							<span class="font-medium">{m.adm_field_channel()}</span>
							<input
								type="text"
								class="input"
								placeholder="#security-alerts"
								bind:value={slack_channel}
								disabled={readonly || !$canEditSettings}
							/>
						</label>
					</div>
					<div class="md:col-span-2 text-sm opacity-70">
						{slack_webhook_configured ? m.adm_webhook_configured() : m.adm_webhook_missing()}
					</div>
					<div class="space-y-2">
						<SlideToggle name="slack_notify_on_escalation" bind:checked={slack_notify_on_escalation} disabled={readonly || !$canEditSettings}>
							{m.adm_notify_on_escalation()}
						</SlideToggle>
						<SlideToggle name="slack_notify_on_verdict" bind:checked={slack_notify_on_verdict} disabled={readonly || !$canEditSettings}>
							{m.adm_notify_on_verdict()}
						</SlideToggle>
					</div>
				</div>
			{/if}
		</div>
	{/if}
</div>
