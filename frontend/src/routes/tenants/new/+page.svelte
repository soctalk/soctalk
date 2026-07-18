<script lang="ts">
	import { goto } from '$app/navigation';
	import {
		tenantsApi,
		type TenantOnboard,
		type ExternalSiemOnboard
	} from '$lib/api/tenants';
	import { addToast, authSession, isMsspScope } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';
	import { localizedGoto } from '$lib/i18n';

	// Onboarding wizard. Four steps for poc/persistent — identity → profile →
	// branding → review — and a conditional FIFTH "External SIEM" step that
	// appears only for the ``provided`` profile (bring-your-own Wazuh), where
	// the tenant supplies external indexer + API credentials. The step
	// indicator, content, validity gate and Next/Create buttons are all driven
	// off the reactive ``steps`` list so the count grows/shrinks with profile.
	//
	// Mirrors the e2e contract (slug placeholder ``acme``, profile radio
	// ``value=poc``, ``data-testid=create-tenant``) so existing tests keep
	// working when pointed at canonical.

	// Local form shape for the External SIEM step. Every field is a concrete
	// string/boolean so the inputs can two-way bind without optional-narrowing
	// noise; it is converted to the API's ``ExternalSiemOnboard`` (with a blank
	// ``api_token`` dropped) at submit time.
	interface SiemForm {
		indexer_url: string;
		indexer_username: string;
		indexer_password: string;
		api_url: string;
		api_username: string;
		api_password: string;
		api_token: string;
		verify_ssl: boolean;
	}

	interface WizardForm {
		slug: string;
		display_name: string;
		profile: 'poc' | 'persistent' | 'provided';
		branding_app_name: string;
		branding_logo_url: string;
		branding_primary_color: string;
		branding_secondary_color: string;
		contact_email: string;
		llm_base_url: string;
		llm_model: string;
		// Optional per-role model overrides. Blank → the primary llm_model is
		// used for everything; only included in the payload when non-blank.
		llm_fast_model: string;
		llm_reasoning_model: string;
		// Per-tenant LLM credentials. Optional for poc/persistent (blank →
		// MSSP shared install key); REQUIRED for 'provided' where the key
		// gates the External SIEM step. Both inputs (Profile disclosure and
		// the External SIEM sub-section) bind to these same fields.
		// '' means "inherit the install default" — the wizard leaves the LLM
		// fields out of the payload so the backend applies the MSSP's own
		// install default (provider/model/base_url + shared key). Picking a
		// concrete provider overrides it per-tenant.
		llm_provider: '' | 'openai-compatible' | 'anthropic';
		llm_api_key: string;
		// Present only while profile === 'provided'; cleared otherwise.
		external_siem?: SiemForm;
	}

	const blankSiem = (): SiemForm => ({
		indexer_url: '',
		indexer_username: '',
		indexer_password: '',
		api_url: '',
		api_username: '',
		api_password: '',
		api_token: '',
		verify_ssl: true
	});

	let step = 1;
	let submitting = false;

	// Auth lands asynchronously from the layout's /api/auth/me call;
	// only redirect once the session is actually resolved AND the user
	// is non-MSSP. Otherwise the page would race the layout and
	// redirect every fresh load.
	$: if ($authSession.user && !$isMsspScope) {
		localizedGoto('/');
	}

	let form: WizardForm = {
		slug: '',
		display_name: '',
		profile: 'poc',
		branding_app_name: '',
		branding_logo_url: '',
		branding_primary_color: '#1a73e8',
		branding_secondary_color: '#fbbc04',
		contact_email: '',
		llm_base_url: 'https://api.openai.com/v1',
		llm_model: 'gpt-4o',
		llm_fast_model: '',
		llm_reasoning_model: '',
		llm_provider: '',
		llm_api_key: '',
		external_siem: undefined
	};

	// Reactive step list — the conditional 'External SIEM' step is spliced in
	// only for the 'provided' profile. Everything downstream (indicator,
	// content switch, Next/Create) keys off this.
	// Step CODES drive the logic; display labels resolve via stepLabel() at
	// render time (i18n #52 — labels were previously logic discriminators).
	type StepCode = 'identity' | 'profile' | 'siem' | 'branding' | 'review';
	const STEP_LABELS: Record<StepCode, () => string> = {
		identity: m.tnew_step_identity,
		profile: m.tnew_step_profile,
		siem: m.tnew_step_siem,
		branding: m.tnew_step_branding,
		review: m.tnew_step_review
	};
	$: steps = (form.profile === 'provided'
		? ['identity', 'profile', 'siem', 'branding', 'review']
		: ['identity', 'profile', 'branding', 'review']) as StepCode[];
	$: currentLabel = steps[step - 1];
	// If the list shrinks (provided → poc) while we're parked on a now-missing
	// step, clamp back into range. Profile is only editable on step 2, so this
	// is a defensive net rather than a hot path.
	$: if (step > steps.length) step = steps.length;

	// Initialise the nested external_siem block when the profile becomes
	// 'provided' (so its inputs can bind) and CLEAR it when the profile moves
	// to poc/persistent. Tracking the previous value fires this exactly on a
	// transition rather than on every reactive pass.
	let lastProfile: WizardForm['profile'] = form.profile;
	$: if (form.profile !== lastProfile) {
		lastProfile = form.profile;
		form.external_siem =
			form.profile === 'provided' ? (form.external_siem ?? blankSiem()) : undefined;
	}

	function isValidUrl(value: string): boolean {
		if (!value.trim()) return false;
		try {
			new URL(value);
			return true;
		} catch {
			return false;
		}
	}

	$: slugValid = /^[a-z0-9-]{3,32}$/.test(form.slug);
	$: identityValid = !!form.display_name.trim() && slugValid;

	// External SIEM step is valid only with both endpoints as well-formed URLs
	// and the four credential fields non-empty. ``api_token`` is optional.
	$: siemValid =
		!!form.external_siem &&
		isValidUrl(form.external_siem.indexer_url) &&
		!!form.external_siem.indexer_username.trim() &&
		!!form.external_siem.indexer_password.trim() &&
		isValidUrl(form.external_siem.api_url) &&
		!!form.external_siem.api_username.trim() &&
		!!form.external_siem.api_password.trim();

	// For 'provided' the tenant must bring their own LLM key — the backend
	// rejects a blank llm_api_key with a 422, so the External SIEM step
	// (where the key is surfaced prominently) gates on it too.
	$: llmKeyValid = !!form.llm_api_key.trim();

	// Validity of the *current* step gates the Next button. Profile/Branding
	// have no required input so they are always advanceable.
	$: stepValid =
		currentLabel === 'identity'
			? identityValid
			: currentLabel === 'siem'
				? siemValid && llmKeyValid
				: true;

	function next() {
		if (step < steps.length) step += 1;
	}

	function prev() {
		if (step > 1) step -= 1;
	}

	// Build the API payload. For 'provided' we attach the nested external_siem
	// object (dropping a blank optional api_token); for poc/persistent we omit
	// it entirely so the controller fills wazuh_url/indexer_url in-cluster.
	function toOnboard(): TenantOnboard {
		const payload: TenantOnboard = {
			slug: form.slug,
			display_name: form.display_name,
			profile: form.profile,
			branding_app_name: form.branding_app_name,
			branding_logo_url: form.branding_logo_url,
			branding_primary_color: form.branding_primary_color,
			branding_secondary_color: form.branding_secondary_color,
			contact_email: form.contact_email
		};
		// LLM: '' provider means "inherit the install default" — leave
		// provider/base_url/model out of the payload entirely so the backend's
		// SOCTALK_LLM_*_DEFAULT fallback applies (else an explicit
		// openai-compatible/gpt-4o/api.openai.com would defeat it and every
		// tenant would come up on OpenAI regardless of the install default).
		// Picking a concrete provider ships the full endpoint override.
		if (form.llm_provider.trim()) {
			payload.llm_provider = form.llm_provider;
			payload.llm_base_url = form.llm_base_url;
			payload.llm_model = form.llm_model;
		}
		// Per-tenant key follows the api_token pattern: only included when
		// non-blank so the backend falls back to the MSSP shared install key
		// for poc/persistent tenants that leave it empty.
		if (form.llm_api_key.trim()) payload.llm_api_key = form.llm_api_key;
		// Per-role model overrides: same omission pattern — blank means
		// "use the primary model" and the key is left out entirely.
		if (form.llm_fast_model.trim()) payload.llm_fast_model = form.llm_fast_model.trim();
		if (form.llm_reasoning_model.trim())
			payload.llm_reasoning_model = form.llm_reasoning_model.trim();
		if (form.profile === 'provided' && form.external_siem) {
			const s = form.external_siem;
			const external_siem: ExternalSiemOnboard = {
				indexer_url: s.indexer_url,
				indexer_username: s.indexer_username,
				indexer_password: s.indexer_password,
				api_url: s.api_url,
				api_username: s.api_username,
				api_password: s.api_password,
				verify_ssl: s.verify_ssl
			};
			if (s.api_token.trim()) external_siem.api_token = s.api_token;
			payload.external_siem = external_siem;
		}
		return payload;
	}

	async function submit() {
		submitting = true;
		try {
			const tenant = await tenantsApi.onboard(toOnboard());
			addToast({
				type: 'success',
				title: m.tnew_created_title(),
				message: m.tnew_created_msg({ name: tenant.display_name, slug: tenant.slug })
			});
			await localizedGoto(`/tenants/${tenant.id}`);
		} catch (e) {
			addToast({
				type: 'error',
				title: m.tnew_onboard_failed(),
				message: e instanceof Error ? e.message : String(e)
			});
		} finally {
			submitting = false;
		}
	}
</script>

<div class="space-y-4 max-w-2xl mx-auto">
	<div class="flex items-center gap-3">
		<button class="btn btn-sm variant-ghost-surface" on:click={() => localizedGoto('/tenants')}>
			{m.tnew_back_to_tenants()}
		</button>
	</div>
	<h1 class="h2">{m.tnew_title()}</h1>

	<!-- Step indicator -->
	<ol class="flex gap-2 text-sm opacity-70">
		{#each steps as label, i}
			<li
				data-testid="wizard-step"
				class:font-bold={step === i + 1}
				class:opacity-100={step === i + 1}
			>
				{i + 1}. {STEP_LABELS[label]()}
			</li>
			{#if i < steps.length - 1}<li class="opacity-30">→</li>{/if}
		{/each}
	</ol>

	<div class="card p-6 space-y-4">
		{#if currentLabel === 'identity'}
			<h3 class="h3">{m.tnew_step_identity()}</h3>
			<label class="label">
				<span class="font-medium">{m.tnew_display_name()}</span>
				<input name="display_name" class="input" bind:value={form.display_name} placeholder="Acme Corp" />
			</label>
			<label class="label">
				<span class="font-medium">{m.tnew_slug()}</span>
				<input name="slug" class="input" bind:value={form.slug} placeholder="acme" />
				<small class="opacity-60">{m.tnew_slug_hint()}</small>
			</label>
			<label class="label">
				<span class="font-medium">{m.tnew_contact_email()}</span>
				<input
					name="contact_email"
					type="email"
					class="input"
					bind:value={form.contact_email}
					placeholder="ops@acme.example"
				/>
			</label>
		{:else if currentLabel === 'profile'}
			<h3 class="h3">{m.tnew_step_profile()}</h3>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="poc" />
				<div>
					<div class="font-medium">{m.tnew_poc()}</div>
					<div class="text-sm opacity-70">{m.tnew_poc_desc()}</div>
				</div>
			</label>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="persistent" />
				<div>
					<div class="font-medium">{m.tnew_persistent()}</div>
					<div class="text-sm opacity-70">{m.tnew_persistent_desc()}</div>
				</div>
			</label>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="provided" />
				<div>
					<div class="font-medium">{m.tnew_provided()}</div>
					<div class="text-sm opacity-70">{m.tnew_provided_desc()}</div>
				</div>
			</label>

			<details class="card p-3 bg-surface-500/10">
				<summary class="cursor-pointer text-sm opacity-80">{m.tnew_llm_advanced()}</summary>
				<div class="mt-3 space-y-2">
					<label class="label">
						<span class="text-sm">{m.tnew_base_url()}</span>
						<input class="input" bind:value={form.llm_base_url} />
					</label>
					<label class="label">
						<span class="text-sm">{m.tnew_model()}</span>
						<input class="input" bind:value={form.llm_model} />
					</label>
					<label class="label">
						<span class="text-sm">{m.tnew_fast_model()}</span>
						<input name="llm_fast_model" class="input" bind:value={form.llm_fast_model} />
						<small class="opacity-60">{m.tnew_blank_primary_hint()}</small>
					</label>
					<label class="label">
						<span class="text-sm">{m.tnew_thinking_model()}</span>
						<input
							name="llm_reasoning_model"
							class="input"
							bind:value={form.llm_reasoning_model}
						/>
						<small class="opacity-60">{m.tnew_blank_primary_hint()}</small>
					</label>
					<label class="label">
						<span class="text-sm">{m.tnew_provider()}</span>
						<select name="llm_provider" class="select" bind:value={form.llm_provider}>
							<option value="">{m.tnew_use_install_default()}</option>
							<option value="openai-compatible">openai-compatible</option>
							<option value="anthropic">anthropic</option>
						</select>
						<small class="opacity-60">{m.tnew_provider_hint()}</small>
					</label>
					<label class="label">
						<span class="text-sm">{m.tnew_api_key()}</span>
						<input
							name="llm_api_key"
							type="password"
							autocomplete="off"
							class="input"
							bind:value={form.llm_api_key}
						/>
						{#if form.profile === 'provided'}
							<small class="opacity-60">{m.tnew_key_required_hint()}</small>
						{:else}
							<small class="opacity-60">{m.tnew_key_blank_hint()}</small>
						{/if}
					</label>
				</div>
			</details>
		{:else if currentLabel === 'siem'}
			<h3 class="h3">{m.tnew_step_siem()}</h3>
			<p class="text-sm opacity-70">{m.tnew_siem_intro()}</p>
			{#if form.external_siem}
				<div class="card p-4 space-y-4 bg-surface-500/10">
					<div class="space-y-2">
						<div class="text-sm font-medium">{m.tnew_indexer_section()}</div>
						<label class="label">
							<span class="text-sm">{m.tnew_indexer_url()}</span>
							<input
								name="indexer_url"
								class="input"
								bind:value={form.external_siem.indexer_url}
								placeholder="https://indexer.example.com:9200"
							/>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="label">
								<span class="text-sm">{m.tnew_indexer_username()}</span>
								<input
									name="indexer_username"
									class="input"
									bind:value={form.external_siem.indexer_username}
									placeholder="admin"
								/>
							</label>
							<label class="label">
								<span class="text-sm">{m.tnew_indexer_password()}</span>
								<input
									name="indexer_password"
									type="password"
									class="input"
									bind:value={form.external_siem.indexer_password}
								/>
							</label>
						</div>
					</div>
					<div class="space-y-2">
						<div class="text-sm font-medium">{m.tnew_api_section()}</div>
						<label class="label">
							<span class="text-sm">{m.tnew_api_url()}</span>
							<input
								name="api_url"
								class="input"
								bind:value={form.external_siem.api_url}
								placeholder="https://wazuh.example.com:55000"
							/>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="label">
								<span class="text-sm">{m.tnew_api_username()}</span>
								<input
									name="api_username"
									class="input"
									bind:value={form.external_siem.api_username}
									placeholder="wazuh-wui"
								/>
							</label>
							<label class="label">
								<span class="text-sm">{m.tnew_api_password()}</span>
								<input
									name="api_password"
									type="password"
									class="input"
									bind:value={form.external_siem.api_password}
								/>
							</label>
						</div>
						<label class="label">
							<span class="text-sm">{m.tnew_api_token()}</span>
							<input
								name="api_token"
								type="password"
								class="input"
								bind:value={form.external_siem.api_token}
							/>
							<small class="opacity-60">{m.tnew_api_token_hint()}</small>
						</label>
					</div>
					<label class="flex items-center gap-2">
						<input
							name="verify_ssl"
							type="checkbox"
							class="checkbox"
							bind:checked={form.external_siem.verify_ssl}
						/>
						<span class="text-sm">{m.tnew_verify_tls()}</span>
					</label>
				</div>
			{/if}
			<!-- Provided tenants bring their own LLM key — REQUIRED here (the
			     backend 422s without it), bound to the same form fields as the
			     'LLM (advanced)' disclosure on the Profile step. -->
			<div class="card p-4 space-y-2 bg-surface-500/10" data-testid="wizard-llm-credentials">
				<div class="text-sm font-medium">{m.tnew_llm_required()}</div>
				<p class="text-sm opacity-70">{m.tnew_llm_required_hint()}</p>
				<label class="label">
					<span class="text-sm">{m.tnew_provider()}</span>
					<select name="llm_provider" class="select" bind:value={form.llm_provider}>
						<option value="">{m.tnew_use_install_default_inferred()}</option>
						<option value="openai-compatible">openai-compatible</option>
						<option value="anthropic">anthropic</option>
					</select>
				</label>
				<label class="label">
					<span class="text-sm">{m.tnew_api_key()}</span>
					<input
						name="llm_api_key"
						type="password"
						autocomplete="off"
						class="input"
						bind:value={form.llm_api_key}
					/>
				</label>
			</div>
		{:else if currentLabel === 'branding'}
			<h3 class="h3">{m.tnew_step_branding()}</h3>
			<label class="label">
				<span class="font-medium">{m.tnew_app_name()}</span>
				<input
					name="branding_app_name"
					class="input"
					bind:value={form.branding_app_name}
					placeholder={form.display_name || 'Acme Security'}
				/>
			</label>
			<label class="label">
				<span class="font-medium">{m.tnew_logo_url()}</span>
				<input name="branding_logo_url" class="input" bind:value={form.branding_logo_url} placeholder="https://…/logo.svg" />
			</label>
			<div class="grid grid-cols-2 gap-3">
				<label class="label">
					<span class="font-medium">{m.tnew_primary_color()}</span>
					<input type="color" class="input h-10" bind:value={form.branding_primary_color} />
				</label>
				<label class="label">
					<span class="font-medium">{m.tnew_secondary_color()}</span>
					<input type="color" class="input h-10" bind:value={form.branding_secondary_color} />
				</label>
			</div>
		{:else if currentLabel === 'review'}
			<h3 class="h3">{m.tnew_step_review()}</h3>
			<dl class="space-y-1 text-sm">
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_display_name()}</dt><dd>{form.display_name}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_slug()}</dt><dd><code class="text-xs">{form.slug}</code></dd></div>
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_step_profile()}</dt><dd>{form.profile}</dd></div>
				{#if form.profile === 'provided' && form.external_siem}
					<div class="flex justify-between"><dt class="opacity-60">{m.tnew_indexer_url()}</dt><dd><code class="text-xs">{form.external_siem.indexer_url || '—'}</code></dd></div>
					<div class="flex justify-between"><dt class="opacity-60">{m.tnew_indexer_user()}</dt><dd>{form.external_siem.indexer_username || '—'}</dd></div>
					<div class="flex justify-between"><dt class="opacity-60">{m.tnew_api_url()}</dt><dd><code class="text-xs">{form.external_siem.api_url || '—'}</code></dd></div>
					<div class="flex justify-between"><dt class="opacity-60">{m.tnew_api_user()}</dt><dd>{form.external_siem.api_username || '—'}</dd></div>
					<div class="flex justify-between"><dt class="opacity-60">{m.tnew_verify_tls_short()}</dt><dd>{form.external_siem.verify_ssl ? m.tnew_yes() : m.tnew_no()}</dd></div>
				{/if}
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_contact()}</dt><dd>{form.contact_email || '—'}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_app_name()}</dt><dd>{form.branding_app_name || form.display_name}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">{m.tnew_primary_short()}</dt><dd>
					<span class="inline-block w-4 h-4 rounded align-middle mr-2" style="background:{form.branding_primary_color}"></span>
					<code class="text-xs">{form.branding_primary_color}</code>
				</dd></div>
				<!-- Per-role override fragments only render when non-blank — a
				     blank override never shows up as an empty literal. -->
				<div class="flex justify-between"><dt class="opacity-60">LLM</dt><dd data-testid="review-llm">{form.llm_provider.trim() ? `${form.llm_provider} · ${form.llm_model}` : m.tnew_install_default()}{form.llm_fast_model.trim() ? ` · fast: ${form.llm_fast_model.trim()}` : ''}{form.llm_reasoning_model.trim() ? ` · thinking: ${form.llm_reasoning_model.trim()}` : ''}</dd></div>
				<!-- Key is NEVER rendered in full — set/not-set plus a last-4 mask only. -->
				<div class="flex justify-between"><dt class="opacity-60">LLM API key</dt><dd data-testid="review-llm-key">{form.llm_api_key.trim() ? m.tnew_key_set({ last4: form.llm_api_key.trim().slice(-4) }) : m.tnew_key_not_set()}</dd></div>
			</dl>
			<p class="text-xs opacity-60">{m.tnew_submit_hint()} <code>pending → provisioning → active</code>.</p>
		{/if}
	</div>

	<div class="flex justify-between">
		<button class="btn variant-ghost-surface" on:click={prev} disabled={step === 1}>
			{m.tnew_back()}
		</button>
		{#if step < steps.length}
			<button
				class="btn variant-filled-primary"
				on:click={next}
				disabled={!stepValid || submitting}
			>
				{m.tnew_next()}
			</button>
		{:else}
			<button
				class="btn variant-filled-primary"
				data-testid="create-tenant"
				on:click={submit}
				disabled={submitting}
			>
				{#if submitting}
					<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
				{/if}
				{m.tnew_create()}
			</button>
		{/if}
	</div>
</div>
