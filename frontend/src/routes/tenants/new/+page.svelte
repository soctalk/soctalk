<script lang="ts">
	import { goto } from '$app/navigation';
	import {
		tenantsApi,
		type TenantOnboard,
		type ExternalSiemOnboard
	} from '$lib/api/tenants';
	import { addToast, authSession, isMsspScope } from '$lib/stores';

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
		goto('/');
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
		external_siem: undefined
	};

	// Reactive step list — the conditional 'External SIEM' step is spliced in
	// only for the 'provided' profile. Everything downstream (indicator,
	// content switch, Next/Create) keys off this.
	$: steps =
		form.profile === 'provided'
			? ['Identity', 'Profile', 'External SIEM', 'Branding', 'Review']
			: ['Identity', 'Profile', 'Branding', 'Review'];
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

	// Validity of the *current* step gates the Next button. Profile/Branding
	// have no required input so they are always advanceable.
	$: stepValid =
		currentLabel === 'Identity'
			? identityValid
			: currentLabel === 'External SIEM'
				? siemValid
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
			contact_email: form.contact_email,
			llm_base_url: form.llm_base_url,
			llm_model: form.llm_model
		};
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
				title: 'Tenant created',
				message: `Provisioning ${tenant.display_name} (${tenant.slug})…`
			});
			await goto(`/tenants/${tenant.id}`);
		} catch (e) {
			addToast({
				type: 'error',
				title: 'Onboard failed',
				message: e instanceof Error ? e.message : String(e)
			});
		} finally {
			submitting = false;
		}
	}
</script>

<div class="space-y-4 max-w-2xl mx-auto">
	<div class="flex items-center gap-3">
		<button class="btn btn-sm variant-ghost-surface" on:click={() => goto('/tenants')}>
			← Tenants
		</button>
	</div>
	<h1 class="h2">Create customer</h1>

	<!-- Step indicator -->
	<ol class="flex gap-2 text-sm opacity-70">
		{#each steps as label, i}
			<li
				data-testid="wizard-step"
				class:font-bold={step === i + 1}
				class:opacity-100={step === i + 1}
			>
				{i + 1}. {label}
			</li>
			{#if i < steps.length - 1}<li class="opacity-30">→</li>{/if}
		{/each}
	</ol>

	<div class="card p-6 space-y-4">
		{#if currentLabel === 'Identity'}
			<h3 class="h3">Identity</h3>
			<label class="label">
				<span class="font-medium">Display name</span>
				<input name="display_name" class="input" bind:value={form.display_name} placeholder="Acme Corp" />
			</label>
			<label class="label">
				<span class="font-medium">Slug</span>
				<input name="slug" class="input" bind:value={form.slug} placeholder="acme" />
				<small class="opacity-60">3–32 chars, lowercase letters/digits/hyphens. Used in URLs and namespace.</small>
			</label>
			<label class="label">
				<span class="font-medium">Contact email</span>
				<input
					name="contact_email"
					type="email"
					class="input"
					bind:value={form.contact_email}
					placeholder="ops@acme.example"
				/>
			</label>
		{:else if currentLabel === 'Profile'}
			<h3 class="h3">Profile</h3>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="poc" />
				<div>
					<div class="font-medium">PoC</div>
					<div class="text-sm opacity-70">
						Ephemeral, single-node, node-local storage, no ingress, tight resource quotas. Right for demo tenants.
					</div>
				</div>
			</label>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="persistent" />
				<div>
					<div class="font-medium">Persistent</div>
					<div class="text-sm opacity-70">
						Single-node but durable. PVC-backed indexer + manager. No HA (deferred).
					</div>
				</div>
			</label>
			<label class="flex items-start gap-3 p-3 rounded border border-surface-500/30 hover:border-primary-500 cursor-pointer">
				<input type="radio" class="radio" bind:group={form.profile} value="provided" />
				<div>
					<div class="font-medium">Provided (bring your own Wazuh)</div>
					<div class="text-sm opacity-70">
						The tenant already runs Wazuh. SocTalk deploys only the adapter + runs-worker
						and points them at your external indexer + API. You'll enter the credentials
						in the next step.
					</div>
				</div>
			</label>

			<details class="card p-3 bg-surface-500/10">
				<summary class="cursor-pointer text-sm opacity-80">LLM (advanced)</summary>
				<div class="mt-3 space-y-2">
					<label class="label">
						<span class="text-sm">Base URL</span>
						<input class="input" bind:value={form.llm_base_url} />
					</label>
					<label class="label">
						<span class="text-sm">Model</span>
						<input class="input" bind:value={form.llm_model} />
					</label>
				</div>
			</details>
		{:else if currentLabel === 'External SIEM'}
			<h3 class="h3">External SIEM</h3>
			<p class="text-sm opacity-70">
				SocTalk connects to your existing Wazuh. The Indexer (OpenSearch) and the API
				(manager) authenticate with separate credentials.
			</p>
			{#if form.external_siem}
				<div class="card p-4 space-y-4 bg-surface-500/10">
					<div class="space-y-2">
						<div class="text-sm font-medium">Wazuh Indexer (OpenSearch)</div>
						<label class="label">
							<span class="text-sm">Indexer URL</span>
							<input
								name="indexer_url"
								class="input"
								bind:value={form.external_siem.indexer_url}
								placeholder="https://indexer.example.com:9200"
							/>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="label">
								<span class="text-sm">Indexer username</span>
								<input
									name="indexer_username"
									class="input"
									bind:value={form.external_siem.indexer_username}
									placeholder="admin"
								/>
							</label>
							<label class="label">
								<span class="text-sm">Indexer password</span>
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
						<div class="text-sm font-medium">Wazuh API (manager)</div>
						<label class="label">
							<span class="text-sm">API URL</span>
							<input
								name="api_url"
								class="input"
								bind:value={form.external_siem.api_url}
								placeholder="https://wazuh.example.com:55000"
							/>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="label">
								<span class="text-sm">API username</span>
								<input
									name="api_username"
									class="input"
									bind:value={form.external_siem.api_username}
									placeholder="wazuh-wui"
								/>
							</label>
							<label class="label">
								<span class="text-sm">API password</span>
								<input
									name="api_password"
									type="password"
									class="input"
									bind:value={form.external_siem.api_password}
								/>
							</label>
						</div>
						<label class="label">
							<span class="text-sm">API token (optional)</span>
							<input
								name="api_token"
								type="password"
								class="input"
								bind:value={form.external_siem.api_token}
							/>
							<small class="opacity-60">Optional pre-minted manager token; overrides password auth.</small>
						</label>
					</div>
					<label class="flex items-center gap-2">
						<input
							name="verify_ssl"
							type="checkbox"
							class="checkbox"
							bind:checked={form.external_siem.verify_ssl}
						/>
						<span class="text-sm">Verify TLS certificates (uncheck for self-signed)</span>
					</label>
				</div>
			{/if}
		{:else if currentLabel === 'Branding'}
			<h3 class="h3">Branding</h3>
			<label class="label">
				<span class="font-medium">App name</span>
				<input
					name="branding_app_name"
					class="input"
					bind:value={form.branding_app_name}
					placeholder={form.display_name || 'Acme Security'}
				/>
			</label>
			<label class="label">
				<span class="font-medium">Logo URL</span>
				<input name="branding_logo_url" class="input" bind:value={form.branding_logo_url} placeholder="https://…/logo.svg" />
			</label>
			<div class="grid grid-cols-2 gap-3">
				<label class="label">
					<span class="font-medium">Primary color</span>
					<input type="color" class="input h-10" bind:value={form.branding_primary_color} />
				</label>
				<label class="label">
					<span class="font-medium">Secondary color</span>
					<input type="color" class="input h-10" bind:value={form.branding_secondary_color} />
				</label>
			</div>
		{:else if currentLabel === 'Review'}
			<h3 class="h3">Review</h3>
			<dl class="space-y-1 text-sm">
				<div class="flex justify-between"><dt class="opacity-60">Display name</dt><dd>{form.display_name}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">Slug</dt><dd><code class="text-xs">{form.slug}</code></dd></div>
				<div class="flex justify-between"><dt class="opacity-60">Profile</dt><dd>{form.profile}</dd></div>
				{#if form.profile === 'provided' && form.external_siem}
					<div class="flex justify-between"><dt class="opacity-60">Indexer URL</dt><dd><code class="text-xs">{form.external_siem.indexer_url || '—'}</code></dd></div>
					<div class="flex justify-between"><dt class="opacity-60">Indexer user</dt><dd>{form.external_siem.indexer_username || '—'}</dd></div>
					<div class="flex justify-between"><dt class="opacity-60">API URL</dt><dd><code class="text-xs">{form.external_siem.api_url || '—'}</code></dd></div>
					<div class="flex justify-between"><dt class="opacity-60">API user</dt><dd>{form.external_siem.api_username || '—'}</dd></div>
					<div class="flex justify-between"><dt class="opacity-60">Verify TLS</dt><dd>{form.external_siem.verify_ssl ? 'yes' : 'no'}</dd></div>
				{/if}
				<div class="flex justify-between"><dt class="opacity-60">Contact</dt><dd>{form.contact_email || '—'}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">App name</dt><dd>{form.branding_app_name || form.display_name}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">Primary</dt><dd>
					<span class="inline-block w-4 h-4 rounded align-middle mr-2" style="background:{form.branding_primary_color}"></span>
					<code class="text-xs">{form.branding_primary_color}</code>
				</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">LLM</dt><dd>{form.llm_model}</dd></div>
			</dl>
			<p class="text-xs opacity-60">
				Submitting kicks off namespace + chart provisioning. The tenant will land in <code>pending → provisioning → active</code>.
			</p>
		{/if}
	</div>

	<div class="flex justify-between">
		<button class="btn variant-ghost-surface" on:click={prev} disabled={step === 1}>
			Back
		</button>
		{#if step < steps.length}
			<button
				class="btn variant-filled-primary"
				on:click={next}
				disabled={!stepValid || submitting}
			>
				Next
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
				Create
			</button>
		{/if}
	</div>
</div>
