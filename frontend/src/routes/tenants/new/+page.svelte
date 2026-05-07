<script lang="ts">
	import { goto } from '$app/navigation';
	import { tenantsApi, type TenantOnboard } from '$lib/api/tenants';
	import { addToast, authSession, isMsspScope } from '$lib/stores';

	// 4-step onboarding: identity → profile → branding → review.
	// Mirrors the e2e contract (slug placeholder ``acme``, profile radio
	// ``value=poc``, ``data-testid=create-tenant``) so existing tests
	// keep working when pointed at canonical.

	let step = 1;
	let submitting = false;

	// Auth lands asynchronously from the layout's /api/auth/me call;
	// only redirect once the session is actually resolved AND the user
	// is non-MSSP. Otherwise the page would race the layout and
	// redirect every fresh load.
	$: if ($authSession.user && !$isMsspScope) {
		goto('/');
	}

	const form: TenantOnboard = {
		slug: '',
		display_name: '',
		profile: 'poc',
		branding_app_name: '',
		branding_logo_url: '',
		branding_primary_color: '#1a73e8',
		branding_secondary_color: '#fbbc04',
		contact_email: '',
		llm_base_url: 'https://api.openai.com/v1',
		llm_model: 'gpt-4o'
	};

	$: slugValid = /^[a-z0-9-]{3,32}$/.test(form.slug);
	$: step1Valid = !!form.display_name.trim() && slugValid;

	function next() {
		if (step < 4) step += 1;
	}

	function prev() {
		if (step > 1) step -= 1;
	}

	async function submit() {
		submitting = true;
		try {
			const tenant = await tenantsApi.onboard(form);
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
		{#each ['Identity', 'Profile', 'Branding', 'Review'] as label, i}
			<li class:font-bold={step === i + 1} class:opacity-100={step === i + 1}>
				{i + 1}. {label}
			</li>
			{#if i < 3}<li class="opacity-30">→</li>{/if}
		{/each}
	</ol>

	<div class="card p-6 space-y-4">
		{#if step === 1}
			<h3 class="h3">Identity</h3>
			<label class="label">
				<span class="font-medium">Display name</span>
				<input class="input" bind:value={form.display_name} placeholder="Acme Corp" />
			</label>
			<label class="label">
				<span class="font-medium">Slug</span>
				<input class="input" bind:value={form.slug} placeholder="acme" />
				<small class="opacity-60">3–32 chars, lowercase letters/digits/hyphens. Used in URLs and namespace.</small>
			</label>
			<label class="label">
				<span class="font-medium">Contact email</span>
				<input
					type="email"
					class="input"
					bind:value={form.contact_email}
					placeholder="ops@acme.example"
				/>
			</label>
		{:else if step === 2}
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
		{:else if step === 3}
			<h3 class="h3">Branding</h3>
			<label class="label">
				<span class="font-medium">App name</span>
				<input
					class="input"
					bind:value={form.branding_app_name}
					placeholder={form.display_name || 'Acme Security'}
				/>
			</label>
			<label class="label">
				<span class="font-medium">Logo URL</span>
				<input class="input" bind:value={form.branding_logo_url} placeholder="https://…/logo.svg" />
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
		{:else if step === 4}
			<h3 class="h3">Review</h3>
			<dl class="space-y-1 text-sm">
				<div class="flex justify-between"><dt class="opacity-60">Display name</dt><dd>{form.display_name}</dd></div>
				<div class="flex justify-between"><dt class="opacity-60">Slug</dt><dd><code class="text-xs">{form.slug}</code></dd></div>
				<div class="flex justify-between"><dt class="opacity-60">Profile</dt><dd>{form.profile}</dd></div>
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
		{#if step < 4}
			<button
				class="btn variant-filled-primary"
				on:click={next}
				disabled={(step === 1 && !step1Valid) || submitting}
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
