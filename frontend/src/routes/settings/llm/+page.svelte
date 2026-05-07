<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TenantLlmConfig } from '$lib/api/client';
	import { addToast, authSession, isMsspScope } from '$lib/stores';
	import { goto } from '$app/navigation';

	// Tenant-side BYOK page. Tenant_admins paste their own LLM API
	// key here so the runs-worker (which executes investigation
	// graphs FOR this tenant only) consumes the tenant's vendor
	// credential instead of the MSSP's shared install key.
	//
	// Provider + base URL are MSSP-controlled and shown read-only —
	// the install's outbound egress allowlist is provider-pinned, so
	// letting the tenant flip Anthropic→OpenAI from this form would
	// either DoS their own runs (egress blocked) or require us to
	// re-render Cilium policy at request time. Both worse than
	// "tenant supplies a credential within the MSSP's chosen
	// provider".

	let cfg: TenantLlmConfig | null = null;
	let loading = true;
	let saving = false;
	let clearing = false;
	let error: string | null = null;
	let pasted = '';

	onMount(async () => {
		try {
			cfg = await api.tenantLlm.get();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load LLM config';
		} finally {
			loading = false;
		}
	});

	// MSSP users can land here if they navigate by URL — bounce them
	// to the MSSP-side per-tenant LLM page rather than show a
	// permission error. Tenant-pinned MSSP users (Open SOC) DO see
	// this page and can paste a key on the tenant's behalf — that's
	// the legitimate use case for the wholesale model.
	$: if ($authSession.user && $isMsspScope) {
		goto('/tenants');
	}

	async function setKey() {
		if (!pasted.trim()) {
			error = 'Paste a non-empty API key';
			return;
		}
		saving = true;
		error = null;
		try {
			cfg = await api.tenantLlm.setKey(pasted.trim());
			pasted = '';
			addToast({
				type: 'success',
				title: 'LLM key updated',
				message:
					'Your investigation runs will use this key starting with the next case.',
			});
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to update LLM key';
		} finally {
			saving = false;
		}
	}

	async function clearKey() {
		clearing = true;
		error = null;
		try {
			cfg = await api.tenantLlm.clearKey();
			addToast({
				type: 'success',
				title: 'Reverted to MSSP shared key',
				message:
					'Your runs will resume on your service provider’s shared LLM credential.',
			});
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to clear LLM key';
		} finally {
			clearing = false;
		}
	}
</script>

<svelte:head>
	<title>LLM Settings — SocTalk</title>
</svelte:head>

<div class="space-y-6 max-w-3xl">
	<header class="flex items-baseline justify-between">
		<h1 class="h2">LLM Provider</h1>
		<a href="/settings" class="anchor text-sm">← All settings</a>
	</header>

	<p class="opacity-80 text-sm">
		Investigation runs use this credential to call your LLM provider.
		By default your service provider funds these calls on a shared
		install-wide key. Paste your own key below to bring your own
		account — your runs will be billed to <strong>you</strong>, not your
		MSSP.
	</p>

	{#if loading}
		<div class="card p-6 flex items-center gap-3">
			<span
				class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"
			></span>
			<span>Loading…</span>
		</div>
	{:else if !cfg}
		<div class="card p-6 text-error-500">
			{error ?? 'Failed to load configuration.'}
		</div>
	{:else}
		<div class="card p-6 space-y-5">
			<div>
				<h3 class="h4">Provider</h3>
				<dl class="grid grid-cols-3 gap-2 text-sm mt-2">
					<dt class="opacity-60">Vendor</dt>
					<dd class="col-span-2">
						<code class="text-xs">{cfg.provider}</code>
					</dd>
					<dt class="opacity-60">Endpoint</dt>
					<dd class="col-span-2">
						<code class="text-xs">{cfg.base_url}</code>
					</dd>
					<dt class="opacity-60">Model</dt>
					<dd class="col-span-2">
						<code class="text-xs">{cfg.model}</code>
					</dd>
				</dl>
				<p class="text-xs opacity-60 mt-2">
					These are configured by your service provider and apply to all
					tenants on this install. Contact your MSSP if you need a
					different provider.
				</p>
			</div>

			<hr class="opacity-30" />

			<div>
				<h3 class="h4">API key</h3>
				{#if cfg.has_api_key}
					<div
						class="mt-2 flex items-center gap-3 p-3 rounded
                          bg-success-500/10 border border-success-500/30"
					>
						<span class="badge variant-soft-success">BYOK active</span>
						<code class="text-xs">{cfg.api_key_preview}</code>
						<span class="text-xs opacity-70 ml-auto">
							Investigation runs use your key.
						</span>
					</div>
				{:else}
					<div
						class="mt-2 flex items-center gap-3 p-3 rounded
                          bg-warning-500/10 border border-warning-500/30"
					>
						<span class="badge variant-soft-warning">MSSP shared</span>
						<span class="text-xs">
							Your service provider's shared key is in use. Paste
							your own below to switch.
						</span>
					</div>
				{/if}

				<form
					on:submit|preventDefault={setKey}
					class="mt-4 space-y-3"
				>
					<label class="block">
						<span class="text-sm opacity-80">
							{cfg.has_api_key ? 'Replace key' : 'New API key'}
						</span>
						<input
							type="password"
							class="input mt-1"
							placeholder="sk-ant-… or sk-…"
							bind:value={pasted}
							autocomplete="off"
							disabled={saving || clearing}
						/>
					</label>
					<p class="text-xs opacity-60">
						Stored encrypted at rest in your service provider's
						control plane and mounted into your investigation
						worker only. Never visible to other tenants.
					</p>
					{#if error}
						<p class="text-error-500 text-sm">{error}</p>
					{/if}
					<div class="flex items-center gap-2">
						<button
							type="submit"
							class="btn variant-filled-primary"
							disabled={saving || clearing || !pasted.trim()}
						>
							{saving ? 'Saving…' : cfg.has_api_key ? 'Replace key' : 'Save key'}
						</button>
						{#if cfg.has_api_key}
							<button
								type="button"
								class="btn variant-ghost-surface"
								on:click={clearKey}
								disabled={saving || clearing}
								title="Stop using your own key; resume on the MSSP shared credential."
							>
								{clearing ? 'Reverting…' : 'Revert to MSSP shared'}
							</button>
						{/if}
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>
