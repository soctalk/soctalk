<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type AuthSession } from '$lib/api/client';
	import { addToast, authSession, tenantContext } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';
	import { localizedGoto } from '$lib/i18n';

	// Dev convenience: pre-fill the bootstrap admin creds when running
	// vite dev so you can hit Sign in immediately. Stripped from
	// production builds — ``import.meta.env.DEV`` is constant-folded
	// by Vite so the strings never reach a built bundle.
	let email = import.meta.env.DEV ? 'auto1969@example.test' : '';
	let password = import.meta.env.DEV ? 'dev-admin-pw-12345' : '';
	let loading = true;
	let submitting = false;
	let mode: AuthSession['mode'] = 'none';
	let enabled = false;

	onMount(async () => {
		try {
			const session = await api.auth.session();
			authSession.set(session);
			enabled = session.enabled;
			mode = session.mode;

			if (!session.enabled || session.user) {
				await localizedGoto('/');
			}
		} catch (e) {
			addToast({
				type: 'error',
				title: m.login_error_title(),
				message: e instanceof Error ? e.message : m.login_session_check_failed()
			});
		} finally {
			loading = false;
		}
	});

	async function submit() {
		submitting = true;
		try {
			// Only pin tenant_slug when the URL is a *tenant* slug. MSSP
			// slugs identify the install, not a tenant scope — login
			// resolves to the user's own tenant_id (or cross-tenant for
			// mssp_admin) without a slug pin.
			const res = await api.auth.login({
				email,
				password,
				tenant_slug:
					$tenantContext?.kind === 'tenant' ? $tenantContext.slug : null
			});
			authSession.set({ enabled: true, mode: 'internal', user: res.user });
			// Bootstrap admins land with must_change=true. Until they
			// clear it, the auth middleware rejects every non-whitelisted
			// API call — sending them to /account/password is the only
			// usable surface, so don't drop them on the dashboard.
			if (res.must_change) {
				await localizedGoto('/account/password?must_change=1');
			} else {
				await localizedGoto('/');
			}
		} catch (e) {
			addToast({
				type: 'error',
				title: m.login_failed_title(),
				message: e instanceof Error ? e.message : m.login_invalid_creds()
			});
		} finally {
			submitting = false;
		}
	}

	async function refresh() {
		loading = true;
		try {
			const session = await api.auth.session();
			authSession.set(session);
			enabled = session.enabled;
			mode = session.mode;
			if (!session.enabled || session.user) {
				await localizedGoto('/');
			}
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-[calc(100vh-2rem)] flex items-center justify-center p-4">
	<div class="card max-w-md w-full p-6 space-y-4">
		<div class="space-y-1">
			{#if $tenantContext?.branding.logo_url}
				<img src={$tenantContext.branding.logo_url} alt="" class="h-10 mb-2" />
			{/if}
			<h1 class="h2">{m.login_title()}</h1>
			<p class="text-sm opacity-70">
				{$tenantContext?.branding.app_name ?? 'SocTalk Control Plane'}
			</p>
			{#if $tenantContext}
				<p class="text-xs opacity-50">
					{$tenantContext.kind === 'mssp' ? m.scope_mssp() : m.scope_tenant()}:
					<code>{$tenantContext.slug}</code>
				</p>
			{/if}
		</div>

		{#if loading}
			<div class="flex items-center gap-2 opacity-70">
				<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
				<span>{m.login_loading()}</span>
			</div>
		{:else if !enabled}
			<p class="opacity-70">{m.login_auth_disabled()}</p>
			<button type="button" class="btn variant-filled-primary" on:click={() => localizedGoto('/')}>{m.login_continue()}</button>
		{:else if mode === 'proxy'}
			<p class="opacity-70">{m.login_proxy_hint()}</p>
			<button type="button" class="btn variant-filled-primary" on:click={refresh} disabled={loading}>
				{m.login_refresh()}
			</button>
		{:else}
			<form class="space-y-3" on:submit|preventDefault={submit}>
				<label class="label">
					<span class="font-medium">{m.login_email()}</span>
					<input type="email" class="input" autocomplete="email" bind:value={email} />
				</label>
				<label class="label">
					<span class="font-medium">{m.login_password()}</span>
					<input type="password" class="input" autocomplete="current-password" bind:value={password} />
				</label>
				<button type="submit" class="btn variant-filled-primary w-full" disabled={submitting}>
					{#if submitting}
						<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
					{/if}
					{m.login_submit()}
				</button>
			</form>
		{/if}
	</div>
</div>

