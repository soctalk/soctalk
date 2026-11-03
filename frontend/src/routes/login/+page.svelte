<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { api, ApiError, type AuthSession } from '$lib/api/client';
	import { safeNextPath } from '$lib/auth/session-expiry';
	import { addToast, authSession, tenantContext } from '$lib/stores';
	import { m } from '$lib/paraglide/messages';
	import { localizedGoto } from '$lib/i18n';
	import { formatDateTime } from '$lib/i18n/format';

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
	// Shown inline under the form until the next attempt. A toast is easy to
	// miss and times out; a failed sign-in must stay on screen.
	let loginError = '';

	// Why the user is here (internal-auth §8.4, §8.6): an expired session or
	// a sign-out. Informational, not an error, and gone once they submit.
	let noticeDismissed = false;
	$: notice = noticeDismissed
		? ''
		: $page.url.searchParams.get('expired') === '1'
			? m.login_session_expired()
			: $page.url.searchParams.get('signed_out') === '1'
				? m.login_signed_out()
				: '';

	// Where to go once signed in: `next` when it is a same-origin app path,
	// else the landing route. localizedGoto re-applies this page's locale.
	$: landing = safeNextPath($page.url.searchParams.get('next')) ?? '/';

	/** Locked-until timestamp from a 423, whose detail is an object. */
	function lockedUntil(e: ApiError): string | null {
		try {
			const body = JSON.parse(e.message) as { detail?: { locked_until?: unknown } };
			const until = body.detail?.locked_until;
			return typeof until === 'string' ? until : null;
		} catch {
			return null;
		}
	}

	function describeLoginError(e: unknown): string {
		if (e instanceof ApiError) {
			if (e.status === 401) return m.login_invalid_creds();
			if (e.status === 429) return m.login_too_many_attempts();
			if (e.status === 423) {
				const until = lockedUntil(e);
				return until
					? m.login_locked_until({ until: formatDateTime(until) })
					: m.login_locked();
			}
		}
		return e instanceof Error && e.message ? e.message : m.login_invalid_creds();
	}

	onMount(async () => {
		try {
			const session = await api.auth.session();
			authSession.set(session);
			enabled = session.enabled;
			mode = session.mode;

			if (!session.enabled || session.user) {
				await localizedGoto(landing);
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
		loginError = '';
		noticeDismissed = true;
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
			// usable surface, so don't drop them on the dashboard (nor on
			// `next`, which would bounce straight back there).
			if (res.must_change) {
				await localizedGoto('/account/password?must_change=1');
			} else {
				await localizedGoto(landing);
			}
		} catch (e) {
			loginError = describeLoginError(e);
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
				await localizedGoto(landing);
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

		{#if notice}
			<div class="alert variant-soft-primary p-3" role="status" data-testid="login-notice">
				<p class="alert-message text-sm">{notice}</p>
			</div>
		{/if}

		{#if loading}
			<div class="flex items-center gap-2 opacity-70">
				<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current"></span>
				<span>{m.login_loading()}</span>
			</div>
		{:else if !enabled}
			<p class="opacity-70">{m.login_auth_disabled()}</p>
			<button type="button" class="btn variant-filled-primary" on:click={() => localizedGoto(landing)}>{m.login_continue()}</button>
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
				{#if loginError}
					<div class="alert variant-soft-error p-3" role="alert">
						<div class="alert-message">
							<p class="font-medium">{m.login_failed_title()}</p>
							<p class="text-sm">{loginError}</p>
						</div>
					</div>
				{/if}
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

