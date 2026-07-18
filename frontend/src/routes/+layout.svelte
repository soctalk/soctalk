<script lang="ts">
	import '../app.css';
	import { onMount, onDestroy } from 'svelte';
	import { page } from '$app/stores';
	import { api } from '$lib/api/client';
	import {
		initSSE,
		closeSSE,
		sseStatus,
		pendingReviewsCount,
		authSession,
		canReview,
		isAuthenticated,
		isMsspScope,
		isMsspUser,
		canChat,
		canManageTenantUsers,
		canManageUsers,
		canViewTenantAuthorization,
		tenantContext,
		detectSlugFromHostname
	} from '$lib/stores';
	import Toast from '$lib/components/Toast.svelte';
	import { AppShell, AppBar, AppRail, AppRailAnchor } from '@skeletonlabs/skeleton';
	import { m } from '$lib/paraglide/messages';
	import type { Locale } from '$lib/paraglide/runtime';
	import {
		LOCALE_LABELS,
		SUPPORTED_LOCALES,
		currentLocale,
		localizeHref,
		localizedGoto,
		stripLocale,
		switchLocale
	} from '$lib/i18n';

	// Navigation items. `label` holds the message FUNCTION (called at render
	// time) — never evaluate messages at module scope (#52: the locale is set
	// by the layout load, after this module initializes).
	const navItems = [

		{ href: '/', label: m.nav_dashboard, icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
		{ href: '/tenants', label: m.nav_tenants, icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4', mssp: true },
		{ href: '/investigations', label: m.nav_investigations, icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' },
		{ href: '/review', label: m.nav_reviews, icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z', badge: true, review: true },
		{ href: '/chat', label: m.nav_chat, icon: 'M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z', chat: true },
		{ href: '/analytics', label: m.nav_analytics, icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
		{ href: '/audit', label: m.nav_audit_log, icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
		{ href: '/triage-policies', label: m.nav_triage_policies, icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253', msspUser: true },
		{ href: '/response-playbooks', label: m.nav_response_playbooks, icon: 'M13 10V3L4 14h7v7l9-11h-7z', msspUser: true },
		{ href: '/authorization', label: m.nav_authorization, icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', msspUser: true },
		{ href: '/mssp-users', label: m.nav_staff_users, icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', manageUsers: true },
		{ href: '/my-authorization', label: m.nav_authorization, icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', tenantAuthz: true },
		{ href: '/tenant-users', label: m.nav_users, icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', tenantUsers: true },
		{ href: '/settings', label: m.nav_settings, icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z' }

	];

	// All path comparisons run on the locale-STRIPPED pathname (#52): the URL
	// may carry a /pt-br style prefix that reroute does not remove from
	// page.url. Links go the other way through localizeHref().
	let currentPath = '/';
	$: currentPath = stripLocale($page.url.pathname);

	const locale = currentLocale();

	let visibleNavItems = navItems;
	let sseStarted = false;
	let authReady = false;

	$: if (authReady && !sseStarted && $isAuthenticated && currentPath !== '/login') {
		initSSE();
		sseStarted = true;
	}
	$: if (sseStarted && (!authReady || !$isAuthenticated)) {
		closeSSE();
		sseStarted = false;
	}

	onMount(async () => {
		// Slug-driven landing: extract leading slug from the host and
		// let the server decide whether it's an MSSP or a tenant
		// (single endpoint /api/public/scope-by-slug). Failures are
		// non-fatal — fall through to generic SocTalk branding.
		try {
			const slug = detectSlugFromHostname(window.location.hostname);
			if (slug) {
				const scope = await api.public.scopeBySlug(slug);
				tenantContext.set(scope);
			}
		} catch (e) {
			if (import.meta.env.DEV) console.warn('[Slug] resolution failed:', e);
		}

		try {
			const session = await api.auth.session();
			authSession.set(session);

			if (session.enabled && !session.user && currentPath !== '/login') {
				await localizedGoto('/login');
			}
		} catch (e) {
			// Session check failed (API unreachable, auth misconfigured, or an
			// old API without /api/auth/me). Without a user the dashboard would
			// wait forever on a spinner — route to /login so the failure is
			// visible and diagnosable instead of silent.
			console.error('[Auth] session check failed:', e);
			if (currentPath !== '/login') {
				await localizedGoto('/login');
			}
		} finally {
			authReady = true;
		}
	});

	onDestroy(() => {
		closeSSE();
	});

	async function logout() {
		try {
			await api.auth.logout();
		} finally {
			authSession.update((s) => ({ ...s, user: null }));
			closeSSE();
			sseStarted = false;
			if ($authSession.enabled) {
				await localizedGoto('/login');
			}
		}
	}

	// Scope-chip: lets MSSP users clear an active tenant pin and return
	// to the cross-tenant view; hidden for tenant-bound users (whose
	// scope is fixed to their home tenant). After the API switch we
	// re-navigate to the dashboard with ``invalidateAll`` so the
	// currently-rendered page data (loaded under the old pin) refreshes
	// against the new cross-tenant session.
	async function clearTenantScope() {
		try {
			const updated = await api.auth.assumeTenant(null);
			authSession.update((s) => ({ ...s, user: updated }));
			await localizedGoto('/', { invalidateAll: true });
		} catch (e) {
			if (import.meta.env.DEV) console.error('[Scope] clear failed:', e);
		}
	}

	function onLocaleChange(e: Event) {
		const next = (e.currentTarget as HTMLSelectElement).value as Locale;
		switchLocale(next, $page.url.pathname, $page.url.search);
	}

	$: visibleNavItems = navItems.filter((item) => {
		if (item.review && !$canReview) return false;
		if (item.chat && !$canChat) return false;
		if (item.mssp && !$isMsspScope) return false;
		// Visible to any MSSP-type user regardless of tenant-pin state — used by
		// surfaces that make sense both cross-tenant and while pinned (Triage Policies:
		// built-ins are install-wide, authored triage policies are per pinned tenant).
		if (item.msspUser && !$isMsspUser) return false;
		// Tenant self-service surfaces (Engagements) — only for tenant-audience users that hold
		// the capability; MSSP operators don't get the tenant nav item.
		if (item.tenantAuthz && !$canViewTenantAuthorization) return false;
		if (item.tenantUsers && !$canManageTenantUsers) return false;
		if (item.manageUsers && !$canManageUsers) return false;
		return true;
	});
</script>

{#if currentPath === '/login'}
	<slot />
{:else}
<AppShell>
	<svelte:fragment slot="sidebarLeft">
		<AppRail>
			<!-- Logo/Brand -->
			<svelte:fragment slot="lead">
				<AppRailAnchor href={localizeHref('/')} class="lg:aspect-auto">
					<div class="flex flex-col items-center gap-1 py-2">
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-8 w-8"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
							/>
						</svg>
						<span class="text-xs font-bold">SocTalk</span>
					</div>
				</AppRailAnchor>
			</svelte:fragment>

			<!-- Navigation Items -->
			{#each visibleNavItems as item}
				<AppRailAnchor
					href={localizeHref(item.href)}
					selected={currentPath === item.href || (item.href !== '/' && currentPath.startsWith(item.href))}
				>
					<svelte:fragment slot="lead">
						<div class="relative">
							<svg
								xmlns="http://www.w3.org/2000/svg"
								class="h-6 w-6"
								fill="none"
								viewBox="0 0 24 24"
								stroke="currentColor"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d={item.icon}
								/>
							</svg>
							{#if item.badge && $pendingReviewsCount > 0}
								<span class="badge-icon variant-filled-warning absolute -top-1 -right-1 text-xs">
									{$pendingReviewsCount}
								</span>
							{/if}
						</div>
					</svelte:fragment>
					<span class="text-xs block text-center whitespace-normal [overflow-wrap:anywhere] [hyphens:auto] leading-tight"
					>{item.label()}</span
				>
				</AppRailAnchor>
			{/each}

			<!-- Locale switcher + SSE status -->
			<svelte:fragment slot="trail">
				<div class="p-2 flex flex-col items-center gap-2">
					<select
						class="select text-xs !py-0.5 max-w-[5rem]"
						data-testid="locale-switcher"
						title={m.language()}
						value={locale}
						on:change={onLocaleChange}
					>
						{#each SUPPORTED_LOCALES as loc}
							<option value={loc}>{LOCALE_LABELS[loc]}</option>
						{/each}
					</select>
					<div
						class="w-3 h-3 rounded-full {$sseStatus.connected
							? 'bg-green-500 status-indicator-active'
							: 'bg-red-500 status-indicator-error'}"
						title={$sseStatus.connected ? m.status_connected() : $sseStatus.error || m.status_disconnected()}
					></div>
					<span class="text-xs opacity-60">
						{$sseStatus.connected ? m.status_live() : m.status_offline()}
					</span>
				</div>
			</svelte:fragment>
		</AppRail>
	</svelte:fragment>

	<svelte:fragment slot="header">
		<AppBar class="border-b border-surface-500/30">
			<svelte:fragment slot="lead">
				<div class="h4">
					{#if currentPath === '/'}
						{m.nav_dashboard()}
					{:else if currentPath.startsWith('/investigations')}
						{m.nav_investigations()}
					{:else if currentPath.startsWith('/review')}
						{m.header_human_review()}
					{:else if currentPath.startsWith('/analytics')}
						{m.nav_analytics()}
					{:else if currentPath.startsWith('/audit')}
						{m.nav_audit_log()}
					{:else if currentPath.startsWith('/triage-policies')}
						{m.nav_triage_policies()}
					{:else if currentPath.startsWith('/settings')}
						{m.nav_settings()}
					{/if}
				</div>
			</svelte:fragment>
			<svelte:fragment slot="trail">
				<div class="flex items-center gap-3">
					{#if $authSession.enabled && $authSession.user}
						<!-- Scope chip: makes "all tenants" vs "single tenant"
						     visually unambiguous so MSSP users never confuse
						     cross-tenant context for a single-tenant SIEM. -->
						{#if $authSession.user.current_tenant && ($authSession.user.current_tenant_display_name || $authSession.user.current_tenant_slug)}
							<div class="flex items-center gap-1">
								<span class="badge variant-filled-warning text-xs">
									{m.chip_tenant()}
									{$authSession.user.current_tenant_display_name ||
										$authSession.user.current_tenant_slug}
								</span>
								{#if $isMsspUser}
									<button
										type="button"
										class="btn btn-sm variant-ghost-warning text-xs"
										title={m.chip_clear_title()}
										on:click={clearTenantScope}
									>
										{m.chip_clear()}
									</button>
								{/if}
							</div>
						{:else if $isMsspScope}
							<a
								href={localizeHref('/tenants')}
								class="badge variant-soft-primary text-xs"
								title={m.chip_all_tenants_title()}
							>
								{m.chip_all_tenants()}
							</a>
						{/if}
						<div class="flex flex-col items-end">
							<span class="text-sm opacity-90">{$authSession.user.email}</span>
							<span class="text-xs opacity-60">
								{$authSession.user.role}
							</span>
						</div>
						<button type="button" class="btn btn-sm variant-ghost-surface" on:click={logout}>
							{m.logout()}
						</button>
					{:else}
						<span class="text-sm opacity-60">{m.tagline()}</span>
					{/if}
				</div>
			</svelte:fragment>
		</AppBar>
	</svelte:fragment>

	<!-- Page Content -->
	<div class="container mx-auto p-4">
		<slot />
	</div>
</AppShell>

<!-- Toast Notifications -->
<Toast />
{/if}
