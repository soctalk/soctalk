<!--
  MSSP fleet dashboard — answers "where do I look now, across customers?"
  Renders on `/` when ``$isMsspScope`` is true (MSSP user with no
  ``current_tenant`` pin). Tenant-pinned MSSP users and customer roles
  see the per-tenant dashboard instead.

  Five widgets:
    1. Pending reviews by tenant
    2. Open investigations by tenant (oldest + max severity)
    3. Stuck cases (active + no activity in N hours)
    4. Per-tenant adapter health
    5. Repeated IOCs across ≥2 tenants (7d)

  Each widget is independently fetched + independently renders an
  empty state, so a slow query in one panel doesn't gate the others.

  Visual conventions match ``/tenants`` and ``/investigations``:
  - ``card overflow-hidden`` chrome around tables (no inner padding;
    the table provides its own).
  - ``table-container`` + ``table table-hover`` for striped, aligned
    rows with hover affordance.
  - Severity / state as ``badge variant-filled-*`` chips; "—" /
    "never" rendered ``opacity-40`` so empty data doesn't compete
    with real data.
  - UUIDs ``font-mono text-xs opacity-70`` with a ``title`` tooltip
    holding the full identifier.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import {
		api,
		type MsspPendingReviewRow,
		type MsspOpenByTenantRow,
		type MsspStuckInvestigationRow,
		type MsspTenantHealthRow,
		type MsspRepeatedIocRow
	} from '$lib/api/client';
	import { authSession } from '$lib/stores';

	// Same deep-link contract as MsspAnalytics: clicking a tenant
	// in an *operational* widget (open-by-tenant, pending reviews)
	// drops the analyst into the per-tenant SOC view, not the
	// management page. Tenant-health stays linked to /tenants/{id}
	// since its actions (retry / decommission) are admin-side.
	async function drillIntoTenant(slug: string) {
		try {
			const updated = await api.auth.assumeTenant(slug);
			authSession.update((s) => ({ ...s, user: updated }));
			await goto('/', { invalidateAll: true });
		} catch (e) {
			console.error('[Dashboard] drill-in failed:', e);
		}
	}

	let pendingReviews: MsspPendingReviewRow[] = [];
	let openByTenant: MsspOpenByTenantRow[] = [];
	let stuckInvestigations: MsspStuckInvestigationRow[] = [];
	let tenantHealth: MsspTenantHealthRow[] = [];
	let repeatedIocs: MsspRepeatedIocRow[] = [];
	let errors: Record<string, string> = {};
	let loading = true;

	const STUCK_HOURS = 8;
	const IOC_DAYS = 7;

	function severityLabel(s: number | null | undefined): string {
		if (s == null) return '—';
		if (s >= 12) return 'critical';
		if (s >= 8) return 'high';
		if (s >= 5) return 'medium';
		return 'low';
	}

	// Map numeric severity → Skeleton chip variant. Mirrors the
	// helper on /investigations so a "critical" pill looks identical
	// across the app: red for critical, amber for high, secondary for
	// medium, tertiary for low, soft for unknown.
	function severityChip(s: number | null | undefined): string {
		if (s == null) return 'variant-soft';
		if (s >= 12) return 'variant-filled-error';
		if (s >= 8) return 'variant-filled-warning';
		if (s >= 5) return 'variant-filled-secondary';
		return 'variant-filled-tertiary';
	}

	function tenantStateChip(state: string): string {
		switch (state) {
			case 'active':
				return 'variant-filled-success';
			case 'pending':
			case 'provisioning':
				return 'variant-filled-warning';
			case 'degraded':
				return 'variant-filled-error';
			default:
				return 'variant-soft';
		}
	}

	function ageSeconds(iso: string): number {
		return Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
	}

	function humanAge(seconds: number): string {
		if (seconds < 60) return `${seconds}s`;
		if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
		if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h`;
		return `${Math.floor(seconds / 86_400)}d`;
	}

	async function load(name: string, fn: () => Promise<unknown>) {
		try {
			return await fn();
		} catch (e) {
			// Svelte 4 reactivity: ``errors[name] = X`` doesn't notify
			// the template — reassign the object reference instead.
			errors = { ...errors, [name]: e instanceof Error ? e.message : String(e) };
			return null;
		}
	}

	onMount(async () => {
		const [pr, ob, st, th, ri] = await Promise.all([
			load('pendingReviews', () => api.msspDashboard.pendingReviews()),
			load('openByTenant', () => api.msspDashboard.openByTenant()),
			load('stuckInvestigations', () => api.msspDashboard.stuckInvestigations(STUCK_HOURS)),
			load('tenantHealth', () => api.msspDashboard.tenantHealth()),
			load('repeatedIocs', () => api.msspDashboard.repeatedIocs(IOC_DAYS))
		]);
		if (pr) pendingReviews = (pr as { items: MsspPendingReviewRow[] }).items;
		if (ob) openByTenant = (ob as { items: MsspOpenByTenantRow[] }).items;
		if (st) stuckInvestigations = (st as { items: MsspStuckInvestigationRow[] }).items;
		if (th) tenantHealth = (th as { items: MsspTenantHealthRow[] }).items;
		if (ri) repeatedIocs = (ri as { items: MsspRepeatedIocRow[] }).items;
		loading = false;
	});

	$: degradedTenants = tenantHealth.filter((t) => t.unhealthy);
	$: pendingReviewsTotal = pendingReviews.reduce((acc, r) => acc + r.count, 0);
</script>

<div class="space-y-6 p-6">
	<header class="flex items-center justify-between">
		<div>
			<h1 class="h2">MSSP Dashboard</h1>
			<p class="opacity-70 text-sm">Cross-tenant fleet view. Click a row to drill in.</p>
		</div>
	</header>

	<!-- TOP STRIP — KPI exceptions only.
	     Number ``text-3xl`` (was 2xl) and label ``text-sm uppercase``
	     (was xs uppercase) brings the size ratio to ~2:1 instead of
	     ~3.6:1 — the label survives at a glance instead of dissolving
	     beneath the number. -->
	<section class="grid grid-cols-1 md:grid-cols-4 gap-4">
		<div class="card p-4 space-y-1" data-testid="strip-pending-reviews">
			<div class="text-sm opacity-70 uppercase tracking-wide">Pending reviews</div>
			<div class="text-3xl font-semibold leading-tight">{pendingReviewsTotal}</div>
			<div class="text-xs opacity-60">
				across {pendingReviews.length} tenant{pendingReviews.length === 1 ? '' : 's'}
			</div>
		</div>
		<div class="card p-4 space-y-1" data-testid="strip-stuck">
			<div class="text-sm opacity-70 uppercase tracking-wide">Stuck cases ({STUCK_HOURS}h)</div>
			<div class="text-3xl font-semibold leading-tight">{stuckInvestigations.length}</div>
			<div class="text-xs opacity-60">no activity in {STUCK_HOURS}h</div>
		</div>
		<div class="card p-4 space-y-1" data-testid="strip-degraded">
			<div class="text-sm opacity-70 uppercase tracking-wide">Degraded tenants</div>
			<div
				class="text-3xl font-semibold leading-tight {degradedTenants.length
					? 'text-error-500'
					: ''}"
			>
				{degradedTenants.length}
			</div>
			<div class="text-xs opacity-60">adapter silent or non-active</div>
		</div>
		<div class="card p-4 space-y-1" data-testid="strip-iocs">
			<div class="text-sm opacity-70 uppercase tracking-wide">Repeated IOCs ({IOC_DAYS}d)</div>
			<div class="text-3xl font-semibold leading-tight">{repeatedIocs.length}</div>
			<div class="text-xs opacity-60">seen in ≥2 tenants</div>
		</div>
	</section>

	<!-- MAIN ROW: queue (left) + cross-tenant signal (right) -->
	<section class="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
		<!-- Open investigations by tenant -->
		<div class="space-y-2" data-testid="panel-open-by-tenant">
			<header class="flex items-baseline justify-between px-1">
				<h2 class="h3">Open investigations by tenant</h2>
				<span class="opacity-60 text-xs">oldest first</span>
			</header>
			{#if loading}
				<div class="card p-4"><p class="opacity-60 text-sm">Loading…</p></div>
			{:else if errors.openByTenant}
				<div class="card p-4"><p class="text-error-500 text-sm">{errors.openByTenant}</p></div>
			{:else if openByTenant.length === 0}
				<div class="card p-4">
					<p class="opacity-60 text-sm">No open investigations across the fleet.</p>
				</div>
			{:else}
				<div class="card overflow-hidden">
					<div class="table-container">
						<table class="table table-hover">
							<thead>
								<tr>
									<th>Tenant</th>
									<th class="text-center !w-20">Open</th>
									<th class="!w-24">Oldest</th>
									<th class="text-center !w-32">Max severity</th>
								</tr>
							</thead>
							<tbody>
								{#each openByTenant as r (r.tenant_id)}
									<tr>
										<td>
											<button
												type="button"
												class="anchor text-left bg-transparent border-0 p-0 cursor-pointer"
												on:click={() => drillIntoTenant(r.slug)}
												title="Open this tenant's SOC"
											>
												{r.display_name || r.slug}
											</button>
										</td>
										<td class="text-center font-medium">{r.open_count}</td>
										<td class="font-mono text-xs opacity-70">
											{r.oldest_opened_at
												? humanAge(ageSeconds(r.oldest_opened_at))
												: '—'}
										</td>
										<td class="text-center">
											<span class="badge {severityChip(r.max_severity)}">
												{severityLabel(r.max_severity)}
											</span>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}
		</div>

		<!-- Repeated IOCs across tenants -->
		<div class="space-y-2" data-testid="panel-repeated-iocs">
			<header class="flex items-baseline justify-between px-1">
				<h2 class="h3">Repeated IOCs across tenants</h2>
				<span class="opacity-60 text-xs">last {IOC_DAYS}d, ≥2 tenants</span>
			</header>
			{#if loading}
				<div class="card p-4"><p class="opacity-60 text-sm">Loading…</p></div>
			{:else if errors.repeatedIocs}
				<div class="card p-4"><p class="text-error-500 text-sm">{errors.repeatedIocs}</p></div>
			{:else if repeatedIocs.length === 0}
				<div class="card p-4">
					<p class="opacity-60 text-sm">
						No IOCs seen in ≥2 tenants in the last {IOC_DAYS} days.
					</p>
				</div>
			{:else}
				<div class="card overflow-hidden">
					<div class="table-container">
						<table class="table table-hover">
							<thead>
								<tr>
									<th class="!w-24">Type</th>
									<th>Value</th>
									<th class="text-center">Tenants</th>
									<th class="!w-24">Last seen</th>
									<th class="text-center !w-28">Severity</th>
								</tr>
							</thead>
							<tbody>
								{#each repeatedIocs as r (r.ioc_type + ':' + r.ioc_value)}
									<tr>
										<td>
											<span class="badge variant-soft text-xs">{r.ioc_type}</span>
										</td>
										<td>
											<code class="font-mono text-xs opacity-80">{r.ioc_value}</code>
										</td>
										<td
											class="text-center"
											title={r.tenants.map((t) => t.slug).join(', ')}
										>
											<span class="font-medium">{r.tenant_count}</span>
											<span class="text-xs opacity-60">
												({r.tenants.map((t) => t.slug).join(', ')})
											</span>
										</td>
										<td class="font-mono text-xs opacity-70">
											{humanAge(ageSeconds(r.last_seen))}
										</td>
										<td class="text-center">
											<span class="badge {severityChip(r.max_severity)}">
												{severityLabel(r.max_severity)}
											</span>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}
		</div>
	</section>

	<!-- LOWER ROW: stuck cases + tenant health -->
	<section class="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
		<div class="space-y-2" data-testid="panel-stuck-investigations">
			<header class="flex items-baseline justify-between px-1">
				<h2 class="h3">Stuck cases ({STUCK_HOURS}h)</h2>
				<span class="opacity-60 text-xs">oldest activity first</span>
			</header>
			{#if loading}
				<div class="card p-4"><p class="opacity-60 text-sm">Loading…</p></div>
			{:else if errors.stuckInvestigations}
				<div class="card p-4">
					<p class="text-error-500 text-sm">{errors.stuckInvestigations}</p>
				</div>
			{:else if stuckInvestigations.length === 0}
				<div class="card p-4"><p class="opacity-60 text-sm">No stuck cases — nice.</p></div>
			{:else}
				<div class="card overflow-hidden">
					<div class="table-container">
						<table class="table table-hover">
							<thead>
								<tr>
									<th class="!w-28">Case</th>
									<th>Tenant</th>
									<th class="!w-24">Stuck for</th>
									<th class="text-center !w-28">Severity</th>
								</tr>
							</thead>
							<tbody>
								{#each stuckInvestigations as c (c.investigation_id)}
									<tr>
										<td>
											<a
												href="/investigations/{c.investigation_id}"
												class="anchor font-mono text-xs"
												title={c.investigation_id}
											>
												{c.investigation_id.slice(0, 8)}…
											</a>
										</td>
										<td>{c.display_name || c.slug}</td>
										<td class="font-mono text-xs opacity-70">
											{humanAge(c.stuck_for_seconds)}
										</td>
										<td class="text-center">
											<span class="badge {severityChip(c.severity)}">
												{severityLabel(c.severity)}
											</span>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}
		</div>

		<div class="space-y-2" data-testid="panel-tenant-health">
			<header class="flex items-baseline justify-between px-1">
				<h2 class="h3">Tenant health</h2>
				<span class="opacity-60 text-xs">
					{degradedTenants.length} degraded / {tenantHealth.length} total
				</span>
			</header>
			{#if loading}
				<div class="card p-4"><p class="opacity-60 text-sm">Loading…</p></div>
			{:else if errors.tenantHealth}
				<div class="card p-4"><p class="text-error-500 text-sm">{errors.tenantHealth}</p></div>
			{:else if tenantHealth.length === 0}
				<div class="card p-4"><p class="opacity-60 text-sm">No tenants yet.</p></div>
			{:else}
				<div class="card overflow-hidden">
					<div class="table-container">
						<table class="table table-hover">
							<thead>
								<tr>
									<th>Tenant</th>
									<th class="text-center !w-32">State</th>
									<th class="!w-32">Last heartbeat</th>
								</tr>
							</thead>
							<tbody>
								{#each tenantHealth as t (t.tenant_id)}
									<tr>
										<td>
											<a href="/tenants/{t.tenant_id}" class="anchor">
												{t.display_name || t.slug}
											</a>
										</td>
										<td class="text-center">
											<span class="badge {tenantStateChip(t.state)}">{t.state}</span>
										</td>
										<td class="font-mono text-xs">
											{#if t.heartbeat_age_seconds == null}
												<span class="opacity-40">never</span>
											{:else}
												<span class="opacity-80">{humanAge(t.heartbeat_age_seconds)}</span>
											{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}
		</div>
	</section>

	<!-- Pending reviews per-tenant breakdown — compact list (not a
	     table). A 2-column table at full width put ``Tenant`` and
	     ``Pending`` 85%/15% apart with a sea of empty space between;
	     a flex list with ``max-w-md`` keeps the eye on the data. -->
	{#if pendingReviewsTotal > 0}
		<section class="space-y-2 max-w-md" data-testid="panel-pending-reviews">
			<header class="flex items-baseline justify-between px-1">
				<h2 class="h3">Pending reviews by tenant</h2>
			</header>
			<div class="card divide-y divide-surface-500/20">
				{#each pendingReviews as r (r.tenant_id)}
					<button
						type="button"
						class="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-surface-500/10 transition-colors"
						on:click={() => drillIntoTenant(r.slug)}
						title="Open this tenant's SOC"
					>
						<span class="anchor">{r.display_name || r.slug}</span>
						<span class="badge variant-soft-primary font-medium">{r.count}</span>
					</button>
				{/each}
			</div>
		</section>
	{/if}
</div>
