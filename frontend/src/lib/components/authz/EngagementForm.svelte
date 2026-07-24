<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { m } from '$lib/paraglide/messages';
	import type { TenantEngagement } from '$lib/api/client';

	// Declare a bounded pentest/red-team window. Client-side validation mirrors the
	// server's fail-closed rules (core/ir/campaign.py) so an invalid scope is caught
	// inline instead of coming back as a raw 400: a tester source axis is REQUIRED and
	// so is at least one bounded target axis, because an empty scope would deconflict
	// every alert in the window.
	export let saving = false;
	export let error: string | null = null;
	// When cloning an existing engagement, carry its scope but never its window.
	export let seed: TenantEngagement | null = null;

	const dispatch = createEventDispatcher();

	let name = seed?.name ?? '';
	let kind = seed?.kind ?? 'pentest';
	let startsAt = '';
	let endsAt = '';
	let sourceIps = (seed?.scope_source_ips ?? []).join(', ');
	let hosts = (seed?.scope_hosts ?? []).join(', ');
	let techniques = (seed?.scope_techniques ?? []).join(', ');
	let localError: string | null = null;

	function csv(s: string): string[] {
		return s
			.split(',')
			.map((v) => v.trim())
			.filter((v) => v.length > 0);
	}

	// IPv4/IPv6/CIDR shape check: rejects out-of-range octets and CIDR bits.
	function looksLikeIp(v: string): boolean {
		const slash = v.indexOf('/');
		const addr = slash >= 0 ? v.slice(0, slash) : v;
		const cidr = slash >= 0 ? v.slice(slash + 1) : undefined;
		const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
		if (v4) {
			if (!v4.slice(1).every((o) => Number(o) <= 255)) return false;
			return cidr === undefined || (/^\d+$/.test(cidr) && Number(cidr) <= 32);
		}
		if (addr.includes(':') && /^[0-9a-fA-F:.]+$/.test(addr)) {
			return cidr === undefined || (/^\d+$/.test(cidr) && Number(cidr) <= 128);
		}
		return false;
	}

	function validate(): string | null {
		if (!name.trim()) return m.authz_err_eng_name();
		const start = new Date(startsAt).getTime();
		const end = new Date(endsAt).getTime();
		if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return m.authz_err_eng_window();
		if (end - start > 90 * 24 * 60 * 60 * 1000) return m.authz_err_eng_max_days();
		const ips = csv(sourceIps);
		if (!ips.length || !ips.every(looksLikeIp)) return m.authz_err_eng_source_ip();
		const techs = csv(techniques).map((t) => t.toUpperCase());
		if (!csv(hosts).length && !techs.length) return m.authz_err_eng_target();
		if (techs.length && !techs.every((t) => /^T\d{4}(\.\d{3})?$/.test(t)))
			return m.authz_err_eng_technique();
		return null;
	}

	function submit() {
		localError = validate();
		if (localError) return;
		dispatch('submit', {
			name,
			kind,
			starts_at: new Date(startsAt).toISOString(),
			ends_at: new Date(endsAt).toISOString(),
			scope_source_ips: csv(sourceIps),
			scope_hosts: csv(hosts),
			scope_techniques: csv(techniques).map((t) => t.toUpperCase())
		});
	}
</script>

<form class="card p-4 rounded border space-y-3" on:submit|preventDefault={submit}>
	<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_name()}</span>
			<input class="input" bind:value={name} required placeholder={m.adm_placeholder_engagement_name()} />
		</label>
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_kind()}</span>
			<select class="select" bind:value={kind}>
				<option value="pentest">pentest</option>
				<option value="red_team">red_team</option>
				<option value="vuln_scan">vuln_scan</option>
			</select>
		</label>
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_starts()}</span>
			<input class="input" type="datetime-local" bind:value={startsAt} required />
		</label>
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_ends()}</span>
			<input class="input" type="datetime-local" bind:value={endsAt} required />
		</label>
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_source_ips()}</span>
			<input class="input font-mono" bind:value={sourceIps} placeholder="203.0.113.0/24" />
		</label>
		<label class="flex flex-col gap-1">
			<span class="opacity-70">{m.adm_field_hosts()}</span>
			<input class="input font-mono" bind:value={hosts} placeholder="web-01, db-01" />
		</label>
		<label class="flex flex-col gap-1 sm:col-span-2">
			<span class="opacity-70">{m.authz_field_techniques()}</span>
			<input class="input font-mono" bind:value={techniques} placeholder="T1078, T1110.001" />
		</label>
	</div>
	{#if localError ?? error}
		<div class="alert variant-filled-error text-sm"><span>{localError ?? error}</span></div>
	{/if}
	<div class="flex justify-end gap-2">
		<button type="button" class="px-3 py-2 text-sm" on:click={() => dispatch('cancel')}>
			{m.common_cancel()}
		</button>
		<button type="submit" class="px-3 py-2 rounded bg-blue-600 text-white text-sm" disabled={saving}>
			{saving ? m.adm_declaring() : m.adm_declare()}
		</button>
	</div>
</form>
