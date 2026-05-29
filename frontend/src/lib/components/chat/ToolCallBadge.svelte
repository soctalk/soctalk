<!--
  Compact "the agent ran a tool" indicator. Defaults to collapsed
  ("queried 30 events ✓"); expand on click to show args+result JSON.
-->
<script lang="ts">
	export let name: string;
	export let args: Record<string, unknown>;
	export let result: unknown = undefined;
	export let truncated = false;

	let expanded = false;

	// Pull the _tenant envelope (added by the agent dispatcher in
	// fleet-scope conversations) so the badge can show "@ acme-corp".
	// Tenant-scope results don't carry it (would be redundant).
	$: tenantSlug = (() => {
		const data = (result as { data?: unknown })?.data ?? result;
		if (data && typeof data === 'object') {
			const env = (data as Record<string, unknown>)._tenant;
			if (env && typeof env === 'object') {
				return String((env as Record<string, unknown>).slug ?? '');
			}
		}
		return '';
	})();

	function summarise(): string {
		if (result === undefined) return 'running…';
		const raw = (result as { data?: unknown })?.data ?? result;
		// Strip the _tenant envelope before summarising — when the
		// agent wraps a list as {"_tenant": ..., "rows": [...]}, the
		// row count is on .rows; bare-list responses keep the
		// original shape.
		const data = (() => {
			if (raw && typeof raw === 'object' && '_tenant' in (raw as object)) {
				const r = (raw as Record<string, unknown>).rows;
				return r !== undefined ? r : raw;
			}
			return raw;
		})();
		if (Array.isArray(data)) return `${data.length} rows${truncated ? ', truncated' : ''}`;
		if (data && typeof data === 'object') {
			const obj = data as Record<string, unknown>;
			if (obj.error) return `error: ${String(obj.error).slice(0, 60)}`;
			return Object.keys(obj).filter(k => k !== '_tenant').slice(0, 3).join(', ');
		}
		return String(data).slice(0, 60);
	}

	function shortArgs(): string {
		const entries = Object.entries(args)
			// Hide tenant_slug from the arg display — it shows up in the
			// "@ slug" badge already; printing it twice is noise.
			.filter(([k]) => k !== 'tenant_slug')
			.slice(0, 2);
		return entries.map(([k, v]) => `${k}=${JSON.stringify(v).slice(0, 24)}`).join(', ');
	}
</script>

<button
	type="button"
	class="badge variant-soft-tertiary text-xs cursor-pointer hover:opacity-80 self-start text-left max-w-full"
	on:click={() => (expanded = !expanded)}
>
	<svg
		xmlns="http://www.w3.org/2000/svg"
		class="h-3 w-3 inline-block mr-1"
		fill="none"
		viewBox="0 0 24 24"
		stroke="currentColor"
	>
		<path
			stroke-linecap="round"
			stroke-linejoin="round"
			stroke-width="2"
			d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
		/>
	</svg>
	<span class="font-mono">{name}({shortArgs()})</span>
	{#if tenantSlug}
		<span class="badge variant-soft-secondary text-xs ml-1">@ {tenantSlug}</span>
	{/if}
	<span class="opacity-70 ml-1">→ {summarise()}</span>
	{#if truncated}<span class="badge variant-soft-warning text-xs ml-1">truncated</span>{/if}
</button>

{#if expanded}
	<div class="bg-surface-700 rounded p-2 text-xs font-mono overflow-x-auto max-h-48 overflow-y-auto">
		<div class="opacity-70 mb-1">args:</div>
		<pre>{JSON.stringify(args, null, 2)}</pre>
		<div class="opacity-70 mt-2 mb-1">result:</div>
		<pre>{JSON.stringify(result, null, 2)}</pre>
	</div>
{/if}
