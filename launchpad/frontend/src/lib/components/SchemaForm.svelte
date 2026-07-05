<script lang="ts">
	import type { JSONSchema } from '$lib/api';

	// Renders a form from a plugin's JSON-schema config. `value` is bound and
	// mutated in place; any platform's fields appear with zero per-platform code.
	export let schema: JSONSchema | undefined;
	export let value: Record<string, unknown> = {};
	export let testidPrefix = 'cfg';
	export let exclude: string[] = []; // field keys to hide (e.g. network-owned 'tailnet')

	interface Field {
		key: string;
		type: string;
		required: boolean;
		isArray: boolean;
	}

	$: fields = buildFields(schema, value, exclude);

	function inferType(v: unknown): string {
		if (Array.isArray(v)) return 'array';
		if (typeof v === 'number') return 'number';
		if (typeof v === 'boolean') return 'boolean';
		return 'string';
	}

	// Render every config entry: schema-declared fields first (with type +
	// required info), then any extra keys already present on the value that the
	// plugin schema doesn't declare, so ALL config entries are editable, not
	// just the ones a plugin happens to advertise.
	function buildFields(
		s: JSONSchema | undefined,
		val: Record<string, unknown>,
		ex: string[]
	): Field[] {
		const hidden = new Set(ex);
		const required = new Set(s?.required ?? []);
		const seen = new Set<string>();
		const out: Field[] = [];
		for (const [key, prop] of Object.entries(s?.properties ?? {})) {
			if (hidden.has(key)) continue;
			const type = prop.type ?? 'string';
			out.push({ key, type, required: required.has(key), isArray: type === 'array' });
			seen.add(key);
		}
		for (const key of Object.keys(val ?? {})) {
			if (hidden.has(key) || seen.has(key)) continue;
			const type = inferType(val[key]);
			out.push({ key, type, required: false, isArray: type === 'array' });
			seen.add(key);
		}
		return out.sort((a, b) => Number(b.required) - Number(a.required) || a.key.localeCompare(b.key));
	}

	function arrayText(v: unknown): string {
		return Array.isArray(v) ? v.join('\n') : '';
	}
	function setArray(key: string, text: string) {
		value[key] = text
			.split('\n')
			.map((s) => s.trim())
			.filter(Boolean);
		value = value;
	}
	function setStr(key: string, v: string) {
		value[key] = v;
		value = value;
	}
	function setNumber(key: string, raw: string) {
		value[key] = raw === '' ? undefined : Number(raw);
		value = value;
	}
	function setBool(key: string, v: boolean) {
		value[key] = v;
		value = value;
	}
</script>

{#if fields.length === 0}
	<p class="text-sm text-slate-500">This platform takes no configuration.</p>
{:else}
	<div class="grid grid-cols-2 gap-3">
		{#each fields as f (f.key)}
			<div class={f.isArray ? 'col-span-2' : ''}>
				<div class="field-label">
					{f.key}{#if f.required}<span class="text-accent-400"> *</span>{/if}
					<span class="text-slate-600 lowercase">· {f.type}</span>
				</div>
				{#if f.isArray}
					<textarea
						class="field-input font-mono text-xs"
						rows="2"
						data-testid={`${testidPrefix}-${f.key}`}
						value={arrayText(value[f.key])}
						on:input={(e) => setArray(f.key, e.currentTarget.value)}
					></textarea>
				{:else if f.type === 'integer' || f.type === 'number'}
					<input
						class="field-input"
						type="number"
						data-testid={`${testidPrefix}-${f.key}`}
						value={value[f.key] ?? ''}
						on:input={(e) => setNumber(f.key, e.currentTarget.value)}
					/>
				{:else if f.type === 'boolean'}
					<input
						type="checkbox"
						class="mt-2"
						data-testid={`${testidPrefix}-${f.key}`}
						checked={Boolean(value[f.key])}
						on:change={(e) => setBool(f.key, e.currentTarget.checked)}
					/>
				{:else}
					<input
						class="field-input"
						data-testid={`${testidPrefix}-${f.key}`}
						value={value[f.key] ?? ''}
						on:input={(e) => setStr(f.key, e.currentTarget.value)}
					/>
				{/if}
			</div>
		{/each}
	</div>
{/if}
