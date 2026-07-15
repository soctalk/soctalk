<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import {
		STATE_CONTRACT,
		OPERATOR_LABELS,
		contractField,
		emptyGroup,
		emptyRule,
		type RuleGroup,
		type RuleRow
	} from './schema';

	export let group: RuleGroup;
	export let depth = 0;

	const dispatch = createEventDispatcher<{ change: void }>();

	function changed() {
		group = group;
		dispatch('change');
	}

	function addRule() {
		group.children = [...group.children, emptyRule()];
		changed();
	}

	function addGroup() {
		const g = emptyGroup();
		g.op = group.op === 'and' ? 'or' : 'and';
		g.children = [emptyRule()];
		group.children = [...group.children, g];
		changed();
	}

	function remove(i: number) {
		group.children = group.children.filter((_, idx) => idx !== i);
		changed();
	}

	/** Operators offered for a field, by its contract type. */
	function opsFor(fieldPath: string): string[] {
		const f = contractField(fieldPath);
		if (!f) return ['=='];
		if (f.type === 'boolean') return ['=='];
		if (f.type === 'number') return ['==', '!=', '<', '<=', '>', '>='];
		return ['==', '!=', 'in']; // enum + string
	}

	function onFieldChange(rule: RuleRow) {
		const f = contractField(rule.field);
		if (!opsFor(rule.field).includes(rule.op)) rule.op = '==';
		if (f?.type === 'boolean') rule.value = true;
		else if (f?.type === 'number') rule.value = 0.5;
		else if (rule.op === 'in') rule.value = [];
		else rule.value = f?.values?.[0] ?? '';
		changed();
	}

	function onOpChange(rule: RuleRow) {
		const f = contractField(rule.field);
		if (rule.op === 'in' && !Array.isArray(rule.value)) {
			rule.value = rule.value === '' || rule.value == null ? [] : [rule.value];
		} else if (rule.op !== 'in' && Array.isArray(rule.value)) {
			rule.value = rule.value[0] ?? f?.values?.[0] ?? '';
		}
		changed();
	}

	function listValue(rule: RuleRow): string {
		return Array.isArray(rule.value) ? rule.value.map((v) => String(v)).join(', ') : '';
	}

	function setListValue(rule: RuleRow, text: string) {
		rule.value = text
			.split(',')
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
		changed();
	}

	function setNumberValue(rule: RuleRow, text: string) {
		const n = Number(text);
		rule.value = Number.isFinite(n) ? n : 0;
		changed();
	}

	/** Svelte's template TS doesn't narrow each-block unions; the enclosing
	 * {#if child.kind} guarantees this cast. */
	function asRule(c: RuleGroup | RuleRow): RuleRow {
		return c as RuleRow;
	}

	// Template expressions may not assign to {@const} vars — mutate here instead.
	function setField(rule: RuleRow, value: string) {
		rule.field = value;
		onFieldChange(rule);
	}

	function setOp(rule: RuleRow, value: string) {
		rule.op = value;
		onOpChange(rule);
	}

	function setScalarValue(rule: RuleRow, value: string) {
		rule.value = value;
		changed();
	}

	function setBoolValue(rule: RuleRow, text: string) {
		rule.value = text === 'true';
		changed();
	}
</script>

<div
	class="space-y-2 {depth > 0
		? 'border-l-2 border-surface-500/30 pl-3 ml-1'
		: ''}"
>
	<div class="flex items-center gap-2">
		<div class="btn-group variant-soft [&>button]:!py-0.5 [&>button]:!px-2 text-xs">
			<button
				class:variant-filled-primary={group.op === 'and'}
				on:click={() => {
					group.op = 'and';
					changed();
				}}
				type="button"
				title="Every row below must hold"
			>
				ALL
			</button>
			<button
				class:variant-filled-primary={group.op === 'or'}
				on:click={() => {
					group.op = 'or';
					changed();
				}}
				type="button"
				title="At least one row below must hold"
			>
				ANY
			</button>
		</div>
		<span class="text-xs opacity-50">of the following must hold</span>
	</div>

	{#each group.children as child, i}
		<div class="flex items-start gap-2">
			{#if child.kind === 'group'}
				<div class="flex-1">
					<svelte:self bind:group={child} depth={depth + 1} on:change />
				</div>
			{:else}
				{@const rule = asRule(child)}
				{@const field = contractField(rule.field)}
				<div class="flex-1 flex flex-wrap items-center gap-2">
					<select
						class="select w-auto max-w-[15rem] !py-1 text-xs"
						value={rule.field}
						on:change={(e) => setField(rule, e.currentTarget.value)}
					>
						{#each STATE_CONTRACT as f}
							<option value={f.path}>{f.label}</option>
						{/each}
					</select>

					{#if field?.type === 'boolean'}
						<select
							class="select w-auto !py-1 text-xs"
							value={rule.value === true ? 'true' : 'false'}
							on:change={(e) => setBoolValue(rule, e.currentTarget.value)}
						>
							<option value="true">is true</option>
							<option value="false">is false</option>
						</select>
					{:else}
						<select
							class="select w-auto !py-1 text-xs"
							value={rule.op}
							on:change={(e) => setOp(rule, e.currentTarget.value)}
						>
							{#each opsFor(rule.field) as op}
								<option value={op}>{OPERATOR_LABELS[op] ?? op}</option>
							{/each}
						</select>

						{#if rule.op === 'in'}
							<input
								class="input !py-1 text-xs w-56"
								placeholder="value, value, …"
								value={listValue(rule)}
								on:change={(e) => setListValue(rule, e.currentTarget.value)}
							/>
						{:else if field?.type === 'number'}
							<input
								class="input !py-1 text-xs w-24"
								type="number"
								step="0.05"
								value={typeof rule.value === 'number' ? rule.value : 0}
								on:change={(e) => setNumberValue(rule, e.currentTarget.value)}
							/>
						{:else if field?.type === 'enum'}
							<select
								class="select w-auto !py-1 text-xs"
								value={rule.value}
								on:change={(e) => setScalarValue(rule, e.currentTarget.value)}
							>
								{#each field.values ?? [] as v}
									<option value={v}>{v}</option>
								{/each}
							</select>
						{:else}
							<input
								class="input !py-1 text-xs w-40"
								list="cond-suggest-{rule.field}"
								value={typeof rule.value === 'string' ? rule.value : String(rule.value ?? '')}
								on:change={(e) => setScalarValue(rule, e.currentTarget.value)}
							/>
							{#if field?.values?.length}
								<datalist id="cond-suggest-{rule.field}">
									{#each field.values as v}
										<option value={v}></option>
									{/each}
								</datalist>
							{/if}
						{/if}
					{/if}
					{#if field}
						<span class="text-xs opacity-40 hidden xl:inline" title={field.help}>ⓘ</span>
					{/if}
				</div>
			{/if}
			<button
				class="btn-icon btn-icon-sm variant-soft-error flex-shrink-0"
				on:click={() => remove(i)}
				type="button"
				title="Remove"
			>
				✕
			</button>
		</div>
	{/each}

	<div class="flex gap-2">
		<button class="btn btn-sm variant-soft !py-0.5 text-xs" on:click={addRule} type="button">
			+ condition
		</button>
		{#if depth < 3}
			<button class="btn btn-sm variant-soft !py-0.5 text-xs" on:click={addGroup} type="button">
				+ group
			</button>
		{/if}
	</div>
</div>
