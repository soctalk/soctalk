<!--
  Textarea + send button. Enter to send, Shift+Enter for newline.
  Auto-resizes up to a max height; scrollbar after that.
-->
<script lang="ts">
	import { createEventDispatcher, tick } from 'svelte';

	export let disabled = false;
	// Scope of the parent conversation. Drives the placeholder so a
	// fleet chat hints the user to mention tenant names ("acme-corp")
	// while a tenant chat stays neutral.
	export let scope: 'tenant' | 'mssp_fleet' = 'tenant';

	const dispatch = createEventDispatcher<{ send: { text: string } }>();
	let value = '';
	let textarea: HTMLTextAreaElement;

	async function handleKeydown(ev: KeyboardEvent) {
		if (ev.key === 'Enter' && !ev.shiftKey) {
			ev.preventDefault();
			submit();
		}
	}

	async function submit() {
		const text = value.trim();
		if (!text || disabled) return;
		value = '';
		await tick();
		autosize();
		dispatch('send', { text });
	}

	function autosize() {
		if (!textarea) return;
		textarea.style.height = 'auto';
		textarea.style.height = Math.min(textarea.scrollHeight, 160) + 'px';
	}
</script>

<form
	class="flex items-end gap-2 p-3 border-t border-surface-500/20"
	on:submit|preventDefault={submit}
>
	<textarea
		bind:this={textarea}
		bind:value
		on:input={autosize}
		on:keydown={handleKeydown}
		placeholder={disabled
			? 'Waiting for response…'
			: scope === 'mssp_fleet'
				? 'Ask about any tenant. Use tenant slugs (e.g. "acme-corp") to scope queries.'
				: 'Ask the SOC analyst…'}
		rows="1"
		{disabled}
		class="textarea flex-1 resize-none"
		style="min-height: 38px; max-height: 160px; padding: 0.5rem 0.875rem; line-height: 1.4;"
	></textarea>
	<button
		type="submit"
		class="btn btn-sm variant-filled-primary"
		disabled={disabled || !value.trim()}
	>
		Send
	</button>
</form>
