<!--
  Textarea + send button. Enter to send, Shift+Enter for newline.
  Auto-resizes up to a max height; scrollbar after that.
-->
<script lang="ts">
	import { createEventDispatcher, tick } from 'svelte';

	export let disabled = false;

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
		placeholder={disabled ? 'Waiting for response…' : 'Ask the SOC analyst…'}
		rows="1"
		{disabled}
		class="textarea flex-1 resize-none"
		style="min-height: 38px; max-height: 160px;"
	></textarea>
	<button
		type="submit"
		class="btn btn-sm variant-filled-primary"
		disabled={disabled || !value.trim()}
	>
		Send
	</button>
</form>
