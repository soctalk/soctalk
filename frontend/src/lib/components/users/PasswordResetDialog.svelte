<script lang="ts">
	// Admin password reset (internal-auth §8.5): confirm, then show the one-time
	// password once with a copy button. The password lives only in this
	// component's state; the parent unmounts the dialog on `close`, so it is gone
	// once the dialog closes and is never written to a store or to storage.
	import { createEventDispatcher, onMount, tick } from 'svelte';
	import { m } from '$lib/paraglide/messages';

	export let email: string;
	export let userId: string;
	/** Performs the reset server-side and resolves to the one-time password. */
	export let reset: (userId: string) => Promise<string>;

	const dispatch = createEventDispatcher<{ close: void }>();

	let phase: 'confirm' | 'working' | 'done' = 'confirm';
	let password = '';
	let error: string | null = null;
	let cancelButton: HTMLButtonElement;
	let passwordField: HTMLInputElement;

	onMount(() => cancelButton?.focus());

	async function confirmReset() {
		phase = 'working';
		error = null;
		try {
			password = await reset(userId);
			phase = 'done';
			await tick();
			passwordField?.focus();
			passwordField?.select();
		} catch (e) {
			error = e instanceof Error && e.message ? e.message : m.pwreset_failed();
			phase = 'confirm';
		}
	}

	function close() {
		password = '';
		dispatch('close');
	}

	async function copyAndClose() {
		error = null;
		try {
			await navigator.clipboard.writeText(password);
		} catch {
			// No clipboard (e.g. a plain-HTTP origin): keep the dialog open so the
			// admin can still select and copy the password by hand.
			error = m.pwreset_copy_failed();
			passwordField?.select();
			return;
		}
		close();
	}

	function onKeydown(e: KeyboardEvent) {
		// Escape cancels the confirmation only; once the password is on screen,
		// closing is an explicit button press so it is not lost by accident.
		if (e.key === 'Escape' && phase === 'confirm') close();
	}
</script>

<svelte:window on:keydown={onKeydown} />

<div class="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
	<div class="flex min-h-full items-center justify-center p-4">
		<div
			class="card w-full max-w-md p-5 space-y-3"
			role="dialog"
			aria-modal="true"
			aria-labelledby="pwreset-title"
		>
			{#if phase === 'done'}
				<h2 id="pwreset-title" class="h4">{m.pwreset_done_title({ email })}</h2>
				<p class="text-sm opacity-80">{m.pwreset_done_hint()}</p>
				<label class="block text-sm">
					<span class="opacity-70">{m.pwreset_field_label()}</span>
					<input
						bind:this={passwordField}
						class="input mt-1 font-mono"
						type="text"
						readonly
						autocomplete="off"
						spellcheck="false"
						value={password}
						on:focus={(e) => e.currentTarget.select()}
					/>
				</label>
				{#if error}
					<p class="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>
				{/if}
				<div class="flex justify-end gap-2 pt-1">
					<button class="px-3 py-2 text-sm" on:click={close}>{m.common_close()}</button>
					<button
						class="px-3 py-2 rounded bg-blue-600 text-white text-sm hover:bg-blue-700"
						on:click={copyAndClose}
					>
						{m.pwreset_copy_and_close()}
					</button>
				</div>
			{:else}
				<h2 id="pwreset-title" class="h4">{m.pwreset_confirm_title({ email })}</h2>
				<p class="text-sm opacity-80">{m.pwreset_confirm_body()}</p>
				{#if error}
					<p class="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>
				{/if}
				<div class="flex justify-end gap-2 pt-1">
					<button
						bind:this={cancelButton}
						class="px-3 py-2 text-sm"
						on:click={close}
						disabled={phase === 'working'}
					>
						{m.common_cancel()}
					</button>
					<button
						class="px-3 py-2 rounded bg-red-600 text-white text-sm hover:bg-red-700"
						on:click={confirmReset}
						disabled={phase === 'working'}
					>
						{phase === 'working' ? m.pwreset_working() : m.pwreset_action()}
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
