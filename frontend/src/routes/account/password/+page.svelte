<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api, ApiError } from '$lib/api/client';
	import { addToast, authSession } from '$lib/stores';

	let oldPassword = '';
	let newPassword = '';
	let confirmPassword = '';
	let submitting = false;
	let success = false;
	let errorMessage: string | null = null;

	// must_change=1 in the URL pre-flips the heading + banner so the
	// flow reads as "you must change your password" rather than just
	// "change your password". Set by the layout's redirect when the
	// session has must_change=true.
	$: mustChange = $page.url.searchParams.get('must_change') === '1';

	$: meetsLength = newPassword.length >= 12;
	$: matches = newPassword.length > 0 && newPassword === confirmPassword;
	$: canSubmit = meetsLength && matches && oldPassword.length > 0 && !submitting;

	onMount(async () => {
		// If we landed here without a session, bounce to /login.
		if (!$authSession.user) {
			try {
				const session = await api.auth.session();
				authSession.set(session);
				if (!session.user) await goto('/login');
			} catch {
				await goto('/login');
			}
		}
	});

	async function submit() {
		if (!canSubmit) return;
		submitting = true;
		errorMessage = null;
		try {
			await api.auth.changePassword(oldPassword, newPassword);
			success = true;
			oldPassword = newPassword = confirmPassword = '';
			// Refresh session so the next page load doesn't bounce back.
			try {
				const session = await api.auth.session();
				authSession.set(session);
			} catch {
				/* swallow — fall through to dashboard */
			}
			setTimeout(() => goto('/', { invalidateAll: true }), 800);
		} catch (err) {
			if (err instanceof ApiError) {
				errorMessage = err.message || 'Could not change password.';
			} else {
				errorMessage = err instanceof Error ? err.message : 'Something went wrong.';
			}
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Change Password - SocTalk</title>
</svelte:head>

<div class="container max-w-md mx-auto py-10 space-y-4">
	<h1 class="h2">{mustChange ? 'Set a new password' : 'Change password'}</h1>

	{#if mustChange}
		<aside class="alert variant-soft-warning">
			Your administrator requires you to set a new password before continuing.
		</aside>
	{/if}

	{#if success}
		<aside class="alert variant-filled-success">
			Password updated. Redirecting to your dashboard…
		</aside>
	{:else}
		<form on:submit|preventDefault={submit} class="card p-6 space-y-4">
			{#if $authSession.user}
				<p class="text-xs opacity-70">Signed in as <code>{$authSession.user.email}</code></p>
			{/if}

			<label class="label">
				<span>Current password</span>
				<input
					type="password"
					class="input"
					autocomplete="current-password"
					required
					bind:value={oldPassword}
					disabled={submitting}
				/>
			</label>

			<label class="label">
				<span>New password</span>
				<input
					type="password"
					class="input"
					autocomplete="new-password"
					required
					bind:value={newPassword}
					disabled={submitting}
				/>
				<span class="text-xs opacity-60">
					{meetsLength ? '✓' : '·'} at least 12 characters
				</span>
			</label>

			<label class="label">
				<span>Confirm new password</span>
				<input
					type="password"
					class="input"
					autocomplete="new-password"
					required
					bind:value={confirmPassword}
					disabled={submitting}
				/>
				{#if confirmPassword.length > 0}
					<span class="text-xs opacity-60">
						{matches ? '✓ matches' : '· does not match'}
					</span>
				{/if}
			</label>

			{#if errorMessage}
				<div class="alert variant-filled-error">
					<span>Error: {errorMessage}</span>
				</div>
			{/if}

			<button
				type="submit"
				class="btn variant-filled-primary w-full"
				disabled={!canSubmit}
			>
				{#if submitting}
					<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
				{/if}
				Update password
			</button>
		</form>
	{/if}
</div>
