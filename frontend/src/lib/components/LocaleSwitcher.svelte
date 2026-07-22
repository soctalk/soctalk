<script lang="ts">
	// Compact locale switcher for the narrow (88px) nav rail. A native <select>
	// there truncates the selected value to "En" because the long endonyms
	// (e.g. "Português (Brasil)") can't fit the rail. This is a button showing a
	// globe + short code that opens a floating menu listing the FULL native names
	// untruncated (the menu floats beyond the rail width).
	import { page } from '$app/stores';
	import type { Locale } from '$lib/paraglide/runtime';
	import {
		SUPPORTED_LOCALES,
		LOCALE_LABELS,
		LOCALE_SHORT,
		switchLocale
	} from '$lib/i18n';
	import { m } from '$lib/paraglide/messages';

	export let locale: Locale;

	let open = false;

	function choose(next: Locale) {
		open = false;
		if (next !== locale) switchLocale(next, $page.url.pathname, $page.url.search);
	}

	// Close on outside click / Escape.
	function onWindowClick(e: MouseEvent) {
		if (!(e.target as HTMLElement)?.closest?.('[data-locale-switcher]')) open = false;
	}
	function onKey(e: KeyboardEvent) {
		if (e.key === 'Escape') open = false;
	}
</script>

<svelte:window on:click={onWindowClick} on:keydown={onKey} />

<div class="relative" data-locale-switcher>
	<button
		type="button"
		class="btn btn-sm variant-soft-surface !px-2 !py-1 flex items-center gap-1"
		data-testid="locale-switcher"
		title={m.language()}
		aria-haspopup="listbox"
		aria-expanded={open}
		on:click|stopPropagation={() => (open = !open)}
	>
		<!-- globe -->
		<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
			<circle cx="12" cy="12" r="9" />
			<path d="M3 12h18M12 3c2.5 2.7 2.5 15.3 0 18M12 3c-2.5 2.7-2.5 15.3 0 18" />
		</svg>
		<span class="text-xs font-medium">{LOCALE_SHORT[locale]}</span>
	</button>

	{#if open}
		<ul
			class="absolute z-50 bottom-full mb-1 left-0 w-max
			       rounded-md border border-surface-500/40 bg-surface-700 shadow-xl py-1"
			role="listbox"
			aria-label={m.language()}
		>
			{#each SUPPORTED_LOCALES as loc}
				<li role="option" aria-selected={loc === locale}>
					<button
						type="button"
						class="w-full text-left px-3 py-1.5 text-sm whitespace-nowrap hover:bg-surface-600
						       {loc === locale ? 'font-semibold text-primary-400' : ''}"
						on:click|stopPropagation={() => choose(loc)}
					>
						{LOCALE_LABELS[loc]}
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
