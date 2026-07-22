<script lang="ts">
	// Compact locale switcher for the narrow (88px) nav rail. A native <select>
	// there truncates the selected value to "En" because the long endonyms
	// (e.g. "Português (Brasil)") can't fit the rail. This is a globe + short-code
	// trigger that opens a menu listing the FULL native names.
	//
	// The menu is PORTALED to <body> and positioned `fixed`: the rail is an
	// overflow-hidden container, so an in-place absolute popover gets clipped at
	// the 88px rail edge. Portaling escapes that clip entirely.
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
	let trigger: HTMLButtonElement;
	let menuLeft = 0;
	let menuBottom = 0;

	function place() {
		if (!trigger) return;
		const r = trigger.getBoundingClientRect();
		menuLeft = r.left; // left-align the menu to the trigger; it grows rightward
		menuBottom = window.innerHeight - r.top + 4; // open upward, 4px gap
	}

	function toggle() {
		open = !open;
		if (open) place();
	}

	function choose(next: Locale) {
		open = false;
		if (next !== locale) switchLocale(next, $page.url.pathname, $page.url.search);
	}

	// Append a node to <body> so it escapes the rail's overflow clip.
	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return { destroy() { node.remove(); } };
	}

	function onWindowClick(e: MouseEvent) {
		const t = e.target as HTMLElement;
		if (!t?.closest?.('[data-locale-menu]') && !t?.closest?.('[data-locale-trigger]')) open = false;
	}
	function onKey(e: KeyboardEvent) {
		if (e.key === 'Escape') open = false;
	}
</script>

<svelte:window on:click={onWindowClick} on:keydown={onKey} on:resize={() => open && place()} />

<button
	bind:this={trigger}
	type="button"
	class="btn btn-sm variant-soft-surface !px-2 !py-1 flex items-center gap-1"
	data-testid="locale-switcher"
	data-locale-trigger
	title={m.language()}
	aria-haspopup="listbox"
	aria-expanded={open}
	on:click|stopPropagation={toggle}
>
	<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
		<circle cx="12" cy="12" r="9" />
		<path d="M3 12h18M12 3c2.5 2.7 2.5 15.3 0 18M12 3c-2.5 2.7-2.5 15.3 0 18" />
	</svg>
	<span class="text-xs font-medium">{LOCALE_SHORT[locale]}</span>
</button>

{#if open}
	<ul
		use:portal
		data-locale-menu
		class="fixed z-[999] w-max rounded-md border border-surface-500/40 bg-surface-700 shadow-xl py-1"
		style="left:{menuLeft}px; bottom:{menuBottom}px;"
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
