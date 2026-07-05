import type { Config } from 'tailwindcss';

// Colors + font mirror the SocTalk web app's Skeleton "crimson" theme so the
// Launchpad does not diverge from the official product styling.
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	darkMode: 'class',
	theme: {
		extend: {
			colors: {
				// crimson theme surface scale
				surface: {
					900: '#15171f',
					800: '#1a1c26',
					700: '#202330',
					600: '#27293a',
					500: '#2b2e40',
				},
				// crimson theme primary (kept under `accent` so existing utility
				// classes map straight through to the official brand colour)
				accent: {
					700: '#9f112d',
					600: '#bf1436',
					500: '#d4163c',
					400: '#e15c77',
				},
			},
			fontFamily: {
				sans: [
					'Inter',
					'ui-sans-serif',
					'system-ui',
					'-apple-system',
					'BlinkMacSystemFont',
					'"Segoe UI"',
					'Roboto',
					'"Helvetica Neue"',
					'Arial',
					'"Noto Sans"',
					'sans-serif',
				],
			},
		},
	},
	plugins: [],
} satisfies Config;
