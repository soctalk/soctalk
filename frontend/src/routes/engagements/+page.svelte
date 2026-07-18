<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { localizeHref } from '$lib/i18n';
</script>

<!-- Superseded: engagements now live in the tenant Authorization area (see +page.ts, which
	 redirects to /my-authorization?tab=engagements). This component only renders if the redirect
	 is bypassed (e.g. JS disabled). -->
<div class="max-w-4xl mx-auto p-4 text-sm opacity-70">
	{m.adm_eng_moved_prefix()} <a class="underline" href={localizeHref('/my-authorization?tab=engagements')}>{m.nav_authorization()}</a>{m.adm_eng_moved_suffix()}
</div>
