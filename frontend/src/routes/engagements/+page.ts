import { redirect } from '@sveltejs/kit';

// Engagements were unified into the tenant Authorization area (an engagement is a kind of
// authorization). Keep the old path working as a deep link into the Engagements tab.
export const load = () => {
	throw redirect(308, '/my-authorization?tab=engagements');
};
