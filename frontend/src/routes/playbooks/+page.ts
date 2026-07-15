import { redirect } from '@sveltejs/kit';
// The policy kind was renamed Playbooks -> Triage Policies. Keep the old URL working.
export const load = () => {
	throw redirect(308, '/triage-policies');
};
