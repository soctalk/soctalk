import { redirect } from '@sveltejs/kit';
// Old editor URL kept working after the Playbooks -> Triage Policies rename.
export const load = ({ url }: { url: URL }) => {
	throw redirect(308, `/triage-policies/editor${url.search}`);
};
