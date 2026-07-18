// Client-side schema helpers for the response-playbook no-code editor (#49 phase 2).
// Mirrors the server contract (soctalk/response/{models,capabilities,conditions}.py):
// the editor produces the same JSON the API validates fail-closed, so this is a
// convenience/UX layer — the server remains the source of truth.
//
// i18n (#52): this module keeps PROTOCOL CODES only. Display strings resolve
// through capLabel()/capDescription()/whenToSentence() etc. at CALL time —
// message functions must never be evaluated at module scope (the locale is
// activated after modules initialize).
import { m } from '$lib/paraglide/messages';

export interface ResponseCapabilityMeta {
	name: string;
	/** tier-0 fires without approval; gated routes to a human-approved proposal. */
	autonomous: boolean;
	/** may appear in on_close (server: ON_CLOSE_ALLOWED = annotate only). */
	onCloseAllowed: boolean;
}

export const CAPABILITIES: ResponseCapabilityMeta[] = [
	{ name: 'annotate_investigation', autonomous: true, onCloseAllowed: true },
	{ name: 'notify_webhook', autonomous: true, onCloseAllowed: false },
	{ name: 'external_action', autonomous: false, onCloseAllowed: false }
];

/** Localized display label for a capability code (falls back to the code). */
export function capLabel(name: string): string {
	switch (name) {
		case 'annotate_investigation':
			return m.cap_annotate_label();
		case 'notify_webhook':
			return m.cap_notify_label();
		case 'external_action':
			return m.cap_external_label();
		default:
			return name;
	}
}

/** Localized description for a capability code (falls back to empty). */
export function capDescription(name: string): string {
	switch (name) {
		case 'annotate_investigation':
			return m.cap_annotate_desc();
		case 'notify_webhook':
			return m.cap_notify_desc();
		case 'external_action':
			return m.cap_external_desc();
		default:
			return '';
	}
}

export const CAP_BY_NAME: Record<string, ResponseCapabilityMeta> = Object.fromEntries(
	CAPABILITIES.map((c) => [c.name, c])
);

// The documented read-only condition contract (RESPONSE_STATE_CONTRACT).
export const SCALAR_FIELDS = [
	'disposition',
	'worker_disposition',
	'floor_vetoed',
	'verdict_confidence',
	'severity'
] as const;
// ATT&CK: mitre.techniques = canonical Txxxx technique ids (never names);
// mitre.tactics = the tactic strings the source emits (Wazuh sends names like
// "Lateral Movement", not TA refs).
export const LIST_FIELDS = ['rule.groups', 'rule.ids', 'mitre.techniques', 'mitre.tactics'] as const;

export const COMPARISONS = ['==', '!=', '>=', '<=', '>', '<'] as const;

export interface WhenRow {
	field: string;
	op: string; // a comparison, or 'in' for list fields
	value: string;
}

export const emptyWhen = (): WhenRow => ({ field: 'severity', op: '>=', value: '10' });

function coerce(v: string): unknown {
	const t = v.trim();
	if (t === 'true') return true;
	if (t === 'false') return false;
	if (t !== '' && !Number.isNaN(Number(t))) return Number(t);
	return v;
}

/** A single WhenRow -> the JSONLogic-subset condition the server accepts, or null. */
export function rowToWhen(row: WhenRow | null): Record<string, unknown> | null {
	if (!row || !row.field) return null;
	const isList = (LIST_FIELDS as readonly string[]).includes(row.field);
	if (isList) {
		// membership: {"in": [value, {var: field}]}
		return { in: [coerce(row.value), { var: row.field }] };
	}
	return { [row.op]: [{ var: row.field }, coerce(row.value)] };
}

/** Parse a stored `when` back into a single WhenRow, or null if it isn't a
 *  single-row shape the builder can show (then the action edits as JSON). */
export function whenToRow(when: unknown): WhenRow | null {
	if (!when || typeof when !== 'object') return null;
	const obj = when as Record<string, unknown>;
	const keys = Object.keys(obj);
	if (keys.length !== 1) return null;
	const op = keys[0];
	const args = obj[op];
	if (!Array.isArray(args) || args.length !== 2) return null;
	if (op === 'in') {
		const target = args[1] as Record<string, unknown>;
		if (!target || typeof target !== 'object' || !('var' in target)) return null;
		return { field: String(target.var), op: 'in', value: String(args[0]) };
	}
	if (!(COMPARISONS as readonly string[]).includes(op)) return null;
	const lhs = args[0] as Record<string, unknown>;
	if (!lhs || typeof lhs !== 'object' || !('var' in lhs)) return null;
	return { field: String(lhs.var), op, value: String(args[1]) };
}

/** A human sentence for a stored `when` condition, for the flow diagram. */
export function whenToSentence(when: unknown): string {
	const row = whenToRow(when);
	if (!row) return when ? m.when_advanced() : '';
	if (row.op === 'in') return m.when_contains({ field: row.field, value: row.value });
	return m.when_cmp({ field: row.field, op: row.op, value: row.value });
}

export interface ResponseActionDef {
	capability: string;
	when?: Record<string, unknown>;
	params?: Record<string, unknown>;
}

export interface ResponsePlaybookDef {
	id: string;
	version?: number;
	priority?: number;
	applies_to?: {
		rule_groups?: string[];
		rule_ids?: string[];
		mitre_techniques?: string[];
		mitre_tactics?: string[];
	};
	response?: { on_escalate?: ResponseActionDef[]; on_close?: ResponseActionDef[] };
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,127}$/;

/** Fail-closed-ish client validation mirroring the server, for inline feedback. */
export function validateDefinition(def: ResponsePlaybookDef): string[] {
	const errs: string[] = [];
	if (!def.id || !SLUG_RE.test(def.id)) {
		errs.push(m.verr_id_slug());
	}
	const esc = def.response?.on_escalate ?? [];
	const cls = def.response?.on_close ?? [];
	if (esc.length === 0 && cls.length === 0) {
		errs.push(m.verr_need_action());
	}
	if (esc.length > 8) errs.push(m.verr_max_escalate());
	if (cls.length > 4) errs.push(m.verr_max_close());
	for (const a of esc) {
		if (!CAP_BY_NAME[a.capability]) errs.push(m.verr_unknown_cap({ cap: a.capability }));
	}
	for (const a of cls) {
		const meta = CAP_BY_NAME[a.capability];
		if (!meta) errs.push(m.verr_unknown_cap({ cap: a.capability }));
		else if (!meta.onCloseAllowed) {
			errs.push(m.verr_close_annotation({ cap: a.capability }));
		}
	}
	return errs;
}
