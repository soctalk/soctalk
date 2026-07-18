/**
 * Client-side model of the triage-policy grammar, mirrored from the backend
 * (src/soctalk/triage_policy/{models,conditions,authoring,registry}.py).
 *
 * The server remains the authority — everything here is a pre-flight mirror so
 * the visual editor can give inline feedback before a round-trip. Every
 * constant below has a named counterpart in the backend; if they drift, the
 * server's fail-closed validation still rejects, so drift degrades to a worse
 * error message, never to an unsafe accept.
 */
import { m } from '$lib/paraglide/messages';

// ---------------------------------------------------------------- vocabularies

/** conditions.STATE_CONTRACT — the only fields a guardrail condition may read. */
export interface ContractField {
	path: string;
	label: () => string;
	type: 'enum' | 'boolean' | 'number' | 'string';
	/** Closed set for 'enum'; suggestions (free text allowed) for 'string'. */
	values?: string[];
	help: () => string;
}

export const STATE_CONTRACT: ContractField[] = [
	{
		path: 'authz.class',
		label: m.tp_contract_authz_class_label,
		type: 'enum',
		values: ['covered', 'contradicted', 'absent'],
		help: m.tp_contract_authz_class_help
	},
	{
		path: 'authz.in_scope',
		label: m.tp_contract_authz_in_scope_label,
		type: 'boolean',
		help: m.tp_contract_authz_in_scope_help
	},
	{
		path: 'authz.sanctioned_or_routine',
		label: m.tp_contract_authz_sanctioned_or_routine_label,
		type: 'boolean',
		help: m.tp_contract_authz_sanctioned_or_routine_help
	},
	{
		path: 'authz.actor_genuine',
		label: m.tp_contract_authz_actor_genuine_label,
		type: 'boolean',
		help: m.tp_contract_authz_actor_genuine_help
	},
	{
		path: 'authz.policy_allowed',
		label: m.tp_contract_authz_policy_allowed_label,
		type: 'boolean',
		help: m.tp_contract_authz_policy_allowed_help
	},
	{
		path: 'verdict',
		label: m.tp_contract_verdict_label,
		type: 'enum',
		values: ['close', 'needs_more_info', 'escalate'],
		help: m.tp_contract_verdict_help
	},
	{
		path: 'verdict_confidence',
		label: m.tp_contract_verdict_confidence_label,
		type: 'number',
		help: m.tp_contract_verdict_confidence_help
	},
	{
		path: 'asset.data_classification',
		label: m.tp_contract_asset_data_classification_label,
		type: 'string',
		values: ['pci', 'phi', 'pii', 'confidential', 'internal', 'public'],
		help: m.tp_contract_asset_data_classification_help
	},
	{
		path: 'asset.environment',
		label: m.tp_contract_asset_environment_label,
		type: 'string',
		values: ['production', 'staging', 'development'],
		help: m.tp_contract_asset_environment_help
	},
	{
		path: 'asset.criticality',
		label: m.tp_contract_asset_criticality_label,
		type: 'string',
		values: ['critical', 'high', 'medium', 'low'],
		help: m.tp_contract_asset_criticality_help
	},
	{
		path: 'enrichment.ioc',
		label: m.tp_contract_enrichment_ioc_label,
		type: 'boolean',
		help: m.tp_contract_enrichment_ioc_help
	},
	{
		path: 'correlation.active_incident',
		label: m.tp_contract_correlation_active_incident_label,
		type: 'boolean',
		help: m.tp_contract_correlation_active_incident_help
	}
];

export const CONTRACT_PATHS = new Set(STATE_CONTRACT.map((f) => f.path));

export function contractField(path: string): ContractField | undefined {
	return STATE_CONTRACT.find((f) => f.path === path);
}

export function contractFieldLabel(path: string): string {
	return contractField(path)?.label() ?? path;
}

/** conditions.ALLOWED_OPERATORS (minus 'var', which the builder implies). */
export const COMPARISON_OPS = ['==', '!=', '<', '<=', '>', '>='] as const;
export const LOGIC_OPS = ['and', 'or', '!', '!!'] as const;
export const MEMBERSHIP_OPS = ['in'] as const;

export const OPERATOR_LABELS: Record<string, () => string> = {
	'==': m.tp_operator_eq,
	'!=': m.tp_operator_neq,
	'<': m.tp_operator_lt,
	'<=': m.tp_operator_lte,
	'>': m.tp_operator_gt,
	'>=': m.tp_operator_gte,
	in: m.tp_operator_in
};

export function operatorLabel(op: string): string {
	return OPERATOR_LABELS[op]?.() ?? op;
}

/** Backend structural limits (conditions.py). */
export const CONDITION_MAX_DEPTH = 8;
export const CONDITION_MAX_NODES = 64;
export const CONDITION_MAX_LIST = 32;

/** models.py / authoring.py vocabularies. */
export const KNOWN_STEP_NODES = ['gather_authorization_context'] as const;
export const KNOWN_DECISION_MODULES = ['authorization_engine'] as const;
export const KNOWN_PHASES = ['triage', 'decide'] as const;
/** Actions an authored policy may GRANT in legal_actions. CLOSE is deliberately
 * absent (mirrors authoring.py): granting it adds nothing over an unconstrained
 * phase, and a set like {decide: [CLOSE]} would remap every proposal to a forced
 * verdict-less close. */
export const GRANTABLE_ACTIONS = ['ENRICH', 'CONTEXTUALIZE', 'INVESTIGATE', 'VERDICT'] as const;

export const SUPERVISOR_ACTIONS = [
	'ENRICH',
	'CONTEXTUALIZE',
	'INVESTIGATE',
	'VERDICT',
	'CLOSE'
] as const;
export const GUARDRAIL_EFFECTS = ['override', 'interrupt'] as const;
export const GUARDRAIL_TARGETS = ['escalate', 'needs_more_info', 'human_review'] as const;
export const DECISION_RANK: Record<string, number> = {
	close: 0,
	needs_more_info: 1,
	escalate: 2
};
export const MAX_GUARDRAILS = 16;
export const FILE_PRIORITY_FLOOR = 60;
export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,127}$/;
export const MAX_DEFINITION_BYTES = 64 * 1024;
export const MAX_REASON_LEN = 512;

/** Top-level fields an authored definition may carry (TriagePolicy is extra="forbid";
 * deterministic_disposition is built-in-only and rejected for authored docs). */
export const AUTHORABLE_FIELDS = new Set([
	'id',
	'version',
	'tenant',
	'status',
	'priority',
	'applies_to',
	'required_steps',
	'decision_modules',
	'legal_actions',
	'close_signoff_data_classes',
	'guardrails'
]);

export const AUTHORIZATION_TRACKS = ['account', 'fim'] as const;

// ---------------------------------------------------------------- types

export type ConditionNode = Record<string, unknown>;

export interface GuardrailDef {
	when: ConditionNode;
	effect: (typeof GUARDRAIL_EFFECTS)[number];
	to: (typeof GUARDRAIL_TARGETS)[number];
	reason: string;
}

export interface TriagePolicyDef {
	id: string;
	version?: number;
	tenant?: string;
	status?: string;
	priority: number;
	applies_to?: { rule_groups?: string[]; rule_ids?: string[]; authorization_tracks?: string[] };
	required_steps?: string[];
	decision_modules?: string[];
	legal_actions?: Record<string, string[]>;
	close_signoff_data_classes?: string[];
	guardrails?: GuardrailDef[];
}

// ------------------------------------------------- condition <-> builder model
//
// The builder edits a restricted, always-representable shape: one group tree of
// AND/OR groups whose leaves are field-operator-value rows. Any valid backend
// condition that doesn't fit (e.g. a bare `!` over an `or`, literal-vs-literal
// comparisons, `!!` coercions) round-trips to null and the UI falls back to a
// raw-JSON escape hatch for that rule — never silently rewrites it.

export interface RuleRow {
	kind: 'rule';
	field: string;
	/** '==','!=','<','<=','>','>=','in' — booleans use '==' with true/false. */
	op: string;
	value: string | number | boolean | null | (string | number | boolean | null)[];
}

export interface RuleGroup {
	kind: 'group';
	op: 'and' | 'or';
	children: (RuleGroup | RuleRow)[];
}

export function emptyGroup(): RuleGroup {
	return { kind: 'group', op: 'and', children: [] };
}

export function emptyRule(): RuleRow {
	return { kind: 'rule', field: 'verdict', op: '==', value: 'close' };
}

/** Builder model -> backend condition dict. */
export function groupToCondition(group: RuleGroup): ConditionNode | null {
	const parts = group.children
		.map((c) => (c.kind === 'group' ? groupToCondition(c) : ruleToCondition(c)))
		.filter((c): c is ConditionNode => c !== null);
	if (parts.length === 0) return null;
	if (parts.length === 1) return parts[0];
	return { [group.op]: parts };
}

function ruleToCondition(rule: RuleRow): ConditionNode {
	return { [rule.op]: [{ var: rule.field }, rule.value] };
}

/**
 * Backend condition dict -> builder model, or null when the shape is valid for
 * the backend but not representable in the row/group builder.
 */
export function conditionToGroup(node: unknown): RuleGroup | null {
	const parsed = parseNode(node);
	if (parsed === null) return null;
	if (parsed.kind === 'group') return parsed;
	return { kind: 'group', op: 'and', children: [parsed] };
}

function parseNode(node: unknown): RuleGroup | RuleRow | null {
	if (typeof node !== 'object' || node === null || Array.isArray(node)) return null;
	const entries = Object.entries(node as Record<string, unknown>);
	if (entries.length !== 1) return null;
	const [op, args] = entries[0];
	if (op === 'and' || op === 'or') {
		const list = Array.isArray(args) ? args : [args];
		// An EMPTY group is backend-valid (and:[] is truthy, or:[] is falsy) but the
		// builder would silently drop it on save, changing semantics — JSON mode instead.
		if (list.length === 0) return null;
		const children: (RuleGroup | RuleRow)[] = [];
		for (const a of list) {
			const child = parseNode(a);
			if (child === null) return null;
			children.push(child);
		}
		return { kind: 'group', op, children };
	}
	if (op === '==' || op === '!=' || op === '<' || op === '<=' || op === '>' || op === '>=' || op === 'in') {
		if (!Array.isArray(args) || args.length !== 2) return null;
		const [lhs, rhs] = args;
		const field = varPath(lhs);
		if (field === null || !CONTRACT_PATHS.has(field)) return null;
		// Boolean fields render as a bare is-true/is-false control that hides the
		// operator — a backend-valid `!=` would display (and re-save) inverted.
		// Only `==` is representable; everything else stays in JSON mode.
		if (contractField(field)?.type === 'boolean' && op !== '==') return null;
		if (op === 'in') {
			if (!Array.isArray(rhs) || !rhs.every(isScalar)) return null;
			return { kind: 'rule', field, op, value: rhs as RuleRow['value'] };
		}
		if (!isScalar(rhs)) return null;
		return { kind: 'rule', field, op, value: rhs as RuleRow['value'] };
	}
	return null; // '!', '!!', var-only truthiness, etc. — JSON escape hatch
}

function varPath(node: unknown): string | null {
	if (typeof node !== 'object' || node === null || Array.isArray(node)) return null;
	const entries = Object.entries(node as Record<string, unknown>);
	if (entries.length !== 1 || entries[0][0] !== 'var') return null;
	return typeof entries[0][1] === 'string' ? entries[0][1] : null;
}

function isScalar(v: unknown): boolean {
	return (
		v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
	);
}

// ---------------------------------------------------------------- validation
// Mirrors conditions.validate_condition + authoring.validate_authored.

export function validateCondition(node: unknown): string[] {
	const errors: string[] = [];
	if (typeof node !== 'object' || node === null || Array.isArray(node)) {
		return [m.tp_validate_condition_root()];
	}
	const counter = { n: 0 };
	walkValidate(node, 0, counter, errors);
	return errors;
}

function walkValidate(node: unknown, depth: number, counter: { n: number }, errors: string[]): void {
	if (errors.length > 4) return; // enough feedback; avoid error floods
	counter.n += 1;
	if (counter.n > CONDITION_MAX_NODES) {
		errors.push(m.tp_validate_condition_nodes({ max: CONDITION_MAX_NODES }));
		return;
	}
	if (depth > CONDITION_MAX_DEPTH) {
		errors.push(m.tp_validate_condition_depth({ max: CONDITION_MAX_DEPTH }));
		return;
	}
	if (node === null || ['string', 'number', 'boolean'].includes(typeof node)) return;
	if (Array.isArray(node)) {
		if (node.length > CONDITION_MAX_LIST) {
			errors.push(m.tp_validate_condition_list_cap({ max: CONDITION_MAX_LIST }));
		}
		if (!node.every(isScalar)) errors.push(m.tp_validate_condition_list_scalars());
		return;
	}
	if (typeof node !== 'object') {
		errors.push(m.tp_validate_condition_unsupported_value({ value: String(node) }));
		return;
	}
	const entries = Object.entries(node as Record<string, unknown>);
	if (entries.length !== 1) {
		errors.push(m.tp_validate_condition_single_mapping({ shape: '{operator: args}' }));
		return;
	}
	const [op, args] = entries[0];
	const allowed = ['var', ...COMPARISON_OPS, ...LOGIC_OPS, ...MEMBERSHIP_OPS];
	if (!allowed.includes(op)) {
		errors.push(m.tp_validate_operator_not_allowed({ op }));
		return;
	}
	if (op === 'var') {
		if (typeof args !== 'string') errors.push(m.tp_validate_var_string());
		else if (!CONTRACT_PATHS.has(args))
			errors.push(m.tp_validate_field_not_contract({ field: args }));
		return;
	}
	const argsList = Array.isArray(args) ? args : [args];
	if ((COMPARISON_OPS as readonly string[]).includes(op) && argsList.length !== 2) {
		errors.push(m.tp_validate_op_two_args({ op }));
	}
	if (op === 'in' && argsList.length !== 2) errors.push(m.tp_validate_op_two_args({ op }));
	if ((op === '!' || op === '!!') && argsList.length !== 1) {
		errors.push(m.tp_validate_op_one_arg({ op }));
	}
	for (const a of argsList) walkValidate(a, depth + 1, counter, errors);
}

/** Pre-flight mirror of authoring.validate_authored. Returns author-facing errors. */
export function validateDefinition(def: Record<string, unknown>): string[] {
	const errors: string[] = [];
	for (const key of Object.keys(def)) {
		if (key === 'deterministic_disposition') {
			errors.push(m.tp_validate_builtin_only());
		} else if (!AUTHORABLE_FIELDS.has(key)) {
			errors.push(m.tp_validate_unknown_field({ field: key }));
		}
	}
	const id = def.id;
	if (typeof id !== 'string' || !SLUG_RE.test(id)) {
		errors.push(m.tp_validate_id_slug());
	}
	const priority = def.priority ?? 100;
	if (typeof priority !== 'number' || !Number.isInteger(priority) || priority < FILE_PRIORITY_FLOOR) {
		errors.push(m.tp_validate_priority_floor({ floor: FILE_PRIORITY_FLOOR }));
	}
	const steps = (def.required_steps as unknown[]) ?? [];
	for (const s of steps) {
		if (!(KNOWN_STEP_NODES as readonly string[]).includes(String(s))) {
			errors.push(m.tp_validate_unknown_step({ step: String(s) }));
		}
	}
	const modules = (def.decision_modules as unknown[]) ?? [];
	for (const mod of modules) {
		if (!(KNOWN_DECISION_MODULES as readonly string[]).includes(String(mod))) {
			errors.push(m.tp_validate_unknown_module({ module: String(mod) }));
		}
	}
	const legal = (def.legal_actions as Record<string, unknown[]>) ?? {};
	for (const [phase, actions] of Object.entries(legal)) {
		if (!(KNOWN_PHASES as readonly string[]).includes(phase)) {
			errors.push(m.tp_validate_unknown_phase({ phase }));
			continue;
		}
		for (const a of actions ?? []) {
			if (!(SUPERVISOR_ACTIONS as readonly string[]).includes(String(a))) {
				errors.push(m.tp_validate_unknown_action({ action: String(a), phase }));
			} else if (!(GRANTABLE_ACTIONS as readonly string[]).includes(String(a))) {
				errors.push(m.tp_validate_close_not_grantable({ phase }));
			}
		}
	}
	const guardrails = (def.guardrails as GuardrailDef[]) ?? [];
	if (guardrails.length > MAX_GUARDRAILS) {
		errors.push(m.tp_validate_max_guardrails({ max: MAX_GUARDRAILS }));
	}
	guardrails.forEach((g, i) => {
		const n = i + 1;
		if (!(GUARDRAIL_EFFECTS as readonly string[]).includes(g.effect)) {
			errors.push(m.tp_validate_guardrail_effect({ n }));
		}
		if (!(GUARDRAIL_TARGETS as readonly string[]).includes(g.to)) {
			errors.push(m.tp_validate_guardrail_target({ n }));
		}
		if (g.effect === 'interrupt' && g.to !== 'human_review') {
			errors.push(m.tp_validate_guardrail_interrupt_target({ n }));
		}
		if (g.effect === 'override' && g.to === 'human_review') {
			errors.push(m.tp_validate_guardrail_override_target({ n }));
		}
		if (!g.reason || g.reason.length < 1 || g.reason.length > MAX_REASON_LEN) {
			errors.push(m.tp_validate_guardrail_reason({ n, max: MAX_REASON_LEN }));
		}
		for (const e of validateCondition(g.when)) {
			errors.push(m.tp_validate_guardrail_condition({ n, error: e }));
		}
	});
	const bytes = new TextEncoder().encode(JSON.stringify(def)).length;
	if (bytes > MAX_DEFINITION_BYTES) {
		errors.push(m.tp_validate_definition_bytes({ max: MAX_DEFINITION_BYTES }));
	}
	return errors;
}

// ------------------------------------------------------------ guard simulation
// Mirrors conditions._eval + the guardrail portion of guard.evaluate_guard so
// the editor can preview which rule WOULD fire against a sample context. The
// worker's guard remains the authority — this is a what-if lens, not policy.

export function evaluateCondition(node: unknown, ctx: Record<string, unknown>): boolean {
	try {
		return Boolean(evalNode(node, ctx));
	} catch {
		return false; // malformed-at-runtime = does not fire, same as the backend
	}
}

function lookup(ctx: Record<string, unknown>, dotted: string): unknown {
	let node: unknown = ctx;
	for (const part of dotted.split('.')) {
		if (typeof node !== 'object' || node === null || Array.isArray(node)) return null;
		node = (node as Record<string, unknown>)[part];
	}
	return node === undefined ? null : node;
}

function evalNode(node: unknown, ctx: Record<string, unknown>): unknown {
	if (typeof node !== 'object' || node === null || Array.isArray(node)) return node;
	const [op, args] = Object.entries(node as Record<string, unknown>)[0];
	if (op === 'var') return lookup(ctx, String(args));
	const argsList = Array.isArray(args) ? args : [args];
	const vals = argsList.map((a) => evalNode(a, ctx));
	switch (op) {
		case '==':
			return vals[0] === vals[1];
		case '!=':
			return vals[0] !== vals[1];
		case '<':
		case '<=':
		case '>':
		case '>=': {
			const [a, b] = vals;
			if (a === null || b === null || a === undefined || b === undefined) return false;
			if (op === '<') return (a as number) < (b as number);
			if (op === '<=') return (a as number) <= (b as number);
			if (op === '>') return (a as number) > (b as number);
			return (a as number) >= (b as number);
		}
		case 'and':
			return vals.every(Boolean);
		case 'or':
			return vals.some(Boolean);
		case '!':
			return !vals[0];
		case '!!':
			return Boolean(vals[0]);
		case 'in': {
			const container = vals[1];
			if (Array.isArray(container)) return container.includes(vals[0]);
			if (typeof container === 'string') return container.includes(String(vals[0]));
			return false;
		}
		default:
			return false;
	}
}

export interface SimOutcome {
	stage: 'floor' | 'guardrail' | 'signoff' | 'commit';
	/** Index into guardrails when stage === 'guardrail'. */
	index?: number;
	effect?: 'override' | 'interrupt';
	/** The decision that stands. On an interrupt this is the UNCHANGED draft —
	 * the backend keeps the verdict and sets interrupted; a human disposes. */
	finalDecision: string;
	/** True when the draft is held for human sign-off (interrupt semantics). */
	heldForReview?: boolean;
	reason: string;
}

/** What the guard would do to a draft verdict — floor edges, then first-match
 * guardrail (raise-only overrides), then close sign-off, mirroring guard.py. */
export function simulateGuard(def: TriagePolicyDef, ctx: Record<string, unknown>): SimOutcome {
	const verdict = String(lookup(ctx, 'verdict') ?? '');
	const ioc = Boolean(lookup(ctx, 'enrichment.ioc'));
	const authzClass = String(lookup(ctx, 'authz.class') ?? 'absent');
	if (verdict === 'close' && ioc) {
		return {
			stage: 'floor',
			finalDecision: 'escalate',
			reason: m.tp_sim_reason_ioc_floor()
		};
	}
	if (verdict === 'close' && authzClass === 'contradicted') {
		return {
			stage: 'floor',
			finalDecision: 'escalate',
			reason: m.tp_sim_reason_authz_floor()
		};
	}
	const rails = def.guardrails ?? [];
	for (let i = 0; i < rails.length; i++) {
		const g = rails[i];
		if (!evaluateCondition(g.when, ctx)) continue;
		if (g.effect === 'override') {
			if ((DECISION_RANK[g.to] ?? -1) <= (DECISION_RANK[verdict] ?? 99)) continue; // raise-only
			return {
				stage: 'guardrail',
				index: i,
				effect: 'override',
				finalDecision: g.to,
				reason: g.reason
			};
		}
		return {
			stage: 'guardrail',
			index: i,
			effect: 'interrupt',
			finalDecision: verdict, // draft stands — routed to review, not rewritten
			heldForReview: true,
			reason: g.reason
		};
	}
	const signoff = (def.close_signoff_data_classes ?? []).map((c) => c.toLowerCase());
	const dataClass = String(lookup(ctx, 'asset.data_classification') ?? '').toLowerCase();
	if (verdict === 'close' && dataClass && signoff.includes(dataClass)) {
		return {
			stage: 'signoff',
			effect: 'interrupt',
			finalDecision: verdict, // draft stands — held for sign-off
			heldForReview: true,
			reason: m.tp_sim_reason_signoff({ dataClass })
		};
	}
	return {
		stage: 'commit',
		finalDecision: verdict,
		reason: m.tp_sim_reason_commit()
	};
}

// ------------------------------------------------------------- plain language

/** A human-readable sentence for a condition, used in summaries and previews. */
export function conditionToSentence(node: unknown): string {
	const group = conditionToGroup(node);
	if (group === null) return m.tp_condition_custom_json();
	return groupSentence(group);
}

function groupSentence(group: RuleGroup): string {
	const parts = group.children.map((c) =>
		c.kind === 'group' ? m.tp_condition_group({ condition: groupSentence(c) }) : ruleSentence(c)
	);
	return parts.join(group.op === 'and' ? m.tp_condition_join_and() : m.tp_condition_join_or());
}

function ruleSentence(rule: RuleRow): string {
	const field = contractField(rule.field);
	const name = field?.label() ?? rule.field;
	if (field?.type === 'boolean' && rule.op === '==') {
		return rule.value === true
			? m.tp_condition_bool_true({ field: name })
			: m.tp_condition_bool_false({ field: name });
	}
	const val = Array.isArray(rule.value)
		? rule.value.map((v) => String(v)).join(', ')
		: String(rule.value);
	switch (rule.op) {
		case '==':
			return m.tp_condition_op_eq({ field: name, value: val });
		case '!=':
			return m.tp_condition_op_neq({ field: name, value: val });
		case '<':
			return m.tp_condition_op_lt({ field: name, value: val });
		case '<=':
			return m.tp_condition_op_lte({ field: name, value: val });
		case '>':
			return m.tp_condition_op_gt({ field: name, value: val });
		case '>=':
			return m.tp_condition_op_gte({ field: name, value: val });
		case 'in':
			return m.tp_condition_op_in({ field: name, value: val });
		default:
			return m.tp_condition_op_unknown({ field: name, op: rule.op, value: val });
	}
}
