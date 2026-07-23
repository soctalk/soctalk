// Human-readable rendering + status derivation for authorization facts and
// engagements. Kept UI-framework-free so it can be unit-tested and reused by
// list rows, the fact-form live preview, and the engagement cards.
//
// Facts carry a loose shape (`AuthorizationFact` is an open interface), so we
// read kind-specific fields defensively via a record view rather than casts.

import type { AuthorizationFact, TenantEngagement } from '$lib/api/client';

type Rec = Record<string, unknown>;

function s(v: unknown): string | undefined {
	return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function shortDate(iso: string | null | undefined): string {
	if (!iso) return '';
	// Trust the ISO date portion; avoids locale churn in summaries.
	return iso.slice(0, 10);
}

/** Account: "svc-deploy → sudo-exec on db-01". FIM: "modify on /etc/sudoers*". */
function scopePhrase(fact: AuthorizationFact): string {
	const sc = (fact.scope ?? {}) as Rec;
	if (fact.track === 'fim') {
		const target = s(sc.target) ?? 'any path';
		const ct = s(sc.change_type) ?? 'any change';
		return `${ct} on ${target}`;
	}
	const subject = s(sc.subject);
	const action = s(sc.action);
	const target = s(sc.target);
	const parts: string[] = [];
	if (subject) parts.push(subject);
	if (action) parts.push(`${parts.length ? '→ ' : ''}${action}`);
	if (target) parts.push(`on ${target}`);
	return parts.length ? parts.join(' ') : 'any activity';
}

function appliesPhrase(fact: AuthorizationFact): string {
	const a = (fact as Rec).applies_to as Rec | undefined;
	if (!a) return '';
	const dims = ['env', 'criticality', 'data_class', 'config_class']
		.map((k) => {
			const v = a[k];
			return Array.isArray(v) && v.length ? `${k}: ${v.join('/')}` : null;
		})
		.filter(Boolean);
	return dims.length ? ` (${dims.join(', ')})` : '';
}

/** One-line, plain-English summary of a fact for list rows and the form preview. */
export function factSummary(fact: AuthorizationFact): string {
	const f = fact as unknown as Rec;
	const until = s(fact.valid_until as string) ? `, until ${shortDate(fact.valid_until)}` : '';
	switch (fact.kind) {
		case 'grant': {
			const cls = s(f.grant_class);
			const scope = scopePhrase(fact);
			if (cls === 'change_ticket') {
				const id = s(fact.id) ?? 'change ticket';
				return `Change ticket ${id} permits ${scope}${until}`;
			}
			if (cls === 'routine_observation') {
				const seen = typeof f.seen_count === 'number' ? f.seen_count : undefined;
				const ioc = f.ioc === true ? ', IOC present' : '';
				return `Routine${seen != null ? ` (seen ${seen}×)` : ''}: ${scope}${ioc}`;
			}
			return `Baseline: ${scope} is routine${until}`;
		}
		case 'prohibition': {
			if (fact.track === 'fim') {
				const cts = Array.isArray(f.forbid_change_type)
					? (f.forbid_change_type as string[]).join('/')
					: 'any';
				const sc = (fact.scope ?? {}) as Rec;
				const path = s(sc.target) ? ` to ${s(sc.target)}` : '';
				return `Forbid ${cts} change${path}${appliesPhrase(fact)}`;
			}
			const acct = s(f.forbid_account_type);
			const action = s(f.forbid_action) ?? 'that action';
			const who = acct ? `${acct} accounts` : 'accounts';
			return `${who} may not ${action}${appliesPhrase(fact)}`;
		}
		case 'change_freeze': {
			const scopeRec = (f.freeze_scope ?? {}) as Rec;
			const envs = Array.isArray(scopeRec.envs) ? (scopeRec.envs as string[]) : [];
			const cfg = Array.isArray(scopeRec.config_classes)
				? (scopeRec.config_classes as string[])
				: [];
			const what = envs.length ? envs.join('/') : cfg.length ? cfg.join('/') : 'everything';
			const win = `${shortDate(s(f.start) as string)} → ${shortDate(s(f.end) as string)}`;
			return `Change freeze on ${what} (${win})`;
		}
		case 'entity_context': {
			const name = s(f.name) ?? 'entity';
			const type = s(f.entity_type) ?? 'entity';
			const attrs = ['environment', 'criticality', 'data_classification', 'compromise_status']
				.map((k) => s(f[k]))
				.filter(Boolean);
			const desc = attrs.length ? `${attrs.join(', ')} ` : '';
			return `${name} is a ${desc}${type}`;
		}
		default:
			return s(fact.id) ?? 'authorization fact';
	}
}

// ---- engagements ----

export type EngagementStatus = 'scheduled' | 'active' | 'expired' | 'revoked';

/**
 * Derive lifecycle status client-side: the API's EngagementDTO has no status
 * field, only starts_at / ends_at / revoked_at. `nowMs` is injectable for tests.
 */
export function engagementStatus(e: TenantEngagement, nowMs = Date.now()): EngagementStatus {
	if (e.revoked_at) return 'revoked';
	const start = Date.parse(e.starts_at);
	const end = Date.parse(e.ends_at);
	if (!Number.isNaN(start) && nowMs < start) return 'scheduled';
	if (!Number.isNaN(end) && nowMs > end) return 'expired';
	return 'active';
}

/** Skeleton badge variant class for an engagement status. */
export function engagementStatusVariant(status: EngagementStatus): string {
	switch (status) {
		case 'active':
			return 'variant-filled-success';
		case 'scheduled':
			return 'variant-soft-primary';
		case 'revoked':
			return 'variant-soft-error';
		case 'expired':
		default:
			return 'variant-soft';
	}
}
