/**
 * Tenant lifecycle API. Backed by V1's /api/mssp/tenants surface; only
 * mssp_admin/mssp_analyst roles can read or mutate. UI gating happens
 * via the ``isMsspScope`` store — anything that imports this module
 * must check role first.
 */

const API_BASE = '/api';

class TenantApiError extends Error {
	constructor(public status: number, message: string) {
		super(message);
	}
}

async function _request<T>(endpoint: string, init: RequestInit = {}): Promise<T> {
	const r = await fetch(`${API_BASE}${endpoint}`, {
		credentials: 'include',
		...init,
		headers: {
			'Content-Type': 'application/json',
			...(init.headers ?? {})
		}
	});
	if (!r.ok) {
		const body = await r.text();
		throw new TenantApiError(r.status, body || r.statusText);
	}
	if (r.status === 204) return undefined as unknown as T;
	return (await r.json()) as T;
}

export type TenantProfile = 'poc' | 'persistent' | 'provided' | 'legacy';

export type TenantState =
	| 'pending'
	| 'provisioning'
	| 'active'
	| 'suspended'
	| 'degraded'
	| 'decommissioning'
	| 'archived'
	| 'purged';

export interface Tenant {
	id: string;
	slug: string;
	display_name: string;
	state: TenantState;
	profile?: TenantProfile | null;
	created_at: string;
	state_changed_at: string;
	runtime?: Record<string, unknown> | null;
}

export interface TenantOnboard {
	slug: string;
	display_name: string;
	profile: 'poc' | 'persistent' | 'provided';
	branding_app_name?: string | null;
	branding_logo_url?: string | null;
	branding_primary_color?: string | null;
	branding_secondary_color?: string | null;
	contact_email?: string | null;
	llm_base_url?: string;
	llm_model?: string;
}

export interface LifecycleEvent {
	id: string;
	timestamp: string;
	event_type: string;
	from_state: string | null;
	to_state: string | null;
	actor_id: string | null;
	details: Record<string, unknown>;
}

export const tenantsApi = {
	list: () => _request<Tenant[]>('/mssp/tenants'),
	get: (id: string) => _request<Tenant>(`/mssp/tenants/${id}`),
	onboard: (body: TenantOnboard) =>
		_request<Tenant>('/mssp/tenants/onboard', {
			method: 'POST',
			body: JSON.stringify(body)
		}),
	retry: (id: string) =>
		_request<unknown>(`/mssp/tenants/${id}:retry`, { method: 'POST' }),
	suspend: (id: string) =>
		_request<Tenant>(`/mssp/tenants/${id}:suspend`, { method: 'POST' }),
	resume: (id: string) =>
		_request<Tenant>(`/mssp/tenants/${id}:resume`, { method: 'POST' }),
	decommission: (id: string) =>
		_request<Tenant>(`/mssp/tenants/${id}:decommission`, { method: 'POST' }),
	events: (id: string, limit = 100) =>
		_request<LifecycleEvent[]>(`/mssp/tenants/${id}/events?limit=${limit}`)
};

export function tenantStateBadge(state: TenantState): string {
	switch (state) {
		case 'active':
			return 'variant-filled-success';
		case 'pending':
		case 'provisioning':
			return 'variant-filled-warning';
		case 'degraded':
		case 'suspended':
			return 'variant-filled-error';
		case 'decommissioning':
		case 'archived':
		case 'purged':
			return 'variant-filled-surface';
		default:
			return 'variant-filled-tertiary';
	}
}
