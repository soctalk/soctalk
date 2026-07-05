// Thin API client. Token comes from ?t= on first load, moves to
// sessionStorage, and the query param is stripped from history.

let token = '';

export function initToken(): void {
	const url = new URL(window.location.href);
	const t = url.searchParams.get('t');
	if (t) {
		sessionStorage.setItem('lp_token', t);
		url.searchParams.delete('t');
		history.replaceState(null, '', url.toString());
	}
	token = sessionStorage.getItem('lp_token') ?? '';
}

export function getToken(): string {
	if (!token) token = sessionStorage.getItem('lp_token') ?? '';
	return token;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(path, {
		method,
		headers: {
			'X-Launchpad-Token': getToken(),
			...(body ? { 'Content-Type': 'application/json' } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
	if (!res.ok) {
		let msg = `${res.status}`;
		try {
			const e = await res.json();
			msg = e?.error?.message ?? msg;
		} catch {
			/* not json */
		}
		throw new Error(msg);
	}
	return res.json() as Promise<T>;
}

export interface VMSnapshot {
	key: string;
	role: string;
	name: string;
	ipv4?: string;
	ssh_user?: string;
	hostname?: string;
	url?: string;
}

export interface GateSnapshot {
	id: string;
	instructions: string;
}

export interface RunSnapshot {
	id: string;
	status: string;
	error?: string;
	phase: string;
	started_at: string;
	ended_at?: string;
	last_seq: number;
	vms: VMSnapshot[];
	gates: GateSnapshot[] | null;
	config: Record<string, unknown>;
}

export interface JournalEvent {
	seq: number;
	ev: string;
	time: string;
	phase?: string;
	vm_key?: string;
	step?: string;
	percent?: number;
	message?: string;
	level?: string;
	gate_id?: string;
	instructions?: string;
	ipv4?: string;
	error?: { category: string; code: string; message: string };
}

export interface JSONSchema {
	type?: string;
	properties?: Record<string, JSONSchema>;
	required?: string[];
	items?: JSONSchema;
	minimum?: number;
	maximum?: number;
	additionalProperties?: boolean;
}

export interface Platform {
	name: string;
	version: string;
	capabilities: string[];
	config_schema?: JSONSchema;
	credential_env?: string[];
	available: boolean;
	error?: string;
}

export interface Host {
	name: string;
	platform: string;
	config: Record<string, unknown>;
	env?: Record<string, string>; // secret credentials (redacted in responses)
}

export interface Network {
	name: string;
	kind: string;
	tailnet: string;
	api_key: string; // secret (redacted in responses)
}

export interface ProbeResult {
	ok: boolean;
	message: string;
}

export interface TenantPlacement {
	slug: string;
	host: string;
}

export interface RunRequest {
	run_id: string;
	network: string;
	mssp_host: string;
	tenants: TenantPlacement[];
	install: Record<string, unknown>;
}

export const api = {
	listRuns: () => req<RunSnapshot[]>('GET', '/api/runs'),
	listPlatforms: () => req<Platform[]>('GET', '/api/platforms'),
	listHosts: () => req<Host[]>('GET', '/api/hosts'),
	putHost: (name: string, host: Host) => req<Host>('PUT', `/api/hosts/${encodeURIComponent(name)}`, host),
	deleteHost: (name: string) => req<{ ok: boolean }>('DELETE', `/api/hosts/${encodeURIComponent(name)}`),
	probeHost: (name: string, network?: string) =>
		req<ProbeResult>('POST', `/api/hosts/${encodeURIComponent(name)}/probe`, network ? { network } : {}),
	listNetworks: () => req<Network[]>('GET', '/api/networks'),
	putNetwork: (name: string, net: Network) => req<Network>('PUT', `/api/networks/${encodeURIComponent(name)}`, net),
	deleteNetwork: (name: string) => req<{ ok: boolean }>('DELETE', `/api/networks/${encodeURIComponent(name)}`),
	probeNetwork: (name: string) =>
		req<ProbeResult>('POST', `/api/networks/${encodeURIComponent(name)}/probe`),
	getRun: (id: string) => req<RunSnapshot>('GET', `/api/runs/${id}`),
	startRun: (cfg: unknown) => req<{ run_id: string }>('POST', '/api/runs', cfg),
	cancel: (id: string) => req<{ ok: boolean }>('POST', `/api/runs/${id}/cancel`),
	down: (id: string) => req<{ ok: boolean }>('POST', `/api/runs/${id}/down`),
	resolveGate: (id: string, gid: string) =>
		req<{ ok: boolean }>('POST', `/api/runs/${id}/gates/${gid}`),
};

// openEventStream connects the run's WS with replay-from-seq and
// auto-reconnect (2s backoff, resuming from the last seen seq).
export function openEventStream(
	runId: string,
	sinceSeq: number,
	onEvent: (ev: JournalEvent) => void,
): () => void {
	let closed = false;
	let ws: WebSocket | null = null;
	let lastSeq = sinceSeq;

	const connect = () => {
		if (closed) return;
		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		ws = new WebSocket(
			`${proto}://${location.host}/api/runs/${runId}/ws?since_seq=${lastSeq}&t=${getToken()}`,
		);
		ws.onmessage = (m) => {
			try {
				const ev = JSON.parse(m.data) as JournalEvent;
				if (ev.seq > lastSeq) lastSeq = ev.seq;
				onEvent(ev);
			} catch {
				/* skip bad frame */
			}
		};
		ws.onclose = () => {
			ws = null;
			if (!closed) setTimeout(connect, 2000);
		};
	};
	connect();
	return () => {
		closed = true;
		ws?.close();
	};
}
