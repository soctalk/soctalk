/**
 * Chat conversation store + SSE-over-POST streaming client.
 *
 * The backend's POST /api/chat/conversations/{id}/messages returns a
 * `text/event-stream` response — but the browser's native EventSource
 * only does GET (no body), so we read the response body ourselves with
 * fetch() + ReadableStream + a small SSE frame parser. AbortController
 * carries the abort signal so closing the dock or clicking Stop
 * cancels the LLM call promptly (the backend polls
 * request.is_disconnected() in parallel).
 *
 * Event types match `soctalk.chat.sse`:
 *   delta · tool_call · tool_result · proposed_action · usage · done · error · heartbeat
 */

import { get, writable, type Writable } from 'svelte/store';

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface ConversationRow {
	id: string;
	tenant_id: string;
	created_by_user_id: string;
	investigation_id: string | null;
	title: string | null;
	model_name: string;
	status: 'active' | 'closed' | 'budget_exhausted';
	total_tokens: number;
	total_dollars: number;
	budget_dollars: number;
	created_at: string;
	last_message_at: string | null;
}

export type MessageRole = 'user' | 'assistant' | 'tool' | 'system' | 'action';

export interface MessageRow {
	id: string;
	role: MessageRole;
	content: Record<string, unknown>;
	tokens_in: number;
	tokens_out: number;
	dollars: number;
	created_at: string;
}

// In-flight assistant turn — we accumulate streaming deltas into one
// virtual row before flushing to the message log when the turn ends.
export interface PendingAssistant {
	id: 'pending';
	role: 'assistant';
	text: string;
	toolCalls: ToolCallView[];
	proposedActions: ProposedActionView[];
	streaming: boolean;
}

export interface ToolCallView {
	call_id: string;
	name: string;
	args: Record<string, unknown>;
	result?: unknown;
	truncated?: boolean;
}

export interface ProposedActionView {
	type: 'proposed_action';
	action: 'approve_review' | 'reject_review' | 'expire_review';
	target: { kind: string; id: string; title?: string | null };
	reason: string;
	evidence?: Array<{ kind: string; id: string; label?: string }>;
	confidence?: number | null;
	feedback?: string;
	// Set after the analyst clicks Confirm.
	confirmed_at?: string;
	// The message id the action is stored as — server-assigned, lazily
	// resolved by refetching the conversation after the stream ends.
	message_id?: string;
}

export interface UsageView {
	tokens_in: number;
	tokens_out: number;
	dollars: number;
	conv_total_dollars: number;
}

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

interface ChatState {
	conversation: ConversationRow | null;
	messages: MessageRow[];
	pending: PendingAssistant | null;
	usage: UsageView | null;
	loading: boolean;
	error: string | null;
	streaming: boolean;
}

function emptyState(): ChatState {
	return {
		conversation: null,
		messages: [],
		pending: null,
		usage: null,
		loading: false,
		error: null,
		streaming: false
	};
}

export function createChatStore(): {
	state: Writable<ChatState>;
	open: (investigationId?: string | null, model?: string | null) => Promise<void>;
	openExisting: (conversationId: string) => Promise<void>;
	send: (text: string) => Promise<void>;
	stop: () => void;
	confirmAction: (messageId: string) => Promise<void>;
	close: () => void;
} {
	const state = writable<ChatState>(emptyState());
	let abortCtrl: AbortController | null = null;

	async function _ensureConversation(
		investigationId?: string | null,
		model?: string | null
	): Promise<ConversationRow> {
		const cur = get(state).conversation;
		if (cur) return cur;

		state.update((s) => ({ ...s, loading: true, error: null }));
		try {
			const body: Record<string, string> = {};
			if (investigationId) body.investigation_id = investigationId;
			if (model) body.model = model;
			const conv = await _fetchJson<ConversationRow>('/api/chat/conversations', {
				method: 'POST',
				body: JSON.stringify(body)
			});
			state.update((s) => ({
				...s,
				conversation: conv,
				messages: [],
				usage: null
			}));
			return conv;
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'failed to create conversation';
			state.update((s) => ({ ...s, error: msg, loading: false }));
			throw e;
		} finally {
			state.update((s) => ({ ...s, loading: false }));
		}
	}

	async function open(
		investigationId?: string | null,
		model?: string | null
	): Promise<void> {
		// Reuse the most recent active conversation for this scope if
		// there is one — avoids spawning a new thread every dock open.
		state.update((s) => ({ ...s, loading: true, error: null }));
		try {
			const q = investigationId ? `?investigation_id=${investigationId}` : '';
			const list = await _fetchJson<{ items: ConversationRow[] }>(
				`/api/chat/conversations${q}`,
				{ method: 'GET' }
			);
			const existing = list.items.find((c) => c.status === 'active');
			if (existing) {
				await openExisting(existing.id);
				return;
			}
			await _ensureConversation(investigationId ?? null, model ?? null);
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'failed to open chat';
			state.update((s) => ({ ...s, error: msg }));
		} finally {
			state.update((s) => ({ ...s, loading: false }));
		}
	}

	async function openExisting(conversationId: string): Promise<void> {
		state.update((s) => ({ ...s, loading: true, error: null }));
		try {
			const detail = await _fetchJson<{
				conversation: ConversationRow;
				messages: MessageRow[];
			}>(`/api/chat/conversations/${conversationId}`, { method: 'GET' });
			state.update((s) => ({
				...s,
				conversation: detail.conversation,
				messages: detail.messages,
				usage: {
					tokens_in: 0,
					tokens_out: 0,
					dollars: 0,
					conv_total_dollars: detail.conversation.total_dollars
				}
			}));
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'failed to load conversation';
			state.update((s) => ({ ...s, error: msg }));
		} finally {
			state.update((s) => ({ ...s, loading: false }));
		}
	}

	async function send(text: string): Promise<void> {
		const conv = get(state).conversation;
		if (!conv) {
			state.update((s) => ({ ...s, error: 'No conversation open.' }));
			return;
		}
		if (get(state).streaming) {
			return;
		}

		// Optimistically append the user message + spawn an empty
		// pending assistant.
		const localUserId = `local-${Date.now()}`;
		state.update((s) => ({
			...s,
			error: null,
			streaming: true,
			messages: [
				...s.messages,
				{
					id: localUserId,
					role: 'user',
					content: { text },
					tokens_in: 0,
					tokens_out: 0,
					dollars: 0,
					created_at: new Date().toISOString()
				}
			],
			pending: {
				id: 'pending',
				role: 'assistant',
				text: '',
				toolCalls: [],
				proposedActions: [],
				streaming: true
			}
		}));

		abortCtrl = new AbortController();
		try {
			const url = `/api/chat/conversations/${conv.id}/messages`;
			const res = await fetch(url, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream'
				},
				credentials: 'same-origin',
				body: JSON.stringify({ text }),
				signal: abortCtrl.signal
			});
			if (!res.ok || !res.body) {
				const errText = await res.text().catch(() => '');
				throw new Error(`chat send failed (${res.status}): ${errText.slice(0, 200)}`);
			}
			for await (const ev of parseSseStream(res.body)) {
				_applyEvent(state, ev);
			}
		} catch (e) {
			if ((e as Error).name === 'AbortError') {
				// User-initiated stop; not an error.
			} else {
				const msg = e instanceof Error ? e.message : 'stream failed';
				state.update((s) => ({ ...s, error: msg }));
			}
		} finally {
			abortCtrl = null;
			// Reload conversation messages so the server-assigned IDs
			// (and any persisted proposed_action rows) replace the local
			// optimistic state cleanly.
			const cur = get(state).conversation;
			if (cur) {
				try {
					const detail = await _fetchJson<{
						conversation: ConversationRow;
						messages: MessageRow[];
					}>(`/api/chat/conversations/${cur.id}`, { method: 'GET' });
					state.update((s) => ({
						...s,
						conversation: detail.conversation,
						messages: detail.messages,
						pending: null,
						streaming: false
					}));
				} catch {
					state.update((s) => ({ ...s, pending: null, streaming: false }));
				}
			}
		}
	}

	function stop(): void {
		if (abortCtrl) {
			abortCtrl.abort();
		}
	}

	async function confirmAction(messageId: string): Promise<void> {
		const conv = get(state).conversation;
		if (!conv) return;
		try {
			await _fetchJson<{ ok: boolean }>(
				`/api/chat/conversations/${conv.id}/messages/${messageId}/confirm`,
				{ method: 'POST', body: '{}' }
			);
			await openExisting(conv.id);
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'confirm failed';
			state.update((s) => ({ ...s, error: msg }));
		}
	}

	function close(): void {
		if (abortCtrl) abortCtrl.abort();
		state.set(emptyState());
	}

	return { state, open, openExisting, send, stop, confirmAction, close };
}

// ---------------------------------------------------------------------------
// Event application
// ---------------------------------------------------------------------------

interface SseEvent {
	event: string;
	data: Record<string, unknown>;
}

function _applyEvent(state: Writable<ChatState>, ev: SseEvent): void {
	state.update((s) => {
		const pending = s.pending
			? { ...s.pending, toolCalls: [...s.pending.toolCalls], proposedActions: [...s.pending.proposedActions] }
			: null;
		if (!pending) return s;
		switch (ev.event) {
			case 'delta': {
				pending.text += (ev.data.text as string) ?? '';
				break;
			}
			case 'tool_call': {
				pending.toolCalls.push({
					call_id: ev.data.call_id as string,
					name: ev.data.name as string,
					args: (ev.data.args as Record<string, unknown>) ?? {}
				});
				break;
			}
			case 'tool_result': {
				const cid = ev.data.call_id as string;
				const tc = pending.toolCalls.find((t) => t.call_id === cid);
				if (tc) {
					tc.result = ev.data.result;
					tc.truncated = !!ev.data.truncated;
				}
				break;
			}
			case 'proposed_action': {
				pending.proposedActions.push(ev.data as unknown as ProposedActionView);
				break;
			}
			case 'usage': {
				return {
					...s,
					pending,
					usage: ev.data as unknown as UsageView
				};
			}
			case 'done': {
				pending.streaming = false;
				return { ...s, pending, streaming: false };
			}
			case 'error': {
				return {
					...s,
					pending,
					error: (ev.data.message as string) ?? (ev.data.category as string)
				};
			}
		}
		return { ...s, pending };
	});
}

// ---------------------------------------------------------------------------
// SSE frame parser (over POST-body stream)
// ---------------------------------------------------------------------------

async function* parseSseStream(body: ReadableStream<Uint8Array>): AsyncIterable<SseEvent> {
	const reader = body.getReader();
	const decoder = new TextDecoder();
	let buf = '';
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			buf += decoder.decode(value, { stream: true });
			// SSE frames are separated by a blank line (\n\n).
			let idx: number;
			while ((idx = buf.indexOf('\n\n')) >= 0) {
				const frame = buf.slice(0, idx);
				buf = buf.slice(idx + 2);
				const parsed = _parseFrame(frame);
				if (parsed) yield parsed;
			}
		}
		buf += decoder.decode();
		if (buf.length > 0) {
			const parsed = _parseFrame(buf);
			if (parsed) yield parsed;
		}
	} finally {
		try {
			reader.releaseLock();
		} catch {
			/* ignore */
		}
	}
}

function _parseFrame(raw: string): SseEvent | null {
	let event = 'message';
	const dataLines: string[] = [];
	for (const line of raw.split('\n')) {
		if (line.startsWith('event:')) {
			event = line.slice(6).trim();
		} else if (line.startsWith('data:')) {
			dataLines.push(line.slice(5).trim());
		}
	}
	if (dataLines.length === 0) return null;
	try {
		const data = JSON.parse(dataLines.join('\n'));
		return { event, data };
	} catch {
		return null;
	}
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

async function _fetchJson<T>(url: string, init: RequestInit): Promise<T> {
	const res = await fetch(url, {
		...init,
		credentials: 'same-origin',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json',
			...(init.headers ?? {})
		}
	});
	if (!res.ok) {
		const body = await res.text().catch(() => '');
		throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
	}
	return (await res.json()) as T;
}
