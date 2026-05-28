# SocTalk AI Chat — Plan

## Goals & non-goals

**Goals**
- Conversational analyst interface that's tool-grounded against Wazuh + SocTalk's own
  data (no free-form hallucination).
- Two surfaces: per-investigation dock (auto-scoped) + global `/chat` route (open-ended).
- Agent can *propose* actions (approve/reject review, close investigation) but never
  executes them — analyst clicks Confirm, which goes through the existing review API.
- Full audit trail: conversations + messages stored, role-aware-session same as
  audit/analytics.
- Cost-bounded: per-turn cap, per-conversation cap, integrates with the existing tenant
  daily $15 cap.

**Non-goals (Phase 1)**
- Voice/audio.
- Image upload.
- Proactive notifications ("hey, I noticed…").
- Multi-agent / agent-to-agent.
- Cross-tenant context spillover for tenant-bound users.
- Auto-confirmation of proposed actions via chat ("yes do it" should *not* bypass the
  button).

---

## Architecture

```
Browser
  /chat global page  ─┐
  Inv. detail dock   ─┤   SSE
  Top-bar trigger    ─┼─►   /api/chat/conversations/{id}/messages
  Review-card inline ─┘
                                  │
                                  ▼
                          POST handler (SSE)
                                  │
                                  ▼
                     soctalk.chat.agent (LangGraph)
                          │            │
                ┌─────────┘            └──────────┐
                ▼                                  ▼
        Read-only DB tools                MCP tools (Wazuh,
        (role-aware session)              and Cortex/MISP/TheHive
        get_investigation,                when bound — reuse the
        list_pending_reviews,             same MCPClientManager the
        recent_alerts,                    verdict node uses)
        audit_trail,
        tenant_stats,
        search_investigations
                │
                ▼
        PostgreSQL (RLS-scoped or BYPASSRLS by role)
                │
                ▼
        New tables: conversations, chat_messages
        Existing: investigations, pending_reviews, alerts, events
```

The agent never has a write tool. The only state-changing path is: agent emits
`proposed_action` part → frontend renders a button → analyst clicks → POST to existing
`/api/review/{id}/approve` (or sibling). Audit trail picks it up exactly as it does
today.

---

## File layout

**Backend** (new)

```
src/soctalk/chat/
  __init__.py
  agent.py            # LangGraph chat node + loop
  tools.py            # Read-only DB tools, role-aware
  actions.py          # Proposed-action emitter + schema
  cost.py             # Per-conversation budget tracker
  prompts.py          # System prompt (per-investigation + global variants)
  sse.py              # SSE event types + serializer

src/soctalk/core/api/
  chat.py             # FastAPI router for /api/chat/*

src/soctalk/persistence/
  chat_models.py      # SQLModel for conversations, chat_messages

alembic/versions/
  NNNN_chat_tables.py # conversations + chat_messages + RLS policies
```

**Frontend** (new)

```
frontend/src/routes/
  chat/+page.svelte          # global list + active pane
  chat/[id]/+page.svelte     # specific conversation

frontend/src/lib/components/chat/
  ChatPanel.svelte           # the dock/panel (reused on inv. detail + review)
  MessageList.svelte
  UserMessage.svelte
  AssistantMessage.svelte
  ToolCallBadge.svelte
  ProposedActionCard.svelte
  Composer.svelte
  CostFooter.svelte
  ChatBubble.svelte          # floating "Ask AI" trigger
  ConversationList.svelte    # for /chat route

frontend/src/lib/stores/
  chat.ts                    # active conversation, messages, streaming state, abort
```

**Frontend** (integration edits)

```
frontend/src/routes/+layout.svelte           # add nav entry + top-bar "Ask AI" chip
frontend/src/routes/investigations/[id]/...  # mount ChatPanel as right rail
frontend/src/routes/review/+page.svelte      # add "Ask AI" link on expanded card
```

---

## Data model

```sql
CREATE TABLE conversations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id),
    created_by_user_id   UUID NOT NULL REFERENCES users(id),
    -- ON DELETE SET NULL so closing/deleting an investigation doesn't
    -- block conversation cleanup; the conversation just becomes global
    -- and the agent loses the case context on next turn (which is
    -- correct — the case is gone).
    investigation_id     UUID REFERENCES investigations(id) ON DELETE SET NULL,
    title                TEXT,
    model_name           TEXT NOT NULL,
    -- Conversation pins the model at creation. Switching the tenant's
    -- chat model mid-conversation does NOT migrate existing rows;
    -- ``conversations.model_name`` is the source of truth for the
    -- agent loop. Operators changing models start a new conversation.
    status               TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','closed','budget_exhausted')),
    -- BIGINT, not INT. A long-running ops conversation can plausibly
    -- hit hundreds of millions of tokens (tool results compound) and
    -- INT overflows at 2.1B.
    total_tokens         BIGINT NOT NULL DEFAULT 0,
    total_dollars        FLOAT NOT NULL DEFAULT 0.0,
    budget_dollars       FLOAT NOT NULL DEFAULT 1.0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_message_at      TIMESTAMPTZ
);

CREATE TABLE chat_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    role            TEXT NOT NULL
                     CHECK (role IN ('user','assistant','tool','system','action')),
    content         JSONB NOT NULL,
                    -- user/assistant: {"text": "..."}
                    -- tool:           {"name": "...", "args": {...}, "result": {...}, "truncated": bool}
                    -- action:         see "proposed action shape" below
                    -- system:         {"text": "..."}
    -- Enforce required JSON shape per role so we don't end up with a
    -- free-for-all union the projector can't trust.
    CONSTRAINT ck_chat_messages_content_shape CHECK (
        (role = 'user'      AND content ? 'text') OR
        (role = 'assistant' AND content ? 'text') OR
        (role = 'system'    AND content ? 'text') OR
        (role = 'tool'      AND content ? 'name' AND content ? 'args' AND content ? 'result') OR
        (role = 'action'    AND content ? 'action' AND content ? 'target')
    ),
    tokens_in       INT DEFAULT 0,
    tokens_out      INT DEFAULT 0,
    dollars         FLOAT DEFAULT 0.0,
    model_name      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS policies on both tables, copied from the events table shape:
--   USING / WITH CHECK: tenant_id matches app.current_tenant_id (or null-null match)
-- Reads use the same role-aware session pattern as audit/analytics.
-- WRITES need an explicit tenant_id stamping rule (see "MSSP-write
-- tenant rule" section below) — the audit/analytics helpers don't
-- INSERT, so we can't just copy them.

CREATE INDEX ix_conversations_tenant_created
    ON conversations (tenant_id, created_at DESC);
CREATE INDEX ix_conversations_investigation
    ON conversations (investigation_id)
    WHERE investigation_id IS NOT NULL;
CREATE INDEX ix_chat_messages_conv_created
    ON chat_messages (conversation_id, created_at);
```

### MSSP-write tenant-id rule

The role-aware session pattern as it exists in `_audit_session_for` and
`_analytics_session_for` is read-only. Chat writes (conversation create, message
append) need an explicit rule for which `tenant_id` to stamp on the row:

1. **If `investigation_id` is provided**, look up that investigation's `tenant_id` and
   use it. The investigation row itself acts as the authoritative tenant binding.
   Validate that the caller's role allows access (MSSP-level: always; tenant-level:
   only if `identity.tenant_id` matches).
2. **If no `investigation_id`** (global chat), use the caller's `current_tenant` pin
   if set (mssp_admin with Open SOC active), else the caller's home `tenant_id`. An
   MSSP-level user *without* a tenant pin cannot create a global chat — they must
   pin first. (Cross-tenant chat is out of scope for Phase 1; a single conversation
   doesn't have a well-defined "tenant" answer for the audit log if it isn't pinned.)
3. **Title auto-generation** is heuristic (first 80 chars of first user message,
   stripped of newlines), NOT an LLM call. Bills nothing, deterministic, simple.

The MSSP BYPASSRLS session is still used for the actual INSERT so the row lands
regardless of `app.current_tenant_id`. The `tenant_id` column is the *data* binding;
the RLS policy is just the *read* gate.

---

## Tool surface

All read-only. All use `_chat_session_for(identity)` — same role-aware helper as
audit/analytics.

| Tool                                                  | Returns                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `get_investigation(investigation_id)`                 | full case row + active pending_review + last 10 alerts + last 20 events                |
| `list_pending_reviews(status, limit=20)`              | titles, severities, AI decisions, created_at                                           |
| `recent_alerts(rule_id?, severity_min?, hours=24, limit=50)` | alert rows truncated to safe size                                              |
| `audit_trail(investigation_id?, event_type?, hours=72, limit=100)` | events table query                                                      |
| `tenant_stats(days=7)`                                | rolled-up counts: alerts, investigations, pending, escalation rate, AI confidence avg  |
| `search_investigations(query, limit=20)`              | ILIKE on title + summary                                                               |
| **MCP tools** (Wazuh + future)                        | reuse existing binding — same as the verdict node uses                                 |

Every tool result is wrapped in a size guard: max 8 KB per result, with
`truncated: true` + a hint if exceeded.

---

## Proposed-action shape

```json
{
  "type": "proposed_action",
  "action": "approve_review",
  "target": {
    "kind": "pending_review",
    "id": "d2f30f53-...",
    "title": "MITRE T1110 brute force"
  },
  "reason": "10 failed SSH attempts from 185.220.x.x within 30s, AI confidence 0.85, no enrichment data needed to confirm pattern.",
  "evidence": [
    {"kind": "alert", "id": "...", "label": "SOCTALK_ATTACK T1110.001"},
    {"kind": "event", "id": "...", "label": "verdict.rendered"},
    {"kind": "investigation", "id": "...", "label": "..."}
  ],
  "confidence": 0.85,
  "feedback": "AI-suggested; analyst confirmed via chat"
}
```

`action` is one of: `approve_review`, `reject_review`, `expire_review`,
`close_investigation`.

### Confirmation flow (security-critical)

The model **never controls the URL**. The proposed-action payload contains only the
`action` verb and the target's `id` + `kind`. When the analyst clicks Confirm, the
frontend POSTs to a single dispatch endpoint:

```
POST /api/chat/conversations/{conv_id}/messages/{msg_id}/confirm
  body: {}
```

The backend:

1. Loads the `chat_messages` row by `msg_id`, verifies role=`action` and
   conversation_id matches.
2. Reads `content.action` + `content.target` from the row (server-side, NOT trusting
   any client-supplied URL or body).
3. Maps `(action, target.kind)` to the right existing endpoint:
   - `approve_review` / `pending_review` → existing `record_human_decision_received`
     helper with decision="approve"
   - `reject_review` / `pending_review` → same helper with decision="reject"
   - `expire_review` / `pending_review` → existing `record_human_review_expired` helper
   - `close_investigation` / `investigation` → **new** endpoint needed (Phase 3+);
     out of Phase 2 scope
4. Re-runs the same role-aware authorisation check as the direct review endpoints
   (`_resolve_pending_review`-style ownership re-verification).
5. Flips the `chat_messages.content` to include `{confirmed_at, confirmed_by_user_id}`
   so the conversation history shows the resolution.

This keeps the model output trusted only for *what to suggest*, not *what URL to call*.
If the model hallucinates a UUID for a different tenant, step (4) blocks it. If the
model emits a malformed action, step (3) refuses it.

The downside: `close_investigation` is unavailable until a new endpoint exists. The
existing review flow only has approve/reject/expire/request_info. Defer
`close_investigation` to a later phase or build that endpoint as part of Phase 2.

---

## SSE wire format

The POST `/api/chat/conversations/{id}/messages` response is `text/event-stream`.
Custom event types (not Vercel AI SDK protocol — keeps us in control):

```
event: delta
data: {"text": "The supervisor "}

event: tool_call
data: {"call_id": "tc_1", "name": "get_investigation", "args": {"id": "..."}}

event: tool_result
data: {"call_id": "tc_1", "result": {...}, "truncated": false}

event: proposed_action
data: { ...the JSON above... }

event: usage
data: {"tokens_in": 1234, "tokens_out": 87, "dollars": 0.0023, "conv_total_dollars": 0.18}

event: done
data: {"message_id": "...", "stop_reason": "end_turn"}

event: error
data: {"category": "budget_exhausted | provider_error | rate_limited", "message": "..."}
```

Client-side store handles each type: appends delta to active assistant bubble, expands
tool_call to badge, renders proposed_action card, updates cost footer on usage, closes
stream on done/error.

---

## API endpoints

| Method | Path                                                                  | Body                                       | Returns                          |
| ------ | --------------------------------------------------------------------- | ------------------------------------------ | -------------------------------- |
| POST   | `/api/chat/conversations`                                             | `{investigation_id?: str, model?: str}`    | conversation row                 |
| GET    | `/api/chat/conversations`                                             | `?investigation_id=&limit=&offset=`        | paginated list                   |
| GET    | `/api/chat/conversations/{id}`                                        | —                                          | conversation + last 50 messages  |
| DELETE | `/api/chat/conversations/{id}`                                        | —                                          | soft delete (set status=closed)  |
| GET    | `/api/chat/conversations/{id}/messages`                               | `?before=cursor&limit=`                    | paginated messages               |
| POST   | `/api/chat/conversations/{id}/messages`                               | `{text: str}`                              | **SSE stream** of the assistant  |
| POST   | `/api/chat/conversations/{id}/stop`                                   | —                                          | abort an in-flight stream        |
| POST   | `/api/chat/conversations/{conv_id}/messages/{msg_id}/confirm`         | `{}`                                       | confirmed action result          |

All routes role-aware-session. MSSP roles get cross-tenant *reads*; chat *writes*
follow the MSSP-write tenant-id rule above. Tenant roles are scoped to their home
tenant for both reads and writes.

CSRF: handled by the existing global middleware (auth `internal_session_middleware`
applies the Origin/Referer check to all state-changing routes once mounted — no
per-endpoint work).

### Streaming (POST-body SSE)

`POST /messages` returns `Content-Type: text/event-stream` but is *not* consumable by
the browser's native `EventSource` (which only supports GET, no request body). The
frontend reads it via `fetch()` + `ReadableStream` + a small SSE-frame parser. This is
a new abstraction — the existing frontend only consumes a GET-style heartbeat at
`/api/events/stream`. The cost is a thin (~80 lines) custom hook in
`frontend/src/lib/stores/chat.ts` that wraps the fetch loop and yields parsed events;
abort is done via the `AbortController` passed to fetch.

The server polls `request.is_disconnected()` between LLM stream chunks so a closed tab
cancels the LLM call promptly. Without this, a user closing the tab mid-stream still
incurs the full turn's cost — a real bill-leak risk.

---

## Cost guardrails

| Cap                    | Default                            | Source                                                                                                            | Behaviour                                                                                                            |
| ---------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Per-turn input         | 6k tokens                          | `SOCTALK_CHAT_TURN_INPUT_CAP`                                                                                     | enforced by truncating tool results + history; warn if user msg alone exceeds                                        |
| Per-turn output        | 2k tokens                          | model `max_tokens`                                                                                                | model stops naturally                                                                                                |
| Per-conversation       | $1.00 / 60k tokens                 | column on conversations                                                                                           | on overshoot mid-stream: emit budget_exhausted, save partial, conversation status→`budget_exhausted`                 |
| Tenant daily           | rolls up to existing $15 cap       | sum `chat_messages.dollars` + `investigation_runs.dollars_used` over 24h                                          | new turn refused with HTTP 429 if exceeded                                                                           |

### Unified daily-cap query (concrete plan)

The existing `worker_runs.claim_run` cap query is the *worker* path — it gates
*claim*, not chat turns. Two separate enforcement points are needed, both unioning the
same two sources:

```python
def _tenant_daily_spend_query() -> str:
    # Window keyed on *when the spend happened*. For investigation_runs:
    # COALESCE(ended_at, lease_expires_at, claimed_at, started_at).
    # For chat_messages: created_at (point-in-time; no lifecycle).
    return """
        SELECT COALESCE(SUM(s.tokens), 0)::bigint AS tokens,
               COALESCE(SUM(s.dollars), 0)::float AS dollars
        FROM (
            SELECT tokens_used AS tokens, dollars_used AS dollars
              FROM investigation_runs
             WHERE tenant_id = :t
               AND COALESCE(ended_at, lease_expires_at, claimed_at, started_at)
                   >= now() - interval '24 hours'
            UNION ALL
            SELECT (tokens_in + tokens_out)::bigint AS tokens, dollars
              FROM chat_messages
             WHERE tenant_id = :t
               AND created_at >= now() - interval '24 hours'
        ) s
    """
```

This same query runs:
- In `worker_runs.claim_run` (existing call site, replaces the current
  investigation_runs-only query)
- In the chat POST `/messages` handler, *before* kicking off the LangGraph turn

A 24h window on `chat_messages.created_at` is a slightly different semantic than the
runs window (point-in-time vs lifecycle), but the union is honest about cost: each row
represents real LLM spend.

### Conversation context eviction

The per-conversation $1 cap (~60k tokens) is small enough that without context
eviction, you run out in 8–12 turns once tool results are flowing. The agent loop must:

1. Always include: system prompt + last 2 user messages + last 2 assistant messages
   + the most recent `proposed_action` if any.
2. For tool results older than the last 2 turns: replace the full result with a
   1-line summary (`"get_investigation:a3d4 → severity=critical, status=active"`).
3. If the rolling window still exceeds `SOCTALK_CHAT_TURN_INPUT_CAP`, drop the oldest
   tool-result summaries first, then oldest assistant messages, then oldest user
   messages — never the system prompt, never the most recent turn.

This is the part the plan didn't acknowledge and is non-trivial work. ~150 lines of
`agent.py` honestly.

---

## Phasing

**Phase 1 — MVP (≈ 4–6 days)** *(revised from "2 days" after review)*

- Schema migration + SQLModels + RLS policies + CHECK constraints on `content`
- Unified daily-cap query helper (replaces the existing runs-only query in two call sites)
- Conversation-context eviction logic (system + last-2-turns + summarised tool refs)
- `chat/agent.py` with the 5 read tools (skip MCP tools for now), including
  `_classify_llm_error` reuse and `request.is_disconnected()` polling
- `chat/cost.py` with per-conversation budget enforcement + tenant daily check
- `core/api/chat.py` with POST/GET/SSE endpoints + `FOR UPDATE` row lock on
  conversation before kicking off a turn (rejects parallel-tab attempts with 409)
- POST-body SSE plumbing on the frontend (`fetch` + `ReadableStream` + abort), since
  native `EventSource` doesn't accept a body
- `ChatPanel.svelte` + `MessageList` + `UserMessage` + `AssistantMessage` +
  `Composer` + `CostFooter`
- Mount on investigation detail right rail only
- **No proposed actions yet** — read-only loop, prove streaming/cost/audit
- Default model: Sonnet 4.6 for chat (smarter than Haiku, ~3× more expensive but
  bounded by cap)
- Integration test: tenant-A user cannot retrieve tenant-B investigation via any tool
- Integration test: closing the tab mid-stream cancels the LLM call within 1s

**What was missing from the original 2-day estimate** (so the bump is honest):
the POST-body SSE abstraction (no existing pattern in the frontend), the
`FOR UPDATE` lock and 409 contract, mid-stream LangGraph cancellation,
`request.is_disconnected()` polling on the server, the unified-cap migration that
touches the worker's existing cap query, and the context-eviction loop. Each is
a few hours; together they push the estimate.

**Phase 2 — Proposed actions (≈ 1–2 days)**

- `actions.py` emits `proposed_action` parts (no URL — just `action` + `target`)
- New `/messages/{msg_id}/confirm` dispatch endpoint (server-side action→helper map)
- `ProposedActionCard.svelte` with Confirm/Dismiss buttons
- Confirm → dispatch endpoint → existing `record_human_decision_received` /
  `record_human_review_expired` helper; message row flips to include
  `{confirmed_at, confirmed_by_user_id}`
- Phase 2 ships: `approve_review`, `reject_review`, `expire_review`
- **NOT in Phase 2**: `close_investigation` — no existing endpoint for that on the
  IR side; either build the endpoint as part of this phase (adds ~half day) or
  defer to Phase 3+. The plan defers it.

**Phase 3 — Global `/chat` (≈ 1 day)**

- `/chat/+page.svelte` two-pane layout
- `ConversationList.svelte` (recent + pinned + search)
- Sidebar nav entry
- Top-bar "Ask AI" chip with auto-context detection

**Phase 4 — Polish (no deadline)**

- Wire MCP tools (Wazuh) into chat — same binding as the verdict node
- Slash commands (`/investigation`, `/alert`, `/audit`, `/tenant`)
- Conversation full-text search
- Mobile/narrow polish
- Cortex/MISP/TheHive tools when those MCP integrations land

---

## Risks & mitigations

| Risk                                                                 | Mitigation                                                                                                                                                                                |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hallucination when a tool doesn't exist for the question             | System prompt requires the agent to say "I don't have a way to check that" rather than guess; reinforced with few-shot examples in `prompts.py`                                            |
| Tool result truncation drops the relevant row                        | Each tool returns a `truncated: bool` flag + a suggested filter; agent is prompted to refine and re-call when truncated                                                                    |
| Streaming response halts mid-paragraph on budget exhaust             | Emit `budget_exhausted`, persist whatever assistant text streamed, conversation status flips; analyst sees the partial reply + "conversation budget reached" notice with a "start new" button |
| RLS leak via tool that bypasses session                              | One helper `_chat_session_for(identity)` used by every tool, audited; integration test verifies a tenant user can't query another tenant's investigation_id                                |
| Cost-cap edge: parallel turns from two browser tabs                  | Lock the conversation row `FOR UPDATE` before starting a turn; second concurrent turn waits or 409s                                                                                       |
| Provider error leaks raw message into chat                           | Same `_classify_llm_error` shape from verdict node; user sees a category, not the raw provider error string                                                                                |
| Model emits action URL pointing at wrong tenant                      | The `proposed_action` payload never contains a URL. Frontend POSTs to a single dispatch endpoint that derives the call server-side from `(action, target.kind, target.id)` and re-verifies ownership |
| Browser closes mid-stream, server keeps spending                     | Server polls `request.is_disconnected()` between LLM chunks; cancels the LangGraph invoke + persists partial assistant text + emits `done` with `stop_reason=disconnected`                |
| MSSP-chat tenant_id ambiguity                                        | Explicit rule: `investigation_id` present → inherit its tenant; absent → require `current_tenant` pin; cross-tenant chats out of Phase 1 scope                                            |
| Mid-conversation tenant changes chat model                           | `conversations.model_name` is the source of truth for the loop; tenant settings change does NOT migrate existing conversations                                                            |
| Conversation context blows the cap                                   | Active eviction (see "Conversation context eviction" above) — system + last 2 turns full + older tool results summarised; tested with a 50-turn synthetic conversation                  |

---

## Open decisions to lock in before coding

1. **Should chat dollars count toward the tenant daily $15 cap, or have a separate
   chat-only cap?** Recommendation: fold in — single shared spend ceiling is easier to
   reason about. Operators who want chat-specific limits can override via env later.
2. **Default model for chat: Sonnet 4.6 or Haiku 4.5?** Recommendation: Sonnet 4.6 by
   default (chat needs reasoning; conversation budget bounds the blow-up). Per-tenant
   override via existing `llm_reasoning_model` setting, or a new `llm_chat_model`.
3. **Conversation retention: forever or N days?** Recommendation: forever for now
   (audit value), revisit if storage becomes a problem.
4. **Custom SSE vs. Vercel AI SDK protocol?** Recommendation: custom — we want
   first-class `proposed_action` and `tool_call` events with our shape, not theirs.
5. **Auto-confirm proposed actions via "yes do it"?** Recommendation: NO — only the
   button click confirms. Reduces social-engineering risk and keeps the audit log
   unambiguous.

---

## Acceptance criteria (Phase 1)

- Analyst on `/investigations/{id}` opens the right rail, asks "why did this
  escalate?", sees a streamed reply that references `get_investigation` + `audit_trail`
  tool calls.
- Conversation row appears in `conversations` table; messages persisted; tenant_id
  correct under RLS.
- mssp_admin can see all tenants' data via tools; tenant-bound user can only see their
  own (integration test).
- Per-conversation cost footer reflects real cumulative spend; conversation halts
  gracefully when $1 cap is reached.
- Tenant daily cap check refuses new turns when combined chat + runs exceed $15 over
  24h.
- `/api/audit` shows new event type? **No** — chat lives in its own tables for now;
  only action *confirmations* flow into events table via the existing review endpoint.
