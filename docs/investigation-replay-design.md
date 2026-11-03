# Investigation Replay: a cinematic view of the triage pipeline

Status: design brainstorm, 2026-07-24. Nothing built. Pending adversarial
review. An interactive concept mock (`replay-mockup.html`, kept outside the
repo) covers both altitudes described here.

## Purpose

Show, per investigation, what the AI triage pipeline actually did, as a timed
animation anyone can follow: the alert arrives, the pipeline reasons, evidence
accumulates, a verdict forms, the guardrails inspect it, and the case closes
itself or reaches a human. The feature has two jobs at once:

1. Functional: an analyst or a customer admin opens a closed investigation and
   watches the machine show its work, instead of scrolling a raw event list.
2. Persuasive: a screen recording of one good replay is the sales demo for
   auto-close. No canned marketing animation is needed; the product footage is
   the asset.

The one-line story every replay tells: **it closes the noise, shows its work,
and a hard-coded floor can overrule it.**

## Honesty bar

Prior art review for the MITRE widget killed every encoding that implied more
than the data supports (height, glow, "attack chain" language), and the Norse
map critique ("cinema, not science") is the standing test. The replay passes it
by construction if we hold one rule: **every visual beat is a projection of a
persisted event or run record. Nothing moves that did not happen.** Concretely:

- Playback time is scaled real time, with the scale shown ("32s compressed to
  4s"). No invented pacing.
- Confidence dials, evidence lines, and cost meters render persisted fields
  (`verdict.rendered` payload, `investigation_runs.tokens_used`), never
  interpolated fictions.
- The guard veto beat renders only when a `GuardOverride` actually fired.
- No ambient particles, no fake network globes, no decorative motion that is
  not bound to an event.

## The narrative beats

A replay is a sequence of beats, each triggered by events already in the store:

1. **Arrival.** The Wazuh alert lands: rule name, severity, asset. Source:
   `investigation.created`, `alert.added`.
2. **Policy gate.** The triage policy resolves. Either the deterministic
   operational close kills it here (the fast path, no LLM ever wakes), or the
   reasoning graph takes over. Source: `phase.changed`, policy events.
3. **Dispatch.** The supervisor routes work: Wazuh context pulls, Cortex
   enrichment, MISP threat context. Each worker trip is an edge pulse out and
   back on the stage map. Source: `supervisor.decision`,
   `enrichment.requested/completed`, `misp.*`, `analyzer.*`.
4. **Verdict assembly.** The reasoning tier renders its verdict. The card
   builds itself: decision, confidence filling to its real value, key evidence
   lines appearing one by one, alternatives considered, gaps admitted. Source:
   `verdict.rendered` payload (`key_evidence`, `alternative_explanations`,
   `gaps_in_evidence`, `confidence`, `evidence_strength`).
5. **The gate.** The verdict guard and worker floor inspect the proposed
   close. Green pass, or the climax: a red flip, `close` becomes `escalate`,
   with the fired guardrail named (`GUARDRAIL_AUTHZ_CONTRADICTED`,
   `ioc_present`, volume cap). This is the moment that answers the buyer's
   fear about auto-close, so it gets the strongest visual treatment.
6. **Resolution.** The auto-close stamp with the plain-language closure reason
   and the reopen window ("watching for recurrence until ..."), or handoff to
   the human review lane, or TheHive case creation. Source:
   `investigation.auto_closed`, `human.review_requested`,
   `thehive.case_created`. A `reopened` event, when present, plays as an
   epilogue: the close was provisional and the system said so.

Beat 2 carries the economic argument. When the fast path fires, the replay is
deliberately short: a few hundred milliseconds of real time, one gate, done,
with the vetoes that were checked listed ("no IOC, no MITRE mapping, severity
under threshold, disposition attested"). The contrast between a replay that
lasts two seconds and one that lasts twenty is the pitch for the two-plane
architecture, and it needs no extra data to land.

## Data substrate

**Corrected after adversarial review + verification (2026-07-24).**
The first draft of this section claimed the replay could run on a "graph
plane" of dotted `EventType` events (`supervisor.decision`,
`verdict.rendered`, …) already served to the frontend. That premise is
false, verified against the code:

- The dotted vocabulary in `src/soctalk/persistence/events.py` is legacy:
  the event-sourcing runtime behind it was removed
  (`persistence/__init__.py` docstring says so explicitly). Nothing emits
  those events anymore.
- The `/{id}/events` endpoint (`core/api/investigations_bridge.py`) reads
  `investigation_events.kind` — the IR plane. The frontend's dotted-name
  cases in `formatEventSummary` are mostly dead branches falling through to
  the default formatter.
- The reasoning pipeline emits **no durable events at all**: `append_event`
  is called from ingest (`core/ir/triage.py`), review flows
  (`core/ir/review_events.py`), runtime/labels/API, and the response
  executor — but never from `supervisor/`, `triage_policy/`, or `graph/`.
  Supervisor decisions, worker dispatches, verdict payloads, and guard
  evaluations live in graph state and logs, then vanish. Guard *passes* are
  not persisted anywhere; overrides survive only as JSON audit fragments
  without a clean `investigation_id` join.

**Consequence: the replay substrate must be built before any animation.**
The IR plane (`investigation_events`, append-only, monotonic `seq`,
`causation_event_id`, `run_id`, tenant visibility) is the right home; what
is missing is emission. Phase 0 in the sequencing below adds typed IR
events from the pipeline itself:

- `policy_resolved` — triage policy outcome + operational-close veto
  checklist as evaluated (makes the fast-path beat first-class).
- `supervisor_decision` — action + `action_reasoning` + `tp_confidence`
  (the `SupervisorDecision` schema already carries these; persist them).
- `worker_started` / `worker_result` — per worker, with summary payload.
- `verdict_rendered` — the full `Verdict` model as payload.
- `guard_evaluated` — every evaluation, pass or veto, with fired guardrails
  and from/to decisions. Guard state must be persisted at decision time,
  never recomputed later against changed policy.
- Ingest-plane auto-closes already write rows and audit entries but no
  replayable beats; either accept a synthesized single-card summary for
  them or add one `auto_closed` payload carrying the checklist.

Supporting data genuinely persisted today: alert/case timestamps
(`first_event_at`, `opened_at`, `closed_at`), `close_reason`, statuses, and
run-level cost/token accounting on `investigation_runs`. That is enough for
the fleet view's counters and vessels-but not for its per-path taxonomy or
the veto ticker, which both also depend on Phase 0 (normalized guard
decisions, disposition-path dimension).

Each narrative beat above must be labeled in implementation as
**persisted / inferred / unavailable**, and only persisted beats get
animated as facts; inferred ones render visibly softer (e.g. dashed) or not
at all. That matrix is the honesty bar made operational.

## Visual design

### Stage map

A fixed, canonical map of the pipeline rendered with the stack already in the
repo: SvelteFlow plus dagre, custom nodes in the pattern of
`TriagePolicyFlowPreview.svelte` / `FlowNode.svelte`. Nodes mirror
`build_secops_graph()`: policy gate, supervisor, the three workers, verdict,
guard, human review, close. The map is identical for every investigation;
what varies is the journey drawn across it. Familiarity is the point: after
three replays a viewer knows the geography and reads any investigation at a
glance.

Layout is left to right, one screen, no navigation, no zooming world. Camera
movement is limited to a gentle focus shift toward the active node (CSS
transform on the viewport, not user-driven 3D). If the focus shift reads as
gimmick in the first prototype, cut it; the beats carry the piece.

### Playback mechanics

- A timeline scrubber under the map: play, pause, drag, step. Total real
  duration and compression factor displayed. Keyboard accessible.
- Time compression is piecewise, not linear: long quiet gaps (an enrichment
  API round trip) compress hard, decision moments hold longer. The rule is
  deterministic from event timestamps, so two viewers of the same
  investigation see the same film.
- Edge pulses animate along the SvelteFlow edges for dispatch/return; nodes
  light when active; completed nodes keep a subtle done state so the journey
  accumulates visibly.
- A narration rail beside the map prints one plain-language line per beat as
  it lands, reusing (and upgrading) the existing `formatEventSummary`
  vocabulary. The rail is the accessibility fallback: with
  `prefers-reduced-motion`, playback becomes step-through (click advances one
  beat, no motion), and the rail plus static map states carry the full story.
- The guard beat: on a pass, the gate node flashes green with the checks
  listed. On an override, playback holds, the gate goes red, the verdict
  card's `close` visibly flips to `escalate`, and the fired guardrail is named
  in the narration rail. This is the only beat allowed a deliberate pause.

### What is intentionally excluded

- 3D, isometric, or globe treatments. The MITRE review settled this: flat,
  legible, honest.
- Severity-as-glow or any intensity encoding not backed by a field.

## The fleet view: the same geography at scale

The second altitude over the same map: a time-lapse of a day (24 h compressed
to about 60 s) where every dot is one real alert entering at its true arrival
time. This is the "anyone can understand" projection, and it is data-cheaper
than the replay: it needs only per-alert fields already on `alerts`/`cases`
(ingest timestamp, disposition path, outcome, close time), no event-log read.

Uniform rectangles carry no meaning at this altitude, so the fleet map speaks
a glyph notation in which form states function and size states quantity:

- **Intake funnel**: alerts pour in through a narrowing mouth.
- **Gates as barriers**: the policy gate is a bar pair with a slit the stream
  threads; the guard is the heaviest element on the map (double bars, "hard
  floor · can veto") and flares red while a veto is deflecting a dot.
- **Supervisor as hub**: a circle with spokes to small worker satellites,
  because it routes rather than processes.
- **Verdict as prism**: the lane condenses into a decision.
- **Outcome vessels**: two identical capsules on one shared scale, filling
  through the day. CLOSED ends ~93% full of green; HUMAN barely covers its
  bottom in amber. The ratio becomes geometry readable across a room.
- **Volume ribbons**: translucent bands under the dots whose width grows with
  the cumulative count through each path; by mid-morning the fast-path arc is
  visibly the fattest pipe in the system.

Fleet honesty rules, extending the replay bar: ribbon width = alerts through
that path so far; vessel fill = share of the day's total; dots encode identity
only (no severity color, no sizing — status colors stay reserved for
outcomes); flight time is stretched for legibility and captioned as such,
since at this compression a real triage would be an invisible blip; at MSSP
volumes render 1-in-N dots and say so on the canvas — counters and ribbons
stay exact. Never fake density (the Norse-map rule).

**The drill-down contract binds the altitudes into one product**: click any
dot in flight and the view cuts to that alert's replay — from the trailer to
the film. Every dot has an identity and a receipt; that is what separates
this from an ambient attack-map screensaver.

Companion beats on the side rail: outcome counters, the model-spend vs
analyst-hours-not-spent pairing (the business case in two numbers), and a
guard-veto ticker — closes being overruled in public is the trust signal that
keeps the green stream from reading as cavalier.

Placement: the analytics dashboard hero per tenant first; MSSP rollup and
fullscreen wall/kiosk mode are follow-ons.

## Dual clock: replay and live (decided 2026-07-24)

Both altitudes run on one clock abstraction with two bindings. Replay binds
t to a compressed historical window; live binds it to the wall clock at 1×.
Because rendering is a pure function of (data, t), live is not a second
feature — it is the same reducer with a different clock source and an
append-only feed. The transport becomes a DVR: a LIVE badge at the head,
scrub back through a buffer (10 minutes to start), pause holds your place
while the head runs on, one click snaps back to live. A "catch-up cam"
opens a live session by compressing the day so far into a few seconds and
decelerating into the 1× head — also the natural wall-mode loop.

Live inverts the lapse honesty trade-offs: no compression at the head, so a
fast-path close is a genuine sub-second blink and a reasoning run visibly
crosses the map over a minute. Dots waiting at a stage are real queue
depth — dots parked at HUMAN are the review backlog, an encoding that
emerges for free and is honest by construction. Quiet is the default state
and must be designed as such (calm summary, "last alert n minutes ago",
"in flight now"), never papered over with ambient motion: a silent map is
the product working. Real arrivals are bursty (scanner sweeps, correlated
storms), which gives live mode its texture without fakery.

The replay view gets the same duality: an open investigation renders its
journey so far with a live head, beats appending as events land; a closed
one is a finished film.

Transport: poll the existing feeds first (events are append-only with
monotonic seq, so the cursor is free); SSE only if polling proves too
coarse. Server timestamps are the clock authority, never the browser's.

## Placement

A **Replay tab (or mode toggle) on the investigation detail page**, sharing
the route and data loading with the existing timeline. The raw event timeline
stays; replay is a presentation layer over the same feed, not a replacement.
Closed investigations open replay-ready; active ones show the journey so far
with a live head.

For demos: no separate surface in v1. A curated tenant with a representative
investigation (one fast-path kill, one full reasoning close, one guard veto)
gives three screen recordings that cover the pitch.

## Sequencing

Same discipline as the MITRE rail (substrate before spectacle):

0. **Instrumentation.** Emit the typed IR events listed in the data
   substrate section from the pipeline nodes; persist guard evaluations
   (pass and veto) queryably; add the disposition-path dimension the fleet
   aggregate needs. No frontend work until replaying a real investigation
   from persisted events alone is possible. Backfill is optional — replay
   can honestly say "recorded from <date>".
1. **Journey map, step-through.** Static stage map with the investigation's
   path drawn, click-to-step beats, narration rail. No timed animation yet.
   This alone beats the raw timeline and validates event coverage.
2. **Timed playback.** Scrubber, compression, edge pulses, the guard beat.
   This is the cinematic core.
3. **Fleet time-lapse.** Aggregate day endpoint + glyph map + dots/ribbons/
   vessels, reusing the playback engine. Drill-down wired to the replay.
4. **Live heads.** The DVR transport on the fleet (poll-based cursor) and
   the live-replay head on open investigations. Catch-up cam.
5. **Polish.** Focus shift, verdict card assembly animation, showcase
   recordings, wall mode. Each item drops without regret if it reads as toy.

Phase 1 forces the data-gap questions (supervisor payload, fast-path events)
to be answered cheaply, before any animation work depends on them.

## Open questions

- Fast-path evidence: if operational closes emit too little to animate, is
  the synthesized "checks passed" card honest enough, or does the path need
  one new event emitted at close time listing the vetoes evaluated? (One
  small backend change would make the strongest beat first-class.)
- DVR depth and semantics: how far back does the live buffer scrub, and is
  pause-holds-your-place (chosen for now) right, or should resume snap back
  to live?
- The quiet problem: live at 1× is mostly silent for a single tenant
  (roughly an alert a minute at peak). Is quiet-as-proof the right wall
  story, or does the wall want a rolling-window treatment?
- MSSP context: the detail page serves both MSSP analysts and tenant users;
  does the narration rail need visibility-aware wording, or does the existing
  event visibility filtering already cover it?
- One notation or two: the replay keeps labeled rectangles (prose beats
  glyphs when reading a single case up close) while the fleet uses the glyph
  notation — but then the drill-down cut lands on unfamiliar shapes. Unify,
  or accept the asymmetry?
- Glyph audit: does each glyph earn its meaning (the verdict prism is the
  weakest candidate), or does any read as ornament?
- The flight-time stretch in the fleet view: is the on-canvas caption enough
  to clear the honesty bar?
- Sampling threshold: at what alerts/day does 1-in-N dot sampling kick in,
  and how is N chosen and displayed?

## Adversarial review — round 1 verdicts (2026-07-24)

Full transcript in session scratchpad. Headline: **keep the core idea, kill
the v1 spec as originally written** — the substrate claims were false (now
corrected above, verified against code). Findings adopted:

- Phase 0 instrumentation added; graph-plane v1 killed.
- Beat truth matrix (persisted / inferred / unavailable) adopted as the
  operational honesty bar.
- Guard evaluations must be persisted at decision time, pass and veto.
- Product naming: prefer "flight recorder" over "cinematic" in
  customer-facing copy; the drama is the receipt, not the film.
- Positioning: animated triage explainability alone is table stakes
  (Defender XDR attack story, Elastic Attack Discovery, Dropzone/Radiant/
  Prophet/Torq/Intezer all show evidence trails). The differentiator worth
  building is the auditable display of deterministic policy + cost + the
  safety floor overruling the model — the parts competitors do not surface.

Glyph verdicts to fold into the next mock iteration:

- Policy/guard gate bars, supervisor hub, identity-only dots: **keep**
  (named gate checks shown only once persisted; only spokes actually taken
  light up).
- Verdict prism: **change** — too metaphorical; a decision element with
  explicit close / escalate / needs-more-info states.
- Outcome vessels: **change** — keep the shared-scale ratio, restyle from
  "vessel" toward a stacked outcome column (more SOC-native, less toy).
- Intake funnel: **conditional** — only if it depicts real ingest
  aggregation (correlation/coalescing), otherwise it implies filtering that
  is not happening there.
- Volume ribbons: **keep** with legend, scale note, and exact counters.

Still open from the review: sampled dots must each carry a real alert id
(no anonymous dots even under sampling), and drill-down must land on the
clicked dot's own investigation, never a representative one — both are
requirements on the real implementation that the mock cannot satisfy.

## Review — round 3, live-by-default adjudication (2026-07-24)

Question: should the fleet hero default to live instead of the 24h→60s
time-lapse? Verdict adopted and implemented:

- **Default is LIVE on the tenant home dashboard**, as an operational
  panel. The answer to the quiet problem is state made legible, not
  motion: last-alert age, in-flight count, and open investigations
  parked by stage — never an animation ritual (NN/g: repeated
  animations become ignored roadblocks; SOC practice — Splunk queues,
  Sentinel's refresh-off default — expects present-tense state, not
  shows).
- **Catch-up cam demoted to a once-per-session/day intro** inside live,
  skipped under reduced motion. "Replay the day" survives as the
  explicit control.
- **Analytics keeps the lapse, demoted**: lands on the day-so-far still,
  plays only on demand. No MSSP-home hero in v1 (`MsspDashboard` is a
  cross-tenant queue surface and fleet-day requires a pinned tenant).
- **Live substrate**: a dedicated `GET /api/analytics/fleet-live`
  (5-10s poll) with exact counters, `last_alert_at`, `in_flight`,
  `open_by_stage` (each open investigation's LATEST replay beat mapped
  to a stage; unknown reported as unknown, never faked onto a node),
  and UNSAMPLED `recent_arrivals` — the md5-ordered day sample can miss
  or displace a just-arrived alert, so live arrivals get their own
  feed. The live clock is a server-clock store (`server_now` + offset,
  rAF paint-only); `createTimeline()` keeps replay semantics and gained
  only a rate multiplier for the catch-up intro.
- Deferred: DVR scrub on the fleet, MSSP rollup hero, wall mode.

## Review — round 2, implementation (2026-07-24)

Verdict:
direction viable, plan not implementation-ready. Adopted findings:

**Phase 0 is a backend/API project, not an adapter task:**

- The graph runs in the worker process (L2) while IR persistence lives
  behind the L1 API; the worker API only claims/heartbeats/completes runs.
  Node instrumentation therefore needs an event sink: a new
  `POST /api/internal/worker/runs/{run_id}/events` (lease-checked, server
  assigns `seq`, ordered `events[]` batch), injected into graph nodes —
  never direct DB writes from L2.
- The events read endpoint must become a cursor feed:
  `GET /api/investigations/{id}/events?after_seq&limit&order=asc`
  returning `seq`, `run_id`, `visibility`, `causation_event_id`, and a
  `server_now` field. Today it returns only id/type/timestamp/data,
  newest-first — a `last_seq` poller is impossible against that shape.
- Visibility is part of the contract: `append_event` defaults to
  `mssp_only` and RLS hides those rows from tenant users. Phase 0 must
  define customer-safe payloads (or redacted copies), and the beat adapter
  renders filtered beats as *unavailable*, never inferred.
- Fleet aggregate endpoints (`/api/analytics/fleet-day` and the MSSP twin,
  with `date`, `tz`, `sample_limit`) return exact counters plus sampled
  real dots (alert id, investigation id, timestamps, path/outcome, guard
  flags, sample rate).

**Frontend corrections:**

- rAF is a paint invalidator, never the clock. The timeline's authoritative
  time is `server_now + client_offset`, clamped to the newest event and the
  DVR window — otherwise the live head drifts when the tab backgrounds
  (browsers throttle rAF).
- Do not port the mock's DOM model: global ids, `innerHTML` (an XSS vector
  once rule names are tenant data), per-frame `getPointAtLength`,
  per-frame DOM create/remove, seeded fake schedules, `toLocaleString`
  with a hardcoded locale, representative drill-down. Replacements: Svelte
  templates with keyed blocks, typed API data, mount-time path LUTs,
  locale formatters, real investigation links.
- Narration returns message keys + params; Paraglide is called at render,
  never module scope (existing `stores/index.ts` warns about this).
- Testing: existing frontend tests are Playwright route-mock tests; add
  deterministic seek-to-t visual tests, and cover `eventsToBeats` either
  via Vitest (new dep) or through mocked routes.
- Ribbon widths update on count changes, not per frame.

**One open disagreement between review rounds:** round 1 said hand-laid
SVG for both altitudes and explicitly "do not use SvelteFlow for replay"
(determinism, testing); round 2 says use SvelteFlow for the
single-investigation replay map (repo idiom, `TriagePolicyFlowPreview`
precedent) and hand-laid SVG for the fleet. Both agree the fleet map is
hand-laid SVG. Decision deferred to the phase-1 spike: build the replay
journey map both ways behind the same beat reducer and keep whichever
survives a deterministic-screenshot test with less code.
