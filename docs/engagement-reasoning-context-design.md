# Engagement awareness in the reasoning layer

Status: design sketch. Came out of the "can engagements just be authorization
facts?" question. The answer there was no at the model level, but the question
exposed a real gap worth closing, which is what this describes.

## The gap

Engagements never reach the reasoning layer. Grepping `triage_policy/` and
`models/` for "engagement" returns nothing. They exist only inside the
deconfliction gate in `core/ir/campaign.py`, called once from `core/ir/triage.py`.

`deconflict()` is deliberately fail-closed and demands positive attribution: an
in-scope tester source ip must be observed, no observed source may stray, and at
least one target axis (host or technique) must be positively satisfied with
nothing straying. That strictness is correct, because a match sets the alert to
`deconflicted` and skips the LLM entirely.

The consequence is that everything the gate does not positively attribute falls
through to normal triage with no knowledge that a pentest is running at all. That
happens more often than it sounds: NAT or a proxy rewrites the source, the tester
pivots through an internal host, or activity comes from an address nobody thought
to declare. The engagement is real, the customer authorized it, the operator can
see it in the UI, and the model reasoning about the alert is the only party in the
system that has not been told.

The out-of-scope path has a milder version of the same problem. When the tester
source matches but the activity strays, triage sets `force_promote` and writes an
`ir.engagement.out_of_scope` audit row, then runs the LLM. The verdict is produced
without knowing that a declared tester just strayed outside contracted scope,
which is exactly the context that makes the finding interpretable.

## What this is not

Not a second suppression path. Deconfliction stays the only thing that can take an
alert out of the queue, with its current rules unchanged. This proposal only gives
the reasoning layer something it can read.

Not a schema merge. Facts and engagements keep separate storage, separate
lifecycles, and separate evaluation points, for the reasons argued in the
discussion that produced this note: different match axes (facts key on host,
account and action, engagements on source cidr, host and ATT&CK technique),
different lifecycles (facts carry trust and a review gate, engagements are
authoritative on declaration), and very different blast radii.

## Shape

Add an informational field to `AuthorizationContext` in `models/authorization.py`:

```
active_engagements: list[EngagementWindow] = []
deconfliction: DeconflictionOutcome | None = None
```

`EngagementWindow` is a compact summary: id, name, kind, starts_at, ends_at, and
the three scope axes. `DeconflictionOutcome` records what the gate decided for
this alert, either `unattributed` or `out_of_scope` with the straying detail the
gate already computes. A `declared_test` outcome never appears here because triage
returns before the reasoning layer runs.

The population point is `authorization_context_for_alert` in
`core/ir/authz_shadow.py`, which already receives `db`, `tenant_id` and `ts`, so
the window query needs no new plumbing. It reuses the same predicate the gate uses
(`starts_at <= ts <= ends_at`, `revoked_at is null`).

## The safety argument

The critical constraint: this must not become a way to close an alert.

The reason to keep it off the `facts` list, rather than synthesizing a grant, is
that `facts` feeds the deterministic engine that computes `authz.class`. A
synthesized grant could produce `authorized` and let a close commit, which would
hand engagements a suppression path that bypasses the attribution rules the gate
exists to enforce. Injecting one as an `entity_context` fact is equally wrong,
since that kind describes an entity's attributes rather than a time window, and it
would still enter fact evaluation.

Keeping the new field outside `facts` means the deterministic engine's inputs are
unchanged, so `authz.class` is unchanged, so `guard.py` behaviour is unchanged. No
new close path exists by construction. The field is prompt context and nothing
else.

The prompt framing has to carry the same message explicitly: an active engagement
that did not positively attribute this activity is a reason to look harder, not a
reason to relax. The existing "authorization never overrides an IOC" enforcement
in the guard still applies on top.

## Rollout and evidence

Gate it behind a policy flag defaulting to false, consistent with
`engagement_deconfliction_enabled` in `core/ir/policies.py`, so it can be enabled
per tenant after the evals are in.

The claim to falsify before shipping is that awareness improves verdicts without
weakening them. The red-team case that matters most: a genuinely malicious alert
occurring inside a live engagement window from a source outside the declared
tester scope. The verdict must not close. `evals/authz_shadow_redteam.py` is the
right harness, and the soctalk-goldens benchmark is the right place to measure
whether out-of-scope and unattributed cases improve on the analyst ground truth.

If the red-team case regresses, the honest outcome is to keep engagements out of
the reasoning layer and instead surface the unattributed-window signal to the
human queue only, which is a strictly smaller change.
