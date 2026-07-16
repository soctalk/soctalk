"""Response playbooks (issue #49): post-disposition dispatch, downstream of triage.

Where the triage-policy layer (``soctalk.triage_policy``) constrains the judgment
INSIDE the agentic loop, this layer dispatches the response AFTER the effective
disposition is final. The seam is ``complete_run()`` (``core/api/worker_runs.py``):
only there is the disposition post-floor and committed, so only there may response
actions be enqueued — transactionally, into ``investigation_outbox``, drained by
the response executor on the L1 plane. The runs-worker never executes a response
action.

Layer contract, carried over from #43/#44:

- Playbooks are data over a fail-closed capability allowlist (``capabilities``).
- Conditions use the same sandboxed operator language as triage-policy
  guardrails, over the response envelope's declared contract (``models``).
- File-loaded playbooks default to shadow (intended actions audited, nothing
  executed) until explicitly activated.
- The floor gates dispatch itself: the ``SOCTALK_RESPONSE_DISPATCH_KILL`` env or
  the ``response_dispatch_kill`` tenant policy stops every enqueue, and phase 1
  registers tier-0 capabilities only (annotate, signed webhook notify).
"""
