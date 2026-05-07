"""AI-led native incident response subsystem.

Authoritative spec: ``docs/v1/P2-0-core-invariants.md``.
Implementation plan: ``docs/v1/P2-implementation-plan.md``.

Modules:

- ``models``    : SQLModel definitions for IR tables.
- ``events``    : event kinds, coalescing signatures, idempotency helpers.
- ``reducer``   : deterministic reducer over investigation_events → investigation_facts.
- ``runtime``   : run state machine, inbox consumer, outbox executor.
- ``tools``     : tool registry and capability taxonomy.
- ``policies``  : YAML install + Postgres tenant override loader.
- ``triage``    : raw event → alert → investigation promotion pipeline.
"""

from __future__ import annotations
