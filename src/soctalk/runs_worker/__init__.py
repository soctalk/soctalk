"""Per-tenant L2 runs-worker.

Lives in the tenant namespace, claims active investigation_runs from L1 via the
``/api/internal/worker/runs/*`` API, drives them through the LangGraph
supervisor, heartbeats while the graph is in flight, and posts the
terminal status back. Never touches L1 Postgres directly.
"""
