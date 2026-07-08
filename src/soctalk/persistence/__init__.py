"""Persistence layer for soctalk.

Holds the event-type vocabulary and SQLModel table definitions that the
Alembic migration history and live code reference. The legacy event-sourcing
runtime (store, projector, emitter, checkpointing) was removed; V1 writes
investigation events via ``soctalk.core.ir.events``.
"""

from soctalk.persistence.events import EventType
from soctalk.persistence.models import (
    AnalyzerStats,
    Event,
    InvestigationReadModel,
    IOCStats,
    MetricsHourly,
    RuleStats,
)

__all__ = [
    "EventType",
    "Event",
    "AnalyzerStats",
    "InvestigationReadModel",
    "IOCStats",
    "MetricsHourly",
    "RuleStats",
]
