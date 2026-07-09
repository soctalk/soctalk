"""Wire models for the adapter events channel.

``SCHEMA_VERSION`` is the version THIS artifact describes. History:

- **1** — original shape: source_event_id/source/rule_id/severity/
  asset_ids/initial_iocs/ts/description/title/raw.
- **2** — adds (all optional, additive): ``entities`` (typed,
  role-carrying), ``mitre``, ``rule_groups``, ``decoder``, ``full_log``
  (adapter-side redacted), ``template_hash``/``template_version``,
  ``observed_at``, ``redaction_version``; batch envelope gains
  ``schema_version`` and ``batch_seq``.

``asset_ids`` and ``ts`` semantics are frozen: coalescing signatures and
reopen matching key on them (see soctalk.core.ir.events.alert_signature).
``ts`` is strictly event-occurrence time; ``observed_at`` is when the
adapter saw it; the control plane stamps its own ``ingested_at``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

SCHEMA_VERSION = 2


class IngestedIOC(BaseModel):
    type: str = Field(..., max_length=32)
    value: str = Field(..., max_length=2048)


class WireEntity(BaseModel):
    """A typed, role-carrying entity the decoder already parsed.

    ``source_field`` preserves provenance to the decoded field (e.g.
    ``data.srcuser``) so any downstream conclusion can be traced back.
    """

    type: Literal["user", "host", "ip", "process", "hash", "domain", "port"]
    value: str = Field(..., max_length=512)
    role: Literal["actor", "target", "src", "dst", "parent"] | None = None
    source_field: str | None = Field(default=None, max_length=128)


class WireMitre(BaseModel):
    """MITRE ATT&CK references carried on the rule (size-capped)."""

    ids: list[str] = Field(default_factory=list, max_length=16)
    tactics: list[str] = Field(default_factory=list, max_length=16)
    techniques: list[str] = Field(default_factory=list, max_length=16)


class AdapterEvent(BaseModel):
    """One Wazuh (or equivalent) event forwarded by the tenant adapter."""

    # --- schema v1 fields (frozen shapes) ---------------------------------
    source_event_id: str = Field(..., max_length=128)
    source: str = Field(default="wazuh", max_length=32)
    rule_id: str | None = Field(default=None, max_length=64)
    severity: int = Field(ge=0, le=15)
    asset_ids: list[str] = Field(default_factory=list)
    initial_iocs: list[IngestedIOC] = Field(default_factory=list)
    ts: datetime | None = None  # event OCCURRENCE time
    description: str | None = Field(default=None, max_length=1024)
    title: str | None = Field(default=None, max_length=255)
    raw: dict[str, Any] | None = None

    # --- schema v2 additions (all optional) -------------------------------
    entities: list[WireEntity] = Field(default_factory=list, max_length=64)
    mitre: WireMitre | None = None
    rule_groups: list[str] = Field(default_factory=list, max_length=16)
    decoder: str | None = Field(default=None, max_length=128)
    full_log: str | None = Field(default=None, max_length=4096)  # REDACTED
    template_hash: str | None = Field(default=None, max_length=64)
    template_version: str | None = Field(default=None, max_length=16)
    observed_at: datetime | None = None  # when the adapter saw the event
    redaction_version: str | None = Field(default=None, max_length=16)


class IngestBatch(BaseModel):
    tenant_id: UUID
    events: list[AdapterEvent] = Field(..., max_length=500)
    schema_version: int = Field(default=1, ge=1)
    batch_seq: int | None = Field(default=None, ge=0)
