"""AuthorizationFact — the typed authorization/expectedness contract (epic M1).

One fact family, many producers: SIEM-derived routine sightings, analyst answers (HIL),
the ingest API, and connectors all write these facts; the reasoning layer consumes
facts + trust tag and is agnostic to the source. The schema was validated against the
soctalk-goldens benchmark (macro-F1 0.965 frontier / ~0.63 shallow baselines) and is kept
faithful to it by a file-fed parity test (tests/v1/test_authorization_parity.py).

Shape: a discriminated union on ``kind`` over a shared envelope. Every fact also carries
``track`` (account | fim) because the two authorization paradigms diverge in matching
semantics (string equality vs path-glob), freeze rules, and tenancy; per-track field
legality is enforced by validators rather than inferred from which optionals happen
to be set.

None-vs-empty semantics are part of the contract (they are intentionally asymmetric,
mirroring the change-management sources):
  - ``applies_to.env/criticality/data_class``: None = any, [] = applies nowhere
  - ``applies_to.config_class``: None or [] = ANY config class
  - ``forbid_change_type``: None = any change type, [] = no change type

Not represented (the evaluator ignores them today): asset hardware type, business unit,
org parent hierarchy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, TypeAdapter, field_validator, model_validator

AUTHORIZATION_SCHEMA_VERSION = "1"


class AuthorizationTrack(str, Enum):
    """The authorization paradigm a fact or activity belongs to."""

    ACCOUNT = "account"  # host-auth activity: (host, account, action, time)
    FIM = "fim"  # file-integrity change control: (path, change_type, time); actor-free


class AuthorizationSourceType(str, Enum):
    """Who asserted a fact. Trust ordering: connector > system > analyst > telemetry > tenant.

    ``tenant_asserted`` is the lowest tier: a customer asserting authorization about their own
    environment. It is NOT trusted to influence triage until an MSSP analyst reviews it — that
    gate is enforced by the store's ``review_status`` column, not by trust alone.
    """

    TENANT_ASSERTED = "tenant_asserted"
    TELEMETRY_ROUTINE = "telemetry_routine"
    ANALYST_ASSERTED = "analyst_asserted"
    SYSTEM_ASSERTED = "system_asserted"
    CONNECTOR_VERIFIED = "connector_verified"


class GrantClass(str, Enum):
    CHANGE_TICKET = "change_ticket"
    STANDING_BASELINE = "standing_baseline"
    ROUTINE_OBSERVATION = "routine_observation"


class GrantStatus(str, Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REJECTED = "rejected"


class PolicyPriority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AccountKind(str, Enum):
    SERVICE = "service"
    HUMAN = "human"


class AuthorizationEntityKind(str, Enum):
    ASSET = "asset"
    ACCOUNT = "account"
    WATCHED_PATH = "watched_path"
    ORG = "org"


class ChangeKind(str, Enum):
    MODIFY = "modify"
    ADD = "add"
    DELETE = "delete"
    ANY = "any"


class CompromiseStatus(str, Enum):
    CLEAN = "clean"
    SUSPECTED = "suspected"
    COMPROMISED = "compromised"
    CONTAINED = "contained"


# Default trust per source tier. Only the ordering is load-bearing; entity facts sourced
# from an inventory/CMDB record carry that record's own reliability instead.
TRUST_TIER: dict[AuthorizationSourceType, int] = {
    AuthorizationSourceType.TENANT_ASSERTED: 20,
    AuthorizationSourceType.TELEMETRY_ROUTINE: 40,
    AuthorizationSourceType.ANALYST_ASSERTED: 60,
    AuthorizationSourceType.SYSTEM_ASSERTED: 80,
    AuthorizationSourceType.CONNECTOR_VERIFIED: 100,
}


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class RecurringWindow(BaseModel):
    """A recurring daily window, "HH:MM", inclusive on both ends."""

    start: str
    end: str


class FactScope(BaseModel):
    """The activity a fact applies to. Account track: subject + target(host) + action.
    FIM track: target(path glob or watched path) + change_type; no subject."""

    subject: str | None = None
    target: str | None = None
    action: str | None = None
    change_type: ChangeKind | None = None
    recurring_window: RecurringWindow | None = None  # None = no window constraint


class FactProvenance(BaseModel):
    """Where a fact came from; audit-only, never part of reasoning or entity resolution."""

    investigation_id: str | None = None
    review_id: str | None = None
    connector_id: str | None = None
    api_caller: str | None = None
    case_id: str | None = None  # benchmark/parity provenance


class PolicyApplicability(BaseModel):
    """Prohibition scoping. See the module docstring for per-field None/[] semantics."""

    env: list[str] | None = None
    criticality: list[str] | None = None
    data_class: list[str] | None = None
    config_class: list[str] | None = None


class FreezeScope(BaseModel):
    envs: list[str] = Field(default_factory=list)  # account track
    config_classes: list[str] = Field(default_factory=list)  # FIM track


class AuthorizationFactBase(BaseModel):
    """Common envelope: identity, scope, source/trust, calendar validity, lifecycle."""

    id: str
    track: AuthorizationTrack
    tenant: str | None = None
    scope: FactScope = Field(default_factory=FactScope)
    source_type: AuthorizationSourceType = AuthorizationSourceType.SYSTEM_ASSERTED
    trust: int = TRUST_TIER[AuthorizationSourceType.SYSTEM_ASSERTED]
    provenance: FactProvenance = Field(default_factory=FactProvenance)
    created_by: str = ""
    created_at: datetime | None = None
    valid_from: datetime | None = None  # calendar validity; None = unbounded (!= recurring_window)
    valid_until: datetime | None = None
    review_due: datetime | None = None
    last_used: datetime | None = None
    superseded_by: str | None = None

    @field_validator("created_at", "valid_from", "valid_until", "review_due", "last_used")
    @classmethod
    def _coerce_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)


class GrantFact(AuthorizationFactBase):
    """An approving record: a change ticket/request, a standing baseline, or an
    established routine sighting."""

    kind: Literal["grant"] = "grant"
    grant_class: GrantClass
    status: GrantStatus = GrantStatus.APPROVED
    cab_required: bool = False
    cab_approved: bool = True
    emergency: bool = False
    freeze_exception: bool = False
    seen_count: int | None = None  # routine_observation only
    ioc: bool | None = None  # routine_observation only

    @model_validator(mode="after")
    def _class_legality(self) -> GrantFact:
        if self.grant_class == GrantClass.CHANGE_TICKET:
            if self.valid_until is None:
                raise ValueError("change_ticket grants require valid_until")
            if self.seen_count is not None or self.ioc is not None:
                raise ValueError("seen_count/ioc are routine_observation-only fields")
        else:
            if self.status != GrantStatus.APPROVED or self.cab_required or self.emergency:
                raise ValueError(f"{self.grant_class} carries no status/CAB/emergency fields")
            if self.freeze_exception:
                raise ValueError(f"{self.grant_class} cannot carry a freeze exception")
            if self.grant_class == GrantClass.STANDING_BASELINE:
                if self.seen_count is not None or self.ioc is not None:
                    raise ValueError("seen_count/ioc are routine_observation-only fields")
            elif self.seen_count is None:
                raise ValueError("routine_observation requires seen_count")
        return self


class ProhibitionFact(AuthorizationFactBase):
    """A higher-priority prohibition (policy). Only high-priority, non-waivered
    prohibitions block a disposition."""

    kind: Literal["prohibition"] = "prohibition"
    forbid_action: str | None = None  # account track
    forbid_change_type: list[str] | None = None  # FIM track; None = any change type
    forbid_account_type: AccountKind | None = None  # account track
    applies_to: PolicyApplicability = Field(default_factory=PolicyApplicability)
    priority: PolicyPriority = PolicyPriority.HIGH
    waiver_present: bool = False
    break_glass_exception: bool = False

    @model_validator(mode="after")
    def _track_legality(self) -> ProhibitionFact:
        if self.track == AuthorizationTrack.ACCOUNT:
            if self.forbid_action is None:
                raise ValueError("account prohibitions require forbid_action")
            if self.forbid_change_type is not None or self.applies_to.config_class is not None:
                raise ValueError("forbid_change_type/config_class are FIM-track fields")
        else:
            if self.forbid_action is not None or self.forbid_account_type is not None:
                raise ValueError("forbid_action/forbid_account_type are account-track fields")
            if (
                self.applies_to.env is not None
                or self.applies_to.criticality is not None
                or self.applies_to.data_class is not None
            ):
                raise ValueError("applies_to env/criticality/data_class are account-track fields")
        return self


class ChangeFreezeFact(AuthorizationFactBase):
    """A change freeze: env-scoped on the account track, config-class-scoped on FIM."""

    kind: Literal["change_freeze"] = "change_freeze"
    freeze_scope: FreezeScope = Field(default_factory=FreezeScope)
    start: datetime
    end: datetime
    allowed_exception_ids: list[str] = Field(default_factory=list)

    @field_validator("start", "end")
    @classmethod
    def _freeze_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _track_legality(self) -> ChangeFreezeFact:
        if self.track == AuthorizationTrack.ACCOUNT and (
            not self.freeze_scope.envs or self.freeze_scope.config_classes
        ):
            raise ValueError("account freezes scope by envs only")
        if self.track == AuthorizationTrack.FIM and (
            not self.freeze_scope.config_classes or self.freeze_scope.envs
        ):
            raise ValueError("FIM freezes scope by config_classes only")
        return self


class EntityContextFact(AuthorizationFactBase):
    """Context about an entity (asset, account, watched path, org). ``name`` is the
    authoritative entity key. Conflicting records for the same entity resolve by trust."""

    kind: Literal["entity_context"] = "entity_context"
    entity_type: AuthorizationEntityKind
    name: str
    environment: str | None = None
    criticality: str | None = None
    data_classification: str | None = None
    config_class: str | None = None
    owner_org: str | None = None
    custodian_account: str | None = None
    approver: str | None = None
    service_owner: str | None = None
    account_type: AccountKind | None = None
    privileged: bool | None = None
    on_call: bool | None = None
    break_glass: bool | None = None
    compromise_status: CompromiseStatus | None = None
    linked_orgs: list[str] | None = None  # org entities only

    @model_validator(mode="after")
    def _entity_legality(self) -> EntityContextFact:
        account_only = (
            self.account_type,
            self.privileged,
            self.on_call,
            self.break_glass,
            self.service_owner,
        )
        if self.entity_type != AuthorizationEntityKind.ACCOUNT and any(
            v is not None for v in account_only
        ):
            raise ValueError("account attributes on a non-account entity")
        if self.entity_type != AuthorizationEntityKind.ORG and self.linked_orgs is not None:
            raise ValueError("linked_orgs is an org-entity field")
        if self.entity_type != AuthorizationEntityKind.WATCHED_PATH and (
            self.config_class is not None or self.approver is not None
        ):
            raise ValueError("config_class/approver are watched_path fields")
        return self


AuthorizationFact = Annotated[
    GrantFact | ProhibitionFact | ChangeFreezeFact | EntityContextFact,
    Field(discriminator="kind"),
]
AUTHORIZATION_FACT_ADAPTER: TypeAdapter[AuthorizationFact] = TypeAdapter(AuthorizationFact)


class AuthorizationActivity(BaseModel):
    """The activity tuple extracted from the alert that facts are bound against."""

    track: AuthorizationTrack
    host: str | None = None  # account track
    account: str | None = None
    action: str | None = None
    path: str | None = None  # FIM track
    change_type: ChangeKind | None = None
    time: datetime
    interactive: bool = False

    @field_validator("time")
    @classmethod
    def _time_utc(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _track_fields(self) -> AuthorizationActivity:
        if self.track == AuthorizationTrack.ACCOUNT:
            if self.host is None or self.account is None or self.action is None:
                raise ValueError("account activity requires host, account, action")
        elif self.path is None or self.change_type is None:
            raise ValueError("fim activity requires path and change_type")
        return self


class AuthorizationComponents(BaseModel):
    """The four expectedness components. close iff ALL four hold."""

    sanctioned_or_routine: bool
    in_scope: bool
    actor_genuine: bool
    policy_allowed: bool

    @property
    def expected(self) -> bool:
        return (
            self.sanctioned_or_routine
            and self.in_scope
            and self.actor_genuine
            and self.policy_allowed
        )

    @property
    def decision(self) -> str:
        return "close" if self.expected else "escalate"


class AuthorizationContext(BaseModel):
    """The authorization slice of an investigation: the activity tuple plus the facts
    that apply to it. ``components`` is deterministic, engine-computed output
    (soctalk.authorization.engine) — never model- or human-written."""

    tenant: str | None = None
    activity: AuthorizationActivity
    facts: list[AuthorizationFact] = Field(default_factory=list)
    components: AuthorizationComponents | None = None
    note: str | None = None
