"""The canonical model: vocabularies, registry, identity, confidence.

Decision references (issue #24):
1. Identity — deterministic UUIDv5 over each type's identifying properties
   (STIX 2.1 mechanism, our namespace). Never fused; aliasing is explicit
   splittable same-as links (handled at the relationship layer).
2. Type inventory — a closed, versioned vocabulary, small in v1, with an
   ``artifact`` escape hatch.
3. Event participation — closed role vocabulary (+ observer for the sensor)
   and a curated verb set with an allowed-pair matrix; observed vs derived.
4. Temporal — observations are instantaneous; state relationships are
   bitemporal and closed by supersession (relationship layer).
5. Provenance/precedence/confidence — layered authority; two separable
   signals (source reliability + assertion confidence); not-evaluated is a
   distinct state.
6. Retention/visibility — every type declares retention class + default
   audience.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from enum import Enum

MODEL_VERSION = "1"

# Stable namespace for deterministic entity ids (STIX-style UUIDv5). Fixed
# forever — changing it re-keys every entity.
_NAMESPACE = uuid.UUID("6f8a1c2e-9b4d-5e7f-8a1b-2c3d4e5f6a7b")


# --------------------------------------------------------------------- enums


class EntityType(str, Enum):
    """Closed v1 type vocabulary. ``artifact`` is the escape hatch so
    extraction can capture something novel without a vocabulary release."""

    HOST = "host"
    USER = "user"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILE = "file"
    PROCESS = "process"
    PORT = "port"
    AGENT = "agent"
    RULE = "rule"
    ALERT = "alert"
    ARTIFACT = "artifact"
    # Reference types
    TECHNIQUE = "technique"
    TACTIC = "tactic"


class Role(str, Enum):
    """Closed role vocabulary for event participation. ``observer`` is the
    sensor — never conflate what SAW an event with what participated."""

    ACTOR = "actor"
    TARGET = "target"
    SRC = "src"
    DST = "dst"
    PARENT = "parent"
    OBSERVER = "observer"


class RelationVerb(str, Enum):
    """Curated relationship verbs (not an open grab-bag)."""

    # Observed (stated by telemetry)
    TOUCHED = "touched"          # alert/event touched an entity
    CONNECTED_TO = "connected_to"
    AUTHENTICATED_TO = "authenticated_to"
    EXECUTED = "executed"
    SPAWNED = "spawned"          # process parent->child
    ACCESSED = "accessed"
    RESOLVED_TO = "resolved_to"  # domain -> ip
    HAS_IP = "has_ip"            # host -> ip (state)
    LISTENS_ON = "listens_on"    # host -> port (state)
    MEMBER_OF = "member_of"      # user -> group (state)
    RUNS_SERVICE = "runs_service"  # host -> service (state)
    # Derived (computed by us, always with evidence)
    SAME_AS = "same_as"          # alias link (splittable)
    MAPS_TO_TECHNIQUE = "maps_to_technique"
    CORRELATED_WITH = "correlated_with"


class RelationClass(str, Enum):
    OBSERVED = "observed"    # stated by telemetry
    DERIVED = "derived"      # computed by us; carries evidence ref


class TemporalClass(str, Enum):
    OBSERVATION = "observation"  # instantaneous, one timestamp, immutable
    STATE = "state"              # bitemporal, closed by supersession


class RetentionClass(str, Enum):
    EVIDENCE = "evidence"    # ages out on the evidence store schedule
    ENTITY = "entity"        # persists
    SUMMARY = "summary"      # persists pseudonymized


class Audience(str, Enum):
    MSSP_ONLY = "mssp_only"
    CUSTOMER_VISIBLE = "customer_visible"


class SourceReliability(str, Enum):
    """Admiralty-scale style (MISP), distinct from assertion confidence."""

    ANALYST = "analyst"          # A — reliable, human
    TELEMETRY = "telemetry"      # B — parsed sensor data
    EXTRACTION = "extraction"    # C — compiled/regex extraction
    MODEL = "model"              # D — model-generated hypothesis
    UNKNOWN = "unknown"          # F


# Authority ordering (higher outranks lower). The write path enforces this:
# a lower layer never overwrites a higher one.
AUTHORITY_ORDER: dict[SourceReliability, int] = {
    SourceReliability.ANALYST: 4,
    SourceReliability.TELEMETRY: 3,
    SourceReliability.EXTRACTION: 2,
    SourceReliability.MODEL: 1,
    SourceReliability.UNKNOWN: 0,
}


@dataclass(frozen=True)
class Confidence:
    """Two separable signals; ``evaluated=False`` is distinct from 0."""

    reliability: SourceReliability
    score: int = 0          # 0..100, per-assertion
    evaluated: bool = False

    def outranks(self, other: "Confidence") -> bool:
        return AUTHORITY_ORDER[self.reliability] > AUTHORITY_ORDER[other.reliability]


@dataclass(frozen=True)
class Provenance:
    """Who said it + what evidence it rests on."""

    asserter: str                    # 'analyst:<id>' | 'component:<name>@<ver>' | 'model:<prompt-ver>'
    reliability: SourceReliability
    source_event_id: str | None = None   # resolvable to the #17 evidence store


# ------------------------------------------------------------------- registry


@dataclass(frozen=True)
class TypeSpec:
    entity_type: EntityType
    natural_key: tuple[str, ...]     # fields forming the identifying tuple
    temporal_class: TemporalClass
    retention_class: RetentionClass
    default_audience: Audience
    allowed_roles: tuple[Role, ...]


def _spec(et, key, *, temporal=TemporalClass.OBSERVATION,
          retention=RetentionClass.ENTITY, audience=Audience.MSSP_ONLY,
          roles=(Role.ACTOR, Role.TARGET, Role.SRC, Role.DST)) -> TypeSpec:
    return TypeSpec(et, key, temporal, retention, audience, roles)


TYPE_REGISTRY: dict[EntityType, TypeSpec] = {
    EntityType.HOST: _spec(EntityType.HOST, ("value",), audience=Audience.CUSTOMER_VISIBLE),
    EntityType.USER: _spec(EntityType.USER, ("value",)),
    EntityType.IP: _spec(EntityType.IP, ("value",),
                         roles=(Role.SRC, Role.DST, Role.ACTOR, Role.TARGET)),
    EntityType.DOMAIN: _spec(EntityType.DOMAIN, ("value",)),
    EntityType.URL: _spec(EntityType.URL, ("value",)),
    EntityType.HASH: _spec(EntityType.HASH, ("value",)),
    EntityType.FILE: _spec(EntityType.FILE, ("value",)),
    EntityType.PROCESS: _spec(EntityType.PROCESS, ("host", "pid", "started_at"),
                              roles=(Role.ACTOR, Role.PARENT, Role.TARGET)),
    EntityType.PORT: _spec(EntityType.PORT, ("value",), roles=(Role.SRC, Role.DST)),
    EntityType.AGENT: _spec(EntityType.AGENT, ("value",)),
    EntityType.RULE: _spec(EntityType.RULE, ("value",), roles=(Role.OBSERVER,)),
    EntityType.ALERT: _spec(EntityType.ALERT, ("value",),
                            retention=RetentionClass.EVIDENCE, roles=(Role.OBSERVER,)),
    EntityType.ARTIFACT: _spec(EntityType.ARTIFACT, ("value",)),
    EntityType.TECHNIQUE: _spec(EntityType.TECHNIQUE, ("value",),
                                audience=Audience.CUSTOMER_VISIBLE, roles=()),
    EntityType.TACTIC: _spec(EntityType.TACTIC, ("value",),
                             audience=Audience.CUSTOMER_VISIBLE, roles=()),
}


# Allowed-pair matrix (OpenCTI validation pattern): which (src_type,
# dst_type) each verb may connect. Absent entry => not allowed.
VERB_ALLOWED_PAIRS: dict[RelationVerb, set[tuple[EntityType, EntityType]]] = {
    RelationVerb.HAS_IP: {(EntityType.HOST, EntityType.IP)},
    RelationVerb.LISTENS_ON: {(EntityType.HOST, EntityType.PORT)},
    RelationVerb.RESOLVED_TO: {(EntityType.DOMAIN, EntityType.IP)},
    RelationVerb.SPAWNED: {(EntityType.PROCESS, EntityType.PROCESS)},
    RelationVerb.AUTHENTICATED_TO: {(EntityType.USER, EntityType.HOST)},
    RelationVerb.CONNECTED_TO: {(EntityType.IP, EntityType.IP),
                                (EntityType.HOST, EntityType.HOST)},
    RelationVerb.MAPS_TO_TECHNIQUE: {(EntityType.ALERT, EntityType.TECHNIQUE),
                                     (EntityType.RULE, EntityType.TECHNIQUE)},
    RelationVerb.SAME_AS: {(t, t) for t in EntityType},   # only same-type aliases
}


def is_pair_allowed(verb: RelationVerb, src: EntityType, dst: EntityType) -> bool:
    allowed = VERB_ALLOWED_PAIRS.get(verb)
    if allowed is None:
        # Observed touch/participation verbs are permissive (an alert may
        # touch anything); only the curated state/derived verbs are matrixed.
        return True
    return (src, dst) in allowed


# ------------------------------------------------------------- canonical form


def canonical_value(entity_type: EntityType, value: str, **extra: str) -> str:
    """Canonical form per type (identity is computed over this)."""
    v = (value or "").strip()
    et = entity_type
    if et in (EntityType.HOST, EntityType.USER, EntityType.DOMAIN,
              EntityType.AGENT, EntityType.ARTIFACT):
        return v.lower()
    if et == EntityType.IP:
        return v.lower()
    if et == EntityType.HASH:
        return v.lower()
    if et == EntityType.URL:
        return v  # URLs are case-sensitive in path/query; trim only
    if et in (EntityType.TECHNIQUE, EntityType.TACTIC, EntityType.RULE):
        return v.upper()
    return v


def entity_id(entity_type: EntityType, value: str, **extra: str) -> str:
    """Deterministic UUIDv5 over (type, canonical natural key). Same natural
    key => same id, across churning aliases. Never fused — aliasing lives in
    explicit same_as links."""
    spec = TYPE_REGISTRY[entity_type]
    parts = [entity_type.value]
    for field in spec.natural_key:
        if field == "value":
            parts.append(canonical_value(entity_type, value, **extra))
        else:
            parts.append((extra.get(field) or "").strip().lower())
    name = "|".join(parts)
    return str(uuid.uuid5(_NAMESPACE, name))


def model_fingerprint() -> str:
    """A hash of the vocabulary — CI can diff this to enforce additive-only
    evolution (a changed fingerprint that isn't a superset is a breaking
    change)."""
    items = [MODEL_VERSION]
    items += [e.value for e in EntityType]
    items += [r.value for r in Role]
    items += [v.value for v in RelationVerb]
    return hashlib.sha256("|".join(items).encode()).hexdigest()[:16]
