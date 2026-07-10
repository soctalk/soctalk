"""Canonical entity and event model (issue #24).

The reference vocabulary for SocTalk's world: what kinds of things exist,
how they are identified, how they relate, how those relationships change
over time, and how sure we are. Every later piece (correlation, repeat-
incident recognition, hunting, MITRE contextualization, topology) inherits
this vocabulary — it's the one artifact expensive to change after the fact.

Authored as DATA, not a class hierarchy: closed enums for the vocabularies,
frozen registry entries per type (natural key, canonical form, temporal
class, retention class, default audience, allowed roles), and named,
versioned canonicalizers beside the specs. Dependency-free (stdlib only) so
both the adapter image and the control plane import it.

MODEL_VERSION bumps on any additive vocabulary change; the JSON Schema
exported from the registry is the shared artifact #17 presupposes.
"""

from soctalk_entities.model import (
    MODEL_VERSION,
    Audience,
    Confidence,
    EntityType,
    Provenance,
    RelationClass,
    RelationVerb,
    Role,
    SourceReliability,
    TemporalClass,
    TYPE_REGISTRY,
    VERB_ALLOWED_PAIRS,
    canonical_value,
    entity_id,
    is_pair_allowed,
)
from soctalk_entities.schema import export_json_schema

__all__ = [
    "MODEL_VERSION",
    "Audience",
    "Confidence",
    "EntityType",
    "Provenance",
    "RelationClass",
    "RelationVerb",
    "Role",
    "SourceReliability",
    "TemporalClass",
    "TYPE_REGISTRY",
    "VERB_ALLOWED_PAIRS",
    "canonical_value",
    "entity_id",
    "is_pair_allowed",
    "export_json_schema",
]
