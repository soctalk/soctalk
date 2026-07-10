"""JSON Schema export from the registry (issue #24).

The registry is the source of truth; this emits the JSON Schema artifact the
adapter validates against and the frontend can codegen from. Committed
alongside the package so CI can diff it for additive-only evolution.
"""

from __future__ import annotations

from typing import Any

from soctalk_entities.model import (
    MODEL_VERSION,
    EntityType,
    RelationClass,
    RelationVerb,
    Role,
    SourceReliability,
    TYPE_REGISTRY,
    model_fingerprint,
)


def export_json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SocTalk canonical entity/event model",
        "model_version": MODEL_VERSION,
        "fingerprint": model_fingerprint(),
        "$defs": {
            "entity_type": {"enum": [e.value for e in EntityType]},
            "role": {"enum": [r.value for r in Role]},
            "relation_verb": {"enum": [v.value for v in RelationVerb]},
            "relation_class": {"enum": [c.value for c in RelationClass]},
            "source_reliability": {"enum": [s.value for s in SourceReliability]},
            "confidence": {
                "type": "object",
                "properties": {
                    "reliability": {"$ref": "#/$defs/source_reliability"},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "evaluated": {"type": "boolean"},
                },
                "required": ["reliability"],
            },
            "entity": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "type": {"$ref": "#/$defs/entity_type"},
                    "value": {"type": "string"},
                },
                "required": ["id", "type", "value"],
            },
        },
        "type_registry": {
            et.value: {
                "natural_key": list(spec.natural_key),
                "temporal_class": spec.temporal_class.value,
                "retention_class": spec.retention_class.value,
                "default_audience": spec.default_audience.value,
                "allowed_roles": [r.value for r in spec.allowed_roles],
            }
            for et, spec in TYPE_REGISTRY.items()
        },
    }
