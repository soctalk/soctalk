"""Authorization/expectedness reasoning over typed AuthorizationFacts (epic M1).

- ``engine``: deterministic evaluator (activity + facts -> four expectedness components)
- ``adapter``: benchmark orgstate.jsonl rows -> facts; stackless (SIEM-only) projection
- ``render``: facts -> prompt/report text for the supervisor and verdict nodes
"""

from soctalk.authorization.engine import (
    ROUTINE_MIN,
    evaluate_authorization,
    find_covering_grants,
)

__all__ = [
    "ROUTINE_MIN",
    "evaluate_authorization",
    "find_covering_grants",
]
