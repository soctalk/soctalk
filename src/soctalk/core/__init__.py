"""SocTalk V1 open-core package.

Code under ``soctalk.core`` is open-source (MIT). By design, it may not import
from ``soctalk_enterprise``. The boundary is enforced in CI via import-linter
(see ``.importlinter`` at repo root).

During the V1 upgrade, multi-tenancy primitives land here under
``soctalk.core.tenancy``; K3s provisioning under ``soctalk.core.provisioning``;
licensing hooks (V1.5+) under ``soctalk.core.licensing``; observability helpers
under ``soctalk.core.observability``.

Legacy single-tenant code remains at ``soctalk.*`` top level until its
multi-tenant refactor lands (phased per ``docs/v1/README.md``).
"""
