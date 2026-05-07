"""V1 FastAPI routers (open-core).

Composed by the top-level app at ``soctalk.api.app``. V1 routes are mounted
under ``/api/mssp/*`` and ``/api/tenant/*`` and use the auth decorators in
``soctalk.core.tenancy.decorators`` for role enforcement.
"""
