# SocTalk V1 Upgrade Artifacts

This directory contains the **V1 upgrade design artifacts**: Phase 0 gate documents plus phased implementation references (install, runbook, upgrade, troubleshooting).

V1 transforms SocTalk from a single-tenant SOC automation appliance into an **MSSP-deployed control plane** that provisions and operates dedicated per-customer OSS SOC stacks on K3s.

## Documents

| # | Artifact | Scope |
|---|---|---|
| [00](00-decisions.md) | **Decisions log** | Every V1 decision, classified `LOCKED` / `MVP-CUT` / `DEFAULT`, with traceability to the artifact it drives |
| [P0-1](P0-1-security-model.md) | **Tenant security model** | Principal catalog (8), actor×resource matrix, RLS policy matrix, Postgres roles, endpoint classification, token schemas, audit rules, secret placement |
| [P0-2](P0-2-chart-audit.md) | **Tenant Helm chart audit** | Per-object classification of Wazuh/TheHive/Cortex charts: namespace-scoped OK vs cluster-prereq vs forbidden/patched |
| [P0-3](P0-3-cni-networkpolicy.md) | **CNI + NetworkPolicy design** | Cilium primary, NP templates for `soctalk-system` ↔ `tenant-*`, FQDN egress for BYO LLM |
| [P0-4](P0-4-postgres-rls.md) | **Postgres RLS hygiene** | Three-role model, FORCE ROW LEVEL SECURITY, policy templates, idempotency key composite, isolation test suite |
| [P0-5](P0-5-secret-placement.md) | **Secret placement policy** | Per-secret table: location, principal access, rotation, generation at provisioning |
| [P0-6](P0-6-wazuh-ingress.md) | **Wazuh ingress + cert enrollment** | Per-tenant hostname, TLS/SNI routing, `authd` enrollment flow, firewall/DNS |
| [P0-7](P0-7-sizing.md) | **Sizing profiles** | small-dev (4/16) and pilot-prod (8/32) references; per-tenant footprint estimates; max-tenants formula |
| [P0-8](P0-8-two-chart-contract.md) | **Two-chart contract** | `soctalk-system` vs `soctalk-tenant` values schemas, compatibility matrix, render→apply flow |

## What Phase 0 does NOT cover

Explicitly deferred to V1.5 or V2 per `00-decisions.md`:

- **Licensing** (D-14): no license verification or feature gating in V1. Pilot MSSPs operate on honor + written commercial terms.
- **Supply chain hardening** (D-15): no cosign / SBOM / Trivy in V1 beyond dependency scans.
- **Backup/restore tooling** (D-16). V1 documents where data lives; MSSP owns external backup.
- **MISP integration** (D-19). V1.5.
- **SocTalk Cloud SaaS**. V1.5.
- **Custom K8s operator with CRDs**. V2.

## Phase 0 gate

Phase 0 completes when every document above is reviewed and merged as a read-only reference, AND the following cross-cutting setup is in place:

- `.importlinter` config active in CI (enforces `src/soctalk/core` cannot import `src/soctalk_enterprise`).
- `scripts/dev-up.sh` brings up k3d + Cilium for local dev and CI.
- `charts/soctalk-system/` and `charts/soctalk-tenant/` skeletons exist with `Chart.yaml`, `values.yaml`, `values.schema.json`.
- `LICENSE` file exists at repo root mirroring `pyproject.toml` MIT declaration.
- Phase 0 spikes for chart audit (P0-2), sizing measurement (P0-7), Wazuh ingress (P0-6) complete and update the documents with real numbers.

## Traceability into Phase 1+

Each artifact identifies its Phase 1+ consumers:

- **Phase 1 (multi-tenant foundation)**: consumes P0-1 (principal model → user/role tables, tenant context middleware, audit), P0-4 (RLS migrations, three-role Postgres setup), P0-5 (secret placement informs tenant provisioning flow).
- **Phase 2 (two Helm charts + K3s control plane)**: consumes P0-2 (patched subcharts), P0-3 (NP templates), P0-6 (Wazuh ingress rendering), P0-7 (resource defaults), P0-8 (chart schemas and render→apply flow).
- **Phase 3**: consumes P0-1 (per-tenant config entities include branding, LLM).
- **Phases 4, 5**: consume P0-1 (endpoint classification + role-based routing + token claims).
- **Phase 6**: consumes P0-1 (lifecycle events, audit), P0-5 (secrets rotation runbook).
- **Phase 8**: consumes P0-6 (customer onboarding runbook), P0-7 (hardware sizing in install guide).

## Implementation artifacts (code + infra)

The V1 implementation artifacts live outside this directory but are indexed here for navigation:

- `src/soctalk/core/tenancy/`: multi-tenant models, context, decorators, auth adapter
- `src/soctalk/core/provisioning/`: TenantController, Helm SDK wrapper, K8s client, secret generation
- `src/soctalk/core/api/`: V1 FastAPI routers (MSSP tenants, branding, LLM config, adapter, health) + composed app at `app_v1.py`
- `src/soctalk/core/observability/`: Prometheus exporter + audit helper
- `src/soctalk_enterprise/`: proprietary-edition package boundary (empty in V1)
- `alembic/versions/v1_0001_multi_tenancy.py`: roles, schema, RLS, composite idempotency
- `charts/soctalk-system/`: install-scoped Helm chart (control plane)
- `charts/soctalk-tenant/`: per-tenant Helm chart (OSS SOC stack + adapter)
- `tests/v1/`: isolation test suite (RLS, worker context, auth/roles)
- `scripts/dev-up.sh`: k3d + Cilium + cert-manager dev harness
- `.importlinter`: open-core boundary CI check
- `.github/workflows/v1-ci.yml`: Python tests + Helm lint + frontend build + chart publish on tag
- `frontend/`: canonical SvelteKit app — single deployment serving both
  MSSP and tenant audiences. Tenant scoping happens at the session
  layer (RLS + role-driven view gating). Replaces the legacy
  `frontend/mssp/` + `frontend/customer/` split.

## Operations docs (Phase 8)

- [install/](install/README.md): cluster prereqs, install steps, first customer onboarding
- [runbook/](runbook/README.md): common operational tasks + failure modes
- [upgrade/](upgrade/README.md): install-level + per-tenant upgrade procedures, rollback
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): symptom → diagnostic → fix index

## Status

All artifacts produced in the current autonomous session are in the working tree; none are committed. MSSP cluster admins reviewing V1 should start with [00-decisions.md](00-decisions.md) and [P0-1-security-model.md](P0-1-security-model.md).
