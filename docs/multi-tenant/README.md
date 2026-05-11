# SocTalk Upgrade Artifacts

This directory contains the **upgrade design artifacts**: the design gate documents plus phased implementation references (install, runbook, upgrade, troubleshooting).

This release transforms SocTalk from a single-tenant SOC automation appliance into an **MSSP-deployed control plane** that provisions and operates dedicated per-customer OSS SOC stacks on K3s.

## Documents

| Doc | Topic | Scope |
|---|---|---|
| [security-model](security-model.md) | **Tenant security model** | Principal catalog (8), actor×resource matrix, RLS policy matrix, Postgres roles, endpoint classification, token schemas, audit rules, secret placement |
| [chart-audit](chart-audit.md) | **Tenant Helm chart audit** | Per-object classification of Wazuh/TheHive/Cortex charts: namespace-scoped OK vs cluster-prereq vs forbidden/patched |
| [cni-networkpolicy](cni-networkpolicy.md) | **CNI + NetworkPolicy design** | Cilium primary, NP templates for `soctalk-system` ↔ `tenant-*`, FQDN egress for BYO LLM |
| [postgres-rls](postgres-rls.md) | **Postgres RLS hygiene** | Three-role model, FORCE ROW LEVEL SECURITY, policy templates, idempotency key composite, isolation test suite |
| [secret-placement](secret-placement.md) | **Secret placement policy** | Per-secret table: location, principal access, rotation, generation at provisioning |
| [wazuh-ingress](wazuh-ingress.md) | **Wazuh ingress + cert enrollment** | Per-tenant hostname, TLS/SNI routing, `authd` enrollment flow, firewall/DNS |
| [sizing](sizing.md) | **Sizing profiles** | small-dev (4/16) and pilot-prod (8/32) references; per-tenant footprint estimates; max-tenants formula |
| [two-chart-contract](two-chart-contract.md) | **Two-chart contract** | `soctalk-system` vs `soctalk-tenant` values schemas, compatibility matrix, render→apply flow |

## Out of scope

Explicitly deferred to a future release:

- **Licensing**: no license verification or feature gating in this release. Pilot MSSPs operate on honor + written commercial terms.
- **Supply chain hardening**: no cosign / SBOM / Trivy in this release beyond dependency scans.
- **Backup/restore tooling**: documents where data lives; MSSP owns external backup.
- **MISP integration**: a future release.
- **SocTalk Cloud SaaS**: a future release.
- **Custom K8s operator with CRDs**: a future release.

## Readiness gate

These design docs are considered complete when every document above is reviewed and merged as a read-only reference, AND the following cross-cutting setup is in place:

- `.importlinter` config active in CI (enforces `src/soctalk/core` cannot import `src/soctalk_enterprise`).
- `scripts/dev-up.sh` brings up k3d + Cilium for local dev and CI.
- `charts/soctalk-system/` and `charts/soctalk-tenant/` skeletons exist with `Chart.yaml`, `values.yaml`, `values.schema.json`.
- `LICENSE` (Apache 2.0) and `NOTICE` files exist at repo root, mirrored by `pyproject.toml`.
- Chart-audit, sizing-measurement, and Wazuh-ingress spikes complete and update the documents with real numbers.

## Implementation artifacts (code + infra)

The implementation artifacts live outside this directory but are indexed here for navigation:

- `src/soctalk/core/tenancy/`: multi-tenant models, context, decorators, auth adapter
- `src/soctalk/core/provisioning/`: TenantController, Helm SDK wrapper, K8s client, secret generation
- `src/soctalk/core/api/`: FastAPI routers (MSSP tenants, branding, LLM config, adapter, health) + composed app at `app_v1.py`
- `src/soctalk/core/observability/`: Prometheus exporter + audit helper
- `src/soctalk_enterprise/`: proprietary-edition package boundary (empty in this release)
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

## Operations docs 

- [install/](install/README.md): cluster prereqs, install steps, first customer onboarding
- [runbook/](runbook/README.md): common operational tasks + failure modes
- [upgrade/](upgrade/README.md): install-level + per-tenant upgrade procedures, rollback
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): symptom → diagnostic → fix index

## Status

All artifacts produced in the current autonomous session are in the working tree; none are committed. MSSP cluster admins reviewing should start with [security-model.md](security-model.md).
