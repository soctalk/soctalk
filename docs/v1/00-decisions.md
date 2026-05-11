# V1 MVP Decisions Log

Enumerated decisions made during the V1 upgrade design, with reasoning. This log anchors all Phase 0 artifacts in `docs/v1/`. Revisions to any item must update this log and any dependent artifact.

Status legend: `[LOCKED]` unchangeable without architectural review; `[MVP-CUT]` deliberately minimized for V1, scheduled for V1.5/V2; `[DEFAULT]` chosen default acceptable to override with user confirmation.

---

## D-01: Product shape `[LOCKED]`

SocTalk V1 is an **MSSP-deployed control plane** that provisions and operates **dedicated per-customer OSS SOC stacks** on K3s. Single-tenant SOC stack per customer; multi-tenant SocTalk control plane via row-level Postgres RLS.

Not in V1: shared multi-tenant OSS backends, Firecracker-level hard isolation, SocTalk Cloud SaaS.

## D-02: Entity cardinality `[LOCKED]`

```
Cloud (1) → MSSP (n) → Install (m; V1: m=1) → Tenant (n)
```

V1 assumes `m=1` (one install per MSSP). Schema and license claims carry `install_id` so multi-install (V1.5+) adds without rework.

## D-03: Deployment tenancy, not app-native `[LOCKED]`

One customer = one K3s namespace + dedicated OSS stack. Isolation controls: `NetworkPolicy`, `ResourceQuota`, `LimitRange`, dedicated `ServiceAccount`, per-namespace `Secret`s, per-namespace `PersistentVolumeClaim`s.

## D-04: Virtualization: K3s + Cilium `[LOCKED]`

K3s is the runtime. **Cilium** is the primary CNI (chosen for NetworkPolicy enforcement and FQDN egress policies needed for BYO LLM). Calico + egress-proxy is the documented alternate install mode.

Not in V1: full Rancher, Firecracker, Talos appliance variant.

## D-05: Two Helm chart classes `[LOCKED]`

- `charts/soctalk-system/`: install-scoped, installed once by MSSP cluster admin via `helm install`.
- `charts/soctalk-tenant/`: tenant-scoped, installed by **SocTalk controller via Helm SDK** on every customer create.

Independent versioning; SocTalk holds a compatibility matrix and refuses out-of-matrix tenant chart versions.

## D-06: Three-layer access model `[LOCKED]`

1. **Ingress** handles authentication via OIDC.
2. **SocTalk application** handles tenant-aware authorization with role-based checks and tenant context.
3. **Kubernetes RBAC** is scoped to platform components only; end users never touch the K8s API.

## D-07: Principal catalog (8 principals) `[LOCKED]`

User (4-role), Worker, System, SocTalk K8s ServiceAccount, Tenant adapter, Wazuh agent, MSSP cluster admin, Cloud license issuer. Full catalog in `P0-1-security-model.md`.

## D-08: 4-role user model `[LOCKED]`

`platform_admin`, `mssp_admin`, `analyst`, `customer_viewer`. Customer side is view-only in MVP; approvals are an analyst workflow on the MSSP side.

## D-09: Multi-tenancy enforcement: Postgres RLS + FORCE RLS `[LOCKED]`

Shared database + `tenant_id` column on every tenant-scoped table. **Row-Level Security with `FORCE ROW LEVEL SECURITY`**. Three Postgres roles: `soctalk_admin` (owner, migrations), `soctalk_app` (runtime, RLS-subject), `soctalk_mssp` (`BYPASSRLS`, system-context only). See `P0-4-postgres-rls.md`.

## D-10: Core code license: Apache 2.0 `[LOCKED]`

Relicensed from MIT to Apache 2.0 (May 2026) before external contributions land. Reason: explicit patent grant matters for enterprise/MSSP procurement legal review; Apache 2.0 is the prevailing license for cloud-native infra OSS (Kubernetes, Prometheus, OPA, Falco). `LICENSE` carries the canonical Apache text; `NOTICE` carries the attribution.

Source-available (BSL-1.1) is a V1.5+ consideration if hyperscaler-cannibalization pressure emerges. Not now.

## D-11: Open-core file layout `[LOCKED]`

- `src/soctalk/core/`: open-source (Apache 2.0), default runtime.
- `src/soctalk_enterprise/`: proprietary modules, empty in V1 except CI import-boundary wiring.
- CI enforces `core` cannot import from `soctalk_enterprise` via `import-linter` (see `.importlinter`).

## D-12: OIDC ingress reference: OAuth2-Proxy `[DEFAULT]`

OAuth2-Proxy is the recommended reference in the install guide. Lightweight, delegates to any IdP (Google, Azure AD, Okta, Keycloak, Dex, generic OIDC). Keycloak and Dex are documented as supported alternatives.

## D-13: Admission enforcement: VAP in V1 `[LOCKED]`

SocTalk controller is granted cluster-scoped `namespaces:create,delete,get,list,watch` and workload verbs needed for tenant lifecycle operations. V1 installs Kubernetes `ValidatingAdmissionPolicy` guards that only constrain the SocTalk controller ServiceAccount: namespace create/update/delete must target names beginning with `tenant-` and carrying `tenant=true` plus `managed-by=soctalk`; namespaced resource mutations are limited to the SocTalk system namespace and `tenant-*` namespaces.

MSSP cluster-admin users are intentionally outside that policy and remain trusted break-glass operators.

Kyverno remains an optional V1.5 hardening path for MSSPs that already standardize on it.

## D-14: Runtime licensing: NONE in V1 `[MVP-CUT]`

No license verification, no JWT signing, no feature gates, no JWKS, no degraded-mode behavior. Pilot MSSPs operate on honor + written commercial terms out of band.

Schema reserves `license_jwt` column (nullable) for future use. V1.5 adds: ed25519-signed JWT (claims: `iss`, `sub=mssp_uuid`, `install_id`, `aud`, `iat`, `nbf`, `exp`, `jti`, `kid`, `ver`, `tier`, `features[]`, `end_client_cap`, `install_cap`, `channel`), offline verification, issuer CLI, feature gate decorators, degraded-mode allowlist, JWKS in ConfigMap for rotation.

## D-15: Supply chain hardening: MINIMAL in V1 `[MVP-CUT]`

Build → tag → push to public OCI registry (GHCR). Single `linux/amd64` arch. Semver tags + `latest`. Dependency scanning via `pip-audit` + `npm audit` as PR gates (cheap, kept in).

**Deferred to V1.5**: cosign signing, Syft SBOM generation, Trivy CVE gate, multi-arch (`linux/arm64`), release channels (`stable`/`beta`).

## D-16: Backup/restore: DOCUMENTATION ONLY in V1 `[MVP-CUT]`

Install guide documents where SocTalk DB and tenant data live. MSSP owns backup externally (Velero, cluster-level snapshot, external `pg_dump` scheduling).

**Deferred to V1.5**: tested `pg_dump`/`pg_restore` runbook, VolumeSnapshot-based PVC backups, decommission auto-backup, recovery drills.

## D-17: Reference hardware profiles `[DEFAULT]`

| Profile | CPU | RAM | Max tenants | Use |
|---|---|---|---|---|
| **small-dev** | 4 vCPU | 16 GB | 1–2 | Development, demos |
| **pilot-prod** | 8 vCPU | 32 GB | 3–5 | Pilot MSSPs |

Documented in `P0-7-sizing.md`. MSSPs with larger needs are V1.5 sizing guidance.

## D-18: BYO LLM, OpenAI-compatible only `[LOCKED]`

Per-tenant LLM config: `provider=openai-compatible`, `base_url`, `model`, `api_key_ref` (K8s Secret reference). No multi-provider routing, no local-LLM sidecar orchestration in V1.

Customer controls the LLM endpoint; MSSP configures it on their behalf via per-tenant config. Cilium FQDN egress policy restricts SocTalk's outbound LLM traffic to exactly the configured host per tenant.

## D-19: MISP integration: V1.5 `[MVP-CUT]`

Wazuh + TheHive + Cortex is the V1 tenant stack. MISP deferred to V1.5.

## D-20: Customer UI scope: VIEW-ONLY in V1 `[LOCKED]`

Customer side (`customer_viewer` role) is view-only: Overview, Incidents, Reports, Audit. No Approvals: those are analyst-side on MSSP UI.

V2+ may introduce customer-side approval role if product demand emerges.

## D-21: Tenant lifecycle scope in V1 `[LOCKED]`

Provisioning API: `create`, `health`, `suspend`, `resume`, `decommission`. Upgrade and rollback are **runbook operations** (documented `helm upgrade`/`helm rollback` procedures). Upgrade API added in V1.5.

## D-22: Secret placement: K8s Secret references in Postgres `[LOCKED]`

No raw secret material in Postgres. Tables store `(namespace, name, version_label)` references. Actual material lives in K8s Secrets, mounted into the pod that needs it.

External Secrets Operator integration is V1.5.

## D-23: Tenant ID convention `[LOCKED]`

- **Internal**: UUID v4 (stable across renames, lifecycle changes).
- **URL-visible**: slug (DNS-safe lowercase, e.g., `acme-corp`), per-MSSP unique but not globally.
- `tenant_id` claims never appear in URL paths (`/api/tenants/:tid/...` is forbidden): tenant context is always token-derived.

## D-24: Namespace naming and labeling `[LOCKED]`

Format: `tenant-<slug>`. Required labels:
- `tenant: "true"`
- `managed-by: "soctalk"`
- `mssp-id: "<uuid>"`
- `install-id: "<uuid>"`
- `tenant-id: "<uuid>"`

Enforced by SocTalk application code and by the system chart's `ValidatingAdmissionPolicy` for the SocTalk controller ServiceAccount.

## D-25: Release tagging `[DEFAULT]`

Semver (`v1.0.0`, `v1.0.1`) + `latest` mutable tag. `stable` / `beta` channel tags deferred to V1.5.

## D-26: JWKS distribution (V1.5 when licensing lands) `[DEFAULT]`

License verification keys distributed via ConfigMap mounted into SocTalk pods, not baked into images. Rotation via Helm values update (no image rebuild). Signing private key stored in HSM/KMS (customer-specific; documented in V1.5 runbook).

---

## Rejected alternatives worth naming

- **Full Rancher as the platform layer**: too heavy, conflicts with MSSPs running their own Rancher, crosses trust boundary.
- **Schema-per-tenant or DB-per-tenant Postgres tenancy**: breaks MSSP cross-tenant views; operationally heavy.
- **Custom K8s operator + CRDs (`SocTenant`/`SocStack`)**. V2 refactor; V1 drives Helm directly from SocTalk backend.
- **GitOps reconciliation (Fleet/ArgoCD) as V1 control plane**: rejected after clarification that SocTalk itself manages K3s in-cluster; reconciler would be redundant for the one-install-per-MSSP MVP model.
- **Build custom Kubernetes agent**: reinvents Rancher/Fleet subset; abandoned in favor of in-cluster SocTalk controller.
- **MCP registry / dynamic integration loading**. V2.
- **Kyverno as mandatory V1 admission**: more policy features than VAP, but requires a CRD dependency. V1 uses native VAP and leaves Kyverno as an optional hardening track.

---

## Decision-to-artifact traceability

| Decision | Drives artifact |
|---|---|
| D-07, D-08, D-09, D-22 | `P0-1-security-model.md` |
| D-03, D-05 (tenant chart side) | `P0-2-chart-audit.md` |
| D-04, D-18 | `P0-3-cni-networkpolicy.md` |
| D-09 | `P0-4-postgres-rls.md` |
| D-22 | `P0-5-secret-placement.md` |
| (new) | `P0-6-wazuh-ingress.md` |
| D-17 | `P0-7-sizing.md` |
| D-05, D-21 | `P0-8-two-chart-contract.md` |
| D-11 | `.importlinter` |
| D-04 | `scripts/dev-up.sh` |
| D-10 | `LICENSE` |
