# P0-2: Tenant Helm Chart Audit

Gate artifact: Classifies every Kubernetes object rendered by upstream charts we bundle in `charts/soctalk-tenant/`, producing a list of **cluster-scoped prerequisites** (installed by MSSP cluster admin or `soctalk-system` chart) versus **namespace-scoped objects** (safe inside `tenant-<slug>`) versus **forbidden/patched** (objects we cannot accept and must remove or replace).

> **Audit methodology**: this document captures the expected classification based on chart inspection. Actual `helm template` runs and diff-vs-classification are required in the Phase 0 spike. Any object found in a real render that isn't listed here becomes a review gate.

## 1 Scope of audit

Charts to audit:

| Upstream | Upstream source | Target version |
|---|---|---|
| Wazuh | `wazuh/wazuh-kubernetes` Helm chart (community) or official OCI chart | Latest stable 4.x supporting single-manager HA |
| TheHive | `StrangeBee/thehive4` Helm chart or community | 5.x |
| Cortex | `TheHive-Project/Cortex` Helm chart or community | 3.x |
| MISP | **deferred a future release** | |

For each chart we vendor the manifest templates (with patches if needed) as subchart dependencies of `charts/soctalk-tenant/`: Version pinning is strict. `Chart.yaml` uses exact semver with digest (OCI) where available.

## 2 Classification rules

For every rendered object, classify as:

- **NS-OK**: namespace-scoped object that lives inside `tenant-<slug>`. Safe, expected.
- **CLUSTER-PREREQ**: cluster-scoped object that must be installed once by the `soctalk-system` chart or documented as MSSP cluster-admin responsibility. Tenant chart must not re-install these per tenant.
- **FORBIDDEN**: object type or capability we refuse to allow in a tenant chart even when upstream declares it (e.g., cluster-wide `ClusterRoleBinding` giving Wazuh privileged access). Must be patched out.
- **PATCH**: keep the object but modify it (e.g., drop `hostPath` volumes, remove privileged `securityContext`, reduce default resource requests).

## 3 Expected classification per upstream chart

### 3.1 Wazuh

Wazuh charts typically render:

| Object | Expected class | Notes |
|---|---|---|
| `Deployment` / `StatefulSet` (manager, indexer, dashboard) | NS-OK | Core stack pods |
| `Service` (manager API, indexer, dashboard, agent ingress 1514/1515) | NS-OK | |
| `ConfigMap` (ossec.conf, indexer.yml, dashboard.yml) | NS-OK | |
| `Secret` (admin pw, mutual TLS certs) | NS-OK | Seeded per-tenant at provisioning |
| `PersistentVolumeClaim` (indexer data, manager data) | NS-OK | Size set via tenant values |
| `ServiceAccount` | NS-OK | Per-tenant SA |
| `Role` + `RoleBinding` (for leader election if used) | NS-OK | Namespace-scoped only |
| `NetworkPolicy` (chart-provided) | PATCH | Replace with SocTalk-rendered NP for consistent posture; don't allow upstream defaults to override default-deny |
| `StorageClass` references | CLUSTER-PREREQ | MSSP must provide a dynamic provisioner; `storageClassName` is a values input |
| `Ingress` | PATCH or disable | Default Wazuh charts often expose 1514/1515 via LoadBalancer or Ingress. We use per-tenant SNI routing at MSSP edge (see `P0-6-wazuh-ingress.md`); chart should render only `Service` of type `ClusterIP`, no `Ingress` / `LoadBalancer` |
| `PodSecurityPolicy` / `SecurityContextConstraints` | CLUSTER-PREREQ if present; forbidden otherwise | PSP is deprecated; if present, remove. OpenShift SCC is not in scope for this release |
| `CustomResourceDefinition` | **FORBIDDEN** in tenant chart | If the chart tries to install a CRD, move to `soctalk-system` chart or document as prerequisite |
| `ClusterRole` / `ClusterRoleBinding` | **FORBIDDEN** in tenant chart | Never install cluster-wide RBAC from a tenant namespace |
| Privileged/host-network/hostPath pods | **FORBIDDEN**; patch out | Wazuh manager doesn't require these for standard operation; indexer doesn't either. If a subchart demands `hostPath` for logs, patch to `emptyDir` + PVC |
| `PodDisruptionBudget` | NS-OK | Optional; depends on Wazuh HA mode. Single-manager topology may skip |

**Expected patches**:
1. Remove any `ClusterRole`/`ClusterRoleBinding` from rendered output.
2. Remove any cluster-scoped resources (`ValidatingWebhookConfiguration`, etc.).
3. Patch `Service` for agent ingress to `ClusterIP` only; real ingress happens at MSSP edge (see P0-6).
4. Strip `Ingress` resources. SocTalk doesn't expose Wazuh dashboards through K8s Ingress in this release (MSSP-side SNI proxy handles it).
5. Ensure all pods have `securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false }`; patch if upstream sets otherwise.
6. Pin images to digests, not `latest`.

### 3.2 TheHive

| Object | Expected class | Notes |
|---|---|---|
| `Deployment` (TheHive app) | NS-OK | |
| `StatefulSet` (Cassandra or external-DB-backed variants) | NS-OK | uses embedded Cassandra; external Cassandra is a future release option |
| `Service` (TheHive web + API on 9000) | NS-OK | |
| `ConfigMap` (application.conf) | NS-OK | Per-tenant config rendered by SocTalk |
| `Secret` (admin credentials, Cortex API key for this tenant's Cortex) | NS-OK | |
| `PersistentVolumeClaim` (Cassandra data, index data) | NS-OK | |
| `ServiceAccount` | NS-OK | |
| `Ingress` | PATCH or disable | Same as Wazuh: dashboard exposure via MSSP-side proxy with tenant routing, not per-namespace Ingress |
| `Job` (bootstrap / init) | NS-OK | OK for first-run cert generation / DB init |
| `CustomResourceDefinition` | **FORBIDDEN**: must be in `soctalk-system` chart if present |
| `ClusterRole` / `ClusterRoleBinding` | **FORBIDDEN** in tenant chart |

**Expected patches**:
1. Strip Ingress; use ClusterIP Services only.
2. Pin Cassandra to digest; set resource limits matching P0-7 sizing.
3. Ensure init Job is idempotent (re-runs harmless).
4. No CRD dependencies.

### 3.3 Cortex

| Object | Expected class | Notes |
|---|---|---|
| `Deployment` (Cortex app) | NS-OK | |
| `StatefulSet` (Elasticsearch or compatible index) | NS-OK | embedded ES; external ES is a future release |
| `Service` (Cortex API on 9001) | NS-OK | |
| `ConfigMap` (application.conf, analyzer lists) | NS-OK | |
| `Secret` (admin, inter-service tokens) | NS-OK | |
| `PersistentVolumeClaim` | NS-OK | |
| `ServiceAccount` | NS-OK | |
| `Job` (analyzer registration) | NS-OK if idempotent |
| `Ingress` | PATCH or disable |
| `PrivilegedContainer` (Docker-in-Docker for analyzer sandboxing, if upstream uses this pattern) | **FORBIDDEN**: patch | Cortex analyzers that require Docker sandboxing are out of scope for this release. Use only analyzers that run in-process or call out to sandboxed external services |

**Known risk**: Cortex historically runs some analyzers as subprocesses or Docker containers. This release limits to "pure-code" analyzers that don't require privileged host access. Analyzer list is pinned in values; analyzers requiring Docker-in-Docker are rejected at provisioning time.

## 4 Cluster prerequisites list (rolled into install guide + `soctalk-system` chart prereq check)

Following the audit, these are **out-of-scope for the tenant chart** and must exist in the cluster before `soctalk-tenant` is applied to any namespace:

| Prerequisite | Why | source |
|---|---|---|
| K3s 1.30+ (or compatible K8s 1.30+) | Baseline plus `ValidatingAdmissionPolicy` v1 | MSSP responsibility |
| NP-enforcing CNI (Cilium primary, Calico alternate) | Isolation enforcement | MSSP responsibility |
| cert-manager | TLS for Ingress, per-tenant Wazuh cert issuance | MSSP responsibility; install guide provides `helm install` recipe |
| Ingress controller (Traefik default in K3s, ingress-nginx common) | MSSP UI + Customer UI + per-tenant WebUI routing | MSSP responsibility |
| Dynamic `StorageClass` (local-path, longhorn, cloud-provider CSI, etc.) | PVC provisioning | MSSP responsibility |
| `VolumeSnapshotClass` if using CSI snapshots | Backup/restore runbook (docs only) | Optional |

The `soctalk-system` chart includes a pre-install hook (`helm.sh/hook: pre-install`) that verifies:
- NP-enforcing CNI active (probes for Cilium or Calico markers)
- cert-manager CRDs present
- Default `StorageClass` set

Hook fails fast with actionable error message if any are missing.

## 5 Patching strategy

Two paths:

1. **Values-driven overrides**: prefer upstream chart values that disable the unwanted object (e.g., `ingress.enabled: false`, `networkPolicy.enabled: false` if upstream's is looser than ours, `rbac.create: true` scoped to namespace only).
2. **Kustomize-style overlay** (Helm's `kustomize` integration or post-render hook) for objects that can't be disabled via values: strip `ClusterRole`s, remove `hostPath` volumes, set `securityContext`.

We vendor upstream charts as pinned subchart dependencies in `charts/soctalk-tenant/charts/`, not as `helm repo` references. This lets us:
- Pin to exact versions (no upstream surprise updates)
- Apply patches as needed without depending on upstream PR acceptance
- Sign our bundle as a single artifact (a future release when cosign lands)

If upstream doesn't meet our needs after patches, the fallback is to write SocTalk-native templates that call the same container images with our own manifests. Phase 0 spike decides this per chart.

## 6 Known unknowns (Phase 0 spike resolves)

Items that require actual `helm template` runs + inspection to confirm:

- [ ] **Wazuh**: does the chosen chart version require CRDs for operator-driven deployment? If yes, move CRDs to `soctalk-system` chart.
- [ ] **TheHive**: does Cassandra require `StorageClass` with specific features (e.g., RWO only, minimum IOPS)? Document in P0-7 sizing.
- [ ] **Cortex**: what analyzers are enabled by default, and do any require Docker-in-Docker? Produce an allowlist of-safe analyzers.
- [ ] **All charts**: any `Job` or `CronJob` that runs with `ServiceAccount` beyond the namespace? Patch to ns-local SA.
- [ ] **All charts**: any `initContainer` with `privileged: true` or `hostPath` mounts? Patch or replace.
- [ ] **All charts**: default `resources.requests` and `limits`: Compare to P0-7 sizing profile; override in values where needed.

Each open item becomes a Phase 0 spike checklist entry. The spike's output is a filled-in classification table and the patched chart ready for `charts/soctalk-tenant/charts/`.

## 7 Output artifact (produced by Phase 0 spike)

The spike produces:

1. **Classified object inventory** (filling in section 3 tables with actual rendered objects).
2. **Patched chart bundles** checked into `charts/soctalk-tenant/charts/wazuh/`, `thehive/`, `cortex/` with pinned versions.
3. **Cluster prerequisites list** merged into install guide.
4. **Analyzer allowlist** for Cortex (safe-only set).
5. **Values schema fragment** for each subchart (inputs SocTalk will provide per-tenant).

The spike's completion is a prerequisite for Phase 2 (Helm chart implementation).

## 8 Phase 0 gate criteria for this artifact

Before Phase 1 begins:

- [x] This document merged as reference.
- [ ] Phase 0 spike executes `helm template` against chosen versions of Wazuh, TheHive, Cortex; produces filled classification tables.
- [ ] Patched charts vendored under `charts/soctalk-tenant/charts/`.
- [ ] Cluster prerequisites list incorporated into install guide draft (Phase 8 deliverable).
- [ ] Analyzer allowlist produced.
