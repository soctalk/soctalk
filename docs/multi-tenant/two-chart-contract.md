# two-chart-contract: Two-Chart Contract

Gate artifact: Defines the contract between `charts/soctalk-system/` and `charts/soctalk-tenant/`: what each chart owns, how values flow, the compatibility matrix, pinning policy, and the render→apply flow SocTalk controller uses.

## 1 Chart classes

| | `soctalk-system` | `soctalk-tenant` |
|---|---|---|
| **Scope** | One per MSSP install | One per end-customer |
| **Target namespace** | `soctalk-system` (fixed) | `tenant-<slug>` (created on install) |
| **Installed by** | MSSP cluster admin (`helm install soctalk-system …`) | SocTalk controller via Helm SDK (triggered by `POST /api/mssp/tenants`) |
| **How often** | Once per cluster lifetime; `helm upgrade` on version change | Per end-customer onboarding; `helm upgrade` on SOC stack version change |
| **Value authorship** | Hand-written by MSSP admin | Rendered by SocTalk from tenant config; never hand-edited |
| **Validates via** | `values.schema.json` | `values.schema.json` (SocTalk also validates pre-render) |
| **Version source of truth** | Chart.yaml semver | Chart.yaml semver |

## 2. `soctalk-system` values schema (draft)

Simplified shape; full JSON Schema artifact lives in `charts/soctalk-system/values.schema.json`.

```yaml
# Install identity
install:
  msspId: <uuid>              # written into Organization row
  msspName: "Example MSSP"
  installId: <uuid>           # written into Organization row; stable across upgrades
  installLabel: "pilot-prod"  # human-readable

# Image sources
image:
  registry: ghcr.io/gbrigandi
  tag: v1.0.0                 # or `latest`
  pullPolicy: IfNotPresent

# Postgres
postgres:
  enabled: true               # false = use external; then postgres.external.* required
  storage:
    size: 20Gi
    storageClassName: ""      # use cluster default
  external:
    host: ""
    port: 5432
    database: "soctalk"
    existingSecret: ""        # Secret must contain admin_user, admin_password, app_user, app_password, mssp_user, mssp_password

# Ingress (for MSSP UI + Customer UI)
ingress:
  enabled: true
  className: traefik          # or nginx, or anything the cluster provides
  tls:
    secretName: soctalk-tls
    issuerRef: letsencrypt-prod
  hostnames:
    mssp: mssp.example.com
    customer: "*.customers.example.com"  # per-tenant subdomain routing

# OIDC (handled at ingress level; SocTalk expects trusted headers)
oidc:
  trustedHeader: X-Forwarded-User
  trustedProxyCIDRs:
    - 10.0.0.0/8                # ingress controller CIDR; SocTalk rejects OIDC headers from other sources

# LLM defaults (per-tenant overrides via tenant chart)
defaults:
  llm:
    provider: openai-compatible
    baseUrl: https://api.openai.com/v1
    model: gpt-4o

# Resource sizing for SocTalk control plane
resources:
  api:
    requests: { cpu: 500m, memory: 512Mi }
    limits:   { cpu: 2,    memory: 2Gi }
  orchestrator:
    requests: { cpu: 500m, memory: 1Gi }
    limits:   { cpu: 2,    memory: 4Gi }
  postgres:
    requests: { cpu: 250m, memory: 512Mi }
    limits:   { cpu: 2,    memory: 2Gi }

# Admission: native guard for SocTalk controller namespace operations.
admission:
  engine: vap    # vap | none

# Licensing: disabled in this release
licensing:
  enabled: false

# Telemetry: disabled in this release (no Cloud backend to send to)
telemetry:
  enabled: false
```

## 3. `soctalk-tenant` values schema (draft)

Matches the tenant config model SocTalk renders from DB. This is the contract SocTalk's controller renders against; `values.schema.json` validates it on both sides.

```yaml
# Tenant identity
tenant:
  id: <uuid>                  # tenant UUID
  slug: acme                  # DNS-safe, MSSP-unique
  msspId: <uuid>
  installId: <uuid>
  displayName: "Acme Corp"

# Branding (referenced by SocTalk UIs, not by data plane)
branding:
  appName: "Acme SOC"
  logoUrl: https://acme.example.com/logo.png
  primaryColor: "#1a73e8"
  secondaryColor: "#fbbc04"
  favicon: ""

# LLM config (per tenant; overrides install defaults)
llm:
  provider: openai-compatible
  baseUrl: https://api.openai.com/v1
  model: gpt-4o
  apiKeyRef:
    namespace: soctalk-system   # see secret-placement; this is the install ns
    name: tenant-<id>-llm       # naming convention
    key: api_key

# Integration endpoints (tenant's external systems, if any)
integrations:
  # These are mostly informational in MVP;
  # real integration endpoints are tenant data plane (Wazuh/TheHive/Cortex in-ns).
  externalCortexUrl: ""        # if tenant wants to use an external Cortex instead of the in-ns one

# Data plane component sizing
components:
  wazuh:
    manager:
      resources:
        requests: { cpu: 200m, memory: 512Mi }
        limits:   { cpu: 500m, memory: 1Gi }
      persistence:
        size: 20Gi
    indexer:
      resources:
        requests: { cpu: 500m, memory: 2Gi }
        limits:   { cpu: 2,    memory: 4Gi }
      persistence:
        size: 50Gi
      jvm:
        heap: 1g
    dashboard:
      enabled: true
      resources:
        requests: { cpu: 100m, memory: 512Mi }
        limits:   { cpu: 500m, memory: 1Gi }
  thehive:
    resources:
      requests: { cpu: 300m, memory: 1Gi }
      limits:   { cpu: 1,    memory: 2Gi }
    cassandra:
      resources:
        requests: { cpu: 500m, memory: 2Gi }
        limits:   { cpu: 1.5,  memory: 4Gi }
      persistence:
        size: 30Gi
  cortex:
    resources:
      requests: { cpu: 200m, memory: 768Mi }
      limits:   { cpu: 800m, memory: 1.5Gi }
    elasticsearch:
      resources:
        requests: { cpu: 300m, memory: 1Gi }
        limits:   { cpu: 1,    memory: 2Gi }
      persistence:
        size: 20Gi
    analyzers: []              # allowlist; empty = safe defaults
  misp:
    enabled: false             # a future release

# Tenant namespace policies
networkPolicies:
  enabled: true
  # LLM endpoint allowlist (mirrors llm.baseUrl hostname for Cilium FQDN policy)
  allowedLlmHosts:
    - api.openai.com

# Resource quota & limits (from sizing)
resourceQuota:
  requests:
    cpu: "3"
    memory: 8Gi
  limits:
    cpu: "7"
    memory: 16Gi
  persistentVolumeClaims: "10"
  pods: "50"

# Wazuh agent ingress
agentIngress:
  hostname: acme.soc.mssp.example.com
  tls:
    issuerRef: letsencrypt-prod  # cert-manager
    secretName: wazuh-tls

# Adapter
adapter:
  image:
    repository: ghcr.io/gbrigandi/soctalk-adapter
    tag: v1.0.0
  resources:
    requests: { cpu: 50m, memory: 128Mi }
    limits:   { cpu: 200m, memory: 256Mi }
  tokenSecretRef:
    name: adapter-token
    key: token

# Labels applied to the tenant namespace
namespaceLabels:
  tenant: "true"
  managed-by: soctalk
  mssp-id: <uuid>
  install-id: <uuid>
  tenant-id: <uuid>
```

## 4 Compatibility matrix

SocTalk holds a compatibility matrix of which `soctalk-tenant` chart versions are supported by which `soctalk-system` version. Attempting to apply an out-of-range combination refuses.

Stored in SocTalk DB:

```sql
CREATE TABLE chart_compatibility (
  soctalk_system_version text NOT NULL,
  tenant_chart_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('supported','deprecated','blocked')),
  notes text,
  PRIMARY KEY (soctalk_system_version, tenant_chart_version)
);
```

Populated at build time from a YAML spec in the repo:

```yaml
# compatibility.yaml
- system: v1.0.0
  tenant:
    - version: v1.0.0
      status: supported
- system: v1.0.1
  tenant:
    - version: v1.0.0
      status: supported
    - version: v1.0.1
      status: supported
- system: v1.1.0
  tenant:
    - version: v1.0.0
      status: deprecated
      notes: "v1.0.x agents still work but upgrade recommended for FQDN egress changes"
    - version: v1.0.1
      status: supported
    - version: v1.1.0
      status: supported
```

Enforcement: SocTalk controller refuses `helm upgrade` with a blocked combo; warns on deprecated but allows; proceeds on supported.

## 5 Version pinning policy

### 5.1 SocTalk-authored images

Pinned by digest in `soctalk-tenant/values.yaml`:
```yaml
adapter:
  image:
    repository: ghcr.io/gbrigandi/soctalk-adapter
    digest: sha256:abc123...
```

### 5.2 Upstream OSS chart subcharts (Wazuh / TheHive / Cortex)

Vendored under `charts/soctalk-tenant/charts/` as directories, not fetched at install time. `Chart.yaml` lists them as local dependencies:

```yaml
dependencies:
  - name: wazuh
    version: "0.3.2-soctalk-v1"
    repository: "file://./charts/wazuh"
  - name: thehive
    version: "5.2.0-soctalk-v1"
    repository: "file://./charts/thehive"
  - name: cortex
    version: "3.1.8-soctalk-v1"
    repository: "file://./charts/cortex"
```

Vendoring reasons (from chart-audit):
- Apply SocTalk patches without depending on upstream acceptance.
- Stable hash for supply-chain attestation (a future release cosign).
- Reproducible builds.

## 6 Render → apply flow

Controller-side flow when `POST /api/mssp/tenants` arrives:

```
1. Validate payload against tenant config JSON Schema.
2. Generate secrets (secret-placement §5): wazuh-bootstrap pw, thehive admin, cortex admin,
   cassandra pw, wazuh authd secret.
3. Write K8s Secrets in soctalk-system (per-tenant LLM, integration creds).
4. Write K8s Secrets in (to-be-created) tenant-<slug>: deferred until ns exists,
   deferred until step 6.
5. Insert Tenant row + TenantSecret references (state=pending).
6. Use SocTalk K8s ServiceAccount:
   a. Create Namespace tenant-<slug> with required labels.
   b. Create per-ns bootstrap Secrets (wazuh-bootstrap, thehive admin, etc.).
   c. helm install soctalk-tenant -n tenant-<slug> --values <rendered-values.yaml>
7. Transition state to provisioning.
8. Wait for all Helm-managed resources to be Ready (timeout 15 min pilot-prod, 30 min small-dev).
9. On adapter heartbeat arriving, transition state to active.
10. Emit TenantLifecycleEvent.
```

On failure at any step:
- Idempotent retry: the controller remembers which step completed (via `TenantLifecycleEvent`).
- If `helm install` fails, rollback via `helm uninstall` + `kubectl delete ns`.
- Tenant state remains `pending` with error details; MSSP operator can retry from UI.

On `POST /api/mssp/tenants/:id:upgrade` (a future release API; runbook):
```
1. Check compatibility matrix.
2. helm upgrade soctalk-tenant -n tenant-<slug> --values <new-values.yaml>
3. Wait for rollout; on failure, helm rollback.
4. Emit TenantLifecycleEvent.
```

On `POST /api/mssp/tenants/:id:decommission`:
```
1. Mark tenant decommissioning; grace period starts.
2. Document how to retrieve tenant data before teardown (backup/restore runbook).
3. After grace period: helm uninstall, kubectl delete ns.
4. Soft-delete Tenant row with deleted_at timestamp.
5. Retention window: keep row in DB for compliance period.
6. Hard delete after retention.
```

## 7 Chart publishing

### 7.1 Distribution

- **(minimal)**: push as OCI artifacts to `ghcr.io/gbrigandi/charts/soctalk-system` and `/charts/soctalk-tenant`: Public, unauthenticated pulls.
- **a future release**: cosign-signed + SBOM attached.

Install guide uses:
```bash
helm install soctalk-system oci://ghcr.io/gbrigandi/charts/soctalk-system \
    --version v1.0.0 \
    --namespace soctalk-system --create-namespace \
    -f values.yaml
```

### 7.2 Versioning cadence

- `soctalk-system` version bumps on any API change, schema change, or feature addition.
- `soctalk-tenant` version bumps on any data plane subchart upgrade or tenant template change.
- Compatibility matrix entry added for every new combination; release notes document supported ranges.

## 8 Testing the contract

A later release and tests:

1. **values.schema.json validation**: `helm lint` + `helm template` with sample values: both charts.
2. **Round-trip render**: SocTalk renders a tenant config → values → apply → read back from K8s → compare. Assert no drift.
3. **Subchart pinning**: `Chart.lock` + digests match expectations; CI fails on drift.
4. **Compatibility matrix enforcement**: unit test for `controller.can_upgrade(system=X, tenant=Y)` across supported / deprecated / blocked combos.
5. **Bundle signing smoke test (a future release)**: `cosign verify` on published chart.

## 9 Gate criteria

- [x] This document merged as reference.
- [ ] `charts/soctalk-system/Chart.yaml` and `values.schema.json` exist in repo with the shape from §2.
- [ ] `charts/soctalk-tenant/Chart.yaml` and `values.schema.json` exist with §3 shape.
- [ ] `compatibility.yaml` exists at repo root with initial `v1.0.0 ↔ v1.0.0` entry.
- [ ] implements §6 flow in SocTalk controller.
- [ ] Publishing charts to GHCR as OCI artifacts.
