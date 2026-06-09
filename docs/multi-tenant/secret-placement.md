# secret-placement: Secret Placement Policy

Gate artifact: Defines where every secret lives, who can read it, how it's rotated, and why raw material never appears in Postgres. Complements security-model §9.

## 1 Invariant

**No raw secret material in the SocTalk database.** Postgres tables that track secrets store references only: `(namespace, name, version_label)`. The material itself is always in a Kubernetes `Secret` object, mounted into the pod that needs it. This:

- Limits blast radius of a SocTalk DB compromise (no material leaks).
- Lets K8s-native rotation mechanisms work (Secret update → pod picks up new value on remount or on next Secret read).
- Aligns with External Secrets Operator integration path in a future release.

## 2 Secret inventory

| Secret | Material | Location | Accessed by | Rotation | Notes |
|---|---|---|---|---|---|
| Postgres credentials (admin) | user/pw | `Secret/soctalk-postgres-admin-creds` in `soctalk-system` | Alembic Job only | Manual; runbook in a future release | Not mounted to long-running pods |
| Postgres credentials (app) | user/pw | `Secret/soctalk-postgres-app-creds` in `soctalk-system` | SocTalk API + orchestrator pods | Manual | |
| Postgres credentials (mssp) | user/pw | `Secret/soctalk-postgres-mssp-creds` in `soctalk-system` | SocTalk API pod only | Manual | Used only inside `system_context()` |
| User JWT signing key | HMAC secret or RSA/Ed25519 private key | `Secret/soctalk-jwt-signing-key` in `soctalk-system` | SocTalk API pod | Manual; automated in a future release | HMAC for MVP simplicity; asymmetric when multi-pod |
| Adapter token signing key | HMAC key | `Secret/soctalk-adapter-signing-key` in `soctalk-system` | SocTalk API + controller pod only | Manual; automated in a future release | Never mounted into tenant namespaces |
| Tenant adapter bearer token | bearer token | `Secret/adapter-token` in `tenant-<slug>` | Tenant adapter pod | Minted on tenant provisioning; rotated by controller | Tenant-bound; cannot mint other tokens |
| Per-tenant LLM API key | bearer token | `Secret/tenant-<id>-llm` in `soctalk-system` | Orchestrator pod (projected by tenant context) | MSSP-initiated via tenant config UI → SocTalk rewrites Secret | Never appears in any other tenant's context |
| Per-tenant Wazuh API credentials | user/pw or token | `Secret/tenant-<id>-wazuh` in `soctalk-system` | Orchestrator MCP subprocess (env at spawn time, tenant context) | MSSP-initiated | |
| Per-tenant TheHive API token | token | `Secret/tenant-<id>-thehive` in `soctalk-system` | Orchestrator MCP subprocess | MSSP-initiated | |
| Per-tenant Cortex API key | token | `Secret/tenant-<id>-cortex` in `soctalk-system` | Orchestrator MCP subprocess | MSSP-initiated | |
| Wazuh manager admin password (per tenant) | password | `Secret/wazuh-bootstrap` in `tenant-<slug>` | Wazuh Deployment pods in that namespace | Runbook; automated in a future release | Generated at tenant provisioning time |
| TheHive admin credentials (per tenant) | user/pw | `Secret/thehive-bootstrap` in `tenant-<slug>` | TheHive Deployment pods | Runbook | |
| Cortex admin credentials (per tenant) | user/pw | `Secret/cortex-bootstrap` in `tenant-<slug>` | Cortex Deployment pods | Runbook | |
| Wazuh inter-service certs (manager↔indexer↔dashboard mTLS) | X.509 | `Secret/wazuh-certs` in `tenant-<slug>` | Wazuh pods in that namespace | Generated once at tenant provisioning; rotation a future release | Often via cert-manager per-tenant Issuer |
| Wazuh agent enrollment secret | shared secret | `Secret/wazuh-authd-secret` in `tenant-<slug>` | Wazuh manager (for enrollment) | Regenerate to force re-enrollment of all agents | Distributed to customer-endpoint admins out-of-band during onboarding |
| External SIEM credentials (per tenant, `provided` profile) | indexer + Wazuh-API HTTP-Basic creds (+ optional pre-minted API token) | `Secret/tenant-external-siem-creds` in `tenant-<slug>` | Tenant **adapter** reads the indexer keys (`INDEXER_USERNAME` / `INDEXER_PASSWORD`); the L1 **chat resolver** reads the API keys (`WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD` / `WAZUH_API_TOKEN`) | `PATCH /api/mssp/tenants/{id}/external-siem` (Postgres-first dual-write → rewrites the Secret → rolling-restarts the adapter) | Five keys: `INDEXER_USERNAME`, `INDEXER_PASSWORD`, `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`, `WAZUH_API_TOKEN` (token only when set). Written at onboard by the controller's `_step_write_external_siem_secret`; see [provided-profile.md](provided-profile.md) |
| Cassandra credentials (TheHive-embedded) | user/pw | `Secret/cassandra-creds` in `tenant-<slug>` | Cassandra StatefulSet + TheHive | Runbook | |
| License material (a future release) | signed JWT | `Secret/soctalk-license` in `soctalk-system` | SocTalk API pod | Issued by Cloud; drop into Secret manually | Single file; `kubectl patch secret` for refresh |

## 3 Cross-namespace mounting: not done

SocTalk orchestrator runs in `soctalk-system` and needs per-tenant LLM keys. Options considered:

1. **Store per-tenant keys in `tenant-<slug>` ns and mount cross-namespace**. K8s doesn't support cross-namespace Secret references in volume mounts. Workarounds exist (CSI driver, external-secrets) but add complexity.
2. **Store per-tenant keys in `soctalk-system` ns**: straightforward; orchestrator lives here. Naming convention (`tenant-<id>-llm`) keeps them separated. **Chosen**.

The alternative (per-tenant ns for each tenant's LLM key) is re-evaluated in a future release with External Secrets Operator, where ESO can sync external-vault-stored secrets into whichever namespace needs them.

## 4 Data plane bootstrap secrets

Wazuh/TheHive/Cortex admin credentials live in their respective tenant namespaces because:

- These pods need them at startup (init containers, first-run setup).
- Cross-ns mounting complications as above.
- Blast radius of namespace compromise already exposes the pods themselves; putting the bootstrap secret in the same namespace doesn't add risk.

Bootstrap secrets are generated by the SocTalk controller at tenant-provisioning time:
1. Controller generates random values (e.g., `openssl rand -hex 32`).
2. Controller creates `Secret` in target `tenant-<slug>` ns.
3. Controller records the reference `(tenant-<slug>, wazuh-bootstrap, v1)` in `TenantSecret` table.
4. Controller renders tenant chart values referencing the Secret by name.
5. `helm install` proceeds; data plane pods read creds at startup.

If the material is lost (e.g., Secret deleted), re-provisioning regenerates new credentials. Data plane pods restart; any dependent services reinitialize. Customer-endpoint agents (which rely on the Wazuh enrollment secret) need re-enrollment if that specific secret rotates: documented in the ops runbook.

## 5 Secret generation conventions

At tenant-provisioning time, SocTalk controller generates:

```python
import secrets

# Administrative passwords: 32-char high-entropy
wazuh_admin_pw = secrets.token_urlsafe(32)
thehive_admin_pw = secrets.token_urlsafe(32)
cortex_admin_pw = secrets.token_urlsafe(32)

# Enrollment shared secret: 48-char
wazuh_authd = secrets.token_urlsafe(48)

# API tokens (for SocTalk → data plane): 48-char
thehive_api_token = secrets.token_urlsafe(48)
cortex_api_key = secrets.token_urlsafe(48)

# Cassandra: 32-char
cassandra_pw = secrets.token_urlsafe(32)
```

SocTalk stores references and version labels; it does not keep the material in memory beyond the provisioning call.

## 6 Rotation (runbook; a future release automation)

For, rotation is a runbook operation:

1. **Per-tenant LLM key rotation** (MSSP initiates via tenant config UI):
   - MSSP admin updates tenant's LLM config with new key.
   - SocTalk controller `kubectl patch secret tenant-<id>-llm ...` in `soctalk-system`.
   - Orchestrator pod picks up change on next worker context build (reads Secret freshly per job).
   - No pod restart.

2. **Wazuh / TheHive / Cortex admin credential rotation** (runbook):
   - Operator runs SocTalk CLI (deliverable): `soctalk-cli rotate-admin --tenant=acme --service=wazuh`.
   - CLI generates new credential, `kubectl patch secret wazuh-bootstrap ...`, restarts Wazuh pods.
   - Brief service interruption per tenant.

3. **Postgres credentials rotation** (runbook, a future release automation):
   - Generate new pw; `ALTER ROLE soctalk_app WITH PASSWORD ...` in Postgres.
   - `kubectl patch secret soctalk-postgres-app-creds ...`.
   - Rolling restart of SocTalk API + orchestrator pods.

4. **JWT signing key rotation** (a future release): zero-downtime rotation requires supporting two valid keys during transition. This release defers this; manual rotation forces a window where all users re-auth.

## 7 Access control

Kubernetes RBAC restricts which ServiceAccounts can read which Secrets:

- `soctalk-api-sa` in `soctalk-system`: can read all Secrets in `soctalk-system` (Postgres creds, JWT keys, all per-tenant LLM and integration secrets, license when a future release).
- `soctalk-controller-sa` in `soctalk-system`: can read/write Secrets in `soctalk-system` and in `tenant-*` namespaces (needed to create/rotate tenant bootstrap secrets).
- `soctalk-orchestrator-sa` in `soctalk-system`: can read per-tenant LLM and integration Secrets in `soctalk-system` only.
- Per-tenant `ServiceAccount` in `tenant-<slug>`: can read only secrets in its own namespace. It can read its own `adapter-token` but never the system signing key.

`Role`/`RoleBinding` templates are part of `soctalk-system` chart (for SocTalk SAs) and `soctalk-tenant` chart (for per-tenant SAs).

## 8 Anti-patterns explicitly rejected

- **Env-var secret injection from `.env` file** (current V0 pattern): fine for single-org, not for multi-tenant. All secrets move to K8s Secrets.
- **Secrets in Helm values.yaml**: never: values files end up in Git, CI logs, Helm history. SocTalk controller renders Secret objects separately and uses `valueFrom.secretKeyRef` in templates.
- **Single shared LLM key for all tenants**: explicitly out-of-scope for BYO LLM. Per-tenant keys always.
- **Secrets in ConfigMaps**: prohibited. ConfigMaps are for non-sensitive config; Secrets for sensitive.

## 9 External Secrets Operator (a future release path)

a future release introduces External Secrets Operator integration:

- MSSP provides a secret backend (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
- `ExternalSecret` resources reference backend paths; ESO syncs to K8s Secrets.
- Per-tenant LLM keys stored in backend with paths like `secret/mssp-abc/tenants/acme/llm`.
- Rotation done in backend; ESO propagates within refresh interval.

The structure (refs in Postgres → K8s Secret → mount) is compatible: only the Secret source changes (ESO-managed vs SocTalk-controller-written).

## 10 Gate criteria

- [x] This document merged as reference.
- [ ] tenant provisioning logic implements secret generation per §5 and writes references to `TenantSecret` table.
- [ ] Helm charts use `valueFrom.secretKeyRef` for all credential injection, never hardcoded values.
- [ ] chart templates include `Role`/`RoleBinding` per §7.
- [ ] runbook covers rotation per §6.
