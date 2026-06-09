# provided-profile: the `provided` (bring-your-own Wazuh) tenant profile

The `provided` profile is the third onboarding shape, alongside `poc` and
`persistent` (see [wazuh-profiles.md](wazuh-profiles.md)). A `provided` tenant
brings their **own, externally-operated** Wazuh stack; SocTalk deploys **no**
in-cluster Wazuh / TheHive / Cortex for them. SocTalk's tenant namespace runs
only the alert **adapter** and the **runs-worker**, and the adapter is pointed
at the customer's external indexer.

This document is the operator contract for `provided`: when to pick it, what
lands in the cluster, the credential model, the credential lifecycle, the
network prerequisites, and the failure modes you will see.

## 1 When to choose `provided`

Choose `provided` when **the customer already runs Wazuh** (on-prem, in their
own cloud, or via a third party) and wants SocTalk to analyze the alerts that
SIEM already produces — not to stand up a second, SocTalk-managed Wazuh.

Pick `provided` when:

- The customer has an established Wazuh manager + indexer (OpenSearch) and a
  fleet of agents already enrolled against **their** manager.
- You must not duplicate ingestion, storage, or agent enrollment in the
  SocTalk cluster.
- You want the smallest per-tenant footprint (no Wazuh/TheHive/Cortex pods,
  no agent ingress, no per-tenant indexer PVCs).

Prefer `poc` or `persistent` instead when SocTalk should own the Wazuh stack
(demo tenants, or customers with no existing SIEM). The profile is fixed at
onboarding; switching profiles is a re-provision, not a toggle.

## 2 What SocTalk deploys (and what it does not)

For a `provided` tenant the tenant chart forces the in-cluster SOC components
**off** (`components.wazuh/thehive/cortex.enabled = false`) regardless of any
stale integration flag, and drops the Wazuh agent ingress. Only the adapter and
the runs-worker are deployed into `tenant-<slug>`.

| Resource in `tenant-<slug>` | `poc` / `persistent` | `provided` |
|---|---|---|
| Wazuh manager + indexer + dashboard | Deployed (in-cluster) | **Not deployed** — customer's external Wazuh |
| TheHive / Cortex | Deployed (when enabled) | **Not deployed** |
| Wazuh agent ingress (per-tenant hostname + TLS) | Deployed | **Not deployed** — agents report to the external manager |
| Wazuh bootstrap Secret (`tenant-bootstrap`) | Generated at provisioning | **Not generated** (no in-cluster Wazuh to seed) |
| Alert adapter (`soctalk-adapter`) | Deployed → in-cluster indexer Service | Deployed → **external** indexer URL |
| runs-worker | Deployed | Deployed |
| `Secret/tenant-external-siem-creds` | — | **Written by the controller** (both credential pairs) |
| Resource quota | poc 2/4 CPU · 4/8Gi · 20 pods · 4 PVC; persistent 2/5 CPU · 6/12Gi · 30 pods · 6 PVC | adapter+worker only: **1/2 CPU · 2/4Gi · 10 pods · 2 PVC** |

Indexer connection details for the adapter (`adapter.wazuhIndexer`) come from
`IntegrationConfig.wazuh_indexer_url` and the `tenant-external-siem-creds`
Secret; TLS verification flows from `IntegrationConfig.wazuh_verify_ssl` into the
adapter's `WAZUH_INDEXER_VERIFY_SSL` env var (allowing `verify=false` for a
self-signed external indexer).

## 3 Dual credential model

An external Wazuh exposes **two** independently-authenticated endpoints, so a
`provided` tenant carries **two HTTP-Basic credential pairs** plus one optional
token. All three live together in a single `Secret/tenant-external-siem-creds`
that mirrors the 4-key layout of the in-cluster `<release>-wazuh-creds` Secret,
so the adapter and chat resolver stay profile-agnostic.

| Endpoint | Default port | Used by | Auth | Secret keys |
|---|---|---|---|---|
| Indexer (OpenSearch) | `:9200` | Tenant **adapter** alert ingest | HTTP-Basic | `INDEXER_USERNAME` / `INDEXER_PASSWORD` |
| Manager API | `:55000` | L1 **chat resolver** | HTTP-Basic → mints a short-lived JWT, **or** a pre-minted Bearer token | `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD`, optional `WAZUH_API_TOKEN` |

- The **indexer** pair is HTTP-Basic against OpenSearch; the adapter uses it to
  pull alerts.
- The **API** pair is HTTP-Basic against the Wazuh manager. The chat resolver
  uses it to `POST /security/user/authenticate` and mint a short-lived JWT.
- `WAZUH_API_TOKEN` is **optional**: when present it is used directly as the
  Bearer token (token precedence), skipping the username/password mint. Its
  absence is always valid — the key is omitted from the Secret entirely when the
  column is null, so no empty env var materializes.

The two pairs are deliberately distinct: rotating indexer credentials need not
touch manager-API credentials and vice-versa.

## 4 Credential lifecycle

Credentials enter and move through the system in one direction:
onboard → `tenant-external-siem-creds` Secret materialization → PATCH endpoint →
adapter restart.

1. **Onboard.** `POST /api/mssp/tenants/onboard` with `profile: "provided"` and
   a nested `external_siem` block (`indexer_url`, `indexer_username`,
   `indexer_password`, `api_url`, `api_username`, `api_password`, optional
   `api_token`, `verify_ssl`). Missing required fields are rejected **422**
   server-side with field-level errors and **no** Tenant row is created
   (`api_token` / `verify_ssl` never trigger 422). The values persist onto the
   tenant's `IntegrationConfig` in the same transaction as the Tenant row:
   `indexer_*` → `wazuh_indexer_*`, `api_username/api_password/api_url` →
   `wazuh_username` / `wazuh_password_plain` / `wazuh_api_url`, `api_token` →
   `wazuh_api_token_plain`, `verify_ssl` → `wazuh_verify_ssl`.
2. **Secret materialization.** During provisioning the controller's
   `_step_write_external_siem_secret` writes `Secret/tenant-external-siem-creds`
   in `tenant-<slug>` from those columns, keyed `INDEXER_USERNAME`,
   `INDEXER_PASSWORD`, `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`, and
   `WAZUH_API_TOKEN` (token key only when set). The step is idempotent
   (create-or-patch) and runs **before** the tenant chart's adapter pod starts.
   No `tenant-bootstrap` Secret is minted, and `_step_write_integration_config`
   is a no-op so the external `wazuh_url` / `wazuh_indexer_url` are never
   clobbered with in-cluster Service URLs.
3. **Rotation via the PATCH endpoint.** `PATCH /api/mssp/tenants/{id}/external-siem`
   (profile-agnostic, all-optional fields; only non-null fields are written)
   updates the `IntegrationConfig` SIEM columns. **Postgres is committed first**
   (the dual-write mirrors `llm_config.update_tenant_llm`), then the endpoint
   rewrites `tenant-external-siem-creds` from the re-read row. A matching
   `GET /api/mssp/tenants/{id}/external-siem` returns a masked shape
   (`has_indexer_password`, `has_api_password`, `has_api_token` booleans);
   plaintext passwords/token are never returned.
4. **Adapter restart.** `secretKeyRef` env vars do **not** refresh on a Secret
   update, so after rewriting the Secret the endpoint patches the
   `soctalk-adapter` Deployment's pod-template annotation
   `soctalk.io/restartedAt`, which rolls the adapter pod onto the new indexer
   credentials. The chat resolver reads the API credentials **live per request**
   and needs no restart. The K8s side effects (Secret write + adapter restart)
   are best-effort: failures are logged via structlog and do **not** roll back
   the committed Postgres update.

## 5 Connectivity prerequisites

Because the SIEM is outside the cluster, **two** egress paths must be open:

1. **Tenant adapter → external indexer (FQDN egress).** The tenant adapter pod
   must reach the external indexer (`:9200`) and is constrained by a Cilium
   `CiliumNetworkPolicy` (`adapter-fqdn-egress`) FQDN allow-list. `render.py`
   populates `networkPolicies.externalSiemHosts` with the deduped hostnames
   parsed from `wazuh_indexer_url` **and** `wazuh_api_url`, and forces
   `networkPolicies.fqdnEgress.enabled = true`, so the rendered policy lists both
   the L1 control-plane host and every external SIEM host under `toFQDNs`. If a
   host is missing from the allow-list the adapter's egress is dropped.
2. **Control-plane egress → external manager (for chat).** The L1 chat resolver
   runs in `soctalk-system` and connects to the external manager API (`wazuh_api_url`,
   `:55000`). `charts/soctalk-system` must permit the API/controller pod to reach
   that manager host (a `CiliumNetworkPolicy` or equivalent). When the
   `soctalk-system` egress is unrestricted (e.g. a local dev profile with Cilium
   disabled) this is a documented no-op.

DNS for both external hostnames must resolve from inside the cluster, and the
external Wazuh's firewall must admit the cluster's egress IPs.

## 6 Failure modes

Two failure classes dominate `provided`, both surfaced to the operator through
the tenant detail page's **External SIEM** panel (which polls
`GET /api/mssp/tenants/{id}/adapter-status`) and the tenant lifecycle events.

| Symptom | Likely cause | How the operator surfaces / fixes it |
|---|---|---|
| **Authentication failure** | Wrong/expired indexer or API credentials; rotated on the customer side; `WAZUH_API_TOKEN` expired | Adapter ingest returns 401/403 → `adapter-status.last_ingest_error` shows the auth error; the chat resolver surfaces `external Wazuh API not configured` (a typed `ExternalSiemNotConfigured`, never an unhandled 500). Fix by `PATCH /api/mssp/tenants/{id}/external-siem` with fresh creds (which rolls the adapter). |
| **Network unreachable** | FQDN egress allow-list missing the host; external Wazuh down; DNS or firewall blocking; wrong URL/port | Adapter / resolver connection times out → `adapter-status` returns `{"reachable": false, "error": "<msg>"}`. Fix by confirming `externalSiemHosts` covers both URLs, the `soctalk-system` egress reaches `:55000`, DNS resolves, and the external Wazuh is up. |
| **TLS verification failure** | Self-signed external indexer/manager cert with verification on | Connection fails on cert validation. Set `verify_ssl = false` (→ `WAZUH_INDEXER_VERIFY_SSL=false` and resolver `verify=false`) via onboard or the PATCH endpoint when the external cert is self-signed. |

The credentials themselves never appear in logs or API responses; only presence
booleans and masked URLs/usernames are returned. See
[secret-placement.md](secret-placement.md) §2 for the Secret inventory row.
