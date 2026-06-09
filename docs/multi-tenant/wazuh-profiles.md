# wazuh-profiles: per-tenant Wazuh deployment profiles

Every tenant is onboarded under one **profile** that fixes how (and whether)
SocTalk deploys Wazuh for it. `render_tenant_values()` branches on the profile
to produce the tenant chart values; `_profile_tenant_overrides()` layers the
per-profile resource quota. This document is the canonical enumeration the
`render.py` module docstring points at.

There are three first-class profiles — `poc`, `persistent`, `provided` — plus
`legacy` (tenants provisioned before profiles existed; the controller refuses to
re-render them and leaves their install-time topology untouched).

## Profiles

- **`poc`** — ephemeral / cheapest viable. Single-node, node-local storage, no
  durable PVCs to speak of, tight resource quotas. Intended for demo tenants.
  SocTalk deploys the full in-cluster Wazuh stack.
- **`persistent`** — single-node but **durable**. PVC-backed indexer and
  manager survive pod/node restarts. No HA (deferred). SocTalk deploys the full
  in-cluster Wazuh stack.
- **`provided`** — **bring-your-own** Wazuh. The customer operates Wazuh
  externally; SocTalk deploys **no** in-cluster Wazuh/TheHive/Cortex and points
  the adapter at the external indexer. See
  [provided-profile.md](provided-profile.md) for the full contract.

## Comparison

| Dimension | `poc` | `persistent` | `provided` |
|---|---|---|---|
| **Wazuh deploy** | In-cluster, single-node, node-local storage | In-cluster, single-node, PVC-backed (durable) | **None** — customer's external (BYO) Wazuh |
| **Indexer URL source** | Derived in-cluster Service DNS (`https://wazuh-<slug>-wazuh-indexer:9200`) | Derived in-cluster Service DNS | `IntegrationConfig.wazuh_indexer_url` (external) |
| **API URL source** | In-cluster manager Service (`wazuh-<slug>-wazuh-manager:55000`) | In-cluster manager Service | `IntegrationConfig.wazuh_api_url` (external) |
| **Agent ingress** | Per-tenant hostname + TLS (agents enroll in-cluster) | Per-tenant hostname + TLS | **None** — agents report to the external manager |
| **Resource quota** | req 2 CPU / 4Gi, lim 4 CPU / 8Gi, 20 pods, 4 PVC | req 2 CPU / 6Gi, lim 5 CPU / 12Gi, 30 pods, 6 PVC | req 1 CPU / 2Gi, lim 2 CPU / 4Gi, 10 pods, 2 PVC (adapter + runs-worker only) |
| **Indexer credentials Secret** | Chart-minted `wazuh-<slug>-wazuh-creds` | Chart-minted `wazuh-<slug>-wazuh-creds` | Controller-written `tenant-external-siem-creds` |
| **Decommission steps** | `helm uninstall` the `wazuh-<slug>` release **and** the `soctalk-tenant` release, then `kubectl delete ns tenant-<slug>` | Same as `poc`; PVCs are reclaimed per the StorageClass policy | `helm uninstall` only the `soctalk-tenant` release (no `wazuh-<slug>` release ever existed — a helm `release: not found` is treated as success), then `kubectl delete ns tenant-<slug>`; the external Wazuh is **untouched** |

## Notes

- The credential **key names** are identical across profiles
  (`INDEXER_USERNAME` / `INDEXER_PASSWORD` for the adapter,
  `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD` / `WAZUH_API_TOKEN` for the chat
  resolver), so only the Secret *name* and the URL *source* change between
  in-cluster and external. See [secret-placement.md](secret-placement.md) §2.
- TLS verification (`IntegrationConfig.wazuh_verify_ssl` →
  `adapter.wazuhIndexer.verifySsl` → `WAZUH_INDEXER_VERIFY_SSL`) is rendered for
  **all** profiles so a self-signed indexer (common for external Wazuh) can set
  `verify=false`.
- Sizing references for `poc` / `persistent` footprints live in
  [sizing.md](sizing.md); the `provided` quota is a fraction because no Wazuh,
  TheHive, or Cortex pods run in-namespace.
- Profile is set at onboarding and is fixed for the tenant's lifetime; changing
  it is a re-provision, not a runtime toggle. `legacy` tenants are never
  re-rendered on the MVP path.
