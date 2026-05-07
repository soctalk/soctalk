# soctalk-tenant

**Status: V1 alpha.** Upstream Wazuh / TheHive / Cortex subcharts are not yet vendored under `./charts/*`; the chart audit (`docs/v1/P0-2-chart-audit.md`) produces the patched versions.

## Purpose

Installs one per-customer OSS SOC stack in a dedicated namespace. One release per end-customer.

Contains:

- **Wazuh** (manager, indexer, dashboard): SIEM
- **TheHive** (case management, with embedded Cassandra)
- **Cortex** (behavioral analysis, with embedded Elasticsearch)
- **SocTalk adapter** (reports tenant health back to `soctalk-system` API)

Does **not** contain:

- Control plane services: those live in `soctalk-system`.
- MISP: deferred to V1.5.

## How this chart is installed

**Not by human operators.** The SocTalk controller (running in `soctalk-system` namespace) installs this chart per tenant via the Helm SDK. Flow:

1. MSSP operator creates a customer via SocTalk MSSP UI.
2. SocTalk controller generates per-tenant secrets (bootstrap admin creds, `authd` shared secret, TLS certs via cert-manager).
3. Controller creates the tenant's namespace (`tenant-<slug>`) with required labels.
4. Controller renders this chart's values from the tenant's config row in SocTalk DB.
5. Controller runs `helm install soctalk-tenant -n tenant-<slug>` via Helm SDK.
6. Controller waits for all pods Ready; waits for adapter heartbeat.
7. Tenant state transitions to `active`.

Direct `helm install` by a human operator is supported only for break-glass / debugging: bypasses SocTalk's DB, bypasses audit, bypasses license cap (V1.5+). Documented as emergency-only.

See `docs/v1/P0-8-two-chart-contract.md` for full render→apply flow.

## Cluster prerequisites

Same as `soctalk-system`: CNI (Cilium), cert-manager, dynamic StorageClass, ingress controller. `soctalk-tenant` does not install cluster-scoped resources.

Per-tenant TLS issuance (Wazuh agent mTLS) uses a `cert-manager` `Issuer` or `ClusterIssuer`: The issuer is specified at install time via `agentIngress.tls.issuerRef`.

## Subchart dependencies

Listed in `Chart.yaml`; vendored (not fetched at install time) once Phase 0 chart audit is complete:

- `wazuh`: patched upstream Wazuh chart
- `thehive`: patched TheHive chart with embedded Cassandra
- `cortex`: patched Cortex chart with embedded Elasticsearch
- `misp`: deferred V1.5

Patches remove cluster-scoped resources (`ClusterRole`, `CRD`, `ValidatingWebhookConfiguration`), remove `Ingress` / `LoadBalancer` Services (ingress handled by MSSP-edge SNI proxy per `P0-6`), strip `hostPath` volumes, enforce `runAsNonRoot`, pin images to digests.

## Files

```
charts/soctalk-tenant/
├── Chart.yaml
├── values.yaml
├── values.schema.json
├── README.md          (this file)
├── templates/
│   └── .gitkeep
└── charts/            (vendored subcharts; populated by Phase 0 audit)
    └── .gitkeep
```
