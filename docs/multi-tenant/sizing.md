# sizing: Sizing Profile for Pilot Installs

Gate artifact: Reference hardware profiles, per-tenant footprint estimates, and guidance on max tenants per node. Numbers are estimates pending design spike measurement on `k3d` + representative workload.

## 1 Reference profiles

Two reference host sizes for this release.

### 1.1 small-dev

Intended for: development, demos, single-tenant POC.

| Resource | Value |
|---|---|
| CPU | 4 vCPU |
| RAM | 16 GB |
| Disk | 100 GB SSD |
| Max tenants | **1–2** |
| SocTalk control plane reserved | ~2 GB RAM, 1 vCPU |
| Per-tenant budget | ~6–8 GB RAM, 1–1.5 vCPU |

Boot times are slower here; `<30 min to OSS stack healthy` SLO applies.

### 1.2 pilot-prod

Intended for: MSSP running real pilot customers, 3–5 tenants.

| Resource | Value |
|---|---|
| CPU | 8 vCPU |
| RAM | 32 GB |
| Disk | 500 GB SSD |
| Max tenants | **3–5** |
| SocTalk control plane reserved | ~3 GB RAM, 1–2 vCPU |
| Per-tenant budget | ~5–7 GB RAM, 1–1.5 vCPU |

Boot times on the `<15 min to OSS stack healthy` SLO.

## 2 Per-tenant footprint (estimates)

These are starting-point values for `ResourceQuota` and `LimitRange` in the tenant chart. design spike measures actuals; actuals replace these in the final values.

| Component | RAM request | RAM limit | CPU request | CPU limit | Disk (PVC) |
|---|---|---|---|---|---|
| Wazuh manager | 512 MB | 1 GB | 200 m | 500 m | 20 GB |
| Wazuh indexer (OpenSearch fork) | 2 GB (heap 1 GB) | 4 GB (heap 2 GB) | 500 m | 2000 m | 50 GB |
| Wazuh dashboard | 512 MB | 1 GB | 100 m | 500 m | |
| Filebeat | 128 MB | 256 MB | 50 m | 200 m | |
| TheHive | 1 GB | 2 GB | 300 m | 1000 m | |
| Cassandra (TheHive backing) | 2 GB | 4 GB | 500 m | 1500 m | 30 GB |
| Cortex | 768 MB | 1.5 GB | 200 m | 800 m | |
| Cortex ElasticSearch | 1 GB | 2 GB | 300 m | 1000 m | 20 GB |
| SocTalk adapter | 128 MB | 256 MB | 50 m | 200 m | |
| **Per-tenant total (limits)** | **~8 GB request, ~16 GB limit** | | **~2.2 vCPU request, ~7.7 vCPU limit** | | **~120 GB** |

Note: limits are burst ceilings; sustained usage is closer to requests. Running 3 tenants on an 8-vCPU / 32 GB / 500 GB host means:
- RAM: ~24 GB of requests (fits), ~48 GB of limits (requires careful overcommit tuning).
- CPU: ~6.6 vCPU of requests (fits with control plane), bursts share total.
- Disk: ~360 GB of tenant PVCs (fits with margin for control plane + SocTalk DB).

This is why `pilot-prod` caps at 5 tenants; beyond 5, memory limits start bumping into node capacity even accounting for overcommit.

## 3 Max-tenants-per-node formula

Approximation:

```
max_tenants = floor((node_total_RAM - control_plane_RAM - safety_margin) / per_tenant_RAM_request)
```

- `control_plane_RAM`: 2 GB (small-dev) or 3 GB (pilot-prod) for SocTalk + Postgres + ingress controller + Cilium + cert-manager.
- `safety_margin`: 10% of node RAM for K8s system pods, CNI, DNS, monitoring.
- `per_tenant_RAM_request`: 8 GB baseline.

For 32 GB pilot-prod: `floor((32 - 3 - 3.2) / 8) = floor(25.8 / 8) = 3` guaranteed tenants without overcommit. With overcommit, 4–5 is safe for typical alert volumes.

## 4 Disk sizing drivers

The dominant disk consumer is the Wazuh indexer (stores indexed events). Ingest rate determines growth:

| Alert rate | Daily index size (rough) | Retention 30 days | Retention 90 days |
|---|---|---|---|
| 10 alerts/sec sustained | ~5 GB/day | 150 GB | 450 GB |
| 1 alert/sec sustained | ~500 MB/day | 15 GB | 45 GB |
| 100 alerts/day | ~10 MB/day | 300 MB | 900 MB |

Tenant PVC sizes in the chart default to **50 GB** for the Wazuh indexer; MSSPs override per-tenant for high-volume customers.

Retention policy defaults to 30 days of hot data in indexer; older data is deleted or archived (doesn't implement hot→cold tiering; a future release adds it).

## 5 Sizing gates

### 5.1 Pre-provisioning check

When MSSP operator creates a new tenant, SocTalk controller runs a sanity check:

```
available_RAM = node.allocatable.memory - sum(ns.resourceQuota.requests.memory for ns in existing_tenant_namespaces) - control_plane_reserve
if (new_tenant.resourceQuota.requests.memory > available_RAM):
    refuse with "insufficient cluster capacity for new tenant"
    or
    prompt MSSP: "this will overcommit; proceed? [y/N]"
```

This gate is softer in this release (warn rather than hard-fail) since MSSPs may intentionally overcommit for light-use customers.

### 5.2 Per-tenant LimitRange enforcement

Every tenant namespace has a `LimitRange`:

```yaml
apiVersion: v1
kind: LimitRange
metadata: { name: tenant-limits, namespace: tenant-acme }
spec:
  limits:
    - type: Container
      default:
        memory: "2Gi"
        cpu: "500m"
      defaultRequest:
        memory: "256Mi"
        cpu: "100m"
      max:
        memory: "6Gi"
        cpu: "2"
```

Prevents an accidentally-misconfigured pod from requesting 30 GB and starving the node.

## 6 Profiles beyond

Documented but not validated in this release:

| Profile | CPU | RAM | Disk | Max tenants |
|---|---|---|---|---|
| **mid-host** | 16 vCPU | 64 GB | 1 TB | 10–15 |
| **large-host** | 32 vCPU | 128 GB | 2 TB | 25–30 |
| **multi-node cluster** | 3 nodes × large | | - | 50+ (a future release multi-install recommended instead) |

Recommendation for MSSPs growing past `pilot-prod` capacity:
- : add a second host, run a second SocTalk install (schema supports this, tooling is manual).
- a future release: multi-install automation in Cloud layer.
- a future release: clustered K3s with proper scheduling across nodes.

## 7 Measurement plan (design spike)

The spike produces real numbers to replace the estimates in §2:

1. Deploy `soctalk-tenant` with one tenant on `k3d` (dev-harness).
2. Idle measurement: take `kubectl top pod -n tenant-acme` snapshot.
3. Load test: inject 10 alerts/sec for 10 minutes; measure peak.
4. Stop load; measure ~5 minutes later for "warm-idle" numbers.
5. Repeat with three tenants in parallel to observe interference.
6. Update this document's tables with measured values.

## 8 Gate criteria

- [x] This document merged as reference.
- [ ] design spike measures real per-tenant footprint; replaces estimates.
- [ ] tenant chart defaults reflect measured footprint.
- [ ] `soctalk-system` chart pre-install hook verifies node meets small-dev or pilot-prod profile.
- [ ] install guide publishes the pilot-prod profile + measurement methodology for MSSPs to validate their infra.
