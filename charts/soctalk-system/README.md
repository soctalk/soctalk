# soctalk-system

**Status: V1 alpha.** Templates cover the MVP control plane. See `docs/multi-tenant/` for context.

## Purpose

Installs SocTalk itself: the MSSP-deployed control plane. One install per MSSP K3s cluster; serves all end-customers belonging to that MSSP.

Contains:

- SocTalk API (FastAPI)
- MSSP UI (SvelteKit)
- Customer UI (SvelteKit)
- Orchestrator (LangGraph + MCP subprocesses)
- Postgres (in-chart StatefulSet; externalizable)
- SocTalk controller ServiceAccount with cluster-scoped namespace verbs (for managing `tenant-*` namespaces)
- ValidatingAdmissionPolicy guard for SocTalk-managed tenant namespaces

Does **not** install:

- The per-customer SOC stacks: those come from `soctalk-tenant`, installed by SocTalk controller.
- CNI, cert-manager, ingress controller, StorageClass: cluster prerequisites installed separately.

## Cluster prerequisites

Must exist in the cluster **before** `helm install soctalk-system`:

1. **Kubernetes 1.30+** (K3s or equivalent) for the default `ValidatingAdmissionPolicy` guard.
2. **NetworkPolicy-enforcing CNI**: Cilium is the supported primary path (see `docs/multi-tenant/cni-networkpolicy.md`). Calico is a documented alternate.
3. **cert-manager** with a `ClusterIssuer` resolvable for TLS (Let's Encrypt / internal CA / self-signed for dev).
4. **Ingress controller**: Traefik (K3s default) or ingress-nginx.
5. **Dynamic StorageClass**: local-path, Longhorn, cloud-provider CSI, etc. PVCs will use default if `postgres.storage.storageClassName` is empty.

For local development, `scripts/dev-up.sh` at repo root brings up a `k3d` cluster with Cilium and cert-manager pre-installed.

## Install

```bash
helm install soctalk-system oci://ghcr.io/soctalk/charts/soctalk-system \
    --version 0.1.0 \
    --namespace soctalk-system --create-namespace \
    -f values.yaml
```

Required values (see `values.schema.json`):

- `install.msspId` (UUID)
- `install.msspName` (string)
- `install.installId` (UUID)
- `ingress.hostnames.mssp` (MSSP UI hostname)
- `ingress.hostnames.customer` (customer UI hostname, may be wildcard like `*.customers.example.com`)

## Upgrade

```bash
helm upgrade soctalk-system oci://ghcr.io/soctalk/charts/soctalk-system \
    --version 0.2.0 \
    --namespace soctalk-system \
    -f values.yaml
```

SocTalk's Alembic migrations run automatically on first API pod startup post-upgrade. Migrations are forward-only; rollback is via `helm rollback` plus Postgres restore if migrations introduced breaking data changes.

## Uninstall

```bash
helm uninstall soctalk-system --namespace soctalk-system
kubectl delete namespace soctalk-system
```

**Warning**: uninstalling destroys SocTalk's Postgres (including all tenant metadata). **Backup first.** V1 backup is manual (see `docs/multi-tenant/secret-placement.md` §6 and forthcoming install guide). `tenant-*` namespaces persist and must be cleaned separately via the SocTalk UI *before* uninstalling, or manually via `kubectl delete namespace tenant-*`.

## Files

```
charts/soctalk-system/
├── Chart.yaml
├── values.yaml
├── values.schema.json
├── README.md            (this file)
└── templates/
    └── .gitkeep
```
