# SocTalk Upgrade Guide

This release supports upgrades via `helm upgrade` for both chart classes. Upgrade and
rollback are **runbook operations** in this release; an API for fleet-wide upgrade
orchestration lands in a future release.

## Pre-flight checklist

Before any upgrade:

1. **Read the release notes** for the target version. Migrations are
   forward-only; a surprise schema change cannot be reverted with
   `helm rollback`.
2. **Verify compatibility matrix**: MSSP UI → System → Versions shows which
   `soctalk-tenant` versions are supported by the target
   `soctalk-system`. Upgrade `soctalk-system` first, then tenants.
3. **Backup** (is MSSP-managed): snapshot Postgres + all tenant PVCs.
   See the [runbook](../runbook/README.md#database-restore-disaster-recovery).
4. **Dry-run** with `helm diff`:
   ```bash
   helm diff upgrade soctalk-system oci://ghcr.io/gbrigandi/charts/soctalk-system \
     --version <new> -n soctalk-system -f values.yaml
   ```

## Upgrade `soctalk-system` (install-level)

```bash
helm upgrade soctalk-system oci://ghcr.io/gbrigandi/charts/soctalk-system \
  --version <new-version> \
  --namespace soctalk-system \
  -f soctalk-system-values.yaml \
  --wait --timeout 10m
```

Alembic migrations run on API pod startup. Monitor:

```bash
kubectl -n soctalk-system logs deploy/soctalk-system-api -f | grep -i alembic
```

### Rollback

```bash
helm rollback soctalk-system <revision> -n soctalk-system --wait
```

**Important**: if the upgrade introduced a migration that touched data,
`helm rollback` will NOT revert the schema. Restore Postgres from the
pre-upgrade backup in addition.

## Upgrade a single tenant's data plane

```bash
helm upgrade tenant-<slug> oci://ghcr.io/gbrigandi/charts/soctalk-tenant \
  --version <new-tenant-chart-version> \
  --namespace tenant-<slug> \
  -f /tmp/tenant-<slug>-values.yaml \
  --wait --timeout 15m
```

Where `/tmp/tenant-<slug>-values.yaml` is the SocTalk-rendered values file
(retrieve from the SocTalk API or regenerate from tenant config):

```bash
soctalk-cli render-values --tenant <slug> > /tmp/tenant-<slug>-values.yaml
```

### Per-tenant rollback

```bash
helm rollback tenant-<slug> <revision> -n tenant-<slug> --wait
```

Tenant data plane rollbacks are safer than system-level rollbacks: the OSS
stacks (Wazuh/TheHive/Cortex) store their own data in PVCs that `helm
rollback` leaves untouched.

## Fleet upgrade (manual loop in this release)

```bash
# List tenants.
kubectl get ns -l tenant=true,managed-by=soctalk -o jsonpath='{.items[*].metadata.name}'

# Upgrade each, pausing between.
for ns in tenant-acme tenant-beta tenant-gamma; do
  echo "upgrading $ns..."
  helm upgrade ${ns} oci://ghcr.io/gbrigandi/charts/soctalk-tenant \
    --version <new> -n $ns -f /tmp/${ns}-values.yaml --wait --timeout 15m
  kubectl -n $ns rollout status deploy/soctalk-adapter
  sleep 60  # let heartbeat settle before next.
done
```

a future release replaces this loop with a canary-aware fleet-upgrade API.

## Upgrade ordering

1. Cluster prereqs (CNI, cert-manager, ingress): update independently.
2. `soctalk-system` chart: install-level, run migrations.
3. `soctalk-tenant` for each tenant: one at a time, watching for regressions.

Never upgrade tenant charts ahead of `soctalk-system`: the compatibility
matrix will reject out-of-range combinations, and the API will refuse to
provision new tenants on mismatched versions.

## Breaking-change tenant chart upgrades

If the tenant chart bumps a Wazuh/TheHive/Cortex major version with schema
change:

1. Snapshot tenant PVCs first.
2. Upgrade in low-traffic window.
3. Verify alerts flow end-to-end immediately after.
4. Be prepared to `helm rollback` + restore PVCs if the data plane's
   schema-migration process fails.

Upstream OSS projects occasionally ship breaking changes. The chart
audit (`docs/multi-tenant/chart-audit.md`) pins exact subchart versions; bumping
those versions is explicit and tested before release.
