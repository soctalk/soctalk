# SocTalk Operator Runbook

Common operational tasks for MSSP operators running a SocTalk install.

## Tenant stuck in `provisioning`

**Symptom**: new customer's tenant row sits in `provisioning` state > 15 min.

1. Check the Helm release status:
   ```bash
   helm status tenant-<slug> -n tenant-<slug>
   ```
2. Check pod events:
   ```bash
   kubectl -n tenant-<slug> get events --sort-by=.lastTimestamp | tail -30
   ```
3. Common causes:
   - `StorageClass` missing / provisioner down → PVCs stuck `Pending`.
     Fix: provision storage; `kubectl describe pvc` shows the reason.
   - ResourceQuota too small for Wazuh indexer request.
     Fix: raise the tenant's ResourceQuota via `helm upgrade` with new values.
   - Image pull failures → check registry auth, firewall.

If a provisioning attempt cannot recover, decommission and retry:

```bash
# From MSSP UI: tenant detail → Decommission → force=true
# Or via API:
curl -X POST https://mssp.../api/mssp/tenants/<id>:decommission?force=true
```

## Tenant in `degraded` state

`degraded` means SocTalk lost contact with the tenant adapter for > 10 min.

1. Check adapter pod:
   ```bash
   kubectl -n tenant-<slug> logs deploy/soctalk-adapter --tail=200
   ```
2. Check NetworkPolicy egress (adapter needs to reach `soctalk-system` API):
   ```bash
   hubble observe --from-pod tenant-<slug>/soctalk-adapter-<pod>
   ```
3. Restart adapter:
   ```bash
   kubectl -n tenant-<slug> rollout restart deploy/soctalk-adapter
   ```

If the data plane is healthy but adapter can't reach `soctalk-system`,
inspect the `adapter-egress` NetworkPolicy.

## License expired (future releases only)

*has no license enforcement. This section documents a future release behavior.*

1. Install banner appears; new tenant creation / upgrades blocked.
2. Get a fresh license JWT from Cloud portal.
3. Replace the Secret:
   ```bash
   kubectl -n soctalk-system patch secret soctalk-license \
     --type='json' -p="[{\"op\":\"replace\",\"path\":\"/data/license.jwt\",\"value\":\"$(base64 < new_license.jwt)\"}]"
   kubectl -n soctalk-system rollout restart deploy/soctalk-system-api
   ```

## Rotate per-tenant LLM key

1. MSSP admin → customer detail → Settings → LLM → paste new key → Save.
2. SocTalk controller overwrites `tenant-<id>-llm` Secret in
   `soctalk-system`. Orchestrator picks up the change on next worker
   context build (no pod restart needed).

## Rotate data plane bootstrap secrets

```bash
soctalk-cli rotate-admin --tenant <slug> --service wazuh
```

Brief service interruption per-service during rotation. Agents need to
re-enroll only if the Wazuh `authd` shared secret is rotated:

```bash
soctalk-cli rotate-agent-secret --tenant <slug>
# Distribute new secret to customer endpoint admin via secure channel.
```

## Database restore (disaster recovery)

This release backup is MSSP-managed externally (Velero, cluster snapshots, external
`pg_dump`). To restore:

1. Stop SocTalk API + orchestrator:
   ```bash
   kubectl -n soctalk-system scale deploy soctalk-system-api --replicas=0
   kubectl -n soctalk-system scale deploy soctalk-system-orchestrator --replicas=0
   ```
2. Restore Postgres data from your backup.
3. Restart workloads.

Tenant data plane PVCs follow the same pattern: restore per-namespace then
`helm upgrade` the tenant release to re-attach.

## Emergency: disable a tenant immediately

Suspend via UI (best) scales the data plane to zero. If the tenant must be
cut off at the network layer immediately, apply a deny-all NetworkPolicy:

```bash
kubectl -n tenant-<slug> apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: emergency-deny-all }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
EOF
```

Reverse by deleting that NetworkPolicy.

## Audit log review

MSSP-wide audit log: UI → Audit tab. Filter by tenant, actor, action,
timestamp. For compliance exports, use the API:

```bash
curl https://mssp.../api/mssp/audit?since=2026-01-01&tenant=<id> > audit.json
```

## Cross-tenant data leak suspicion

If you suspect cross-tenant access:

1. Check recent RLS test suite runs: they pass in CI for every release.
2. Probe the DB directly:
   ```bash
   kubectl -n soctalk-system exec -it statefulset/soctalk-system-postgres -- \
     psql -U soctalk_app -d soctalk \
     -c "SET app.current_tenant_id='<tenant-a>'; SELECT tenant_id FROM events LIMIT 5;"
   ```
3. If leak confirmed, file a P1 incident. RLS + FORCE ROW LEVEL SECURITY
   is the last line of defense: an unpatched leak indicates an application
   bug *or* a Postgres role misconfiguration.

## Common mistakes

- Running migrations as `soctalk_app` → will fail; use `soctalk_admin` creds.
- Editing `soctalk-tenant` values directly in Helm → bypasses SocTalk DB
  state. Always go through the API.
- Creating `tenant-*` namespaces manually → labels will be missing; SocTalk
  won't recognize them. Always use the tenant create flow.
