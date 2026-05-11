# SocTalk Troubleshooting Index

Symptoms → diagnostic → fix. Runbook for the most common failure modes.

| Symptom | First check | Fix |
|---|---|---|
| `helm install soctalk-system` fails in pre-install hook | `kubectl logs -n soctalk-system job/<release>-preinstall-check` | Install missing cluster prereq (CNI / cert-manager / StorageClass) per install guide §1 |
| API pod `CrashLoopBackOff` on startup | `kubectl logs -n soctalk-system deploy/soctalk-system-api` | Most often: bad DATABASE_URL Secret, Postgres not ready yet, Alembic migration failure. Check Postgres pod first |
| `helm install` succeeds but MSSP UI 502 | ingress controller logs; verify ingress Service `endpoints` populated | OIDC proxy not deployed or not injecting trusted headers; check trusted-proxy CIDR |
| Tenant create returns 500 | API logs show `ProvisionError` | Usually `helm install tenant-*` failed. Check `helm status tenant-<slug>`. Namespace + resource quota issues are most common |
| Tenant stuck `provisioning` > 15 min | `kubectl -n tenant-<slug> get events --sort-by=.lastTimestamp` | See runbook "Tenant stuck in provisioning" |
| Tenant goes `degraded` | adapter logs in tenant ns | NetworkPolicy egress, adapter pod crash, or DNS misresolved |
| Cross-tenant data visible | Run isolation test suite | **P1 incident.** RLS is the last line: failure indicates app or Postgres role misconfiguration |
| LLM calls failing for one tenant | Worker logs: look for 401/403 from LLM provider | `tenant-<id>-llm` Secret `api_key` empty or wrong. Rotate via UI |
| Wazuh agent can't connect | Check MSSP edge L4 proxy + DNS + TLS cert for `<slug>.soc.mssp.*` | P0-6 §8; ensure SNI routes to the right tenant's Wazuh manager |
| Postgres StatefulSet won't start (Pending) | `kubectl describe pvc -n soctalk-system` | No default StorageClass, or class doesn't support RWO, or cluster out of disk |
| `PolicyViolation` messages from ingress controller | NetworkPolicy allow-rules | Make sure ingress ns is labeled `kubernetes.io/metadata.name=ingress-system` |
| Cilium Hubble shows DROPPED flows between tenant and soctalk-system | Check NetworkPolicies + Cilium identities | Adapter egress policy missing or wrong namespaceSelector |
| Customer user login → 403 on /api/tenant/* | JWT claims | Ensure user row has `tenant_id` set and `role=customer_viewer` |
| MSSP user impersonation not showing in customer audit | Audit query | Verify `acting_as` column populated on write; customer audit view joins on `tenant_id = own AND acting_as IS NOT NULL` |
| `pip-audit` CI job reports CVEs | Review advisory | Non-fatal for this release; upgrade when maintainers publish fix |
| Isolation test fails in CI (FORCE RLS admin can see rows) | Check migration applied | Re-run `alembic upgrade head`; ensure `FORCE ROW LEVEL SECURITY` applied to every tenant-scoped table |
| `cosign verify` fails for a chart (future releases) | Key rotation | Pull latest cosign pubkey from releases page; verify against the correct `kid` |

## Collecting diagnostic bundles

When escalating to vendor support (you), collect:

```bash
# SocTalk system-level state
kubectl get all,events,networkpolicies,resourcequotas \
  -n soctalk-system -o yaml > soctalk-system.yaml
kubectl -n soctalk-system logs deploy/soctalk-system-api --tail=500 > api.log
kubectl -n soctalk-system logs deploy/soctalk-system-orchestrator --tail=500 > orch.log

# Specific tenant
kubectl get all,events,networkpolicies,resourcequotas,limitranges \
  -n tenant-<slug> -o yaml > tenant.yaml
kubectl -n tenant-<slug> logs deploy/soctalk-adapter --tail=500 > adapter.log

# Helm state
helm status -n soctalk-system soctalk-system > helm-system.txt
helm status -n tenant-<slug> tenant-<slug> > helm-tenant.txt

# SocTalk version + lifecycle events for the tenant
soctalk-cli debug-bundle --tenant <slug> > bundle.json

tar czf soctalk-debug-$(date +%s).tgz *.yaml *.log *.txt bundle.json
```

Send the tarball to `support@your-mssp.example` (you, during pilots).
**Review for customer data leakage before sharing externally**: logs may
contain alert excerpts.
