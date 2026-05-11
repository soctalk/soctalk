# wazuh-ingress: Wazuh Agent Ingress and Cert Enrollment

Gate artifact: Specifies how customer endpoints' Wazuh agents reach the per-tenant Wazuh manager across tenant isolation, including hostname strategy, TLS, routing, enrollment flow, and firewall/DNS requirements.

## 1 Problem

Each tenant has a dedicated Wazuh manager running in `tenant-<slug>` namespace. Wazuh agents are installed on the customer's endpoints (outside the MSSP's cluster) and must connect to **their tenant's** Wazuh manager on:

- **1514/TCP**: agent event stream (encrypted with Wazuh's native protocol over TLS)
- **1515/TCP**: agent enrollment / `authd` (registration using shared secret)

Constraints:

- Many tenants on one cluster → cannot expose 1514/1515 on a single NodePort (port collision).
- Agents must reach only *their* tenant's manager (not another tenant's).
- Customer endpoints are on unknown networks (corporate LAN, cloud VMs, laptops): Connectivity via public internet most commonly.
- TLS certificates must be tenant-specific (chain of trust scoped per-customer).

## 2 Chosen pattern: per-tenant hostname + SNI-routing L4 proxy at MSSP edge

Each tenant gets a DNS name like `acme.soc.mssp.example.com`: An L4 proxy at the MSSP edge (HAProxy, Envoy, or nginx-stream) terminates incoming TCP connections on 1514/1515, uses **TLS SNI inspection** to identify the tenant, and routes to the tenant's Wazuh manager Service in the cluster.

### 2.1 Topology

```
Customer endpoint (Wazuh agent)
        │
        │ TCP 1514 to acme.soc.mssp.example.com
        │ (TLS connection, SNI=acme.soc.mssp.example.com)
        ▼
┌───────────────────────────────┐
│ MSSP edge. L4 proxy           │
│ (HAProxy / Envoy / nginx       │
│  stream module)                │
│                                │
│ Inspects SNI hostname:         │
│   acme.soc.mssp.example.com    │
│   → route to tenant-acme/      │
│         wazuh-manager:1514      │
│                                │
│   beta.soc.mssp.example.com    │
│   → route to tenant-beta/       │
│         wazuh-manager:1514      │
└─────────────┬──────────────────┘
              │
              │ cluster-internal TCP
              ▼
  tenant-acme namespace        tenant-beta namespace
  ┌─────────────────┐          ┌─────────────────┐
  │ wazuh-manager   │          │ wazuh-manager   │
  │ Service: 1514   │          │ Service: 1514   │
  │ Pod with        │          │ Pod with        │
  │ tenant-specific │          │ tenant-specific │
  │ TLS cert        │          │ TLS cert        │
  └─────────────────┘          └─────────────────┘
```

### 2.2 DNS

Two DNS setups supported:

1. **Wildcard**. `*.soc.mssp.example.com` resolves to MSSP edge proxy's public IP. Simplest; SNI routing does the rest.
2. **Explicit per-tenant**. `acme.soc.mssp.example.com`, `beta.soc.mssp.example.com`, each resolving to the same edge proxy IP. More records, same outcome.

Recommend wildcard for MVP; MSSPs can pivot to explicit records for certificate scoping reasons later.

### 2.3 TLS certificates

Each tenant gets a certificate whose SAN covers `<slug>.soc.mssp.example.com`. Options:

- **Per-tenant cert via cert-manager + Let's Encrypt** (recommended for MVP): cert-manager `Certificate` CR per tenant, issued by a DNS-01 or HTTP-01 `ClusterIssuer`: Cert stored in `tenant-<slug>` ns as `Secret/wazuh-tls`: Renewed automatically.
- **Wildcard cert for `*.soc.mssp.example.com`**: one cert covers all tenants. Simpler, but means any tenant's Wazuh manager can present the cert for any tenant's agent during MSSP-side proxy failures: acceptable risk for this release since the routing is the real enforcement.
- **MSSP-provided internal CA**: for MSSPs running their own PKI, cert-manager can issue from an in-cluster `Issuer` backed by the MSSP CA.

Install guide documents all three; pilot defaults to Let's Encrypt per-tenant.

### 2.4 L4 proxy choice

Three viable options:

| Option | Pros | Cons |
|---|---|---|
| **HAProxy** (SNI mode) | Battle-tested, very small footprint | Config is text-based, reload on change |
| **Envoy** (TCP filter + SNI) | Dynamic xDS config, rich observability | Heavier; more moving parts |
| **nginx-stream module** | Familiar to many ops teams | Stream module needs to be compiled in; some distros ship without |

MVP reference: **HAProxy** running as a Deployment in `soctalk-system` or on MSSP edge nodes. Config managed by SocTalk controller (regenerated + reloaded on tenant create/delete).

Sample HAProxy config (excerpt):

```
frontend wazuh-agents
    mode tcp
    bind *:1514
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend tenant-acme if { req.ssl_sni -i acme.soc.mssp.example.com }
    use_backend tenant-beta if { req.ssl_sni -i beta.soc.mssp.example.com }
    default_backend drop

backend tenant-acme
    mode tcp
    server wazuh tenant-acme.wazuh-manager.svc.cluster.local:1514

backend tenant-beta
    mode tcp
    server wazuh tenant-beta.wazuh-manager.svc.cluster.local:1514

backend drop
    mode tcp
    # no servers; implicit reject
```

## 3 Agent enrollment flow

Wazuh's `authd` registration on 1515/TCP requires a shared secret. Each tenant has its own `authd` secret (stored in `Secret/wazuh-authd-secret` in the tenant namespace). Enrollment:

1. **MSSP operator** onboards a new customer. SocTalk generates the `authd` shared secret at tenant-provisioning time.
2. **MSSP operator** provides customer-endpoint admin with:
   - Tenant's Wazuh manager hostname (`acme.soc.mssp.example.com`)
   - Ports (1514 events, 1515 enrollment)
   - `authd` shared secret (via secure channel: secrets management platform, encrypted email, whatever the MSSP uses)
   - Wazuh agent installer (standard upstream package)
3. **Customer endpoint admin** installs Wazuh agent with the hostname and enrolls:
   ```bash
   /var/ossec/bin/agent-auth \
       -m acme.soc.mssp.example.com \
       -P "<authd-shared-secret>"
   ```
4. Agent registers with tenant's manager, receives its own per-agent certificate.
5. Subsequent connections on 1514 are per-agent mTLS.

Routing at 1515 works the same way as 1514 (SNI-based L4 routing). The `authd` shared secret is tenant-scoped: an agent using `acme`'s secret can only register with `acme`'s manager (the routing enforces it; the secret is verified by the manager).

## 4 Firewall / network requirements

MSSP-side:
- Public IPs for edge proxy (one IP, or per-region IPs for MSSPs with geo-distributed MSSP regions).
- Edge proxy allows inbound 1514/TCP, 1515/TCP from 0.0.0.0/0 (or customer-specific CIDRs if MSSP prefers).
- Cluster-internal firewall (NodePort range or internal CIDR) allows edge proxy → tenant namespace Wazuh manager.

Customer-side:
- Agents allow outbound 1514/1515/TCP to the MSSP's edge hostname.
- No inbound from MSSP to customer endpoints (Wazuh is pull-less: events originate from agent).

## 5 Certificate revocation / agent removal

To revoke a specific agent:
1. MSSP operator opens tenant in MSSP UI → Agents tab → revokes.
2. SocTalk calls Wazuh manager API to remove the agent's registration.
3. Customer-endpoint admin uninstalls the agent (optional, housekeeping).

To revoke all agents for a tenant (e.g., customer offboarding):
1. Rotate tenant's `authd` shared secret (re-enrollment required for new agents).
2. Delete all existing agent registrations via Wazuh API.
3. Tenant decommission  eventually tears down the manager.

## 6 Alternative connectivity patterns (documented, not built)

### 6.1 Customer-managed VPN / tunnel

If a customer's network policy disallows agents sending telemetry over public internet:
- Customer provisions a WireGuard/IPsec tunnel to MSSP's private network.
- MSSP routes tunnel traffic to the same edge proxy (or directly to cluster on internal addresses).
- Agent configuration points at an internal hostname.

Not implemented in this release tooling; documented as a setup pattern for MSSPs who need it.

### 6.2 Tailscale / overlay network

Similar to 6.1; MSSP and customer join a Tailscale network, agent reaches `acme.soc.mssp.ts.net` directly. Good for small customers; documented.

### 6.3 Per-region MSSP edge

For MSSPs with geographic separation (EU, US, APAC), multiple edge proxies in different regions. Tenant assigned to nearest region; DNS reflects (`acme.soc.eu.mssp.example.com`, `acme.soc.us.mssp.example.com`). design supports this because the edge proxy → tenant namespace routing is just cluster-internal DNS lookup. a future release automation for multi-region dispatch.

## 7 Runbook: onboarding a customer's first agent

1. MSSP operator creates tenant in MSSP UI → SocTalk provisions stack, generates `authd` secret.
2. MSSP operator navigates to tenant detail → "Agent Onboarding" section.
3. Section displays:
   - Tenant hostname: `acme.soc.mssp.example.com`
   - Ports: 1514/TCP (events), 1515/TCP (enrollment)
   - `authd` shared secret (masked; copy-to-clipboard + one-time reveal)
   - Sample `agent-auth` command
   - Firewall requirements
4. MSSP operator copies to secure channel, shares with customer endpoint admin.
5. Customer endpoint admin installs + enrolls.
6. MSSP operator watches tenant detail → Agents tab, sees agent appear within ~30 seconds.

## 8 Testing (design spike + pilot validation)

Design spike validates:
- HAProxy config template with two tenants; prove SNI routing works.
- cert-manager per-tenant cert issuance (or wildcard).
- End-to-end: spin up two tenants in `k3d`, deploy HAProxy as NodePort, enroll an agent at each via localhost:1515 with SNI override, verify events flow to the correct tenant's Wazuh indexer.

A later release pilot validates:
- Real customer endpoint (on actual separate network) successfully enrolls.
- Cross-tenant probe: try to enroll an `acme` agent with `beta`'s `authd` secret against `beta`'s hostname; expect rejection. Try vice versa. Both should fail.

## 9 Gate criteria

- [x] This document merged as reference.
- [ ] design spike produces working HAProxy config template with per-tenant routing.
- [ ] design spike validates cert-manager per-tenant cert issuance.
- [ ] SocTalk controller implements `authd` secret generation + HAProxy config re-render.
- [ ] install guide documents MSSP-edge proxy deployment + DNS setup + firewall rules.
- [ ] customer-onboarding runbook includes agent enrollment walkthrough.
