# MSSP Pilot Quickstart — tutorial plan

**Status:** plan, not the tutorial itself. The artifact described here will
live at `docs.soctalk.ai/mssp-pilot/`.

> **Reviewer brief — read first.** This is a documentation plan, not
> code. Review it from a DX/UX angle, biased toward the perspective of
> two readers:
>
> 1. An **MSSP technical lead** who has 90 minutes and one budget-holder
>    expecting a screenshot at the end. Has used k8s but isn't fluent;
>    runs VMware/Proxmox in their org; wants to evaluate SocTalk.
> 2. A **tenant IT contact** who's been pinged by their MSSP and asked
>    to provision one Linux VM, install Tailscale, run two commands.
>    Does not want to read the whole tutorial; wants the section that
>    applies to them.
>
> Focus areas for the review:
>
> - Is the path linear enough that a first-time reader doesn't get lost?
>   The tutorial has unavoidable variations (4-5 hypervisors, 2 VPN
>   providers, Wazuh-or-not). Does the chosen variation handling
>   (tabs + callouts) work, or does it collapse into a confusing
>   choose-your-own-adventure?
> - The handoff moment — §4 generates four strings the MSSP must convey
>   to the tenant manually. Is the friction honest about itself? Does
>   the tutorial signpost that this manual handoff is a known rough edge,
>   not the steady state, clearly enough?
> - Tenant-side §5: same Linux VM, same k3s, same chart, but the
>   tenant operator may never have seen SocTalk before. Is the
>   per-tenant section self-contained enough that the MSSP can copy
>   the URL to their tenant contact who reads only §5 without §0-4?
> - The "demo moment" §6 — is the screenshot prescribed (specific
>   query, specific tool badge, specific reply) so the MSSP knows
>   exactly what "success" looks like, or do we leave it open and
>   risk an underwhelming pilot result?
> - What's MISSING — a real pilot will hit something this plan
>   doesn't account for. Where are the silent gotchas (proxy
>   environments, certificate trust, Wazuh version skew, tenant
>   firewalls blocking 443/UDP, etc.)?
> - Naming and information architecture — does `/mssp-pilot/` belong
>   at the top of the docs nav, peer to `/quickstart-vm`? Or is it
>   sub-page of `/install`?
>
> Be opinionated. Brainstorm-stage feedback like *"reorder these
> sections"*, *"merge X and Y"*, *"this section should be its own
> page"*, or *"don't write this part — just link to the existing
> /quickstart-vm and add a 2-paragraph delta"* is welcome.

## Problem

MSSPs evaluating SocTalk run a pilot for 1-3 of their customers. Both
environments are on-prem. There's no current docs path that takes an
MSSP from "I downloaded the VM image" to "I'm asking the AI SOC chat
questions about my tenant's real Wazuh alerts" — they have to stitch
together:

- `/quickstart-vm` (which assumes single-VM, no tenants)
- `/install` (which assumes K3s cluster, Cilium, cert-manager, real
  ingress — way too much for a pilot)
- The implicit knowledge of *how* the tenant side connects to the MSSP
  side (Tailscale, ACLs, bootstrap tokens) — not written down anywhere
  customer-visible yet

Without this doc the pilot path is operator support tickets, not
self-service. With it, an MSSP technical lead can run a pilot to first
chat in 2-3 hours without reaching out.

## Scope

- **In scope:** 1 MSSP control plane + 1-3 tenant data planes, all
  on-prem, connected via Tailscale (or Headscale / NetBird as drop-ins),
  using the published `soctalk-system` VM image at the MSSP and a
  generic Linux VM + helm-installed `soctalk-tenant` chart at each
  tenant.
- **Out of scope:** HA, real TLS (cert-manager), production ingress
  (the pilot uses the tailnet hostname as ingress), MSSP-side cluster
  (the pilot uses k3s baked into the VM image), tenant-side scale
  beyond a few dozen agents.

## Information architecture

Top-level page in the docs nav: **MSSP Pilot Quickstart** at
`/mssp-pilot/`. Peer to `/quickstart-vm` (single-VM demo) and `/install`
(production install). Cross-linked from both:

- From `/quickstart-vm`: "Trying SocTalk as an MSSP for 1-3 customers?
  See [MSSP Pilot Quickstart](/mssp-pilot/) instead."
- From `/install`: "Looking to evaluate before committing to a full
  cluster install? Start with the [MSSP Pilot Quickstart](/mssp-pilot/)."

Tenant-side section linkable directly: `/mssp-pilot/#tenant-side` so an
MSSP can paste a URL fragment to their tenant contact.

## Section structure

### 0. TL;DR + prerequisites (~5 min read)

- One-paragraph "what you'll have at the end" (multi-tenant SocTalk +
  AI chat answering real questions about real Wazuh data).
- Wall-clock estimate: 2-3 hours total, ~90 min hands-on for the MSSP,
  ~30 min hands-on per tenant operator.
- **Pilot scope disclaimer.** Bullet list of what this is NOT (no HA,
  no real TLS, tailnet hostname as ingress, single k3s node per side,
  not a production install). Linked back to `/install` for the
  production path.
- Prerequisites checklist (the things the MSSP gathers before starting):
  - Hypervisor + credentials for the MSSP side
  - Tailscale account (or self-hosted Headscale endpoint)
  - LLM API key (Anthropic or OpenAI)
  - One contact per tenant (name + email)
  - VPN provider opinion (lightly prescribed: Tailscale primary)

### 1. Before you start (~10 min reading + decisions)

- **Architecture diagram.** One picture: MSSP VM (`soctalk-system`),
  N tenant VMs (`soctalk-tenant`), Tailscale tailnet wrapping them all,
  optional existing Wazuh shown dotted-line per tenant. Two boundaries
  marked: trust boundary at the tailnet edge, install boundary at each
  VM. **This is the single diagram the operator references through
  the whole tutorial.**
- **Decision 1: VPN provider.** Tailscale primary (covers ~90% of
  pilots). Headscale callout (1 paragraph) for MSSPs who can't use
  Tailscale-the-company. NetBird callout (1 paragraph) for OSS
  preference. Pick once, stick with it; tutorial uses Tailscale syntax
  with provider-agnostic prose.
- **Decision 2: per-environment hypervisor.** Table: which file format
  goes with which hypervisor (`.vmdk` → vSphere/VirtualBox,
  `.qcow2` → KVM/Proxmox, `.vhdx` → Hyper-V, `.raw` → generic). MSSP
  picks hypervisor for their side now; each tenant operator picks
  theirs when their section runs.
- **Decision 3: per-tenant Wazuh.** Existing or fresh? Asked once per
  tenant; affects §5.5 branch only.
- **Inventory checklist** to copy: hostname / IP for MSSP-side
  hypervisor, vCenter login, Tailscale account email, LLM API key,
  per-tenant contact (name, email, target hypervisor, has-Wazuh).
  Operator fills it before starting.

### 2. Set up the tailnet (~15 min)

- Sign up for Tailscale (or stand up Headscale — collapsed alt block).
- Define the tag schema for SocTalk: `tag:mssp`, `tag:tenant-<slug>`
  per tenant. Worked example for 2 tenants.
- Generate auth keys: one reusable for MSSP-side VMs, one ephemeral
  per tenant.
- Draft an ACL stanza (copy-pasteable JSON block): tenant tags can
  only accept inbound from `tag:mssp`; tenant-to-tenant explicitly
  denied. The block goes into the Tailscale admin UI; screenshot
  shows where to paste it.
- **Checkpoint:** ACL preview confirms what each tag can and can't
  reach. If preview shows tenant-to-tenant reachable, fix before
  moving on.

### 3. MSSP side: stand up the control plane (~30 min)

- Download the `soctalk-system` VM image. Table of which file for
  which hypervisor.
- Import + boot (tabs per hypervisor, with screenshots):
  - vSphere via Web UI: deploy OVF wizard
  - vSphere via `govc`: one-liner
  - Proxmox via Web UI: import disk + create VM
  - Proxmox via CLI: `qm importdisk` + `qm set`
  - Hyper-V: convert vhdx → use Generation 1
  - KVM/libvirt: `virt-install`
  - VirtualBox: convert vmdk → VDI
- SSH in (uses `/quickstart-vm#ssh-access-credentials` cross-link for
  the build-time creds).
- Install Tailscale, join tailnet. Note the assigned hostname
  (`soctalk-mssp.<tailnet>.ts.net`).
- Configure the SocTalk ingress hostname to use the tailnet name.
  (Specific: where in `/etc/soctalk/values.yaml` to set it before the
  wizard runs — or via the wizard's hostname field.)
- Open the wizard at `https://<tailnet-host>:8443/` (TLS will be
  self-signed; pilot accepts this). Screenshot walk:
  - Token entry (from `/var/log/soctalk-setup-token`)
  - MSSP display name + slug
  - Admin email + password
  - LLM provider + API key
- Wait for the chart install (~5 min). Progress on the wizard's
  Finish screen.
- Sign in to the MSSP dashboard.
- **Checkpoint:** empty Tenants list visible. If not, log location
  pointer + troubleshooting cross-link.

### 4. Generate tenant onboarding info per tenant (~5 min each)

- In MSSP dashboard, **Tenants → Add**.
- Fill in the tenant's name + contact + slug + tailscale tag.
- Capture the four strings the tenant operator will need:
  1. Tenant slug
  2. Bootstrap token (one-time, short-lived)
  3. MSSP API URL (the tailnet hostname)
  4. Tenant-tagged Tailscale auth key
- Bundle these into a single fenced YAML block the operator copies as
  ONE paste-able artifact. Format documented in the tutorial.
- **Handoff guidance.** Opinionated: paste into 1Password/Bitwarden
  shared item, share via team password manager, OR email if no PWM is
  in use. Do NOT paste into a public Slack channel or send the
  bootstrap token unencrypted over the same channel as the auth key.
- **The manual-handoff callout.** Inline note flagging that this
  copy-by-hand step is the known rough edge, not the steady state, so
  the reader knows it won't always be like this.

### 5. Tenant side: stand up the data plane (~30 min per tenant)

- **Section header:** *"This section is for tenant IT contacts. The
  MSSP you're working with has sent you a YAML onboarding bundle.
  This section walks you through what to do with it."* Self-contained;
  doesn't reference §1-4 except by glossary.
- Coordinate with the MSSP if anything is missing.
- Provision a Linux VM:
  - Sizing: 4 vCPU, 8 GB RAM, 60 GB disk
  - OS: Ubuntu 24.04 (any other distro works but tutorial uses 24.04)
  - Tabs per hypervisor (same set as §3, abbreviated since the tenant
    operator already knows their hypervisor)
- SSH in. Install Tailscale, join tailnet with the tenant-tagged auth
  key from the bundle. Verify tailnet status.
- Install k3s + helm. One-liner each.
- Save the bundle's onboarding info to a `values.yaml` file. Branch:
  - **5a: Tenant has existing Wazuh.** Add Wazuh API URL + creds
    fields to values. Wazuh must be reachable from the tenant VM
    (LAN or via tailnet).
  - **5b: Tenant doesn't have Wazuh.** Use the `poc` profile that
    chart-installs Wazuh. One linux-ep simulator included for demo
    alerts.
- Helm-install the `soctalk-tenant` chart:
  ```
  helm install <slug> oci://ghcr.io/soctalk/charts/soctalk-tenant \
    --version <ver> -f values.yaml -n tenant-<slug> --create-namespace
  ```
- Verify adapter heartbeat reaches MSSP (within 1-2 minutes).
- **Checkpoint:** tenant flips to "Online" in the MSSP dashboard. If
  not, troubleshooting cross-link.

### 6. The demo moment (~10 min)

The screenshot stakeholders see. **Prescribed** to maximize the
chance of a good outcome:

- Open the MSSP dashboard, sign in as admin.
- Open Chat, ask exactly: `list all tenants`
- Wait for `list_tenants` tool badge → reply.
- Ask exactly: `show me the 5 most recent Wazuh alerts at <tenant-slug>`
- Wait for `get_wazuh_alert_summary @ <tenant-slug>` tool badge →
  reply listing real alert rule IDs + descriptions.
- **Screenshot this.** The badge with the `@ tenant-slug` chip + the
  assistant's natural-language summary is the proof. Tutorial includes
  an example screenshot (from `demo.soctalk.ai` or the lab) so the
  operator knows what they're aiming at.
- If the alerts list is empty (no traffic yet on the tenant), pointer
  to the attack simulator script at `/opt/scripts/run-attack.sh` to
  generate alerts on demand.

### 7. Day 2 — where from here (~5 min read)

- Onboard the tenant's real customers (different Wazuh instances)
  — pointer to per-tenant config.
- Plan the production install — pointer to `/install`.
- What's NOT in the pilot, restated: HA, scale beyond ~50 agents per
  tenant, real TLS, multi-region.
- Migration path: pilot artifacts can be decommissioned, but the
  MSSP's product configuration (tenants list, chat history, LLM key)
  can carry forward to a production install if planned.

### Appendix A — Troubleshooting

Symptom → fix table, biased to the failure modes that are real today:

- Tailscale auth key expired before tenant ran the join command
- Helm pull blocked by tenant's corporate HTTPS proxy
- Wazuh API creds rejected (Wazuh API user disabled, password rotated,
  TLS verify mismatch)
- LLM API key invalid / rate-limited
- MSSP UI 502s after first sign-in (k3s Traefik settling)
- Tenant adapter shows "Connecting" forever (Tailscale ACL too tight)
- Bootstrap token expired before tenant used it (regen path)

### Appendix B — Decommissioning the pilot

Tear-down order: tenants first, then MSSP. Revoke Tailscale auth keys
+ remove ACL stanzas. Archive the MSSP VM if migration to production
is planned; otherwise destroy.

### Appendix C — Hypervisor reference (consolidated)

The full per-hypervisor import + boot commands collected on one page,
so an operator can bookmark just this appendix on subsequent pilots
without re-reading §3 + §5.

## Authorial decisions baked in (worth flagging for review)

- **One canonical path; variation via tabs.** vSphere/Proxmox/Hyper-V/
  KVM/VirtualBox become tabs inside §3 and §5, not five parallel
  tutorials. VPN provider is Tailscale-primary with Headscale/NetBird
  as collapsed alts. Cost: harder to land in the "right" tab if you
  arrive via Google. Benefit: the same tutorial works for everyone.
- **Honest about manual handoff.** §4 documents the four-string copy
  with a callout flagging it as a known rough edge. Doesn't pretend
  smoothness that doesn't exist yet.
- **Tenant operator may read ONLY §5.** Section is structured to be
  self-contained, with terms (slug, bootstrap token, tailnet) glossed
  inline rather than relying on §0-4 having been read.
- **Demo moment is prescribed, not open.** Specific query, specific
  expected response shape, example screenshot. Reduces "I tried it,
  the alerts list was empty, this product doesn't work" feedback.
- **Existing chart deployment, not appliance image, on the tenant
  side.** Because we don't currently ship a tenant appliance image —
  only the system image. Tenant operator spins up generic Ubuntu,
  installs k3s + helm, helm-installs the chart. The tutorial is
  honest about this being the current path.

## Open questions for the reviewer to interrogate

1. **Information architecture.** `/mssp-pilot/` top-level or sub-page
   of `/install/`? My instinct is top-level (MSSP pilots are the
   primary distribution channel right now). What's the counter-case?
2. **The four-string YAML bundle in §4.** Is the format prescribed
   enough that two MSSPs running this independently produce the same
   shape? Or should the format be left flexible and we just enumerate
   the required keys?
3. **The "known rough edge" callouts.** Useful (sets expectations) or
   distracting (reader wonders why the rough edge isn't already fixed)?
   Frequency: I have them in §4 and §5. Should they be in §3 too?
4. **The §6 demo moment specificity.** Currently prescribes the exact
   query strings. Pro: predictable outcome. Con: feels canned and
   reduces operator's sense of discovery. Halfway: prescribe one
   query, then say "now try your own". Worth experimenting in real
   pilots before deciding.
5. **§5 as a standalone page?** Right now §5 is a section inside the
   tutorial, but the tenant operator reads only it. Worth promoting
   to its own page (`/mssp-pilot/tenant-setup/`) with a back-link to
   the main tutorial, so the URL the MSSP shares is cleaner?
6. **Hypervisor coverage.** Tabs for vSphere / Proxmox / Hyper-V /
   KVM / VirtualBox. What about Nutanix? Azure Stack HCI? OpenStack?
   Probably appendix-only for v1, but the cut should be intentional.
7. **What about MSSPs who don't have a Tailscale-style VPN at all
   today?** Tutorial assumes they're willing to install one. Is that
   a fair assumption, or do we need a "Why your pilot needs a mesh
   VPN" pre-section that explains the why before the how?
8. **Tutorial length.** Honest estimate of the full tutorial as
   written: 8-10K words including code blocks. Is that too long for
   a pilot quickstart? Is `/quickstart-vm` shorter / longer / about
   the same? Where could we cut without losing critical steps?
9. **Screenshot density.** Plan implies ~25-30 screenshots
   (per-hypervisor import wizards + Tailscale admin UI + SocTalk
   wizard + dashboard + chat). That's a lot. Where should we trim?
   Skip the per-hypervisor screenshots (already on those vendors' own
   docs) and link out instead?
10. **Maintenance burden.** Tutorial references published image
    tags (`soctalk-system:0.1.x`), chart versions (`oci://...:0.1.x`),
    and Tailscale UI. All move. What's the strategy for keeping it
    current without per-release toil? Pinning versions in the
    tutorial vs. always-latest vs. a "supported versions" table at
    the top?
