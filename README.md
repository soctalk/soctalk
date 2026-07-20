# SocTalk

> Open-source, LLM-driven SOC automation. Continuously triages, investigates,
> and escalates Wazuh alerts — single-host for one team, or multi-tenant for
> MSPs and MSSPs.

**[soctalk.ai](https://soctalk.ai)** ·
**[Docs](https://soctalk.github.io/soctalk-docs/)** ·
**[How it compares](https://soctalk.ai/compare/)** ·
**[Talk with the maintainer](https://calendly.com/gianluca_brigandi/soctalk-adopter-intro)**

![SocTalk Dashboard](docs/images/soctalk-dashboard.png)

SocTalk turns raw Wazuh alerts into investigated, prioritized, and (when you
allow it) auto-resolved cases. A two-tier LLM pipeline routes and reasons over
each alert, a human-in-the-loop step keeps an analyst in control, and a built-in
incident-response workflow records everything for audit and replay. And you can
just ask — a scope-aware chat answers questions about your SOC in plain English,
across the whole MSSP fleet or scoped to a single tenant. Apache-2.0,
Wazuh-powered, bring your own LLM, self-host anywhere.

## Try it in 5 minutes

The demo VM is **batteries-included** — Ubuntu, K3s, the SocTalk charts, and a
first-boot setup wizard baked into one image. Download it, boot it, click through
the wizard.

**GUI (VirtualBox)** — the easiest cross-platform desktop path (Windows, Linux,
Intel Mac): create a VM from the image and boot. Full walkthrough with
screenshots: **[Run on VirtualBox](https://soctalk.github.io/soctalk-docs/virtualbox)**.

**CLI (KVM / QEMU):**

```bash
# qcow2 shown — pick the format for your hypervisor on the Downloads page
curl -L -O https://github.com/soctalk/soctalk/releases/download/v0.1.4/soctalk-demo-0.1.4.qcow2.xz
xz -d soctalk-demo-0.1.4.qcow2.xz

# Boot with KVM and forward the setup wizard to localhost:8443
qemu-system-x86_64 -m 8G -smp 4 -enable-kvm \
  -drive file=soctalk-demo-0.1.4.qcow2,if=virtio \
  -netdev user,id=n,hostfwd=tcp::8443-:8443 -device virtio-net,netdev=n -nographic
```

Then open `https://localhost:8443` and finish in the wizard. Other platforms
(VMware, Hyper-V, Proxmox, AWS, Azure) and the full walkthrough:
**[Quickstart](https://soctalk.github.io/soctalk-docs/quickstart-vm)** ·
**[Downloads](https://soctalk.github.io/soctalk-docs/downloads)**.

## Talk with the maintainer

I'm Gianluca, and I build SocTalk. If you're evaluating it for your own team
or for your customers, hit a wall in the setup wizard, want a second opinion
on an architecture, or are thinking about contributing, book 30 minutes with
me:

**[calendly.com/gianluca_brigandi/soctalk-adopter-intro](https://calendly.com/gianluca_brigandi/soctalk-adopter-intro)**

There is no sales script and nothing to sign up for. Bring a technical
question, a use case, or plain curiosity. Single-team deployments are as
welcome as MSSP fleets. If a call is not your thing,
[open an issue](https://github.com/soctalk/soctalk/issues) or write to
hello@soctalk.ai.

## Features

- **Two-tier LLM triage** — fast router + reasoning verdict, with Anthropic or any OpenAI-compatible provider
- **Conversational chat** — ask the SocTalk agent in plain language; scope-aware across every tenant (MSSP-wide) or bound to one customer (tenant scope)
- **Flexible Wazuh** — provision a dedicated Wazuh SIEM per tenant, or connect SocTalk to a customer's existing Wazuh
- **Continuous Wazuh polling** with correlation and prioritization into investigations
- **Human-in-the-loop**: every AI escalation waits for an analyst decision in the dashboard review queue, recorded in an append-only audit log
- **Triage policies**: no-code guardrails run by a deterministic interpreter; authored policies can only make triage stricter, never suppress a detection ([docs](https://soctalk.github.io/soctalk-docs/triage-policies))
- **Response playbooks**: verdicts dispatch signed disposition envelopes to your SOAR webhook; containment actions are always analyst-approved proposals ([docs](https://soctalk.github.io/soctalk-docs/response-playbooks))
- **Built-in incident response** and case workflow; TheHive, Cortex, and MISP are optional integrations
- **Service KPIs** — alert volume, time-to-verdict, time-to-review, and escalation rate, at both the MSSP (cross-tenant) and per-tenant level
- **Event-sourced** for full auditability and replay, with a real-time dashboard
- **Multi-tenant** — isolated per-customer SOC stacks on k3s/k8s, Postgres row-level security, per-tenant LLM credentials and branding

## Multi-tenant (MSP / MSSP)

![MSSP Dashboard](docs/images/soctalk-mssp-dashboard.png)

Run SocTalk as an MSSP control plane that provisions and operates a dedicated
SOC stack per customer — each in its own Kubernetes namespace with isolated
credentials, branding, and tenant-scoped state under Postgres RLS. For each
tenant, deploy a dedicated Wazuh SIEM or connect to one the customer already
runs; service KPIs roll up across the whole fleet and drill down per tenant.
Two Helm charts ship: `soctalk-system` (control plane) and `soctalk-tenant`
(the per-customer stack the controller renders and applies). See the
**[MSSP UI tour](https://soctalk.github.io/soctalk-docs/mssp-ui)** and
**[Tenant lifecycle](https://soctalk.github.io/soctalk-docs/tenant-lifecycle)**.
For how this model relates to MDR services, wholesale SOC desks, and building
your own Wazuh stack, see **[soctalk.ai/compare](https://soctalk.ai/compare/)**.

## Documentation

Full docs live at **[soctalk.github.io/soctalk-docs](https://soctalk.github.io/soctalk-docs/)**:

- **Get started** — [Quickstart](https://soctalk.github.io/soctalk-docs/quickstart-vm) · [Downloads](https://soctalk.github.io/soctalk-docs/downloads) · [Setup wizard](https://soctalk.github.io/soctalk-docs/setup-wizard) · [Production install](https://soctalk.github.io/soctalk-docs/install)
- **Run on** — [Proxmox](https://soctalk.github.io/soctalk-docs/proxmox) · [AWS](https://soctalk.github.io/soctalk-docs/aws) · [Azure](https://soctalk.github.io/soctalk-docs/azure)
- **Concepts** — [AI pipeline](https://soctalk.github.io/soctalk-docs/ai-pipeline) · [Triage policies](https://soctalk.github.io/soctalk-docs/triage-policies) · [Response playbooks](https://soctalk.github.io/soctalk-docs/response-playbooks) · [Tenant lifecycle](https://soctalk.github.io/soctalk-docs/tenant-lifecycle) · [Human review](https://soctalk.github.io/soctalk-docs/human-review)
- **Guides** — [Multi-tenant Wazuh for MSSPs](https://soctalk.github.io/soctalk-docs/guides/multi-tenant-wazuh-mssp) · [AI triage for Wazuh alerts](https://soctalk.github.io/soctalk-docs/guides/ai-triage-wazuh-alerts) · [Onboarding a customer tenant](https://soctalk.github.io/soctalk-docs/guides/wazuh-tenant-onboarding) · [Open-source SOC stack](https://soctalk.github.io/soctalk-docs/guides/open-source-soc-stack)
- **Reference** — [Architecture](https://soctalk.github.io/soctalk-docs/reference/architecture) · [Security model](https://soctalk.github.io/soctalk-docs/reference/security-model) · [REST API](https://soctalk.github.io/soctalk-docs/reference/api)

Docs and the product site are available in seven languages: English,
Português, Español, 简体中文, Français, Deutsch, Italiano.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
and the [contributor guide](https://soctalk.github.io/soctalk-docs/contribute).

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
