# SocTalk

> Open-source, LLM-driven SOC automation. Continuously triages, investigates,
> and escalates Wazuh alerts — single-host for one team, or multi-tenant for
> MSPs and MSSPs.

![SocTalk Dashboard](docs/images/soctalk-dashboard.png)

SocTalk turns raw Wazuh alerts into investigated, prioritized, and (when you
allow it) auto-resolved cases. A two-tier LLM pipeline routes and reasons over
each alert, a human-in-the-loop step keeps an analyst in control, and a built-in
incident-response workflow records everything for audit and replay. And you can
just ask — a scope-aware chat answers questions about your SOC in plain English,
across the whole MSSP fleet or scoped to a single tenant. Apache-2.0,
Wazuh-powered, bring your own LLM, self-host anywhere.

## Try it in 5 minutes

Download a ready-to-run demo VM, boot it, and click through the setup wizard:

```bash
# qcow2 shown — pick the format for your hypervisor on the Downloads page
curl -L -O https://github.com/soctalk/soctalk/releases/download/v0.1.2/soctalk-demo-0.1.2.qcow2.xz
xz -d soctalk-demo-0.1.2.qcow2.xz

# Boot with KVM and forward the setup wizard to localhost:8443
qemu-system-x86_64 -m 8G -smp 4 -enable-kvm \
  -drive file=soctalk-demo-0.1.2.qcow2,if=virtio \
  -netdev user,id=n,hostfwd=tcp::8443-:8443 -device virtio-net,netdev=n -nographic
```

Then open `https://localhost:8443` and finish in the wizard. Other formats
(VMware, Hyper-V, Azure, AWS, Proxmox) and the full walkthrough:
**[Quickstart](https://soctalk.github.io/soctalk-docs/quickstart-vm)** ·
**[Downloads](https://soctalk.github.io/soctalk-docs/downloads)**.

## Features

- **Two-tier LLM triage** — fast router + reasoning verdict, with Anthropic or any OpenAI-compatible provider
- **Conversational chat** — ask the SocTalk agent in plain language; scope-aware across every tenant (MSSP-wide) or bound to one customer (tenant scope)
- **Flexible Wazuh** — provision a dedicated Wazuh SIEM per tenant, or connect SocTalk to a customer's existing Wazuh
- **Continuous Wazuh polling** with correlation and prioritization into investigations
- **Human-in-the-loop** approvals via dashboard, Slack, or CLI
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

## Documentation

Full docs live at **[soctalk.github.io/soctalk-docs](https://soctalk.github.io/soctalk-docs/)**:

- **Get started** — [Quickstart](https://soctalk.github.io/soctalk-docs/quickstart-vm) · [Downloads](https://soctalk.github.io/soctalk-docs/downloads) · [Setup wizard](https://soctalk.github.io/soctalk-docs/setup-wizard) · [Production install](https://soctalk.github.io/soctalk-docs/install)
- **Run on** — [Proxmox](https://soctalk.github.io/soctalk-docs/proxmox) · [AWS](https://soctalk.github.io/soctalk-docs/aws) · [Azure](https://soctalk.github.io/soctalk-docs/azure)
- **Concepts** — [AI pipeline](https://soctalk.github.io/soctalk-docs/ai-pipeline) · [Tenant lifecycle](https://soctalk.github.io/soctalk-docs/tenant-lifecycle) · [Human review](https://soctalk.github.io/soctalk-docs/human-review)
- **Reference** — [Architecture](https://soctalk.github.io/soctalk-docs/reference/architecture) · [Security model](https://soctalk.github.io/soctalk-docs/reference/security-model) · [REST API](https://soctalk.github.io/soctalk-docs/reference/api)

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
and the [contributor guide](https://soctalk.github.io/soctalk-docs/contribute).

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
