# SocTalk demo image — Packer config

Builds a SocTalk demo image with k3s, helm, and the soctalk-system
chart pre-installed. cloud-init remains enabled so the customer
customizes hostname, SSH keys, helm values, and the LLM key at first
boot. Same source produces an **AWS AMI** and a **QCOW2** (for
KVM / Proxmox).

OVA / Azure VHD / GCP image are easy follow-ons — drop in the matching
Packer source block.

## Layout

```
soctalk-demo.pkr.hcl    Packer config (sources + build block)
scripts/install.sh      Runs inside the build VM. Installs k3s + helm,
                        pre-pulls the chart, lays down the first-boot unit.
scripts/firstboot.sh    Runs at the customer's first boot. Reads their
                        cloud-init-provided config, installs the chart.
files/
  soctalk-firstboot.service  systemd unit that fires firstboot.sh
  values.example.yaml        Reference values file (shipped on image)
  seed/                      cloud-init seed used during the Packer build
                             only; cleaned up before the image is sealed
cloud-init.example.yaml  Example user-data the customer pastes
```

## Prerequisites

- Packer 1.10+ (`brew install packer` or apt)
- AWS credentials in env (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
  if you want the AMI source
- QEMU + cloud-image-utils on Linux if you want the QCOW2 source:
  `sudo apt install qemu-system-x86 cloud-image-utils`

## Build

```bash
cd infra/packer
packer init .
packer fmt .
packer validate -var "version=0.1.0" -var "soctalk_chart_version=0.1.0" .

# Both sources (AMI + QCOW2)
packer build -var "version=0.1.0" -var "soctalk_chart_version=0.1.0" .

# Only the AMI (skip the QCOW2 source)
packer build -only="soctalk-demo.amazon-ebs.soctalk_demo" \
  -var "version=0.1.0" -var "soctalk_chart_version=0.1.0" .

# Only the QCOW2
packer build -only="soctalk-demo.qemu.soctalk_demo" \
  -var "version=0.1.0" -var "soctalk_chart_version=0.1.0" .
```

QCOW2 lands in `build/qemu/soctalk-demo-<version>.qcow2`. AMI ID is
printed by Packer and tagged with `Project=soctalk`.

## Customer usage

### AWS

```bash
aws ec2 run-instances \
  --image-id ami-<id-from-packer> \
  --instance-type t3.xlarge \
  --user-data file://my-cloud-init.yaml \
  --key-name my-keypair
```

`my-cloud-init.yaml` is `cloud-init.example.yaml` with placeholders
replaced.

### Proxmox

```bash
# Import the qcow2
qm importdisk 9000 soctalk-demo-0.1.0.qcow2 local-lvm

# Create the VM (or clone from a template)
qm create 9000 --name soctalk-demo --memory 16384 --cores 8 ...
qm set 9000 --scsi0 local-lvm:vm-9000-disk-0,iothread=1
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --serial0 socket --vga serial0

# Set cloud-init user-data
qm set 9000 --cicustom "user=local:snippets/soctalk.yaml"
qm start 9000
```

### Raw QEMU/KVM

```bash
# Build the cloud-init seed ISO
cloud-localds seed.iso my-cloud-init.yaml

qemu-system-x86_64 -m 16384 -smp 8 \
  -drive file=soctalk-demo-0.1.0.qcow2,format=qcow2 \
  -drive file=seed.iso,format=raw \
  -netdev user,id=net0,hostfwd=tcp::8443-:443 \
  -device virtio-net,netdev=net0 \
  -nographic
```

Then browse to `https://localhost:8443` (or whichever hostname you
configured in `my-cloud-init.yaml`).

## SSH access + credentials

The image ships with **two** possible login identities depending on
whether cloud-init user-data has overridden the build-time state.

### Build-time `ubuntu` user (present in every shipped image)

Set by `files/seed/user-data` while Packer drives the install. The
current Packer build does **NOT** delete or lock this user, so anyone
who boots the image without supplying user-data — or before cloud-init
finishes processing it — can log in with the password baked into this
repo:

| User | Password | Sudo |
|---|---|---|
| `ubuntu` | `packer` | `ALL=(ALL) NOPASSWD:ALL` |

Password SSH auth is also turned on by the seed (`ssh_pwauth: true`),
so the image accepts password logins out of the box.

```bash
# Interactive
ssh ubuntu@<host>
# password: packer

# Non-interactive (requires sshpass)
sshpass -p packer ssh -o StrictHostKeyChecking=accept-new ubuntu@<host>

# Root shell — no further password
sudo -i
```

> [!WARNING]
> **The `ubuntu:packer` credential is in the public Git repo.** Any
> publicly-reachable VM booted from this image without a hardened
> cloud-init user-data is a one-line takeover. See the hardening
> section below.

### Production `ops` user (after cloud-init user-data runs)

The example user-data in [`cloud-init.example.yaml`](./cloud-init.example.yaml)
creates an `ops` user that's SSH-key-only — no password is set:

| User | Auth | Sudo |
|---|---|---|
| `ops` | `ssh_authorized_keys` from your user-data | `ALL=(ALL) NOPASSWD:ALL` |

```bash
ssh -i ~/.ssh/<your-private-key> ops@<host>

# Root shell — no further password
sudo -i
```

Replace `<host>` with the VM IP / hostname (varies by hypervisor —
`virsh domifaddr <domain>`, the VMware MOB, AWS public DNS, the
hostname you assigned via Proxmox, …).

### Hardening checklist

Until the Packer build itself locks the build-time creds (see
[Known follow-ons](#known-follow-ons)), the right operational hygiene
on every booted VM is:

```bash
# As ops (or while still on ubuntu) — disable the build user.
sudo passwd -l ubuntu
sudo usermod -s /usr/sbin/nologin ubuntu

# Disable password SSH auth cluster-wide.
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
sudo systemctl reload ssh
```

Or fold the same commands into your cloud-init `runcmd:` so they
fire on first boot.

## What's baked into the image vs. what the customer supplies

| Baked at Packer build | Supplied by customer cloud-init |
|---|---|
| Ubuntu 24.04 LTS, fully patched | Hostname |
| k3s (installed, not running) | SSH authorized_keys |
| helm | `/etc/soctalk/values.yaml` (msspName, ingress hostnames, etc.) |
| soctalk-system chart at `/opt/soctalk/charts/` | `/etc/soctalk/llm.key` (Anthropic / OpenAI key) |
| systemd unit `soctalk-firstboot.service` (enabled, not yet run) | |

The first-boot flow:

1. Customer boots an instance from the image
2. cloud-init reads user-data, writes `/etc/soctalk/values.yaml` + `/etc/soctalk/llm.key`
3. `soctalk-firstboot.service` fires after `cloud-final.service`
4. firstboot.sh: starts k3s → waits for API → creates LLM Secret →
   `helm install soctalk-system /opt/soctalk/charts/soctalk-system -f values.yaml`
5. Service marks itself done, disables, exits 0
6. Customer browses to the configured hostname

Total wait: ~2 min vs ~20 min for the pure cloud-init path because
k3s + chart are already on disk.

## Known follow-ons

- **Lock the build-time `ubuntu` user before sealing the image.** Add a
  final `provisioner "shell"` step to `soctalk-demo.pkr.hcl` that runs
  `passwd -l ubuntu && cloud-init clean --logs --seed` so the
  `ubuntu:packer` credential + the seed user-data don't ship in the
  released artifact. The packer config's comment at line 102 already
  promises this happens — the cleanup step just hasn't been wired up
  yet. See **SSH access + credentials → Hardening checklist** above.
- **Pre-pull container images.** Currently we pre-pull the chart but
  not the images it references. First boot still needs internet to
  pull from ghcr.io. Adding `ctr images pull` of the soctalk-*
  images in `install.sh` would close that gap at the cost of ~3 GB
  more disk in the image.
- **OVA / Azure VHD / GCP image** sources are straightforward
  additions — drop a `source "virtualbox-iso"` /
  `source "azure-arm"` / `source "googlecompute"` block and add it
  to `build.sources`.
- **CI.** Wired into `.github/workflows/build-packer-images.yml`
  (manual `workflow_dispatch`). Runs `packer build` and uploads the
  QCOW2 as a workflow artifact; on `v*` tags it attaches to the
  GitHub Release as well. (AMI publishing to AWS needs creds wired
  up separately.)
