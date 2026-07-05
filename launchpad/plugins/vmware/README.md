# vmware plugin

Provisions Ubuntu VMs on a standalone VMware ESXi 7/8 host, using govmomi + guestinfo cloud-init.

## Design

Per the [codex design review](https://github.com/soctalk/launchpad/discussions/...):

1. **govmomi (`github.com/vmware/govmomi`)** as the vSphere API client.
2. **Cloud-init via guestinfo** (base64 `guestinfo.userdata` + `guestinfo.metadata` in `ExtraConfig`). Ubuntu's cloud image ships with the VMware datasource enabled; no seed ISO required.
3. **OVA-import on first create.** Downloads the Ubuntu Noble cloud OVA (~500 MB, cached in RAM for the process lifetime), extracts the OVF + VMDKs in Go, and imports via `ovf.Manager.CreateImportSpec` → `ResourcePool.ImportVApp` → `nfc.Lease.Upload`. Subsequent creates clone the imported base VM (`lp-base-<sha1(ovaURL)[:8]>`).
4. **No pre-imported templates required.** The plugin manages its own base VM. If you want to override with a specific existing VM as clone source, set `base_vm: <name>`.

## Config

```yaml
plugin_config:
  esxi_url:   https://<esxi-host>[:port]/
  datastore:  datastore1
  network:    "VM Network"           # default port group name on standalone ESXi
  tailnet:    <your-tailnet>.ts.net
  cpu:        4
  memory_mb:  8192
  disk_gb:    60
  ssh_keys:
    - "ssh-ed25519 AAAA... you@laptop"

  # Optional overrides
  ova_url:    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.ova
  base_vm:    lp-base-my-golden       # override the plugin-managed base VM name
```

## Environment

```bash
export ESXI_URL=https://<esxi-host>/
export ESXI_USERNAME=root
export ESXI_PASSWORD='<esxi-root-password>'
export TAILSCALE_API_KEY=tskey-api-...
```

The manifest's `env:` allow-list forwards all four to the plugin subprocess.

## ESXi prerequisites

- ESXi 7.0 or newer, licensed or in the 60-day eval mode.
- A VMFS datastore with ≥15 GB free per VM (imported base VM + a thin-provisioned clone).
- A port group named as configured (the default `VM Network` works out of the box).
- `root` (or a user with equivalent Datastore.Browse + VirtualMachine.Provisioning.Deploy + VApp.Import privileges).

## Build + verify

```bash
go build -o bin/plugin .
LAUNCHPAD_PLUGIN_DIR=../ launchpad plugin verify vmware
```

## Known limitations

- **Standalone ESXi only.** Not vCenter-aware (no cluster or DRS placement).
- **In-memory OVA hold.** The whole OVA (~500 MB for Noble) is held in RAM once per plugin process. Not a concern on operator hardware, would be for a shared runner. Follow-up: stream via scratch dir.
- **No delta-clone.** Cloning uses full clone; ~4 min per VM on a nested ESXi setup. Follow-up: linked clones.
- **Network is DHCP-only.** No static IP configuration in `guestinfo.metadata`. Follow-up: parse network config from the config.
