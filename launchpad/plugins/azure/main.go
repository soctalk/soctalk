// launchpad-plugin-azure provisions Linux VMs on Microsoft Azure using the
// azure-sdk-for-go Azure Resource Manager clients (armcompute, armnetwork,
// armresources) authenticated with azidentity.
//
// Each VM is booted with a base64 cloud-init CustomData payload that installs
// and joins Tailscale and injects the VMSpec SSH public key(s). The launchpad
// orchestrator then reaches the VM over the tailnet via SSH. Every resource is
// tagged with lp-run-id / lp-vm-key so lookups are idempotent across runs.
//
// Lifecycle per VM: a Standard-SKU public IP, a NIC on a (created-if-missing)
// VNet+subnet, then the VM referencing the NIC. Destroy removes them in reverse
// order (VM, NIC, public IP, plugin-created VNet).
//
// Config (from launchpad, via plugin.initialize params.config):
//   subscription_id: Azure subscription (default env AZURE_SUBSCRIPTION_ID)
//   resource_group:  target resource group (required at create time)
//   location:        Azure region (default "eastus")
//   vm_size:         VM size (default "Standard_B2s")
//   image:           Marketplace image URN (default Ubuntu 24.04)
//   admin_user:      Linux admin username (default "ops")
//   tailnet:         optional tailnet hint (used as tailscale hostname suffix)
//   ssh_keys:        additional authorized public keys ([]string)
//
// Env:
//   AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET / AZURE_SUBSCRIPTION_ID
//   TAILSCALE_API_KEY (auth key used by cloud-init to join the tailnet)
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	sdk "github.com/soctalk/launchpad-sdk-go"
)

const (
	name    = "azure"
	version = "0.1.0"

	tagRunID   = "lp-run-id"
	tagVMKey   = "lp-vm-key"
	tagManaged = "lp-managed"

	sharedVNet   = "lp-vnet"
	sharedSubnet = "lp-subnet"

	defaultLocation = "eastus"
	defaultVMSize   = "Standard_B2s"
	defaultImage    = "Canonical:ubuntu-24_04-lts:server:latest"
	defaultAdmin    = "ops"
	defaultDiskGB   = 50 // OS disk; the SOC tenant (k3s + Wazuh) needs headroom
)

type config struct {
	SubscriptionID string   `json:"subscription_id,omitempty"`
	ResourceGroup  string   `json:"resource_group,omitempty"`
	Location       string   `json:"location,omitempty"`
	VMSize         string   `json:"vm_size,omitempty"`
	Image          string   `json:"image,omitempty"`
	AdminUser      string   `json:"admin_user,omitempty"`
	Tailnet        string   `json:"tailnet,omitempty"`
	TagPrefix      string   `json:"tag_prefix,omitempty"`
	DiskGB         int      `json:"disk_gb,omitempty"`
	SSHKeys        []string `json:"ssh_keys,omitempty"`
}

type plugin struct {
	cfg config

	cred      *azidentity.DefaultAzureCredential
	vms       *armcompute.VirtualMachinesClient
	nics      *armnetwork.InterfacesClient
	publicIPs *armnetwork.PublicIPAddressesClient
	vnets     *armnetwork.VirtualNetworksClient
	subnets   *armnetwork.SubnetsClient
}

var p plugin

// tsAPIKey is the Tailscale API key used to mint ephemeral device auth keys.
// Set once in initialize from the TAILSCALE_API_KEY env (injected per-run from
// the Network resource).
var tsAPIKey string

func main() {
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{
			"TAILSCALE_API_KEY",
			"AZURE_CLIENT_ID",
			"AZURE_TENANT_ID",
			"AZURE_CLIENT_SECRET",
			"AZURE_SUBSCRIPTION_ID",
			"HOME",
			"SSH_AUTH_SOCK",
		},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"subscription_id": map[string]any{"type": "string", "default": os.Getenv("AZURE_SUBSCRIPTION_ID")},
				"resource_group":  map[string]any{"type": "string"},
				"location":        map[string]any{"type": "string", "default": defaultLocation},
				"vm_size":         map[string]any{"type": "string", "default": defaultVMSize},
				"image":           map[string]any{"type": "string", "default": defaultImage},
				"disk_gb":         map[string]any{"type": "integer", "default": defaultDiskGB},
				"admin_user":      map[string]any{"type": "string", "default": defaultAdmin},
				"tailnet":         map[string]any{"type": "string"},
				"ssh_keys": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			},
			"required":             []any{"resource_group"},
			"additionalProperties": false,
		},

		Initialize: initialize,
		Plan:       plan,
		Create:     create,
		WaitReady:  waitReady,
		Destroy:    destroy,
		Inspect:    inspect,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "azure plugin:", err)
		os.Exit(1)
	}
}

func initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	cfg := config{
		Location:  defaultLocation,
		VMSize:    defaultVMSize,
		Image:     defaultImage,
		AdminUser: defaultAdmin,
	}
	cfg.SubscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")

	if v, ok := params.Config["subscription_id"].(string); ok && v != "" {
		cfg.SubscriptionID = v
	}
	if v, ok := params.Config["resource_group"].(string); ok {
		cfg.ResourceGroup = v
	}
	if v, ok := params.Config["location"].(string); ok && v != "" {
		cfg.Location = v
	}
	if v, ok := params.Config["vm_size"].(string); ok && v != "" {
		cfg.VMSize = v
	}
	if v, ok := params.Config["image"].(string); ok && v != "" {
		cfg.Image = v
	}
	if v, ok := params.Config["admin_user"].(string); ok && v != "" {
		cfg.AdminUser = v
	}
	if v, ok := params.Config["tailnet"].(string); ok {
		cfg.Tailnet = v
	}
	if v, ok := params.Config["tag_prefix"].(string); ok {
		cfg.TagPrefix = v
	}
	cfg.DiskGB = defaultDiskGB
	if raw, ok := params.Config["disk_gb"]; ok {
		switch n := raw.(type) {
		case float64:
			if int(n) > 0 {
				cfg.DiskGB = int(n)
			}
		case int:
			if n > 0 {
				cfg.DiskGB = n
			}
		}
	}
	if raw, ok := params.Config["ssh_keys"].([]any); ok {
		for _, k := range raw {
			if s, ok := k.(string); ok && s != "" {
				cfg.SSHKeys = append(cfg.SSHKeys, s)
			}
		}
	}
	p.cfg = cfg

	// Tailscale API key: injected per-run from the Network resource. Required to
	// mint the ephemeral device auth key baked into the VM's cloud-init.
	tsAPIKey = os.Getenv("TAILSCALE_API_KEY")

	if cfg.SubscriptionID == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed",
			"AZURE_SUBSCRIPTION_ID is not set (and subscription_id config is empty)")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed",
			"could not build Azure credential: %v", err)
	}
	p.cred = cred

	p.vms, err = armcompute.NewVirtualMachinesClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "compute client: %v", err)
	}
	p.nics, err = armnetwork.NewInterfacesClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "network interfaces client: %v", err)
	}
	p.publicIPs, err = armnetwork.NewPublicIPAddressesClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "public IP client: %v", err)
	}
	p.vnets, err = armnetwork.NewVirtualNetworksClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "virtual networks client: %v", err)
	}
	p.subnets, err = armnetwork.NewSubnetsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "subnets client: %v", err)
	}

	// One cheap authenticated call to validate creds: list resource groups
	// (first page only). Bounded so we don't hang on IMDS probes.
	rgClient, err := armresources.NewResourceGroupsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "resource groups client: %v", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	pager := rgClient.NewListPager(&armresources.ResourceGroupsClientListOptions{Top: to.Ptr[int32](1)})
	if _, err := pager.NextPage(pctx); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"azure.auth.failed", "Azure API probe failed: %v", err)
	}

	return sdk.InitializeResult{Ready: true}, nil
}

// ------------------------------------------------------------------
// plan / validation
// ------------------------------------------------------------------

func resolveSpec(spec *sdk.VMSpec) {
	if spec.Region == "" {
		spec.Region = p.cfg.Location
	}
	if spec.Image == "" {
		spec.Image = p.cfg.Image
	}
	if spec.SizeHint == "" {
		spec.SizeHint = p.cfg.VMSize
	}
	// Merge plugin-config SSH keys with spec keys.
	if len(p.cfg.SSHKeys) > 0 {
		spec.SSHKeys = append(append([]string{}, spec.SSHKeys...), p.cfg.SSHKeys...)
	}
}

func plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	spec := params.Spec
	resolveSpec(&spec)
	if err := validateSpec(spec); err != nil {
		return sdk.VMPlanResult{}, err
	}
	return sdk.VMPlanResult{
		Summary: fmt.Sprintf("azure: %s in %s (image=%s, rg=%s)",
			spec.SizeHint, spec.Region, spec.Image, p.cfg.ResourceGroup),
		EstimatedDurationSec: 120,
	}, nil
}

func validateSpec(spec sdk.VMSpec) error {
	if spec.RunID == "" || spec.VMKey == "" {
		return sdk.Errf(sdk.CatValidation, "azure.spec.missing_key",
			"run_id and vm_key are required")
	}
	if spec.Region == "" {
		return sdk.Errf(sdk.CatValidation, "azure.spec.missing_region",
			"location is required (set on VMSpec.Region or plugin config)")
	}
	if spec.Image == "" {
		return sdk.Errf(sdk.CatValidation, "azure.spec.missing_image",
			"image URN is required")
	}
	if spec.SizeHint == "" {
		return sdk.Errf(sdk.CatValidation, "azure.spec.missing_size",
			"vm_size is required (e.g. Standard_B2s)")
	}
	return nil
}

func requireClients() error {
	if p.vms == nil {
		return sdk.Errf(sdk.CatAuth,
			"azure.not_initialized",
			"plugin.initialize has not been called successfully (check Azure credentials)")
	}
	return nil
}

func requireResourceGroup() error {
	if p.cfg.ResourceGroup == "" {
		return sdk.Errf(sdk.CatValidation, "azure.config.missing_resource_group",
			"resource_group must be set in plugin config")
	}
	return nil
}

// ------------------------------------------------------------------
// create
// ------------------------------------------------------------------

func create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if err := requireClients(); err != nil {
		return sdk.VMCreateResult{}, err
	}
	if err := requireResourceGroup(); err != nil {
		return sdk.VMCreateResult{}, err
	}
	spec := params.Spec
	resolveSpec(&spec)
	if err := validateSpec(spec); err != nil {
		return sdk.VMCreateResult{}, err
	}

	rg := p.cfg.ResourceGroup
	base := resourceName(spec.RunID, spec.VMKey)

	emit.Progress("lookup", 5, "checking for existing VM")
	if existing, err := findVMByTags(ctx, spec.RunID, spec.VMKey); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"azure.list_failed", "listing existing VMs: %v", err)
	} else if existing != nil {
		emit.Log("info", "reusing existing VM", map[string]any{"vm": *existing.Name})
		ip := ""
		if addr, err := p.getPublicIPAddress(ctx, base+"-ip"); err == nil {
			ip = addr
		}
		return vmToCreateResult(existing, ip), nil
	}

	tags := baseTags(spec)

	// Mint a Tailscale ephemeral auth key and compose cloud-init that installs
	// Tailscale and joins the tailnet on first boot. The orchestrator then
	// resolves this VM by its tailnet hostname (lp-<vmKey>).
	emit.Progress("tailscale", 10, "minting device auth key")
	tag := tailscaleTagForSpec(spec)
	tskey, err := mintTailscaleKey(ctx, p.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}
	customData := base64.StdEncoding.EncodeToString([]byte(composeUserData(cloudInitInputs{
		Hostname:      hostnameFor(spec.VMKey),
		SSHKeys:       mergeSSHKeys(p.cfg.SSHKeys, spec.SSHKeys),
		TailscaleKey:  tskey,
		TailscaleTag:  tag,
		ExtraUserData: spec.UserData,
	})))

	// 1. Ensure VNet + subnet, get subnet ID.
	emit.Progress("network", 15, "ensuring virtual network")
	subnetID, err := p.ensureSubnet(ctx, rg, spec.Region, tags)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// 2. Public IP (Standard SKU, static).
	emit.Progress("network", 30, "creating public IP")
	ipID, err := p.createPublicIP(ctx, rg, spec.Region, base+"-ip", tags)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// 3. NIC referencing subnet + public IP.
	emit.Progress("network", 45, "creating network interface")
	nicID, err := p.createNIC(ctx, rg, spec.Region, base+"-nic", subnetID, ipID, tags)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// 4. VM referencing the NIC.
	emit.Progress("create", 60, "creating virtual machine")
	vm, err := p.createVM(ctx, rg, spec, base, nicID, customData, tags)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	emit.Progress("create", 90, "resolving public IP")
	ip, _ := p.getPublicIPAddress(ctx, base+"-ip")

	emit.Progress("create", 100, "VM created")
	return vmToCreateResult(vm, ip), nil
}

// ensureSubnet creates the shared lp-vnet + lp-subnet if absent and returns the
// subnet resource ID. BeginCreateOrUpdate is idempotent.
func (pl *plugin) ensureSubnet(ctx context.Context, rg, location string, tags map[string]*string) (string, error) {
	// Try the existing subnet first.
	if got, err := pl.subnets.Get(ctx, rg, sharedVNet, sharedSubnet, nil); err == nil && got.ID != nil {
		return *got.ID, nil
	}

	poller, err := pl.vnets.BeginCreateOrUpdate(ctx, rg, sharedVNet, armnetwork.VirtualNetwork{
		Location: to.Ptr(location),
		Tags:     tags,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr("10.10.0.0/16")},
			},
			Subnets: []*armnetwork.Subnet{
				{
					Name: to.Ptr(sharedSubnet),
					Properties: &armnetwork.SubnetPropertiesFormat{
						AddressPrefix: to.Ptr("10.10.0.0/24"),
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.vnet.create_failed", "%v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.vnet.create_failed", "%v", err)
	}
	if res.Properties != nil {
		for _, sn := range res.Properties.Subnets {
			if sn.Name != nil && *sn.Name == sharedSubnet && sn.ID != nil {
				return *sn.ID, nil
			}
		}
	}
	// Fall back to a fresh Get.
	got, err := pl.subnets.Get(ctx, rg, sharedVNet, sharedSubnet, nil)
	if err != nil || got.ID == nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.subnet.lookup_failed", "%v", err)
	}
	return *got.ID, nil
}

func (pl *plugin) createPublicIP(ctx context.Context, rg, location, ipName string, tags map[string]*string) (string, error) {
	poller, err := pl.publicIPs.BeginCreateOrUpdate(ctx, rg, ipName, armnetwork.PublicIPAddress{
		Location: to.Ptr(location),
		Tags:     tags,
		SKU: &armnetwork.PublicIPAddressSKU{
			Name: to.Ptr(armnetwork.PublicIPAddressSKUNameStandard),
		},
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
		},
	}, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.public_ip.create_failed", "%v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.public_ip.create_failed", "%v", err)
	}
	if res.ID == nil {
		return "", sdk.Errf(sdk.CatInternal, "azure.public_ip.no_id", "public IP has no ID")
	}
	return *res.ID, nil
}

func (pl *plugin) createNIC(ctx context.Context, rg, location, nicName, subnetID, ipID string, tags map[string]*string) (string, error) {
	poller, err := pl.nics.BeginCreateOrUpdate(ctx, rg, nicName, armnetwork.Interface{
		Location: to.Ptr(location),
		Tags:     tags,
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("ipconfig1"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						Primary:                   to.Ptr(true),
						PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
						Subnet:                    &armnetwork.Subnet{ID: to.Ptr(subnetID)},
						PublicIPAddress:           &armnetwork.PublicIPAddress{ID: to.Ptr(ipID)},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.nic.create_failed", "%v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"azure.nic.create_failed", "%v", err)
	}
	if res.ID == nil {
		return "", sdk.Errf(sdk.CatInternal, "azure.nic.no_id", "NIC has no ID")
	}
	return *res.ID, nil
}

func (pl *plugin) createVM(ctx context.Context, rg string, spec sdk.VMSpec, base, nicID, customData string, tags map[string]*string) (*armcompute.VirtualMachine, error) {
	imgRef, err := parseImageURN(spec.Image)
	if err != nil {
		return nil, err
	}

	var sshKeys []*armcompute.SSHPublicKey
	for _, pub := range spec.SSHKeys {
		pub = strings.TrimSpace(pub)
		if pub == "" {
			continue
		}
		sshKeys = append(sshKeys, &armcompute.SSHPublicKey{
			KeyData: to.Ptr(pub),
			Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", pl.cfg.AdminUser)),
		})
	}

	poller, err := pl.vms.BeginCreateOrUpdate(ctx, rg, base, armcompute.VirtualMachine{
		Location: to.Ptr(spec.Region),
		Tags:     tags,
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(spec.SizeHint)),
			},
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: imgRef,
				OSDisk: &armcompute.OSDisk{
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					// Size the OS disk so the SOC tenant (k3s + Wazuh) has room;
					// the image default is too small and triggers DiskPressure.
					DiskSizeGB: to.Ptr(int32(pl.cfg.DiskGB)),
					// Delete the managed OS disk when the VM is deleted; otherwise
					// Azure leaves it behind as a billable orphan on teardown.
					DeleteOption: to.Ptr(armcompute.DiskDeleteOptionTypesDelete),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS),
					},
				},
			},
			OSProfile: &armcompute.OSProfile{
				ComputerName:  to.Ptr(computerName(base)),
				AdminUsername: to.Ptr(pl.cfg.AdminUser),
				CustomData:    to.Ptr(customData),
				LinuxConfiguration: &armcompute.LinuxConfiguration{
					DisablePasswordAuthentication: to.Ptr(true),
					SSH: &armcompute.SSHConfiguration{
						PublicKeys: sshKeys,
					},
				},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.Ptr(nicID),
						Properties: &armcompute.NetworkInterfaceReferenceProperties{
							Primary: to.Ptr(true),
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"azure.vm.create_failed", "%v", err)
	}
	res, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"azure.vm.create_failed", "%v", err)
	}
	return &res.VirtualMachine, nil
}

// ------------------------------------------------------------------
// wait_ready
// ------------------------------------------------------------------

func waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if err := requireClients(); err != nil {
		return sdk.VMWaitReadyResult{}, err
	}
	if err := requireResourceGroup(); err != nil {
		return sdk.VMWaitReadyResult{}, err
	}
	rg := p.cfg.ResourceGroup
	vmName := params.VMID
	if vmName == "" {
		vmName = resourceName(params.RunID, params.VMKey)
	}

	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		state, err := p.powerState(ctx, rg, vmName)
		if err != nil {
			return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatNotFound,
				"azure.instance_view.failed", "%v", err)
		}
		if state == "running" {
			ip, _ := p.getPublicIPAddress(ctx, resourceName(params.RunID, params.VMKey)+"-ip")
			if ip == "" && params.VMID != "" {
				ip, _ = p.getPublicIPAddress(ctx, params.VMID+"-ip")
			}
			emit.Progress("wait_ready", 100, "running")
			return sdk.VMWaitReadyResult{Ready: true, IPv4: ip}, nil
		}
		emit.Progress("wait_ready", 50, "power state: "+state)
		select {
		case <-ctx.Done():
			return sdk.VMWaitReadyResult{}, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"azure.wait_ready.timeout", "VM did not reach running within 20m")
}

// ------------------------------------------------------------------
// destroy
// ------------------------------------------------------------------

func destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if err := requireClients(); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	if err := requireResourceGroup(); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	rg := p.cfg.ResourceGroup

	base := params.VMID
	if base == "" {
		base = resourceName(params.RunID, params.VMKey)
	}

	// Determine whether the VM actually exists (idempotency signal).
	existed := false
	if _, err := p.vms.Get(ctx, rg, base, nil); err == nil {
		existed = true
	} else if found, ferr := findVMByTags(ctx, params.RunID, params.VMKey); ferr == nil && found != nil {
		existed = true
		base = *found.Name
	}
	if !existed {
		return sdk.VMDestroyResult{Destroyed: false}, nil
	}

	// Delete in dependency order: VM, then NIC, then public IP.
	emit.Progress("destroy", 30, "deleting VM")
	if err := p.deleteVM(ctx, rg, base); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	emit.Progress("destroy", 60, "deleting NIC")
	if err := p.deleteNIC(ctx, rg, base+"-nic"); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	emit.Progress("destroy", 85, "deleting public IP")
	if err := p.deletePublicIP(ctx, rg, base+"-ip"); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	emit.Progress("destroy", 100, "destroyed")
	return sdk.VMDestroyResult{Destroyed: true}, nil
}

func (pl *plugin) deleteVM(ctx context.Context, rg, vmName string) error {
	poller, err := pl.vms.BeginDelete(ctx, rg, vmName, nil)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.vm.delete_failed", "%v", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.vm.delete_failed", "%v", err)
	}
	return nil
}

func (pl *plugin) deleteNIC(ctx context.Context, rg, nicName string) error {
	poller, err := pl.nics.BeginDelete(ctx, rg, nicName, nil)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.nic.delete_failed", "%v", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.nic.delete_failed", "%v", err)
	}
	return nil
}

func (pl *plugin) deletePublicIP(ctx context.Context, rg, ipName string) error {
	poller, err := pl.publicIPs.BeginDelete(ctx, rg, ipName, nil)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.public_ip.delete_failed", "%v", err)
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return sdk.Errf(sdk.CatProviderUnavailable, "azure.public_ip.delete_failed", "%v", err)
	}
	return nil
}

// ------------------------------------------------------------------
// inspect
// ------------------------------------------------------------------

func inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if err := requireClients(); err != nil {
		return sdk.VMInspectResult{}, err
	}
	if err := requireResourceGroup(); err != nil {
		return sdk.VMInspectResult{}, err
	}
	rg := p.cfg.ResourceGroup

	base := params.VMID
	if base == "" {
		base = resourceName(params.RunID, params.VMKey)
	}

	got, err := p.vms.Get(ctx, rg, base, nil)
	if err != nil {
		if isNotFound(err) {
			// Try tag-based lookup as a fallback.
			if found, ferr := findVMByTags(ctx, params.RunID, params.VMKey); ferr == nil && found != nil {
				base = *found.Name
				got, err = p.vms.Get(ctx, rg, base, nil)
			}
		}
		if err != nil {
			if isNotFound(err) {
				return sdk.VMInspectResult{Exists: false}, nil
			}
			return sdk.VMInspectResult{}, sdk.Errf(sdk.CatInternal,
				"azure.get_failed", "%v", err)
		}
	}

	state, _ := p.powerState(ctx, rg, base)
	ip, _ := p.getPublicIPAddress(ctx, base+"-ip")
	return sdk.VMInspectResult{
		Exists:  true,
		VMID:    base,
		State:   state,
		IPv4:    ip,
		SSHUser: p.cfg.AdminUser,
		Metadata: map[string]string{
			"provider":       "azure",
			"resource_group": rg,
			"location":       derefStr(got.Location),
		},
	}, nil
}

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

func baseTags(spec sdk.VMSpec) map[string]*string {
	tags := map[string]*string{
		tagRunID:   to.Ptr(spec.RunID),
		tagVMKey:   to.Ptr(spec.VMKey),
		tagManaged: to.Ptr("true"),
	}
	for k, v := range spec.Tags {
		tags[k] = to.Ptr(v)
	}
	return tags
}

// findVMByTags locates a VM previously created for this (run_id, vm_key).
func findVMByTags(ctx context.Context, runID, vmKey string) (*armcompute.VirtualMachine, error) {
	pager := p.vms.NewListPager(p.cfg.ResourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vm := range page.Value {
			if vm.Tags == nil {
				continue
			}
			if derefStr(vm.Tags[tagRunID]) == runID && derefStr(vm.Tags[tagVMKey]) == vmKey {
				return vm, nil
			}
		}
	}
	return nil, nil
}

// powerState reads the VM instance view and maps PowerState to a status string.
func (pl *plugin) powerState(ctx context.Context, rg, vmName string) (string, error) {
	iv, err := pl.vms.InstanceView(ctx, rg, vmName, nil)
	if err != nil {
		return "", err
	}
	for _, s := range iv.Statuses {
		code := derefStr(s.Code)
		if strings.HasPrefix(code, "PowerState/") {
			return mapPowerState(strings.TrimPrefix(code, "PowerState/")), nil
		}
	}
	return "unknown", nil
}

func mapPowerState(ps string) string {
	switch strings.ToLower(ps) {
	case "running":
		return "running"
	case "starting":
		return "starting"
	case "stopped", "deallocated", "stopping", "deallocating":
		return "stopped"
	default:
		return "unknown"
	}
}

func (pl *plugin) getPublicIPAddress(ctx context.Context, ipName string) (string, error) {
	got, err := pl.publicIPs.Get(ctx, pl.cfg.ResourceGroup, ipName, nil)
	if err != nil {
		return "", err
	}
	if got.Properties != nil && got.Properties.IPAddress != nil {
		return *got.Properties.IPAddress, nil
	}
	return "", nil
}

func vmToCreateResult(vm *armcompute.VirtualMachine, ip string) sdk.VMCreateResult {
	vmName := derefStr(vm.Name)
	loc := derefStr(vm.Location)
	size := ""
	if vm.Properties != nil && vm.Properties.HardwareProfile != nil && vm.Properties.HardwareProfile.VMSize != nil {
		size = string(*vm.Properties.HardwareProfile.VMSize)
	}
	res := sdk.VMCreateResult{
		VMID:    vmName,
		IPv4:    ip,
		SSHUser: p.cfg.AdminUser,
		SSHPort: 22,
		Metadata: map[string]string{
			"provider":       "azure",
			"resource_group": p.cfg.ResourceGroup,
			"location":       loc,
			"vm_size":        size,
		},
	}
	if vm.ID != nil {
		res.ProviderURL = "https://portal.azure.com/#@/resource" + *vm.ID
	}
	return res
}

// parseImageURN splits "Publisher:Offer:SKU:Version" into an ImageReference.
func parseImageURN(urn string) (*armcompute.ImageReference, error) {
	parts := strings.Split(urn, ":")
	if len(parts) != 4 {
		return nil, sdk.Errf(sdk.CatValidation, "azure.image.bad_urn",
			"image URN %q must be Publisher:Offer:SKU:Version", urn)
	}
	return &armcompute.ImageReference{
		Publisher: to.Ptr(parts[0]),
		Offer:     to.Ptr(parts[1]),
		SKU:       to.Ptr(parts[2]),
		Version:   to.Ptr(parts[3]),
	}, nil
}

// --- Tailscale join + cloud-init composition -------------------------------
// Ported from the qemu-family plugins: cloud VMs join the tailnet on first boot
// via a plugin-minted ephemeral auth key baked into cloud-init. The orchestrator
// discovers each VM by its tailnet hostname (lp-<vmKey>) rather than a public IP.

type cloudInitInputs struct {
	Hostname      string
	SSHKeys       []string
	TailscaleKey  string
	TailscaleTag  string
	ExtraUserData string
}

// composeUserData builds a #cloud-config that provisions the ops user, installs
// Tailscale, and joins the tailnet with the minted auth key.
func composeUserData(in cloudInitInputs) string {
	var b bytes.Buffer
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", in.Hostname)
	b.WriteString("manage_etc_hosts: true\n")
	b.WriteString("users:\n")
	b.WriteString("  - default\n")
	b.WriteString("  - name: ops\n")
	b.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
	b.WriteString("    shell: /bin/bash\n")
	if len(in.SSHKeys) > 0 {
		b.WriteString("    ssh_authorized_keys:\n")
		for _, k := range in.SSHKeys {
			fmt.Fprintf(&b, "      - %s\n", k)
		}
	}
	b.WriteString("package_update: true\n")
	b.WriteString("packages: [curl, ca-certificates, jq]\n")
	b.WriteString("runcmd:\n")
	b.WriteString("  - curl -fsSL https://tailscale.com/install.sh | sh\n")
	fmt.Fprintf(&b,
		"  - tailscale up --auth-key=%q --advertise-tags=%s --hostname=%s\n",
		in.TailscaleKey, in.TailscaleTag, in.Hostname)
	if in.ExtraUserData != "" {
		for _, line := range strings.Split(strings.TrimSpace(in.ExtraUserData), "\n") {
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}
	return b.String()
}

// mintTailscaleKey creates a single-use, ephemeral, pre-authorized device auth
// key tagged for this VM. Requires TAILSCALE_API_KEY (tsAPIKey).
func mintTailscaleKey(ctx context.Context, tailnet, tag string) (string, error) {
	if tailnet == "" {
		return "", sdk.Errf(sdk.CatValidation, "azure.tailscale.no_tailnet", "tailnet is empty")
	}
	if tsAPIKey == "" {
		return "", sdk.Errf(sdk.CatAuth, "azure.tailscale.no_api_key",
			"TAILSCALE_API_KEY is required for minting device auth keys")
	}
	payload := map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     true,
					"preauthorized": true,
					"tags":          []string{tag},
				},
			},
		},
		"expirySeconds": 3600,
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/keys", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable, "azure.tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth, "azure.tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal, "azure.tailscale.key_missing",
			"no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

// tailscaleTagForSpec derives the advertised tag from the VM role/slug so the
// tailnet ACL can group MSSP and tenant devices. Matches the qemu/vmware plugins.
func tailscaleTagForSpec(spec sdk.VMSpec) string {
	prefix := p.cfg.TagPrefix
	role := spec.Tags["role"]
	slug := spec.Tags["tenant_slug"]
	if role == "mssp" {
		return "tag:" + prefix + "mssp"
	}
	if role == "tenant" && slug != "" {
		return "tag:" + prefix + "tenant-" + slug
	}
	return "tag:" + prefix + "lp-" + spec.VMKey
}

func hostnameFor(vmKey string) string {
	return "lp-" + sanitizeHostname(vmKey)
}

func sanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		buf := make([]byte, 4)
		_, _ = rand.Read(buf)
		out = "lp-" + hex.EncodeToString(buf)
	}
	return out
}

func mergeSSHKeys(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, k := range append(append([]string{}, a...), b...) {
		if k = strings.TrimSpace(k); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// resourceName builds the "lp-<runID>-<vmKey>" base name, sanitized for Azure.
func resourceName(runID, vmKey string) string {
	return "lp-" + sanitize(runID) + "-" + sanitize(vmKey)
}

// computerName sanitizes for a Linux hostname (<= 63 chars, alnum + dash).
func computerName(base string) string {
	n := strings.Trim(base, "-")
	if len(n) > 63 {
		n = n[:63]
	}
	return strings.Trim(n, "-")
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "notfound") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "resourcenotfound") ||
		strings.Contains(msg, "statuscode: 404") ||
		strings.Contains(msg, "404 not found")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
