// Package orchestrator drives the MSSP-pilot flow: provision MSSP + tenant
// VMs on a chosen plugin target, gate on manual operator confirmations
// (Tailscale ACL paste), and run to completion.
//
// It emits a stream of events so both the TUI and the headless `drive`
// subcommand can observe + drive.
package orchestrator

import "strings"

// TargetSep separates the platform (plugin name) from the host identity inside
// a composed target key, e.g. "aws@acme-prod". The platform half selects the
// plugin binary; the host half keeps two distinct hosts on the same platform
// from sharing one plugin subprocess and one set of credentials.
const TargetSep = "@"

// PlatformOfTarget returns the plugin/platform name embedded in a target key.
// A bare platform name (no separator, as written in hand-authored YAML) is
// returned unchanged.
func PlatformOfTarget(target string) string {
	if i := strings.IndexByte(target, '@'); i >= 0 {
		return target[:i]
	}
	return target
}

// Config is the shape of the launchpad's own config (distinct from any
// per-plugin config which the launchpad passes through opaquely).
type Config struct {
	RunID string `json:"run_id" yaml:"run_id"`

	// Target is the plugin name to use for VM provisioning.
	Target string `json:"target" yaml:"target"`

	// PluginConfig is passed opaquely to the target plugin's Initialize.
	PluginConfig map[string]any `json:"plugin_config,omitempty" yaml:"plugin_config,omitempty"`

	// SSHKeys are the public keys authorized on every provisioned VM.
	SSHKeys []string `json:"ssh_keys,omitempty" yaml:"ssh_keys,omitempty"`

	// MSSP is the control-plane VM spec.
	MSSP VMSpec `json:"mssp" yaml:"mssp"`

	// Tenants are per-customer VMs.
	Tenants []VMSpec `json:"tenants,omitempty" yaml:"tenants,omitempty"`

	// Install drives the post-provision phase. If empty, install is skipped
	// (VMs are provisioned but SocTalk is not installed).
	Install InstallConfig `json:"install,omitempty" yaml:"install,omitempty"`
}

// InstallConfig configures the post-provision SocTalk install. The launchpad
// SSHes into each VM (via the tailnet) and runs the public installer.
type InstallConfig struct {
	// InstallerURL is where curl fetches the installer from. Defaults to
	// the main branch of github.com/soctalk/soctalk if empty.
	InstallerURL string `json:"installer_url,omitempty" yaml:"installer_url,omitempty"`

	// MSSP admin bootstrap. Consumed by SOCTALK_ADMIN_* env vars.
	MSSPAdminEmail    string `json:"mssp_admin_email,omitempty" yaml:"mssp_admin_email,omitempty"`
	MSSPAdminPassword string `json:"mssp_admin_password,omitempty" yaml:"mssp_admin_password,omitempty"`
	MSSPDisplayName   string `json:"mssp_display_name,omitempty" yaml:"mssp_display_name,omitempty"`

	// LLM provider config. install.sh requires these even for a smoke test —
	// a placeholder key is fine when the pilot flow doesn't exercise the LLM.
	LLMProvider string `json:"llm_provider,omitempty" yaml:"llm_provider,omitempty"`
	LLMAPIKey   string `json:"llm_api_key,omitempty" yaml:"llm_api_key,omitempty"`

	// Optional: SSH user to log in as (default: ops).
	SSHUser string `json:"ssh_user,omitempty" yaml:"ssh_user,omitempty"`
}

// VMSpec is the launchpad-side desired-state for one VM. It's a subset of
// sdk.VMSpec augmented with orchestration hints (Role, TenantSlug) and
// optional per-VM plugin overrides (Target, PluginConfig) so a single
// pilot can span multiple hypervisors (e.g. MSSP on qemu, tenant on vmware).
type VMSpec struct {
	Key      string            `json:"key" yaml:"key"`
	Name     string            `json:"name" yaml:"name"`
	Region   string            `json:"region" yaml:"region"`
	Image    string            `json:"image" yaml:"image"`
	SizeHint string            `json:"size_hint" yaml:"size_hint"`
	Tags     map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`

	Role string `json:"role" yaml:"role"`
	// TenantSlug is set when Role=="tenant". Must match a Tailscale ACL tag.
	TenantSlug string `json:"tenant_slug,omitempty" yaml:"tenant_slug,omitempty"`

	// Target optionally overrides the top-level Config.Target for this VM.
	// Empty → inherit from Config.Target.
	Target string `json:"target,omitempty" yaml:"target,omitempty"`

	// PluginConfig optionally overrides the top-level Config.PluginConfig
	// when this VM's Target differs. Empty → inherit from Config.PluginConfig.
	PluginConfig map[string]any `json:"plugin_config,omitempty" yaml:"plugin_config,omitempty"`
}

// EffectiveTarget returns the plugin name to use for a VM: its own Target
// override, or falls back to the run-level default.
func (v VMSpec) EffectiveTarget(defaultTarget string) string {
	if v.Target != "" {
		return v.Target
	}
	return defaultTarget
}

// EffectivePluginConfig returns the plugin_config to pass to Initialize for
// a VM. If the VM overrides Target but not PluginConfig, or vice versa, we
// fall back to the run-level default for the missing piece.
func (v VMSpec) EffectivePluginConfig(defaultCfg map[string]any) map[string]any {
	if len(v.PluginConfig) > 0 {
		return v.PluginConfig
	}
	return defaultCfg
}
