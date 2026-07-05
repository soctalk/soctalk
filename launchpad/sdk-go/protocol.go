// Package sdk implements the Launchpad plugin protocol (v1).
//
// Wire format: line-delimited JSON-RPC 2.0 on stdio.
//   stdin  : launchpad -> plugin (requests + shutdown notification)
//   stdout : plugin -> launchpad (RPC responses + progress/log notifications)
//   stderr : unstructured human logs for developer eyes only; not parsed
//
// Rules:
//   - Exactly one compact UTF-8 JSON object per line (no pretty-printing).
//   - Max message size: MaxMessageBytes. Larger messages abort the plugin.
//   - Stdout is protocol only. Any non-JSON on stdout is a protocol violation
//     and the plugin will be killed by the parent.
//
// Handshake:
//   1. Plugin emits "plugin.hello" notification (unsolicited) on start.
//   2. Launchpad sends "plugin.initialize" request; plugin replies ok/err.
//   3. Launchpad dispatches method requests one at a time per subprocess.
//   4. Launchpad sends "plugin.shutdown" request; plugin flushes + replies;
//      5s grace, then parent closes stdin, then SIGTERM, then SIGKILL.
package sdk

const (
	// ProtocolVersion identifies the wire protocol; incremented on breaking
	// changes.
	ProtocolVersion = "1"

	// MaxMessageBytes caps a single JSON-RPC message. Anything larger is a
	// protocol violation.
	MaxMessageBytes = 4 * 1024 * 1024 // 4 MiB
)

// JSONRPC framing (v2.0).
type (
	// Envelope covers both requests and responses. Notifications omit ID.
	Envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      *int64          `json:"id,omitempty"`
		Method  string          `json:"method,omitempty"`
		Params  any             `json:"params,omitempty"`
		Result  any             `json:"result,omitempty"`
		Error   *ProtocolError  `json:"error,omitempty"`
	}
)

// ProtocolError is the JSON-RPC 2.0 error object with our extended fields.
//
// Category is a required stable enum for launchpad UI classification.
// Code is a plugin-owned namespaced string (e.g. "hetzner.credentials.missing").
// Retry describes when/whether to retry.
type ProtocolError struct {
	// JSON-RPC 2.0 required fields.
	Code    int    `json:"code"`
	Message string `json:"message"`

	// Launchpad extensions carried in Data.
	Data *ErrorData `json:"data,omitempty"`
}

// ErrorData carries launchpad-specific error metadata.
type ErrorData struct {
	Category ErrorCategory `json:"category"`
	AppCode  string        `json:"app_code"` // namespaced plugin code
	Hint     string        `json:"hint,omitempty"`
	DocsURL  string        `json:"docs_url,omitempty"`
	Retry    *RetryPolicy  `json:"retry,omitempty"`
}

// ErrorCategory is the stable enum launchpad uses to classify plugin errors.
type ErrorCategory string

const (
	CatAuth               ErrorCategory = "auth"
	CatValidation         ErrorCategory = "validation"
	CatQuota              ErrorCategory = "quota"
	CatRateLimited        ErrorCategory = "rate_limited"
	CatTimeout            ErrorCategory = "timeout"
	CatConflict           ErrorCategory = "conflict"
	CatNotFound           ErrorCategory = "not_found"
	CatProviderUnavailable ErrorCategory = "provider_unavailable"
	CatCancelled          ErrorCategory = "cancelled"
	CatInternal           ErrorCategory = "internal"
)

// RetryPolicy tells launchpad how to handle retry for this error.
type RetryPolicy struct {
	// Mode: "never", "immediate", "backoff", "manual" (operator decides).
	Mode       string `json:"mode"`
	AfterMS    int64  `json:"after_ms,omitempty"`     // suggested wait
	MaxAttempts int   `json:"max_attempts,omitempty"` // 0 = unbounded
}

// Standard JSON-RPC 2.0 error codes we use.
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternalError  = -32603

	// Application-defined range: -32000 to -32099
	ErrPluginInternal = -32000
	ErrHandshake      = -32001
	ErrShutdown       = -32002
)

// ------------------------------------------------------------------
// Method names
// ------------------------------------------------------------------

const (
	// Plugin-initiated notifications (no response expected).
	MethodHello    = "plugin.hello"    // sent once by plugin on start
	MethodProgress = "progress"        // per-request progress updates
	MethodLog      = "log"             // structured UI-facing log lines

	// Launchpad-initiated requests to the plugin.
	MethodInitialize = "plugin.initialize"
	MethodShutdown   = "plugin.shutdown"

	MethodVMPlan      = "vm.plan"
	MethodVMCreate    = "vm.create"
	MethodVMWaitReady = "vm.wait_ready"
	MethodVMDestroy   = "vm.destroy"
	MethodVMInspect   = "vm.inspect"
)

// ------------------------------------------------------------------
// Handshake payloads
// ------------------------------------------------------------------

// HelloParams is the payload of the plugin.hello notification.
//
// Metadata only. No credentials, no network calls.
type HelloParams struct {
	ProtocolVersion string   `json:"protocol_version"`
	PluginName      string   `json:"plugin_name"`
	PluginVersion   string   `json:"plugin_version"`
	Capabilities    []string `json:"capabilities"`
	// JSON schema (draft-2020-12) for this plugin's expected config.
	// The launchpad validates operator input against this before calling
	// initialize.
	ConfigSchema map[string]any `json:"config_schema,omitempty"`
	// AllowedEnvVars declares which environment variables the plugin needs
	// launchpad to pass through. Launchpad starts the plugin with a *clean*
	// env plus these variables.
	AllowedEnvVars []string `json:"allowed_env_vars,omitempty"`
}

// InitializeParams is the payload of the plugin.initialize request.
type InitializeParams struct {
	RunID      string         `json:"run_id"`
	Config     map[string]any `json:"config"`
	LogLevel   string         `json:"log_level"` // "debug" | "info" | "warn" | "error"
	DryRun     bool           `json:"dry_run,omitempty"`
}

// InitializeResult is what the plugin returns on successful initialize.
type InitializeResult struct {
	// Ready is true if credentials probed OK and the plugin is ready to serve.
	Ready bool `json:"ready"`
}

// ShutdownParams is the payload of plugin.shutdown. Empty for now.
type ShutdownParams struct{}

// ShutdownResult is what plugin returns on successful shutdown.
type ShutdownResult struct{}

// ------------------------------------------------------------------
// VM lifecycle payloads
// ------------------------------------------------------------------

// VMSpec is the launchpad-authored desired-state for a VM. Plugins are
// pass-throughs; they don't parse SocTalk config, they just apply the spec.
type VMSpec struct {
	RunID    string `json:"run_id"`     // required, correlates across methods
	VMKey    string `json:"vm_key"`     // required, launchpad-authored stable identifier
	Name     string `json:"name"`       // human-friendly display name
	Region   string `json:"region"`     // provider-specific region ID
	Image    string `json:"image"`      // provider-specific OS image ID
	SizeHint string `json:"size_hint"`  // provider-specific plan/type

	CPUs     int    `json:"cpus,omitempty"`     // fallback if size_hint empty
	MemoryMB int    `json:"memory_mb,omitempty"`
	DiskGB   int    `json:"disk_gb,omitempty"`

	SSHKeys  []string          `json:"ssh_keys,omitempty"`  // authorized public keys
	Tags     map[string]string `json:"tags,omitempty"`
	UserData string            `json:"user_data,omitempty"` // cloud-init user-data (raw)

	// Idempotency: if the plugin already has a VM with this run_id+vm_key,
	// return the existing one instead of creating a new one.
	IdempotencyToken string `json:"idempotency_token,omitempty"`
}

// VMPlanParams: dry-run to describe what create would do.
type VMPlanParams struct {
	Spec VMSpec `json:"spec"`
}

// VMPlanResult describes what would happen without side effects.
type VMPlanResult struct {
	Summary           string  `json:"summary"`
	EstimatedCostUSD  float64 `json:"estimated_cost_usd,omitempty"`
	EstimatedDurationSec int  `json:"estimated_duration_sec,omitempty"`
}

// VMCreateParams triggers the actual provisioning.
type VMCreateParams struct {
	Spec VMSpec `json:"spec"`
}

// VMCreateResult is the identity + address block returned after creation.
// The VM may not be fully ready yet; caller should follow up with wait_ready.
type VMCreateResult struct {
	VMID       string            `json:"vm_id"`       // provider-native id
	IPv4       string            `json:"ipv4,omitempty"`
	IPv6       string            `json:"ipv6,omitempty"`
	SSHUser    string            `json:"ssh_user"`
	SSHPort    int               `json:"ssh_port,omitempty"` // default 22
	ProviderURL string           `json:"provider_url,omitempty"` // cloud console link
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// VMWaitReadyParams waits for the VM to be SSH-reachable + cloud-init done.
type VMWaitReadyParams struct {
	RunID string `json:"run_id"`
	VMKey string `json:"vm_key"`
	VMID  string `json:"vm_id"`
	// AwaitCloudInit: whether to wait for /var/lib/cloud/instance/boot-finished.
	AwaitCloudInit bool `json:"await_cloud_init,omitempty"`
}

// VMWaitReadyResult confirms readiness. IPv4/IPv6 are set by plugins that
// can only resolve the VM's address after readiness (e.g. Tailscale-based
// hosts where the address is assigned during device join). Empty means
// "the value from vm.create still applies".
type VMWaitReadyResult struct {
	Ready bool   `json:"ready"`
	IPv4  string `json:"ipv4,omitempty"`
	IPv6  string `json:"ipv6,omitempty"`
}

// VMDestroyParams tears down a VM. Idempotent.
type VMDestroyParams struct {
	RunID string `json:"run_id"`
	VMKey string `json:"vm_key"`
	// VMID and Selector may both be set; the plugin should prefer VMID
	// if present, else fall back to tag-based selectors (name / run_id / vm_key)
	// so cleanup still works after partial state loss.
	VMID     string            `json:"vm_id,omitempty"`
	Selector map[string]string `json:"selector,omitempty"`
}

// VMDestroyResult reports the outcome.
type VMDestroyResult struct {
	Destroyed bool `json:"destroyed"` // false when the VM was already gone
}

// VMInspectParams reads current provider state for a VM (for reconcile after
// crash / state file loss).
type VMInspectParams struct {
	RunID string `json:"run_id"`
	VMKey string `json:"vm_key"`
	VMID  string `json:"vm_id,omitempty"`
}

// VMInspectResult describes what the plugin can see about the VM.
type VMInspectResult struct {
	Exists   bool              `json:"exists"`
	VMID     string            `json:"vm_id,omitempty"`
	State    string            `json:"state,omitempty"` // "starting"|"running"|"stopped"|"unknown"
	IPv4     string            `json:"ipv4,omitempty"`
	IPv6     string            `json:"ipv6,omitempty"`
	SSHUser  string            `json:"ssh_user,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ------------------------------------------------------------------
// Notifications (plugin -> launchpad)
// ------------------------------------------------------------------

// ProgressParams reports progress on an in-flight method call. OpID
// correlates back to the JSON-RPC request ID that initiated the work.
type ProgressParams struct {
	OpID    int64   `json:"op_id"`
	VMKey   string  `json:"vm_key,omitempty"`
	Step    string  `json:"step"`
	Percent float64 `json:"percent"` // 0..100
	Message string  `json:"message,omitempty"`
}

// LogParams is a structured log line the launchpad TUI surfaces to the operator.
type LogParams struct {
	OpID    int64             `json:"op_id,omitempty"`
	VMKey   string            `json:"vm_key,omitempty"`
	Level   string            `json:"level"` // "debug" | "info" | "warn" | "error"
	Message string            `json:"message"`
	Fields  map[string]any    `json:"fields,omitempty"`
}
