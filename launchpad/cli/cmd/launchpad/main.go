// Command launchpad is the CLI entry point.
//
// v1 subcommands:
//
//	launchpad plugin list                    — discovered plugins
//	launchpad plugin verify <name-or-path>   — compliance suite
//	launchpad plugin run <name> <method>     — one-shot RPC (dev tool)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"

	"github.com/soctalk/launchpad/internal/cli"
	"github.com/soctalk/launchpad/internal/pluginhost"
	"github.com/soctalk/launchpad/internal/pluginstore"
)

// version is the CLI release. Injected at build time via
// -ldflags "-X main.version=<tag>"; the value here is the dev default. It also
// pins which signed plugin index the CLI trusts, so build and release must agree.
var version = "0.1.0-alpha"

func main() {
	// Enforce spawn-time plugin trust for every subprocess launch in this
	// process: managed plugins are re-verified against the cached signed index,
	// unsigned/dev plugins require an explicit opt-in.
	pluginhost.SpawnVerifier = pluginstore.VerifySpawn

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		initCmd(os.Args[2:])
	case "plugin":
		pluginCmd(os.Args[2:])
	case "up":
		upCmd(os.Args[2:])
	case "down":
		downCmd(os.Args[2:])
	case "ui":
		uiCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("launchpad", version, "protocol", sdk.ProtocolVersion)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// upCmd parses `launchpad up [--config PATH] [--state PATH] [--headless] [--auto-resolve-gates]`.
func upCmd(args []string) {
	opts := cli.UpOptions{}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--config", "-c":
			i++
			if i < len(args) {
				opts.ConfigPath = args[i]
			}
		case "--state":
			i++
			if i < len(args) {
				opts.StatePath = args[i]
			}
		case "--headless":
			opts.Headless = true
		case "--auto-resolve-gates":
			opts.AutoResolveGates = true
		default:
			fmt.Fprintln(os.Stderr, "unknown flag:", args[i])
			os.Exit(2)
		}
		i++
	}
	if opts.ConfigPath == "" {
		fmt.Fprintln(os.Stderr, "usage: launchpad up --config PATH [--state PATH] [--headless] [--auto-resolve-gates]")
		os.Exit(2)
	}
	ensurePluginsSynced()
	if err := cli.Up(opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// downCmd parses `launchpad down --config PATH [--state PATH] [--headless]`.
func downCmd(args []string) {
	opts := cli.DownOptions{}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--config", "-c":
			i++
			if i < len(args) {
				opts.ConfigPath = args[i]
			}
		case "--state":
			i++
			if i < len(args) {
				opts.StatePath = args[i]
			}
		case "--headless":
			opts.Headless = true
		case "--keep-state":
			opts.KeepState = true
		default:
			fmt.Fprintln(os.Stderr, "unknown flag:", args[i])
			os.Exit(2)
		}
		i++
	}
	if opts.ConfigPath == "" {
		fmt.Fprintln(os.Stderr, "usage: launchpad down --config PATH [--state PATH] [--headless] [--keep-state]")
		os.Exit(2)
	}
	if err := cli.Down(opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// uiCmd parses `launchpad ui [--port N] [--no-open] [--dev] [--token T]`.
func uiCmd(args []string) {
	opts := cli.UIOptions{}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &opts.Port)
			}
		case "--no-open":
			opts.NoOpen = true
		case "--dev":
			opts.Dev = true
		case "--token":
			i++
			if i < len(args) {
				opts.Token = args[i]
			}
		default:
			fmt.Fprintln(os.Stderr, "unknown flag:", args[i])
			os.Exit(2)
		}
		i++
	}
	ensurePluginsSynced()
	if err := cli.UI(opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: launchpad <command> [args]

Commands:
  init                            download + verify all plugins for this platform
  up --config PATH                orchestrate a rollout (MSSP + tenants)
                                  --headless emits JSON events on stdout
                                  --auto-resolve-gates auto-confirms every gate
  down --config PATH              tear down every VM in state (via vm.destroy)
                                  --headless emits JSON events on stdout
                                  --keep-state leave the state file in place
  plugin list [--available]       list installed plugins (or those in the index)
  plugin sync                     re-download + verify plugins into the store
  plugin verify <name-or-path>    run compliance suite against a plugin
  plugin run <name> <method> [json-params]   send one RPC to a plugin
  version                         print launchpad + protocol version

Environment:
  LAUNCHPAD_PLUGIN_DIR      :-separated dev plugin dirs (unsigned)
  LAUNCHPAD_DEV=1           trust unsigned/dev plugins (implies --allow-unsigned)
  LAUNCHPAD_INDEX_BASEURL   override the release index base URL (staging)
  LAUNCHPAD_PUBKEY          hex ed25519 index-signing key (staging/dev)

`)
}

func pluginCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: launchpad plugin <list|sync|verify|run> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		if len(args) > 1 && args[1] == "--available" {
			cmdPluginListAvailable()
		} else {
			cmdPluginList()
		}
	case "sync":
		pluginSyncCmd(args[1:])
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: launchpad plugin verify <name-or-path>")
			os.Exit(2)
		}
		// verify is a dev/CI tool that runs the compliance suite against an
		// explicit local plugin, so allow spawning unsigned builds.
		os.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "1")
		cmdPluginVerify(args[1])
	case "run":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: launchpad plugin run <name> <method> [json-params]")
			os.Exit(2)
		}
		// run is a raw debug tool for an explicitly named plugin.
		os.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "1")
		params := "{}"
		if len(args) >= 4 {
			params = args[3]
		}
		cmdPluginRun(args[1], args[2], params)
	default:
		fmt.Fprintln(os.Stderr, "unknown plugin subcommand:", args[0])
		os.Exit(2)
	}
}

func cmdPluginList() {
	manifests, errs := pluginhost.DiscoverPlugins()
	if len(manifests) == 0 && len(errs) == 0 {
		fmt.Fprintln(os.Stderr, "no plugins discovered")
		fmt.Fprintln(os.Stderr, "hint: install plugins into ~/.launchpad/plugins/<name>/plugin + plugin.yaml,")
		fmt.Fprintln(os.Stderr, "      or set LAUNCHPAD_PLUGIN_DIR to a directory containing them")
		return
	}
	for _, m := range manifests {
		fmt.Printf("%-16s %-12s %s\n", m.Name, m.Version, m.AbsExecutable())
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "warning:", e)
	}
}

// resolveManifest accepts a name (looked up via discovery) or a directory
// path (containing plugin.yaml).
func resolveManifest(nameOrPath string) (*pluginhost.Manifest, error) {
	if strings.ContainsRune(nameOrPath, '/') || strings.ContainsRune(nameOrPath, '.') {
		// Path-ish.
		return pluginhost.LoadManifest(nameOrPath)
	}
	manifests, _ := pluginhost.DiscoverPlugins()
	for _, m := range manifests {
		if m.Name == nameOrPath {
			return m, nil
		}
	}
	return nil, fmt.Errorf("plugin %q not found", nameOrPath)
}

func cmdPluginVerify(nameOrPath string) {
	m, err := resolveManifest(nameOrPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	report, err := pluginhost.Verify(ctx, m, pluginhost.VerifyOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Print(report.String())
	if !report.AllPassed() {
		os.Exit(1)
	}
}

func cmdPluginRun(nameOrPath, method, paramsJSON string) {
	m, err := resolveManifest(nameOrPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	var params any
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		fmt.Fprintln(os.Stderr, "invalid params JSON:", err)
		os.Exit(2)
	}
	ctx := context.Background()
	notifications := make(chan *sdk.Envelope, 32)
	go func() {
		for env := range notifications {
			b, _ := json.Marshal(env)
			fmt.Fprintln(os.Stderr, string(b))
		}
	}()
	client, err := pluginhost.Start(ctx, m, pluginhost.StartConfig{
		Notifications: notifications,
		EnvAllowlist:  m.Env,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Shutdown(sctx)
	}()

	// Auto-initialize.
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.Call(initCtx, sdk.MethodInitialize, sdk.InitializeParams{
		RunID: "cli-run", Config: map[string]any{}, LogLevel: "info",
	}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "initialize:", err)
		os.Exit(1)
	}

	callCtx, ccancel := context.WithTimeout(ctx, 5*time.Minute)
	defer ccancel()
	var result any
	if err := client.Call(callCtx, method, params, &result); err != nil {
		fmt.Fprintln(os.Stderr, method+":", err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(b))
}
