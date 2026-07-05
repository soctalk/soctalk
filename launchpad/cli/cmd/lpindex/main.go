// Command lpindex is the release-time tool that builds and signs the plugin
// index. It reads each plugin's checked-in plugin.yaml for its manifest fields,
// hashes the built artifacts, assembles the index, and signs it with the
// release private key (hex in LAUNCHPAD_SIGN_KEY).
//
// Usage:
//
//	lpindex genkey
//	    Print a fresh ed25519 keypair (embed the public half in the CLI,
//	    keep the private half in the release environment).
//
//	lpindex build --plugins-src DIR --artifacts DIR --base-url URL \
//	              --version V --protocol P --expires-days N --out DIR
//	    Build index.json + index.json.sig over the artifacts.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
	"github.com/soctalk/launchpad/internal/pluginstore"
)

// targets is the release build matrix.
var targets = []struct{ OS, Arch string }{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lpindex <genkey|build> ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		pub, priv, err := pluginstore.GenerateKey()
		fatal(err)
		fmt.Printf("public  (embed as -X .../pluginstore.releasePublicKey): %s\n", pub)
		fmt.Printf("private (set as LAUNCHPAD_SIGN_KEY secret):             %s\n", priv)
	case "build":
		build(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func build(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	pluginsSrc := fs.String("plugins-src", "", "dir of plugin source dirs (each with plugin.yaml)")
	artifacts := fs.String("artifacts", "", "dir of built binaries named <name>_<os>_<arch>[.exe]")
	baseURL := fs.String("base-url", "", "release download base URL")
	ver := fs.String("version", "", "launchpad release version")
	protocol := fs.String("protocol", "1", "plugin protocol version")
	expiresDays := fs.Int("expires-days", 120, "index validity window in days")
	out := fs.String("out", ".", "output dir for index.json + index.json.sig")
	now := fs.Int64("now", time.Now().Unix(), "current unix time (for reproducible builds)")
	_ = fs.Parse(args)

	if *pluginsSrc == "" || *artifacts == "" || *baseURL == "" || *ver == "" {
		fmt.Fprintln(os.Stderr, "build: --plugins-src, --artifacts, --base-url, --version are required")
		os.Exit(2)
	}
	privHex := os.Getenv("LAUNCHPAD_SIGN_KEY")
	if privHex == "" {
		fmt.Fprintln(os.Stderr, "build: LAUNCHPAD_SIGN_KEY (hex ed25519 private key) is required")
		os.Exit(2)
	}
	priv, err := pluginstore.PrivateKeyFromHex(privHex)
	fatal(err)

	entries, err := os.ReadDir(*pluginsSrc)
	fatal(err)

	var specs []pluginstore.PluginSpec
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := pluginhost.LoadManifest(filepath.Join(*pluginsSrc, e.Name()))
		if err != nil {
			continue // dir without a manifest is not a plugin
		}
		spec := pluginstore.PluginSpec{
			Name: m.Name, Version: m.Version, Protocol: firstNonEmpty(m.Protocol, *protocol),
			License: m.License, Homepage: m.Homepage, Env: m.Env,
		}
		for _, t := range targets {
			fname := m.Name + "_" + t.OS + "_" + t.Arch
			if t.OS == "windows" {
				fname += ".exe"
			}
			path := filepath.Join(*artifacts, fname)
			if _, err := os.Stat(path); err != nil {
				continue // this plugin was not built for this platform
			}
			spec.Artifacts = append(spec.Artifacts, pluginstore.ArtifactBuild{
				OS: t.OS, Arch: t.Arch, URL: *baseURL + "/" + fname, Path: path,
			})
			spec.Platforms = append(spec.Platforms, t.OS+"/"+t.Arch)
		}
		if len(spec.Artifacts) == 0 {
			continue
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "build: no plugins with artifacts found")
		os.Exit(1)
	}

	expires := time.Unix(*now, 0).UTC().Add(time.Duration(*expiresDays) * 24 * time.Hour)
	idx, err := pluginstore.BuildIndex(*ver, *protocol, expires, specs)
	fatal(err)
	idxBytes, err := pluginstore.MarshalIndex(idx)
	fatal(err)
	sig := pluginstore.Sign(idxBytes, priv)

	fatal(os.MkdirAll(*out, 0o755))
	fatal(os.WriteFile(filepath.Join(*out, "index.json"), idxBytes, 0o644))
	fatal(os.WriteFile(filepath.Join(*out, "index.json.sig"), sig, 0o644))
	fmt.Fprintf(os.Stderr, "wrote index for %d plugin(s) to %s\n", len(specs), *out)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "lpindex:", err)
		os.Exit(1)
	}
}
