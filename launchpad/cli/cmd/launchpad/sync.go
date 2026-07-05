package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
	"github.com/soctalk/launchpad/internal/pluginstore"
)

// indexSource builds the release index source for this CLI version. The base
// URL is pinned to the CLI's own release tag so build and index agree; a
// LAUNCHPAD_INDEX_BASEURL override points at a staging release for testing.
func indexSource() pluginstore.HTTPSource {
	base := fmt.Sprintf("https://github.com/soctalk/soctalk/releases/download/launchpad-v%s",
		strings.TrimPrefix(version, "v"))
	if v := os.Getenv("LAUNCHPAD_INDEX_BASEURL"); v != "" {
		base = strings.TrimRight(v, "/")
	}
	return pluginstore.HTTPSource{IndexURL: base + "/index.json", SigURL: base + "/index.json.sig"}
}

// syncWith verifies and installs all plugins for this platform from src into
// the managed store, printing a per-plugin report.
func syncWith(src pluginstore.Source) error {
	pub, err := pluginstore.PublicKey()
	if err != nil {
		return err
	}
	store := pluginstore.Open(pluginhost.ManagedPluginDir())
	fmt.Fprintf(os.Stderr, "syncing plugins into %s\n", store.Dir())
	rep, err := store.Sync(context.Background(), pluginstore.Options{
		Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	})
	if rep != nil {
		for _, n := range rep.Installed {
			fmt.Printf("  installed   %s\n", n)
		}
		for _, n := range rep.Skipped {
			fmt.Printf("  up-to-date  %s\n", n)
		}
		for _, n := range rep.NoArtifact {
			fmt.Printf("  skipped     %s (no build for %s)\n", n, pluginstore.Platform())
		}
		for n, e := range rep.Failed {
			fmt.Printf("  FAILED      %s: %s\n", n, e)
		}
	}
	return err
}

// doSync installs from the online release index.
func doSync() error { return syncWith(indexSource()) }

// syncFrom installs from an offline bundle: a directory, or a .tar/.tar.gz/.tgz
// which is extracted (with traversal defenses) to a temp dir first. The bundle
// is verified against the same embedded signing key.
func syncFrom(p string) error {
	dir := p
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		tmp, err := os.MkdirTemp("", "lp-bundle-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if err := pluginstore.ExtractBundle(p, tmp); err != nil {
			return err
		}
		dir = tmp
	}
	return syncWith(pluginstore.DirSource{Dir: dir})
}

func initCmd(args []string) {
	if err := doSync(); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}
}

// ensurePluginsSynced runs before ui/up so a fresh install bootstraps its
// plugins automatically. It no-ops when the store is already current for this
// CLI version, when the operator is in dev mode with their own plugin dir, when
// auto-sync is disabled, or when this is a dev build with no signing key.
func ensurePluginsSynced() {
	if os.Getenv("LAUNCHPAD_NO_AUTO_SYNC") == "1" {
		return
	}
	if pluginhost.AllowUnsigned() && os.Getenv("LAUNCHPAD_PLUGIN_DIR") != "" {
		return // dev is driving their own local plugins
	}
	pub, err := pluginstore.PublicKey()
	if err != nil {
		return // dev build without an embedded signing key; nothing to sync from
	}
	store := pluginstore.Open(pluginhost.ManagedPluginDir())
	// "Current" means the cached index verifies (signature + not expired) and
	// every plugin it provides for this platform is installed and matches, so a
	// partial or expired store is repaired rather than trusted.
	if store.IsCurrent(pub, time.Now(), runtime.GOOS, runtime.GOARCH) {
		return
	}
	fmt.Fprintln(os.Stderr, "first run: fetching verified plugins for this release…")
	if err := doSync(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: automatic plugin sync failed:", err)
		fmt.Fprintln(os.Stderr, "run `launchpad plugin sync` manually, or set LAUNCHPAD_NO_AUTO_SYNC=1 to skip")
	}
}

func pluginSyncCmd(args []string) {
	from := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--from" && i+1 < len(args) {
			from = args[i+1]
			i++
		}
	}
	var err error
	if from != "" {
		err = syncFrom(from)
	} else {
		err = doSync()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sync:", err)
		os.Exit(1)
	}
}

// cmdPluginListAvailable fetches and verifies the release index and prints the
// plugins it offers for this platform.
func cmdPluginListAvailable() {
	pub, err := pluginstore.PublicKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	idxBytes, sig, err := indexSource().Index(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	idx, err := pluginstore.ParseAndVerify(idxBytes, sig, pub, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "index:", err)
		os.Exit(1)
	}
	for _, p := range idx.Plugins {
		mark := " "
		if p.ArtifactFor(runtime.GOOS, runtime.GOARCH) == nil {
			mark = "-" // not built for this platform
		}
		fmt.Printf("%s %-14s %-10s %s\n", mark, p.Name, p.Version, p.Description)
	}
}
