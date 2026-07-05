package pluginstore

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// VerifySpawn is the spawn-time trust check wired into pluginhost.SpawnVerifier.
// It runs immediately before a plugin subprocess is launched.
//
//   - Dev plugins (from LAUNCHPAD_PLUGIN_DIR) are refused unless the operator
//     opted in with --allow-unsigned / LAUNCHPAD_DEV=1.
//   - Managed plugins are re-verified against the cached signed index: the
//     cached index's own signature is re-checked against the embedded public
//     key, then the on-disk binary's SHA-256 and its env allow-list must match
//     the signed record. This defeats any post-install edit to the binary,
//     plugin.yaml, or env policy, because the authority is the signed index,
//     never the editable manifest on disk.
func VerifySpawn(m *pluginhost.Manifest) error {
	if m.Provenance != pluginhost.ProvenanceManaged {
		if pluginhost.AllowUnsigned() {
			return nil
		}
		return fmt.Errorf("plugin %q is unsigned; run `launchpad plugin sync` to install a verified copy, or pass --allow-unsigned for local development", m.Name)
	}

	// Read the cached index from the same store root the plugin was discovered
	// in (m.Dir is <root>/<name>), so a multi-root install verifies correctly.
	store := Open(filepath.Dir(m.Dir))
	idxBytes, sig, err := store.cachedIndexAndSig()
	if err != nil {
		return fmt.Errorf("no verified index cached (run `launchpad plugin sync`): %w", err)
	}
	pub, err := PublicKey()
	if err != nil {
		return err
	}
	idx, err := ParseAndVerify(idxBytes, sig, pub, time.Now())
	if err != nil {
		return fmt.Errorf("cached index failed verification: %w", err)
	}

	for _, p := range idx.Plugins {
		if p.Name != m.Name {
			continue
		}
		art := p.ArtifactFor(runtime.GOOS, runtime.GOARCH)
		if art == nil {
			return fmt.Errorf("no artifact for %s in the signed index", Platform())
		}
		sum, err := fileSHA256(m.AbsExecutable())
		if err != nil {
			return fmt.Errorf("hash binary: %w", err)
		}
		if sum != art.SHA256 {
			return fmt.Errorf("binary does not match the signed index (tampered or stale; run `launchpad plugin sync`)")
		}
		if !sameStringSet(m.Env, p.Env) {
			return fmt.Errorf("env policy does not match the signed index (tampered plugin.yaml)")
		}
		return nil
	}
	return fmt.Errorf("plugin %q is not present in the signed index", m.Name)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
