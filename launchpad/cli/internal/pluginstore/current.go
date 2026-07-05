package pluginstore

import (
	"crypto/ed25519"
	"path/filepath"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// pluginCurrent reports whether the installed plugin at dir matches the signed
// index entry: the binary hash, plus a present manifest whose version, checksum,
// and env policy all match. This means a metadata-only change (same binary, new
// env allow-list or version) or a missing/tampered plugin.yaml triggers a
// reinstall rather than a false "up-to-date".
func pluginCurrent(dir, binName string, p IndexPlugin, art *Artifact) bool {
	sum, err := fileSHA256(filepath.Join(dir, binName))
	if err != nil || sum != art.SHA256 {
		return false
	}
	m, err := pluginhost.LoadManifest(dir)
	if err != nil {
		return false
	}
	return m.Version == p.Version && m.SHA256 == art.SHA256 && sameStringSet(m.Env, p.Env)
}

// IsCurrent reports whether every plugin the signed index provides for this
// platform is installed and matches. The cached index's signature and expiry
// are verified first, so an expired, unsigned, or tampered cache is never
// considered current, and a partial install (some plugins missing) is detected
// so auto-sync retries instead of trusting an incomplete store.
func (s *Store) IsCurrent(pub ed25519.PublicKey, now time.Time, goos, goarch string) bool {
	idxBytes, sig, err := s.cachedIndexAndSig()
	if err != nil {
		return false
	}
	idx, err := ParseAndVerify(idxBytes, sig, pub, now)
	if err != nil {
		return false
	}
	for _, p := range idx.Plugins {
		art := p.ArtifactFor(goos, goarch)
		if art == nil {
			continue // no build for this platform; not expected to be installed
		}
		if !pluginCurrent(filepath.Join(s.dir, p.Name), "plugin"+exeSuffix(goos), p, art) {
			return false
		}
	}
	return true
}
