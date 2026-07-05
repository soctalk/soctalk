// Package pluginstore fetches, verifies, and installs launchpad plugins from a
// signed release index into the managed plugin store. Trust is rooted in a
// single ed25519 signature over the index; the index in turn carries the
// SHA-256 of every plugin artifact and the exact manifest fields (including the
// security-critical env allow-list), so one verified signature covers both
// binary integrity and env policy.
package pluginstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

// Index is the signed catalog of plugins for one launchpad release.
type Index struct {
	SchemaVersion    int           `json:"schema_version"`
	LaunchpadVersion string        `json:"launchpad_version"`
	ProtocolVersion  string        `json:"protocol_version"`
	Expires          time.Time     `json:"expires"`
	Plugins          []IndexPlugin `json:"plugins"`
}

// IndexPlugin is one plugin's signed record: its manifest fields plus the
// per-platform artifacts with their checksums.
type IndexPlugin struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Protocol    string     `json:"protocol"`
	Substrate   string     `json:"substrate"`
	Platforms   []string   `json:"platforms"`
	Description string     `json:"description"`
	Env         []string   `json:"env"`
	License     string     `json:"license"`
	Homepage    string     `json:"homepage"`
	Artifacts   []Artifact `json:"artifacts"`
}

// Artifact is a single built plugin binary for one os/arch.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ArtifactFor returns the artifact matching the given os/arch, or nil.
func (p IndexPlugin) ArtifactFor(goos, goarch string) *Artifact {
	for i := range p.Artifacts {
		if p.Artifacts[i].OS == goos && p.Artifacts[i].Arch == goarch {
			return &p.Artifacts[i]
		}
	}
	return nil
}

// ParseAndVerify checks the detached ed25519 signature over the raw index
// bytes with pub, then parses and validates the index. The signature is
// verified before any of the index content is trusted, and expiry is enforced
// so a stolen key cannot serve a frozen index indefinitely.
func ParseAndVerify(indexBytes, sig []byte, pub ed25519.PublicKey, now time.Time) (*Index, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pub, indexBytes, sig) {
		return nil, fmt.Errorf("index signature verification failed")
	}
	var idx Index
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	if idx.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported index schema_version %d", idx.SchemaVersion)
	}
	if !idx.Expires.IsZero() && now.After(idx.Expires) {
		return nil, fmt.Errorf("index expired at %s", idx.Expires.UTC().Format(time.RFC3339))
	}
	return &idx, nil
}

// verifySHA256 checks that data hashes to the given lowercase-hex digest.
func verifySHA256(data []byte, want string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("sha256 mismatch: want %s got %s", want, got)
	}
	return nil
}

// Platform returns the host's canonical "os/arch" string.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
