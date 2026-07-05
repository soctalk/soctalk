package pluginstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ArtifactBuild points at a built plugin binary on disk for one os/arch, plus
// the URL it will be published at.
type ArtifactBuild struct {
	OS, Arch, URL, Path string
}

// PluginSpec is the release-time description of one plugin: its manifest fields
// (from the checked-in plugin.yaml) plus the built artifacts to publish.
type PluginSpec struct {
	Name, Version, Protocol string
	Substrate, Description  string
	License, Homepage       string
	Platforms               []string
	Env                     []string
	Artifacts               []ArtifactBuild
}

// BuildIndex assembles a signed-ready index, computing the SHA-256 and size of
// each built artifact from disk. The index is the single source of truth: every
// artifact checksum and every plugin's env allow-list is captured here so one
// signature over the result covers both integrity and env policy.
func BuildIndex(launchpadVersion, protocol string, expires time.Time, specs []PluginSpec) (*Index, error) {
	idx := &Index{
		SchemaVersion:    1,
		LaunchpadVersion: launchpadVersion,
		ProtocolVersion:  protocol,
		Expires:          expires,
	}
	for _, sp := range specs {
		p := IndexPlugin{
			Name: sp.Name, Version: sp.Version, Protocol: firstNonEmpty(sp.Protocol, "1"),
			Substrate: sp.Substrate, Platforms: sp.Platforms, Description: sp.Description,
			Env: sp.Env, License: sp.License, Homepage: sp.Homepage,
		}
		for _, a := range sp.Artifacts {
			data, err := os.ReadFile(a.Path)
			if err != nil {
				return nil, fmt.Errorf("%s %s/%s: %w", sp.Name, a.OS, a.Arch, err)
			}
			sum := sha256.Sum256(data)
			p.Artifacts = append(p.Artifacts, Artifact{
				OS: a.OS, Arch: a.Arch, URL: a.URL,
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
			})
		}
		idx.Plugins = append(idx.Plugins, p)
	}
	return idx, nil
}

// MarshalIndex serializes an index deterministically (stable field order) so
// the exact bytes that were signed are the exact bytes verified.
func MarshalIndex(idx *Index) ([]byte, error) {
	return json.MarshalIndent(idx, "", "  ")
}

// Sign returns the detached ed25519 signature over the index bytes.
func Sign(indexBytes []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, indexBytes)
}

// GenerateKey returns a fresh ed25519 keypair for signing releases. The public
// key (hex) is embedded in the CLI; the private key stays in the release
// environment.
func GenerateKey() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// PrivateKeyFromHex decodes a hex-encoded ed25519 private key.
func PrivateKeyFromHex(h string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}
