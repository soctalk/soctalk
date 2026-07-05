package pluginstore

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

// releasePublicKey is the hex-encoded ed25519 public key that signs the release
// index. Injected at build time via -ldflags for real releases; empty in dev
// builds, in which case Sync refuses to run without an explicit override.
var releasePublicKey = ""

// PublicKey returns the trusted signing public key. A LAUNCHPAD_PUBKEY env
// override (hex) is honored so staging/tests can verify a non-release index.
// It fails closed: a dev build with no key configured cannot verify anything.
func PublicKey() (ed25519.PublicKey, error) {
	hexKey := releasePublicKey
	if v := os.Getenv("LAUNCHPAD_PUBKEY"); v != "" {
		hexKey = v
	}
	if hexKey == "" {
		return nil, fmt.Errorf("no signing public key configured (dev build); set LAUNCHPAD_PUBKEY to sync from a signed index")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("bad signing public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
