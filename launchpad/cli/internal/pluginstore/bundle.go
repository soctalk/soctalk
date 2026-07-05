package pluginstore

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DirSource serves the index, its signature, and plugin artifacts from a local
// directory (an unpacked offline bundle). Artifacts are matched by the base
// filename of their index URL, so the same signed index verifies identically
// online and offline. Every byte is still checked against the signed index by
// Sync; the source itself is untrusted.
type DirSource struct{ Dir string }

func (d DirSource) Index(ctx context.Context) ([]byte, []byte, error) {
	idx, err := os.ReadFile(filepath.Join(d.Dir, "index.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle index: %w", err)
	}
	sig, err := os.ReadFile(filepath.Join(d.Dir, "index.json.sig"))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle index signature: %w", err)
	}
	return idx, sig, nil
}

func (d DirSource) Fetch(ctx context.Context, artifactURL string) ([]byte, error) {
	name, err := artifactBaseName(artifactURL)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(d.Dir, name))
}

// artifactBaseName extracts the trailing filename of an artifact URL and
// rejects anything that could escape the bundle directory.
func artifactBaseName(artifactURL string) (string, error) {
	u, err := url.Parse(artifactURL)
	if err != nil {
		return "", fmt.Errorf("bad artifact url %q: %w", artifactURL, err)
	}
	name := path.Base(u.Path)
	if name == "" || name == "." || name == "/" || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("unsafe artifact name derived from %q", artifactURL)
	}
	return name, nil
}

// bundle extraction limits.
const (
	maxBundleFile  = 512 << 20 // per-file
	maxBundleTotal = 4 << 30   // whole archive
)

// ExtractBundle unpacks a plugin bundle (.tar / .tar.gz / .tgz) into dest with
// full defenses against hostile archives: path traversal, absolute paths,
// symlinks, hardlinks, device/fifo entries, duplicate entries, and oversized
// files are all rejected before anything is written outside intent.
func ExtractBundle(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(archivePath, ".gz") || strings.HasSuffix(archivePath, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gunzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	tr := tar.NewReader(r)
	seen := map[string]bool{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
			// allowed
		default:
			return fmt.Errorf("bundle contains a disallowed entry type (%d) for %q", h.Typeflag, h.Name)
		}
		clean := filepath.Clean(h.Name)
		if clean == "." {
			continue
		}
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("bundle entry escapes destination: %q", h.Name)
		}
		target := filepath.Join(destAbs, clean)
		if target != destAbs && !strings.HasPrefix(target, destAbs+string(filepath.Separator)) {
			return fmt.Errorf("bundle entry escapes destination: %q", h.Name)
		}
		if seen[clean] {
			return fmt.Errorf("bundle has a duplicate entry: %q", h.Name)
		}
		seen[clean] = true

		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if h.Size < 0 || h.Size > maxBundleFile {
			return fmt.Errorf("bundle entry %q too large (%d bytes)", h.Name, h.Size)
		}
		total += h.Size
		if total > maxBundleTotal {
			return fmt.Errorf("bundle exceeds total size limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		// LimitReader is a second guard in case the header understated the size.
		if _, err := io.Copy(out, io.LimitReader(tr, maxBundleFile)); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}
