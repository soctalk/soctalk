package main

// Cloud-image fetching + caching on the target host.
//
// Design: launchpad plugins should not require the operator to pre-stage a
// base image. Given a URL we fetch it *on the target host* (which is where
// the image is used) and cache it under work_dir/_images by default, keyed
// by a short hash of the URL to avoid filename collisions across mirrors.
//
// Verification is opt-in: if base_image_sha256 is set we verify with sha256sum
// on the target and refuse mismatches. If unset we treat presence-with-nonzero
// size as good enough for cache-hit — pinning is the operator's call.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"golang.org/x/crypto/ssh"
)

// imageMu guards concurrent ensureBaseImage calls in a single plugin process
// (parallel vm.create dispatch would otherwise race on the download).
var imageMu sync.Mutex

// cachedBaseImage holds the resolved on-host path once the image is present.
// Reset on plugin restart.
var cachedBaseImage string

func ensureBaseImage(ctx context.Context, client *ssh.Client, emit sdk.Emitter) (string, error) {
	// Operator-supplied local path wins. If they also pinned a sha256, honor
	// it — a stale/corrupted pre-staged image should surface here, not deep
	// inside qemu's boot log.
	if cfg.BaseImage != "" {
		if cfg.BaseImageSHA256 != "" {
			emit.Progress("image_verify", 12, "verifying sha256 of pre-staged image")
			ok, err := imageCacheHit(ctx, client, cfg.BaseImage, cfg.BaseImageSHA256)
			if err != nil {
				return "", sdk.Errf(sdk.CatInternal,
					"wsl2.image.sha256_failed",
					"computing sha256 of pre-staged %s: %v", cfg.BaseImage, err)
			}
			if !ok {
				return "", sdk.Errf(sdk.CatValidation,
					"wsl2.image.sha256_mismatch",
					"pre-staged %s does not match declared sha256 %s", cfg.BaseImage, cfg.BaseImageSHA256)
			}
		}
		return cfg.BaseImage, nil
	}

	imageMu.Lock()
	defer imageMu.Unlock()
	if cachedBaseImage != "" {
		return cachedBaseImage, nil
	}

	cacheDir := cfg.ImageCacheDir
	if cacheDir == "" {
		cacheDir = cfg.WorkDir + "/_images"
	}
	if _, err := runOverSSH(ctx, client, "mkdir -p "+shellEscape(cacheDir)); err != nil {
		return "", sdk.Errf(sdk.CatInternal,
			"wsl2.image.mkdir_cache_failed",
			"cannot create image cache dir %s: %v", cacheDir, err)
	}

	filename := filepath.Base(cfg.BaseImageURL)
	if filename == "" || filename == "/" {
		return "", sdk.Errf(sdk.CatValidation,
			"wsl2.image.bad_url",
			"cannot infer filename from base_image_url %q", cfg.BaseImageURL)
	}
	urlHash := shortURLHash(cfg.BaseImageURL)
	dest := fmt.Sprintf("%s/%s-%s", cacheDir, urlHash, filename)

	ok, hitErr := imageCacheHit(ctx, client, dest, cfg.BaseImageSHA256)
	emit.Log("debug", "image cache probe", map[string]any{"dest": dest, "hit": ok, "err": fmt.Sprintf("%v", hitErr)})
	if ok {
		emit.Progress("image_cache", 12, fmt.Sprintf("cached: %s", dest))
		cachedBaseImage = dest
		return dest, nil
	}

	emit.Progress("image_download", 15, fmt.Sprintf("fetching %s", cfg.BaseImageURL))
	// curl with resume; write to .part then atomically rename. `-fL` fails
	// fast on 4xx/5xx and follows redirects. `--continue-at -` resumes
	// interrupted downloads. `-sS` = silent + show errors.
	dl := fmt.Sprintf(
		"curl -fL -sS --continue-at - -o %s.part %s && mv %s.part %s",
		shellEscape(dest), shellEscape(cfg.BaseImageURL),
		shellEscape(dest), shellEscape(dest),
	)
	if _, err := runOverSSH(ctx, client, dl); err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"wsl2.image.download_failed",
			"downloading %s to %s: %v", cfg.BaseImageURL, dest, err)
	}

	if cfg.BaseImageSHA256 != "" {
		emit.Progress("image_verify", 18, "verifying sha256")
		want := strings.ToLower(cfg.BaseImageSHA256)
		got, err := runOverSSH(ctx, client, fmt.Sprintf("sha256sum %s | awk '{print $1}'", shellEscape(dest)))
		if err != nil {
			return "", sdk.Errf(sdk.CatInternal,
				"wsl2.image.sha256_failed",
				"computing sha256 of %s: %v", dest, err)
		}
		if strings.TrimSpace(strings.ToLower(got)) != want {
			return "", sdk.Errf(sdk.CatValidation,
				"wsl2.image.sha256_mismatch",
				"sha256 mismatch for %s: got %s, want %s", dest, strings.TrimSpace(got), want)
		}
	}

	cachedBaseImage = dest
	return dest, nil
}

// imageCacheHit reports whether dest is present and (if want is set) matches
// the expected sha256. Missing file → miss. Empty file → miss.
func imageCacheHit(ctx context.Context, client *ssh.Client, dest, wantSHA256 string) (bool, error) {
	// Presence + size check first (cheap).
	out, err := runOverSSH(ctx, client, fmt.Sprintf("stat -c %%s %s 2>/dev/null || echo 0", shellEscape(dest)))
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) == "0" {
		return false, nil
	}
	if wantSHA256 == "" {
		return true, nil
	}
	got, err := runOverSSH(ctx, client, fmt.Sprintf("sha256sum %s | awk '{print $1}'", shellEscape(dest)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(strings.ToLower(got)) == strings.ToLower(wantSHA256), nil
}

func shortURLHash(url string) string {
	h := sha1.Sum([]byte(url))
	return hex.EncodeToString(h[:])[:8]
}
