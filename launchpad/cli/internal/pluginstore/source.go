package pluginstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// defaultMaxBytes caps any single download (index, signature, or artifact) to
// defend against oversized/never-ending responses. Plugin binaries are tens of
// MB; 512 MB is a generous ceiling.
const defaultMaxBytes = 512 << 20

// Source supplies the signed index and the plugin artifacts it references.
// Implementations must not follow the URL to anything they would not fetch
// themselves; the caller verifies every byte against the signed index.
type Source interface {
	// Index returns the raw index bytes and its detached signature.
	Index(ctx context.Context) (index, sig []byte, err error)
	// Fetch returns the bytes at an artifact URL taken from the (verified) index.
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPSource fetches the index and artifacts over HTTPS.
type HTTPSource struct {
	IndexURL string
	SigURL   string
	Client   *http.Client
	MaxBytes int64
}

func (h HTTPSource) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

func (h HTTPSource) max() int64 {
	if h.MaxBytes > 0 {
		return h.MaxBytes
	}
	return defaultMaxBytes
}

func (h HTTPSource) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	// LimitReader guards against an oversized body; read one extra byte to
	// detect (and reject) a response that exceeds the cap.
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.max()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > h.max() {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, h.max())
	}
	return data, nil
}

func (h HTTPSource) Index(ctx context.Context) ([]byte, []byte, error) {
	idx, err := h.get(ctx, h.IndexURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch index: %w", err)
	}
	sig, err := h.get(ctx, h.SigURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch index signature: %w", err)
	}
	return idx, sig, nil
}

func (h HTTPSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	return h.get(ctx, url)
}
