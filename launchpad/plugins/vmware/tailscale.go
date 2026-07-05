package main

// Tailscale API helpers — identical to the qemu plugin. Kept per-plugin
// (rather than in the SDK) so plugins choose which providers to depend on.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

func mintTailscaleKey(ctx context.Context, tailnet, tag string) (string, error) {
	if tailnet == "" {
		return "", fmt.Errorf("tailnet is empty")
	}
	payload := map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     true,
					"preauthorized": true,
					"tags":          []string{tag},
				},
			},
		},
		"expirySeconds": 3600,
	}
	body, _ := json.Marshal(payload)
	u := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/keys", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"vmware.tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth,
			"vmware.tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal,
			"vmware.tailscale.key_missing", "no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

type tsDevice struct {
	ID        string   `json:"id"`
	Hostname  string   `json:"hostname"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	LastSeen  string   `json:"lastSeen"`
}

func (d *tsDevice) primaryIPv4() string {
	for _, a := range d.Addresses {
		if strings.Count(a, ".") == 3 {
			return a
		}
	}
	return ""
}

func (d *tsDevice) online() bool {
	if d.LastSeen == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, d.LastSeen)
	if err != nil {
		return false
	}
	return time.Since(t) < 3*time.Minute
}

func findTailscaleDevice(ctx context.Context, tailnet, hostname string) (*tsDevice, error) {
	u := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Devices []tsDevice `json:"devices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for i := range out.Devices {
		d := &out.Devices[i]
		if d.Hostname == hostname {
			return d, nil
		}
		if strings.HasPrefix(d.Name, hostname+".") {
			return d, nil
		}
	}
	return nil, nil
}

func deleteTailscaleDevice(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		"https://api.tailscale.com/api/v2/device/"+id, nil)
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete device %s: %d %s", id, resp.StatusCode, string(raw))
	}
	return nil
}

func sanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "lp"
	}
	return out
}
