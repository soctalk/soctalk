package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The primary loadConfig bug that shipped: yaml.v3 uses yaml tags (or
// lowercased field names), not json tags — so plugin_config, mssp_admin_email,
// etc. silently dropped when the file was YAML. These tests are the regression
// gate.

func TestLoadConfig_YAMLBindsPluginConfig(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pilot.yaml")
	os.WriteFile(f, []byte(`
run_id: r1
target: qemu
plugin_config:
  ssh_host: user@host
  work_dir: /home/user/lp
  tailnet: t.ts.net
mssp:
  key: mssp
  name: soctalk-mssp
tenants:
  - key: tenant-acme
    name: acme
    tenant_slug: acme
install:
  mssp_admin_email: admin@x.demo
  mssp_admin_password: pw
`), 0o600)

	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RunID != "r1" || cfg.Target != "qemu" {
		t.Fatalf("top-level fields: %+v", cfg)
	}
	if cfg.PluginConfig["ssh_host"] != "user@host" {
		t.Fatalf("plugin_config not bound: %v", cfg.PluginConfig)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].TenantSlug != "acme" {
		t.Fatalf("tenants not bound: %+v", cfg.Tenants)
	}
	if cfg.Install.MSSPAdminEmail != "admin@x.demo" {
		t.Fatalf("install.mssp_admin_email not bound: %+v", cfg.Install)
	}
}

func TestLoadConfig_JSONAlsoWorks(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pilot.json")
	os.WriteFile(f, []byte(`{
		"run_id":"r1", "target":"mock",
		"plugin_config":{"ssh_host":"h"},
		"mssp":{"key":"mssp"}
	}`), 0o600)
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PluginConfig["ssh_host"] != "h" {
		t.Fatal("json binding")
	}
}

func TestLoadConfig_TargetRequired(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pilot.yaml")
	os.WriteFile(f, []byte("run_id: r1\n"), 0o600)
	_, err := loadConfig(f)
	if err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Fatalf("expected target-required error, got %v", err)
	}
}

func TestLoadConfig_MSSPKeyDefault(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pilot.yaml")
	os.WriteFile(f, []byte("run_id: r\ntarget: mock\nmssp:\n  name: x\n"), 0o600)
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MSSP.Key != "mssp" || cfg.MSSP.Role != "mssp" {
		t.Fatalf("defaults not applied: %+v", cfg.MSSP)
	}
}
