package main

// cloud-init user-data composition. Same shape as qemu plugin's — the
// Ubuntu image doesn't care whether the datasource is NoCloud (seed ISO)
// or OVFEnv/VMware (guestinfo).

import (
	"bytes"
	"fmt"
	"strings"
)

type cloudInitInputs struct {
	Hostname      string
	SSHKeys       []string
	TailscaleKey  string
	TailscaleTag  string
	ExtraUserData string
}

func composeUserData(in cloudInitInputs) string {
	var b bytes.Buffer
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", in.Hostname)
	b.WriteString("manage_etc_hosts: true\n")
	b.WriteString("users:\n")
	b.WriteString("  - default\n")
	b.WriteString("  - name: ops\n")
	b.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
	b.WriteString("    shell: /bin/bash\n")
	if len(in.SSHKeys) > 0 {
		b.WriteString("    ssh_authorized_keys:\n")
		for _, k := range in.SSHKeys {
			fmt.Fprintf(&b, "      - %s\n", k)
		}
	}
	b.WriteString("package_update: true\n")
	b.WriteString("packages: [curl, ca-certificates, jq]\n")
	b.WriteString("runcmd:\n")
	b.WriteString("  - curl -fsSL https://tailscale.com/install.sh | sh\n")
	fmt.Fprintf(&b,
		"  - tailscale up --auth-key=%q --advertise-tags=%s --hostname=%s\n",
		in.TailscaleKey, in.TailscaleTag, in.Hostname)
	if in.ExtraUserData != "" {
		b.WriteString("write_files:\n")
		b.WriteString("  - path: /etc/launchpad/user-extra.sh\n")
		b.WriteString("    permissions: '0755'\n")
		b.WriteString("    content: |\n")
		for _, line := range strings.Split(in.ExtraUserData, "\n") {
			fmt.Fprintf(&b, "      %s\n", line)
		}
	}
	return b.String()
}
