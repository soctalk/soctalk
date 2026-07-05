module github.com/soctalk/launchpad-plugin-proxmox

go 1.22

require github.com/soctalk/launchpad-sdk-go v0.0.0

require (
	golang.org/x/crypto v0.24.0
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/soctalk/launchpad-sdk-go => ../../sdk-go
