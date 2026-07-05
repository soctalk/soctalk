module github.com/soctalk/launchpad-plugin-vmware

go 1.25.0

require (
	github.com/soctalk/launchpad-sdk-go v0.0.0
	github.com/vmware/govmomi v0.55.0
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/soctalk/launchpad-sdk-go => ../../sdk-go
