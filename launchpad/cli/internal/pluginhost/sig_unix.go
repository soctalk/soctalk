//go:build !windows

package pluginhost

import (
	"os"
	"syscall"
)

func sigterm() os.Signal { return syscall.SIGTERM }
