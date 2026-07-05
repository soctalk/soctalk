//go:build windows

package pluginhost

import "os"

// Windows has no SIGTERM; Kill on Windows is TerminateProcess. Return Kill
// so the graceful path degrades to the same effect.
func sigterm() os.Signal { return os.Kill }
