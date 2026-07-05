package pluginhost

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// stderrRelay copies a plugin's stderr to launchpad's stderr, prefixing each
// line with the plugin name. Plugins are expected to keep stderr small and
// unstructured (developer-facing).
type stderrRelay struct {
	name string
	r    io.Reader
}

func newStderrRelay(name string, r io.Reader) *stderrRelay {
	return &stderrRelay{name: name, r: r}
}

func (s *stderrRelay) start() {
	go func() {
		sc := bufio.NewScanner(s.r)
		for sc.Scan() {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", s.name, sc.Text())
		}
	}()
}
