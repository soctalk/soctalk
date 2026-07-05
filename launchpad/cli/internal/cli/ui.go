package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/soctalk/launchpad/internal/httpapi"
	"github.com/soctalk/launchpad/internal/runmanager"
)

// UIOptions is what `launchpad ui` parses out of flags.
type UIOptions struct {
	Port   int  // 0 = random
	NoOpen bool // skip opening the browser
	Dev    bool // don't serve the embedded SPA (Vite dev server does)
	// Token overrides the random per-server token. ONLY for scripted tests
	// (Playwright needs to know the token before the server prints it).
	Token string
}

// UI starts the HTTP + WS server and (optionally) opens the browser.
func UI(opts UIOptions) error {
	runsDir := defaultStateDir()
	mgr := runmanager.New(runsDir)
	// hosts.json lives one level up from the runs dir (~/.launchpad).
	srv := httpapi.New(mgr, filepath.Dir(runsDir), opts.Dev)
	if opts.Token != "" {
		srv.Token = opts.Token
	}
	if !opts.NoOpen && opts.Port != 0 {
		// Open the browser once the socket is up. Only possible with an
		// explicit --port (with :0 the address isn't known until bind).
		go func() {
			url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", opts.Port, srv.Token)
			if runtime.GOOS == "darwin" {
				_ = exec.Command("open", url).Start()
			} else {
				_ = exec.Command("xdg-open", url).Start()
			}
		}()
	}
	if err := srv.ListenAndServe(opts.Port); err != nil {
		fmt.Fprintln(os.Stderr, "ui server:", err)
		return err
	}
	return nil
}
