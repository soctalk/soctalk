package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

// Client owns one plugin subprocess and its JSON-RPC transport. It's
// serialized at Call level: one method in-flight at a time. For concurrent
// work, callers hold multiple Clients (see Pool).
type Client struct {
	Manifest *Manifest
	Hello    sdk.HelloParams // captured from the plugin's first frame

	cmd       *exec.Cmd
	stdin     io.WriteCloser
	transport *sdk.Transport
	stderr    *stderrRelay

	notifications chan<- *sdk.Envelope // may be nil

	// nextID assigns monotonically increasing request IDs.
	nextID atomic.Int64

	// pending routes response frames back to Call. Key: request ID.
	pending sync.Map

	// mu serializes Call.
	mu sync.Mutex

	// done closes when the subprocess exits.
	done    chan struct{}
	exitErr error
}

// StartConfig configures a plugin subprocess launch.
type StartConfig struct {
	// EnvAllowlist is the set of parent env var names to forward. Only these
	// are inherited; the child starts otherwise clean. Merged with the
	// plugin's HelloParams.AllowedEnvVars in a follow-up Initialize call
	// pattern (in v1 we forward the union declared by the operator's config).
	EnvAllowlist []string

	// ExtraEnv is additional key=value pairs merged into the child env.
	ExtraEnv []string

	// Notifications, if non-nil, receives progress/log frames the plugin
	// emits. It must be drained; missed sends drop silently.
	Notifications chan<- *sdk.Envelope

	// HelloTimeout caps the wait for the plugin's initial hello frame.
	// Default 15s.
	HelloTimeout time.Duration
}

// SpawnVerifier, if set, is called with a manifest immediately before its
// subprocess is spawned. A non-nil error aborts the spawn. It is the single
// chokepoint for spawn-time trust: the main binary wires it to a verifier that
// re-checks a managed plugin's binary and env policy against the cached signed
// index (never the editable plugin.yaml), so tampering after install cannot
// reach execution. Left nil in tests and library use, where no enforcement is
// wanted.
var SpawnVerifier func(*Manifest) error

// Start spawns the plugin subprocess and waits for the hello frame. Caller
// must call Shutdown or Kill to reclaim resources.
func Start(ctx context.Context, m *Manifest, cfg StartConfig) (*Client, error) {
	if cfg.HelloTimeout == 0 {
		cfg.HelloTimeout = 15 * time.Second
	}

	if SpawnVerifier != nil {
		if err := SpawnVerifier(m); err != nil {
			return nil, fmt.Errorf("refusing to spawn plugin %q: %w", m.Name, err)
		}
	}

	// Build a clean environment for the child. Do not use os.Setenv (parent
	// scope). Do not inherit anything from the parent env unless allow-listed.
	env := make([]string, 0, len(cfg.EnvAllowlist)+len(cfg.ExtraEnv)+1)
	for _, key := range cfg.EnvAllowlist {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	env = append(env, cfg.ExtraEnv...)
	// Provide a minimal PATH; some providers shell out to helpers.
	env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")

	cmd := exec.CommandContext(ctx, m.AbsExecutable())
	cmd.Dir = m.Dir
	cmd.Env = env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plugin %q: %w", m.Name, err)
	}

	c := &Client{
		Manifest:      m,
		cmd:           cmd,
		stdin:         stdin,
		transport:     sdk.NewTransport(stdout, stdin),
		stderr:        newStderrRelay(m.Name, stderrPipe),
		notifications: cfg.Notifications,
		done:          make(chan struct{}),
	}
	c.stderr.start()

	// Wait for hello.
	helloCtx, cancel := context.WithTimeout(ctx, cfg.HelloTimeout)
	defer cancel()
	helloEnv, err := c.transport.RecvCtx(helloCtx)
	if err != nil {
		c.hardKill()
		return nil, fmt.Errorf("waiting for plugin.hello: %w", err)
	}
	if helloEnv.Method != sdk.MethodHello {
		c.hardKill()
		return nil, fmt.Errorf("first plugin frame was %q; expected %q", helloEnv.Method, sdk.MethodHello)
	}
	if err := sdk.ParseParams(helloEnv, &c.Hello); err != nil {
		c.hardKill()
		return nil, fmt.Errorf("parse hello params: %w", err)
	}
	if c.Hello.ProtocolVersion != sdk.ProtocolVersion {
		c.hardKill()
		return nil, fmt.Errorf("plugin %q protocol_version=%q; launchpad expects %q",
			m.Name, c.Hello.ProtocolVersion, sdk.ProtocolVersion)
	}

	go c.recvLoop()

	// Reap process exit into c.done for Call to detect early exit.
	go func() {
		c.exitErr = cmd.Wait()
		close(c.done)
	}()

	return c, nil
}

// recvLoop dispatches frames: responses → pending map, notifications →
// notifications channel or dropped.
func (c *Client) recvLoop() {
	for {
		env, err := c.transport.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fmt.Fprintf(os.Stderr, "launchpad: plugin %q recv error: %v\n", c.Manifest.Name, err)
			return
		}
		if env.ID != nil && env.Method == "" {
			// Response frame.
			if p, ok := c.pending.LoadAndDelete(*env.ID); ok {
				p.(chan *sdk.Envelope) <- env
			}
			continue
		}
		if env.Method != "" && env.ID == nil {
			// Notification.
			if c.notifications != nil {
				select {
				case c.notifications <- env:
				default:
					// Drop; consumer isn't draining.
				}
			}
			continue
		}
		// Any other shape is a protocol violation; ignore silently.
	}
}

// Call sends a request, waits for the response, and unmarshals result into dst.
// dst may be nil if the response has no result.
func (c *Client) Call(ctx context.Context, method string, params any, dst any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	id := c.nextID.Add(1)
	resp := make(chan *sdk.Envelope, 1)
	c.pending.Store(id, resp)

	if err := c.transport.Send(sdk.Request(id, method, params)); err != nil {
		c.pending.Delete(id)
		return fmt.Errorf("send %s: %w", method, err)
	}

	select {
	case env := <-resp:
		if env.Error != nil {
			return &RPCError{
				Method: method,
				Code:   env.Error.Code,
				Msg:    env.Error.Message,
				Data:   env.Error.Data,
			}
		}
		if dst != nil {
			return sdk.ParseResult(env, dst)
		}
		return nil
	case <-ctx.Done():
		c.pending.Delete(id)
		return ctx.Err()
	case <-c.done:
		c.pending.Delete(id)
		return fmt.Errorf("plugin %q exited before response (exit err: %v)", c.Manifest.Name, c.exitErr)
	}
}

// Shutdown does the graceful teardown dance: shutdown request (5s), close
// stdin, SIGTERM (5s), SIGKILL.
func (c *Client) Shutdown(ctx context.Context) error {
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var res sdk.ShutdownResult
	shutdownErr := c.Call(sctx, sdk.MethodShutdown, sdk.ShutdownParams{}, &res)

	_ = c.stdin.Close()

	select {
	case <-c.done:
		return shutdownErr
	case <-time.After(5 * time.Second):
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(sigterm())
	}
	select {
	case <-c.done:
		return shutdownErr
	case <-time.After(5 * time.Second):
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	<-c.done
	return shutdownErr
}

// hardKill is for handshake failures where the plugin is unusable.
func (c *Client) hardKill() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

// Wait blocks until the plugin exits.
func (c *Client) Wait() error {
	<-c.done
	return c.exitErr
}

// RPCError is what Call returns when the plugin replies with an error frame.
type RPCError struct {
	Method string
	Code   int
	Msg    string
	Data   *sdk.ErrorData
}

func (e *RPCError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("%s: [%s/%s] %s", e.Method, e.Data.Category, e.Data.AppCode, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Method, e.Msg)
}
