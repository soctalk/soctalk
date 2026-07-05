package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Transport is the line-delimited JSON-RPC framer. It's the same on both
// sides (plugin embeds one wired to os.Stdin/os.Stdout; launchpad embeds
// one wired to the plugin's stdin/stdout pipes).
type Transport struct {
	// mu serializes writes. Multiple goroutines call Send (notifications,
	// responses) so we need exclusion.
	mu sync.Mutex

	scanner *bufio.Scanner
	writer  io.Writer
}

// NewTransport wires a transport to the given reader (incoming frames) and
// writer (outgoing frames). It sets the scanner buffer to MaxMessageBytes so
// oversized messages fail loudly rather than silently truncating.
func NewTransport(r io.Reader, w io.Writer) *Transport {
	sc := bufio.NewScanner(r)
	// Start with a modest buffer, cap at MaxMessageBytes.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, MaxMessageBytes)
	return &Transport{scanner: sc, writer: w}
}

// Send serializes env into a single JSON line and writes it.
//
// Precondition: env.JSONRPC must be "2.0" or empty (we default it).
func (t *Transport) Send(env *Envelope) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if env.JSONRPC == "" {
		env.JSONRPC = "2.0"
	}
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if len(b) > MaxMessageBytes {
		return fmt.Errorf("envelope %d bytes exceeds MaxMessageBytes (%d)", len(b), MaxMessageBytes)
	}
	// Compact JSON is single-line by construction; append \n framing.
	b = append(b, '\n')
	if _, err := t.writer.Write(b); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// Recv reads one frame off the wire and unmarshals it into an Envelope.
// Returns io.EOF when the peer closes cleanly.
func (t *Transport) Recv() (*Envelope, error) {
	// bufio.Scanner is not safe for concurrent Reads, but only one goroutine
	// should be pulling frames. No mutex here.
	if !t.scanner.Scan() {
		if err := t.scanner.Err(); err != nil {
			// Note: bufio.ErrTooLong maps here if a message exceeds MaxMessageBytes.
			return nil, fmt.Errorf("recv: %w", err)
		}
		return nil, io.EOF
	}
	line := t.scanner.Bytes()
	if len(line) == 0 {
		// Skip blank lines gracefully — some plugin runtimes emit them.
		return t.Recv()
	}
	env := &Envelope{}
	if err := json.Unmarshal(line, env); err != nil {
		return nil, fmt.Errorf("parse frame: %w", err)
	}
	if env.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported jsonrpc version %q", env.JSONRPC)
	}
	return env, nil
}

// RecvCtx wraps Recv with context cancellation. Since bufio.Scanner is
// synchronous, we run Recv in a goroutine and select against ctx.Done.
// On cancel we return ctx.Err(); the underlying reader is not interrupted
// (caller is expected to close it to unblock the scanner goroutine).
func (t *Transport) RecvCtx(ctx context.Context) (*Envelope, error) {
	type recvOut struct {
		env *Envelope
		err error
	}
	out := make(chan recvOut, 1)
	go func() {
		env, err := t.Recv()
		out <- recvOut{env, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-out:
		return r.env, r.err
	}
}

// ------------------------------------------------------------------
// Helpers for common envelopes
// ------------------------------------------------------------------

// Notification builds a JSON-RPC notification envelope (no ID).
func Notification(method string, params any) *Envelope {
	return &Envelope{JSONRPC: "2.0", Method: method, Params: params}
}

// Request builds a JSON-RPC request envelope with the given ID.
func Request(id int64, method string, params any) *Envelope {
	return &Envelope{JSONRPC: "2.0", ID: &id, Method: method, Params: params}
}

// SuccessResponse builds an ok response for the given request ID.
func SuccessResponse(id int64, result any) *Envelope {
	return &Envelope{JSONRPC: "2.0", ID: &id, Result: result}
}

// ErrorResponse builds an error response for the given request ID.
func ErrorResponse(id int64, code int, msg string, data *ErrorData) *Envelope {
	return &Envelope{
		JSONRPC: "2.0",
		ID:      &id,
		Error:   &ProtocolError{Code: code, Message: msg, Data: data},
	}
}

// ParseParams unmarshals env.Params into the destination pointer. Convenient
// because Envelope.Params is `any` on the wire (json.RawMessage after Recv
// through the generic Envelope type — but we always end up needing typed
// access).
//
// If env.Params is nil, dst is left zero-valued and no error is returned.
func ParseParams(env *Envelope, dst any) error {
	if env.Params == nil {
		return nil
	}
	// Fast path: env.Params is a json.RawMessage-like value (after json.Unmarshal
	// through `any` it's map[string]any or []any). Re-marshal + unmarshal.
	raw, err := json.Marshal(env.Params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("unmarshal params: %w", err)
	}
	return nil
}

// ParseResult unmarshals env.Result into the destination pointer.
func ParseResult(env *Envelope, dst any) error {
	if env.Result == nil {
		return nil
	}
	raw, err := json.Marshal(env.Result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}
	return nil
}

// ErrEOF is returned when the peer has closed the stream cleanly.
var ErrEOF = errors.New("peer closed")
