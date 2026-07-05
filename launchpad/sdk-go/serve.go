package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// Plugin is the surface a plugin implements. Methods that a plugin does not
// support should return an error with Category=CatValidation and
// AppCode="capability_not_supported"; declaring capabilities correctly in
// Hello is the way to avoid launchpad calling them at all.
type Plugin struct {
	// Metadata.
	Name    string
	Version string

	// ConfigSchema is a JSON schema (draft-2020-12) for the map launchpad
	// will send in initialize.
	ConfigSchema map[string]any

	// AllowedEnvVars enumerates which environment variables the launchpad
	// should pass through to this plugin. Launchpad starts the plugin with a
	// clean environment plus these vars.
	AllowedEnvVars []string

	// Handlers.
	Initialize   func(ctx context.Context, params InitializeParams) (InitializeResult, error)
	Plan         func(ctx context.Context, params VMPlanParams, emit Emitter) (VMPlanResult, error)
	Create       func(ctx context.Context, params VMCreateParams, emit Emitter) (VMCreateResult, error)
	WaitReady    func(ctx context.Context, params VMWaitReadyParams, emit Emitter) (VMWaitReadyResult, error)
	Destroy      func(ctx context.Context, params VMDestroyParams, emit Emitter) (VMDestroyResult, error)
	Inspect      func(ctx context.Context, params VMInspectParams, emit Emitter) (VMInspectResult, error)
	Shutdown     func(ctx context.Context) error
}

// Emitter is the progress+log channel a handler can use during long-running
// work. The op_id is stitched in automatically by the SDK so plugins don't
// have to think about correlation.
type Emitter interface {
	Progress(step string, percent float64, message string)
	Log(level, message string, fields map[string]any)
}

type serverEmitter struct {
	transport *Transport
	opID      int64
	vmKey     string
}

func (e *serverEmitter) Progress(step string, percent float64, message string) {
	_ = e.transport.Send(Notification(MethodProgress, ProgressParams{
		OpID:    e.opID,
		VMKey:   e.vmKey,
		Step:    step,
		Percent: percent,
		Message: message,
	}))
}

func (e *serverEmitter) Log(level, message string, fields map[string]any) {
	_ = e.transport.Send(Notification(MethodLog, LogParams{
		OpID:    e.opID,
		VMKey:   e.vmKey,
		Level:   level,
		Message: message,
		Fields:  fields,
	}))
}

// Serve runs the plugin's main loop. It:
//   1. Emits plugin.hello on start.
//   2. Reads requests from stdin, dispatches to the handler, writes responses.
//   3. Handles plugin.shutdown gracefully.
//   4. Returns nil on clean shutdown, error on protocol violation.
//
// Serve is the intended entry point for a plugin's main() function.
//
//	func main() {
//	  err := sdk.Serve(sdk.Plugin{
//	    Name:    "hetzner",
//	    Version: "0.1.0",
//	    // ...
//	  })
//	  if err != nil {
//	    fmt.Fprintln(os.Stderr, err)
//	    os.Exit(1)
//	  }
//	}
func Serve(p Plugin) error {
	return ServeIO(p, os.Stdin, os.Stdout)
}

// ServeIO is Serve with explicit I/O; useful for tests.
func ServeIO(p Plugin, r io.Reader, w io.Writer) error {
	if err := validatePlugin(&p); err != nil {
		return err
	}
	t := NewTransport(r, w)

	// Phase 1: emit hello. Plugin speaks first per protocol.
	caps := []string{}
	if p.Plan != nil {
		caps = append(caps, MethodVMPlan)
	}
	if p.Create != nil {
		caps = append(caps, MethodVMCreate)
	}
	if p.WaitReady != nil {
		caps = append(caps, MethodVMWaitReady)
	}
	if p.Destroy != nil {
		caps = append(caps, MethodVMDestroy)
	}
	if p.Inspect != nil {
		caps = append(caps, MethodVMInspect)
	}
	if err := t.Send(Notification(MethodHello, HelloParams{
		ProtocolVersion: ProtocolVersion,
		PluginName:      p.Name,
		PluginVersion:   p.Version,
		Capabilities:    caps,
		ConfigSchema:    p.ConfigSchema,
		AllowedEnvVars:  p.AllowedEnvVars,
	})); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Phase 2+: request/response loop.
	for {
		env, err := t.Recv()
		if errors.Is(err, io.EOF) {
			// Parent closed stdin without a shutdown request. Exit clean.
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if env.Method == "" {
			// Response frame — plugins don't originate requests in v1, so
			// this is a protocol violation. Ignore rather than crash.
			continue
		}
		if err := dispatch(&p, t, env); err != nil {
			return err
		}
		if env.Method == MethodShutdown {
			return nil
		}
	}
}

func validatePlugin(p *Plugin) error {
	if p.Name == "" {
		return errors.New("plugin.Name required")
	}
	if p.Version == "" {
		return errors.New("plugin.Version required")
	}
	if p.Initialize == nil {
		return errors.New("plugin.Initialize required")
	}
	return nil
}

func dispatch(p *Plugin, t *Transport, req *Envelope) error {
	ctx := context.Background()
	// Notifications (no ID) get no response.
	respondErr := func(code int, msg string, cat ErrorCategory, appCode, hint string) {
		if req.ID == nil {
			return
		}
		_ = t.Send(ErrorResponse(*req.ID, code, msg, &ErrorData{
			Category: cat,
			AppCode:  appCode,
			Hint:     hint,
		}))
	}
	respondOK := func(result any) {
		if req.ID == nil {
			return
		}
		_ = t.Send(SuccessResponse(*req.ID, result))
	}

	emit := &serverEmitter{transport: t}
	if req.ID != nil {
		emit.opID = *req.ID
	}

	switch req.Method {
	case MethodInitialize:
		var params InitializeParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		res, err := p.Initialize(ctx, params)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "initialize_failed")
			return nil
		}
		respondOK(res)

	case MethodShutdown:
		if p.Shutdown != nil {
			_ = p.Shutdown(ctx)
		}
		respondOK(ShutdownResult{})

	case MethodVMPlan:
		if p.Plan == nil {
			respondErr(ErrMethodNotFound, "vm.plan not supported", CatValidation, "capability_not_supported", "")
			return nil
		}
		var params VMPlanParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		emit.vmKey = params.Spec.VMKey
		res, err := p.Plan(ctx, params, emit)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "plan_failed")
			return nil
		}
		respondOK(res)

	case MethodVMCreate:
		if p.Create == nil {
			respondErr(ErrMethodNotFound, "vm.create not supported", CatValidation, "capability_not_supported", "")
			return nil
		}
		var params VMCreateParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		emit.vmKey = params.Spec.VMKey
		res, err := p.Create(ctx, params, emit)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "create_failed")
			return nil
		}
		respondOK(res)

	case MethodVMWaitReady:
		if p.WaitReady == nil {
			respondErr(ErrMethodNotFound, "vm.wait_ready not supported", CatValidation, "capability_not_supported", "")
			return nil
		}
		var params VMWaitReadyParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		emit.vmKey = params.VMKey
		res, err := p.WaitReady(ctx, params, emit)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "wait_ready_failed")
			return nil
		}
		respondOK(res)

	case MethodVMDestroy:
		if p.Destroy == nil {
			respondErr(ErrMethodNotFound, "vm.destroy not supported", CatValidation, "capability_not_supported", "")
			return nil
		}
		var params VMDestroyParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		emit.vmKey = params.VMKey
		res, err := p.Destroy(ctx, params, emit)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "destroy_failed")
			return nil
		}
		respondOK(res)

	case MethodVMInspect:
		if p.Inspect == nil {
			respondErr(ErrMethodNotFound, "vm.inspect not supported", CatValidation, "capability_not_supported", "")
			return nil
		}
		var params VMInspectParams
		if err := ParseParams(req, &params); err != nil {
			respondErr(ErrInvalidParams, err.Error(), CatValidation, "invalid_params", "")
			return nil
		}
		emit.vmKey = params.VMKey
		res, err := p.Inspect(ctx, params, emit)
		if err != nil {
			respondPluginError(t, req, err, CatInternal, "inspect_failed")
			return nil
		}
		respondOK(res)

	default:
		respondErr(ErrMethodNotFound, fmt.Sprintf("unknown method %q", req.Method), CatValidation, "method_not_found", "")
	}
	return nil
}

// respondPluginError converts a handler error into the wire format.
//
// If the error is a *PluginError, its category/code/hint are used verbatim.
// Otherwise we synthesize an internal-category error with the default code.
func respondPluginError(t *Transport, req *Envelope, err error, defaultCat ErrorCategory, defaultCode string) {
	if req.ID == nil {
		return
	}
	var pe *PluginError
	if errors.As(err, &pe) {
		_ = t.Send(ErrorResponse(*req.ID, ErrPluginInternal, pe.Msg, &ErrorData{
			Category: pe.Category,
			AppCode:  pe.Code,
			Hint:     pe.Hint,
			DocsURL:  pe.DocsURL,
			Retry:    pe.Retry,
		}))
		return
	}
	_ = t.Send(ErrorResponse(*req.ID, ErrPluginInternal, err.Error(), &ErrorData{
		Category: defaultCat,
		AppCode:  defaultCode,
	}))
}

// PluginError is a structured error a handler may return; the SDK translates
// it into the wire error format.
type PluginError struct {
	Category ErrorCategory
	Code     string
	Msg      string
	Hint     string
	DocsURL  string
	Retry    *RetryPolicy
}

// Error implements the error interface.
func (e *PluginError) Error() string { return e.Msg }

// Errf constructs a PluginError from a category, code, and formatted message.
func Errf(cat ErrorCategory, code, format string, args ...any) *PluginError {
	return &PluginError{Category: cat, Code: code, Msg: fmt.Sprintf(format, args...)}
}
