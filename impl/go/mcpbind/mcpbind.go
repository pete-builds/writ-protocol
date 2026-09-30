// Package mcpbind carries Writ over MCP, as docs/adoption.md section 2a
// designs it: the call rides in params._meta["io.writ/call"] on tools/call,
// the tally in result._meta["io.writ/tally"], and a server advertises the
// extension as io.writ/delegation. It works on decoded JSON-RPC params and
// results, so it fits any MCP server or client without an SDK dependency.
package mcpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"writproto/exec"
	"writproto/jcs"
	"writproto/wire"
	"writproto/writ"
)

const (
	Extension = "io.writ/delegation"
	CallKey   = "io.writ/call"
	TallyKey  = "io.writ/tally"
	// OpPrefix makes a tool call's op: mcp/tools/<tool name>.
	OpPrefix = "mcp/tools/"
)

// ExtensionInfo is the entry a server lists for server/discover, naming the
// key it executes under, so a client can delegate to it (the leaf hld).
func ExtensionInfo(did string) map[string]any {
	return map[string]any{Extension: map[string]any{"version": 1, "did": did}}
}

// Advertised reads a server/discover or initialize result: whether the server
// enforces the extension, and the key it executes under.
func Advertised(result map[string]any) (bool, string) {
	ext, _ := result["extensions"].(map[string]any)
	if ext == nil {
		caps, _ := result["capabilities"].(map[string]any)
		ext, _ = caps["extensions"].(map[string]any)
	}
	info, ok := ext[Extension].(map[string]any)
	if !ok {
		return false, ""
	}
	did, _ := info["did"].(string)
	return true, did
}

// Tool performs one MCP tool. It returns the structured result, which is the
// Writ result body, and whether the tool failed (MCP's isError).
type Tool func(ctx context.Context, args map[string]any) (structured map[string]any, isError bool)

// RPCError is a JSON-RPC error for tools/call.
type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

func invalid(reason, msg string) *RPCError {
	return &RPCError{Code: -32602, Message: msg, Data: map[string]any{"reason": reason}}
}

// Server answers tools/call through an executor, so every tool call is
// checked against the writ chain it carries and answered with a tally.
type Server struct {
	E     *exec.Executor
	Tools map[string]Tool
	// Require refuses a tools/call that carries no Writ call. Without it,
	// such a call runs unenforced and its result carries no tally, which a
	// Writ client treats as unenforced (section 2a).
	Require bool
}

// NewServer returns a server over e and installs its tool dispatch as e's
// handler.
func NewServer(e *exec.Executor, tools map[string]Tool, require bool) *Server {
	s := &Server{E: e, Tools: tools, Require: require}
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		tool := s.Tools[strings.TrimPrefix(k.Op, OpPrefix)]
		if tool == nil {
			return exec.Result{St: "failed", ErrCode: "mcp/unknown_tool"}
		}
		body, isErr := tool(ctx, k.Args)
		if isErr {
			return exec.Result{St: "failed", ErrCode: "mcp/tool_error", Res: body}
		}
		return exec.Result{Res: body}
	}
	return s
}

type callParams struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta"`
}

// CallTool answers the params of one tools/call request with its result.
func (s *Server) CallTool(ctx context.Context, params json.RawMessage) (map[string]any, *RPCError) {
	var p callParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalid("malformed", "tools/call params are not an object")
	}
	tool := s.Tools[p.Name]
	if tool == nil {
		return nil, &RPCError{Code: -32602, Message: "unknown tool " + p.Name}
	}
	args := map[string]any{}
	if len(p.Arguments) > 0 && string(p.Arguments) != "null" {
		dec := json.NewDecoder(bytes.NewReader(p.Arguments))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return nil, invalid("malformed", "arguments are not an object")
		}
	}
	raw, carried := p.Meta[CallKey]
	if !carried {
		if s.Require {
			return nil, invalid("missing_call", "this server enforces "+Extension+": the call must carry "+CallKey)
		}
		body, isErr := tool(ctx, args)
		return result(body, isErr, nil), nil
	}
	obj, err := wire.Decode(raw)
	if err != nil {
		return nil, invalid("noncanonical", "the Writ call is not canonical JSON")
	}
	// What was signed and what runs must be the same bytes (section 2a).
	if op, _ := obj["op"].(string); op != OpPrefix+p.Name {
		return nil, invalid("malformed", "the Writ call's op is not "+OpPrefix+p.Name)
	}
	if !sameJSON(obj["args"], args) {
		return nil, invalid("malformed", "the Writ call's args differ from the tool arguments")
	}
	rep, rej := s.E.Execute(ctx, obj)
	if rej != nil {
		return nil, invalid(string(rej.Code), "the Writ call was rejected: "+string(rej.Code))
	}
	body, _ := rep.Res.(map[string]any)
	st, _ := rep.Tally["st"].(string)
	return result(body, st != "ok", rep.Tally), nil
}

func result(body map[string]any, isErr bool, tally wire.Object) map[string]any {
	text := "{}"
	if body != nil {
		if b, err := jcs.Marshal(body); err == nil {
			text = string(b)
		}
	} else if e, ok := tally["err"].(map[string]any); ok && isErr {
		// A refusal has no result body; say why, for the model reading it.
		text = fmt.Sprintf("Writ refused this call: %v", e["code"])
	}
	r := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}
	if body != nil {
		r["structuredContent"] = body
	}
	if tally != nil {
		r["_meta"] = map[string]any{TallyKey: tally}
	}
	return r
}

func sameJSON(a, b any) bool {
	x, err1 := jcs.Marshal(a)
	y, err2 := jcs.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// Client-side rules (section 2a).

// ErrUnenforcedServer: the server does not advertise the extension, and the
// chain carries bounds only an enforcing server would consume.
var ErrUnenforcedServer = errors.New("unenforced_server")

// ErrMissingTally: the server advertised the extension and returned no tally.
var ErrMissingTally = errors.New("missing_tally")

// Params builds tools/call params carrying k, whose op must name tool.
func Params(tool string, k *writ.Call) map[string]any {
	return map[string]any{"name": tool, "arguments": k.Args, "_meta": map[string]any{CallKey: k.Raw}}
}

// Ready refuses to send k to a server that does not advertise the extension
// when any writ in its chain carries a max or count bound.
func Ready(k *writ.Call, advertised bool) error {
	if advertised {
		return nil
	}
	for _, w := range k.Chain {
		for _, b := range w.Bnd {
			if b.T == "max" || b.T == "count" {
				return ErrUnenforcedServer
			}
		}
	}
	return nil
}

// Check verifies the tally in a tools/call result for the call k (spec 6.2),
// with structuredContent as the result body. A result with no tally is
// ErrMissingTally: the work does not count as done.
func Check(k *writ.Call, result map[string]any) (*writ.Tally, error) {
	meta, _ := result["_meta"].(map[string]any)
	raw, ok := meta[TallyKey]
	if !ok {
		return nil, ErrMissingTally
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	obj, err := wire.Decode(b)
	if err != nil {
		return nil, err
	}
	var body any
	if sc, ok := result["structuredContent"]; ok {
		// A client may have decoded numbers as floats; hash the exact integers.
		b, err := json.Marshal(sc)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			return nil, err
		}
	}
	v, t, err := writ.VerifyTally(k.Leaf(), k, obj, body)
	if v != writ.Valid {
		if err == nil {
			err = errors.New(string(v))
		}
		return t, err
	}
	return t, nil
}
