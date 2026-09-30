package mcpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"writproto/exec"
	"writproto/keys"
	"writproto/writ"
)

func fixture(t *testing.T, require bool, bnd map[string]any) (*Server, *keys.Identity, *writ.Writ) {
	t.Helper()
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{7}, 32))
	e := exec.New(S, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	tools := map[string]Tool{
		"echo": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			return map[string]any{"echo": args["message"]}, false
		},
		"fail": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			return map[string]any{"why": "no"}, true
		},
	}
	w, err := writ.Issue(A, S.DID(), bnd, 1<<40, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(e, tools, require), A, w
}

// roundTrip sends params through JSON as a real client would and decodes the
// result the way a client that knows nothing of Writ would.
func roundTrip(t *testing.T, s *Server, params map[string]any) (map[string]any, *RPCError) {
	t.Helper()
	b, _ := json.Marshal(params)
	res, rpcErr := s.CallTool(context.Background(), b)
	if rpcErr != nil {
		return nil, rpcErr
	}
	rb, _ := json.Marshal(res)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	return out, nil
}

func TestToolCallUnderAWrit(t *testing.T) {
	s, A, w := fixture(t, true, map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools/echo"}, "uses": map[string]any{"t": "count", "v": 1}})
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/echo", map[string]any{"message": "hi"})
	res, rpcErr := roundTrip(t, s, Params("echo", k))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	tl, err := Check(k, res)
	if err != nil || tl.St != "ok" || res["isError"] != false {
		t.Fatalf("an enforced echo: %v %+v %v", err, tl, res)
	}
	// A second call under uses 1 is refused with a signed tally, as a tool error.
	k2, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/echo", map[string]any{"message": "again"})
	res, _ = roundTrip(t, s, Params("echo", k2))
	tl, err = Check(k2, res)
	if err != nil || tl.Err == nil || tl.Err.Code != "count_exhausted" || res["isError"] != true {
		t.Fatalf("over the count: %v %+v", err, tl)
	}
	if text := res["content"].([]any)[0].(map[string]any)["text"]; text != "Writ refused this call: count_exhausted" {
		t.Fatalf("a refusal's text for the model: %q", text)
	}
}

func TestWhatWasSignedIsWhatRuns(t *testing.T) {
	s, A, w := fixture(t, true, map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools"}})
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/echo", map[string]any{"message": "hi"})
	p := Params("echo", k)
	p["arguments"] = map[string]any{"message": "something else"}
	if _, rpcErr := roundTrip(t, s, p); rpcErr == nil || rpcErr.Data["reason"] != "malformed" {
		t.Fatalf("arguments differing from the signed args: %v", rpcErr)
	}
	if _, rpcErr := roundTrip(t, s, Params("fail", k)); rpcErr == nil || rpcErr.Data["reason"] != "malformed" {
		t.Fatalf("a call signed for echo sent to fail: %v", rpcErr)
	}
	if _, rpcErr := roundTrip(t, s, map[string]any{"name": "echo", "arguments": map[string]any{"message": "x"}}); rpcErr == nil || rpcErr.Data["reason"] != "missing_call" {
		t.Fatalf("no Writ call on a server that requires one: %v", rpcErr)
	}
	kf, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/fail", map[string]any{})
	res, _ := roundTrip(t, s, Params("fail", kf))
	if tl, err := Check(kf, res); err != nil || tl.St != "failed" || tl.Err.Code != "mcp/tool_error" || res["isError"] != true {
		t.Fatalf("a failing tool: %v %+v", err, tl)
	}
}

// The client's two rules: refuse to send consumable bounds to a server that
// does not advertise the extension, and never count a result with no tally.
func TestClientRules(t *testing.T) {
	s, A, w := fixture(t, false, map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools"}, "uses": map[string]any{"t": "count", "v": 5}})
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/echo", map[string]any{"message": "hi"})
	if err := Ready(k, false); !errors.Is(err, ErrUnenforcedServer) {
		t.Fatalf("a count bound to a server that does not advertise: %v", err)
	}
	if err := Ready(k, true); err != nil {
		t.Fatal(err)
	}
	res, _ := roundTrip(t, s, map[string]any{"name": "echo", "arguments": map[string]any{"message": "hi"}})
	if _, err := Check(k, res); !errors.Is(err, ErrMissingTally) {
		t.Fatalf("a result with no tally: %v", err)
	}
	res, _ = roundTrip(t, s, Params("echo", k))
	res["structuredContent"] = map[string]any{"echo": "forged"}
	if _, err := Check(k, res); err == nil {
		t.Fatal("a result body changed after signing verified")
	}
}
