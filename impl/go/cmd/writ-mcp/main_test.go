package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"writproto/exec"
	"writproto/keys"
	"writproto/mcpbind"
	"writproto/writ"
)

// A scripted MCP session over the stdio transport: initialize, discover,
// list, an enforced call, and an unenforced one refused.
func TestStdioSession(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{7}, 32))
	e := exec.New(S, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	s := newServer(e, true)
	w, _ := writ.Issue(A, S.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools/echo"}}, 1<<40, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "mcp/tools/echo", map[string]any{"message": "hi"})
	lines := []any{
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18"}},
		map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "server/discover"},
		map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
		map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": mcpbind.Params("echo", k)},
		map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{"name": "echo", "arguments": map[string]any{"message": "x"}}},
	}
	var in bytes.Buffer
	for _, l := range lines {
		b, _ := json.Marshal(l)
		in.Write(append(b, '\n'))
	}
	var out bytes.Buffer
	if err := s.run(&in, &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		resps = append(resps, m)
	}
	if len(resps) != 5 {
		t.Fatalf("%d responses, want 5 (the notification gets none)", len(resps))
	}
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %v", init)
	}
	if _, ok := resps[1]["result"].(map[string]any)["extensions"].(map[string]any)[mcpbind.Extension]; !ok {
		t.Fatalf("server/discover does not advertise %s: %v", mcpbind.Extension, resps[1])
	}
	if tl, err := mcpbind.Check(k, resps[3]["result"].(map[string]any)); err != nil || tl.St != "ok" {
		t.Fatalf("the enforced call: %v %+v", err, tl)
	}
	if e, ok := resps[4]["error"].(map[string]any); !ok || e["data"].(map[string]any)["reason"] != "missing_call" {
		t.Fatalf("the unenforced call: %v", resps[4])
	}
}
