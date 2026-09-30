package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"writproto/exec"
	"writproto/keys"
	"writproto/mcpbind"
	"writproto/writ"
)

// upstream is a stand-in MCP server enforcing Writ, run over pipes. advertise
// and stripTally let a test make it misbehave.
func upstream(t *testing.T, in io.Reader, out io.Writer, S *keys.Identity, root string, advertise, stripTally bool) {
	e := exec.New(S, nil)
	e.AcceptRoot = func(d string) bool { return d == root }
	srv := mcpbind.NewServer(e, map[string]mcpbind.Tool{
		"echo": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			return map[string]any{"echo": args["message"]}, false
		},
	}, true)
	sc := bufio.NewScanner(in)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var m message
		_ = json.Unmarshal(sc.Bytes(), &m)
		if len(m.ID) == 0 {
			continue
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": m.ID}
		switch m.Method {
		case "initialize":
			resp["result"] = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}}
		case "server/discover":
			ext := map[string]any{}
			if advertise {
				ext = mcpbind.ExtensionInfo(S.DID())
			}
			resp["result"] = map[string]any{"extensions": ext}
		case "tools/call":
			// A notification in the middle, which the proxy must relay.
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"p": 1}})
			res, rpcErr := srv.CallTool(context.Background(), m.Params)
			if rpcErr != nil {
				resp["error"] = rpcErr
			} else {
				if stripTally {
					delete(res, "_meta")
				}
				resp["result"] = res
			}
		default:
			resp["error"] = map[string]any{"code": -32601, "message": "no"}
		}
		_ = enc.Encode(resp)
	}
}

// session runs the proxy between a scripted client and an upstream.
func session(t *testing.T, bnd map[string]any, advertise, stripTally bool, requests ...map[string]any) ([]map[string]any, string) {
	t.Helper()
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{7}, 32))
	grant, err := writ.Issue(A, B.DID(), bnd, 1<<40, nil)
	if err != nil {
		t.Fatal(err)
	}
	upInR, upInW := io.Pipe()
	upOutR, upOutW := io.Pipe()
	go upstream(t, upInR, upOutW, S, A.DID(), advertise, stripTally)
	p := newProxy(B, grant, upInW, upOutR)
	var receipts bytes.Buffer
	p.receipts = &receipts
	var in bytes.Buffer
	for _, r := range requests {
		b, _ := json.Marshal(r)
		in.Write(append(b, '\n'))
	}
	var out bytes.Buffer
	if err := p.run(&in, &out); err != nil {
		t.Fatal(err)
	}
	upInW.Close()
	var msgs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		dec := json.NewDecoder(strings.NewReader(l))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		msgs = append(msgs, m)
	}
	return msgs, receipts.String()
}

func call(id int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "echo", "arguments": map[string]any{"message": msg}}}
}

func byID(msgs []map[string]any, id string) map[string]any {
	for _, m := range msgs {
		if v, ok := m["id"].(json.Number); ok && v.String() == id {
			return m
		}
	}
	return nil
}

func TestProxySignsCallsAndChecksTallies(t *testing.T) {
	bnd := map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools"}, "uses": map[string]any{"t": "count", "v": 1}}
	msgs, receipts := session(t, bnd, true, false,
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}},
		call(2, "hi"),
		call(3, "again"),
	)
	if byID(msgs, "1")["result"] == nil {
		t.Fatalf("initialize was not relayed: %v", msgs)
	}
	r2, _ := byID(msgs, "2")["result"].(map[string]any)
	if r2 == nil || r2["isError"] != false || r2["structuredContent"].(map[string]any)["echo"] != "hi" {
		t.Fatalf("an enforced call through the proxy: %v", byID(msgs, "2"))
	}
	r3, _ := byID(msgs, "3")["result"].(map[string]any)
	tally := r3["_meta"].(map[string]any)[mcpbind.TallyKey].(map[string]any)
	if r3["isError"] != true || tally["err"].(map[string]any)["code"] != "count_exhausted" {
		t.Fatalf("a second call under uses 1: %v", r3)
	}
	notes := 0
	for _, m := range msgs {
		if m["method"] == "notifications/progress" {
			notes++
		}
	}
	if notes != 2 || strings.Count(receipts, "\n") != 2 {
		t.Fatalf("%d notifications relayed (want 2), %d receipts kept (want 2)", notes, strings.Count(receipts, "\n"))
	}
}

func TestProxyRefusesWhatItCannotVerify(t *testing.T) {
	counted := map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools"}, "uses": map[string]any{"t": "count", "v": 5}}
	msgs, _ := session(t, counted, false, false, call(1, "hi"))
	if reason(byID(msgs, "1")) != "unenforced_server" {
		t.Fatalf("a count bound to a server that does not advertise: %v", msgs)
	}
	msgs, receipts := session(t, counted, true, true, call(1, "hi"))
	if reason(byID(msgs, "1")) != "missing_tally" || receipts != "" {
		t.Fatalf("a server that strips the tally: %v", msgs)
	}
}

func reason(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	s, _ := d["reason"].(string)
	return s
}
