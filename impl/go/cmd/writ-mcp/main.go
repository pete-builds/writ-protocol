// writ-mcp is a minimal MCP server over stdio whose tools run under Writ:
// each tools/call must carry a Writ call in _meta (with -require), is checked
// by the reference executor, and is answered with a signed tally. It serves
// one tool, echo, and exists to show and test the binding of
// docs/adoption.md section 2a with real MCP clients.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"writproto/exec"
	"writproto/keys"
	"writproto/mcpbind"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {
	seedHex := flag.String("seed", "", "32-byte hex seed for the server's key")
	accept := flag.String("accept", "", "comma-separated did:key roots the server acts under")
	store := flag.String("store", "", "path of the durable store (empty for memory)")
	audit := flag.String("audit", "", "path of the audit record (empty for none)")
	require := flag.Bool("require", true, "refuse tool calls that carry no Writ call")
	flag.Parse()
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("-seed must be 32 bytes of hex")
	}
	id, _ := keys.FromSeed(seed)
	st, err := exec.OpenFileStore(*store)
	if err != nil {
		log.Fatal(err)
	}
	e := exec.New(id, st)
	roots := map[string]bool{}
	for _, r := range strings.Split(*accept, ",") {
		if r != "" {
			roots[r] = true
		}
	}
	e.AcceptRoot = func(did string) bool { return roots[did] }
	if *audit != "" {
		al, err := exec.OpenAuditLog(*audit)
		if err != nil {
			log.Fatal(err)
		}
		e.Audit = func(a exec.AuditEntry) { _ = al.Record(a) }
	}
	s := newServer(e, *require)
	if err := s.run(os.Stdin, os.Stdout); err != nil && err != io.EOF {
		log.Fatal(err)
	}
}

type server struct {
	mcp *mcpbind.Server
	did string
}

func newServer(e *exec.Executor, require bool) *server {
	tools := map[string]mcpbind.Tool{
		"echo": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			return map[string]any{"echo": args["message"]}, false
		},
	}
	return &server{mcp: mcpbind.NewServer(e, tools, require), did: e.ID.DID()}
}

// run reads newline-delimited JSON-RPC requests and writes responses, as the
// MCP stdio transport does.
func (s *server) run(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification needs no answer
		}
		result, rpcErr := s.handle(req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *server) handle(req rpcRequest) (any, *mcpbind.RPCError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		return map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}, "extensions": mcpbind.ExtensionInfo(s.did)},
			"serverInfo":      map[string]any{"name": "writ-mcp", "version": "0.1"},
			"instructions":    fmt.Sprintf("Tool calls run under Writ. This server's key is %s.", s.did),
		}, nil
	case "server/discover":
		return map[string]any{"extensions": mcpbind.ExtensionInfo(s.did)}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": []any{map[string]any{
			"name":        "echo",
			"description": "Echo a message back. Runs only under a Writ call that permits mcp/tools/echo.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}, "required": []any{"message"}},
		}}}, nil
	case "tools/call":
		return s.mcp.CallTool(context.Background(), req.Params)
	}
	return nil, &mcpbind.RPCError{Code: -32601, Message: "method not found: " + req.Method}
}
