// writ-mcp-proxy is the MCP client side of Writ, for clients that know
// nothing about it. It is an MCP server over stdio that starts the real MCP
// server as a child process and relays everything between them, except that
// each tools/call leaves carrying a Writ call signed under a grant, and each
// result comes back only if its tally verifies (docs/adoption.md section 2a).
//
//	writ-mcp-proxy -agent-seed-file agent.seed -grant grant.json -- writ-mcp -seed ... -accept ...
//
// The grant is a writ from its root to the agent key. The proxy learns the
// server's key from server/discover, passes the grant on to it unchanged, and
// signs one call per tool call. It refuses a server that does not advertise
// the extension when the grant carries max or count bounds (unenforced_server),
// and turns a result with no tally, or one that does not verify, into an error
// (missing_tally): the work does not count as done. Verified tallies are
// appended to -receipts.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	osexec "os/exec"
	"strings"
	"sync"

	"writproto/keys"
	"writproto/mcpbind"
	"writproto/wire"
	"writproto/writ"
)

func main() {
	seedFile := flag.String("agent-seed-file", "", "file holding the agent's 32-byte hex seed, which signs each call")
	grantFile := flag.String("grant", "", "the grant: a writ from its root to the agent key")
	receipts := flag.String("receipts", "", "append each verified tally to this file as a JSON line")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("usage: writ-mcp-proxy -agent-seed-file F -grant G [-receipts R] -- <mcp server command> [args]")
	}
	agent, grant, err := load(*seedFile, *grantFile)
	if err != nil {
		log.Fatal(err)
	}
	cmd := osexec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Stderr = os.Stderr
	upIn, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	p := newProxy(agent, grant, upIn, upOut)
	if *receipts != "" {
		f, err := os.OpenFile(*receipts, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		p.receipts = f
	}
	err = p.run(os.Stdin, os.Stdout)
	_ = upIn.Close()
	_ = cmd.Wait()
	if err != nil && !errors.Is(err, io.EOF) {
		log.Fatal(err)
	}
}

func load(seedFile, grantFile string) (*keys.Identity, *writ.Writ, error) {
	b, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", seedFile, err)
	}
	agent, err := keys.FromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	g, err := os.ReadFile(grantFile)
	if err != nil {
		return nil, nil, err
	}
	obj, err := wire.Decode(g)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", grantFile, err)
	}
	grant, err := writ.ParseWrit(obj)
	if err != nil {
		return nil, nil, err
	}
	if grant.Hld != agent.DID() {
		return nil, nil, errors.New("the grant is not held by the agent key")
	}
	return agent, grant, nil
}

type proxy struct {
	agent    *keys.Identity
	grant    *writ.Writ
	child    *writ.Writ // the grant passed on to the server's key
	server   string     // the server's did:key, from server/discover
	enforced bool
	probed   bool
	seq      int

	upW      io.Writer
	up       *bufio.Scanner
	out      io.Writer
	outMu    sync.Mutex
	receipts io.Writer
}

func newProxy(agent *keys.Identity, grant *writ.Writ, upW io.Writer, upR io.Reader) *proxy {
	sc := bufio.NewScanner(upR)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	return &proxy{agent: agent, grant: grant, upW: upW, up: sc}
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// run relays one client request at a time: it forwards the request, relays
// anything the server sends meanwhile, and returns the matching response.
func (p *proxy) run(in io.Reader, out io.Writer) error {
	p.out = out
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			p.send(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
			continue
		}
		if m.Method == "tools/call" && len(m.ID) > 0 {
			p.toolCall(m)
			continue
		}
		if err := p.forward(line); err != nil {
			return err
		}
		if len(m.ID) > 0 && m.Method != "" {
			resp, err := p.await(m.ID)
			if err != nil {
				return err
			}
			p.write(resp)
		}
	}
	return sc.Err()
}

func (p *proxy) toolCall(m message) {
	fail := func(reason, msg string) {
		p.send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32000, "message": "writ: " + msg, "data": map[string]any{"reason": reason}}})
	}
	if err := p.probe(); err != nil {
		fail("unreachable_server", err.Error())
		return
	}
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(m.Params, &params); err != nil {
		fail("malformed", "tools/call params are not an object")
		return
	}
	args := map[string]any{}
	if len(params.Arguments) > 0 && string(params.Arguments) != "null" {
		dec := json.NewDecoder(bytes.NewReader(params.Arguments))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			fail("malformed", "arguments are not an object")
			return
		}
	}
	if p.child == nil {
		if p.server == "" {
			fail("unenforced_server", "the server does not name the key it enforces under")
			return
		}
		bnd := map[string]any{}
		for name, b := range p.grant.Bnd {
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
		}
		child, err := writ.Issue(p.agent, p.server, bnd, p.grant.Exp, p.grant)
		if err != nil {
			fail("malformed", err.Error())
			return
		}
		p.child = child
	}
	k, err := writ.NewCall(p.agent, []*writ.Writ{p.grant, p.child}, mcpbind.OpPrefix+params.Name, args)
	if err != nil {
		fail("malformed", "the tool call cannot be signed: "+err.Error())
		return
	}
	if err := mcpbind.Ready(k, p.enforced); err != nil {
		fail(err.Error(), "the server does not advertise "+mcpbind.Extension)
		return
	}
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "method": "tools/call", "params": mcpbind.Params(params.Name, k)})
	if err := p.forward(req); err != nil {
		fail("unreachable_server", err.Error())
		return
	}
	resp, err := p.await(m.ID)
	if err != nil {
		fail("unreachable_server", err.Error())
		return
	}
	var r message
	_ = json.Unmarshal(resp, &r)
	if len(r.Error) > 0 {
		p.write(resp) // the server refused before signing anything
		return
	}
	dec := json.NewDecoder(bytes.NewReader(r.Result))
	dec.UseNumber()
	var result map[string]any
	if err := dec.Decode(&result); err != nil {
		fail("malformed", "the server's result is not an object")
		return
	}
	t, err := mcpbind.Check(k, result)
	if err != nil {
		fail(mcpbind.ErrMissingTally.Error(), "the result carries no tally that verifies: "+err.Error())
		return
	}
	if p.receipts != nil {
		line, _ := json.Marshal(map[string]any{"call": k.Raw, "tally": t.Raw})
		_, _ = p.receipts.Write(append(line, '\n'))
	}
	p.write(resp)
}

// probe asks the server, once, whether it enforces the extension and which
// key it executes under.
func (p *proxy) probe() error {
	if p.probed {
		return nil
	}
	p.seq++
	id, _ := json.Marshal(fmt.Sprintf("writ-proxy-%d", p.seq))
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": "server/discover"})
	if err := p.forward(req); err != nil {
		return err
	}
	resp, err := p.await(id)
	if err != nil {
		return err
	}
	var r message
	_ = json.Unmarshal(resp, &r)
	var result map[string]any
	_ = json.Unmarshal(r.Result, &result)
	p.enforced, p.server = mcpbind.Advertised(result)
	p.probed = true
	return nil
}

func (p *proxy) forward(line []byte) error {
	_, err := p.upW.Write(append(append([]byte(nil), line...), '\n'))
	return err
}

// await reads the server until the response to id, relaying anything else
// (notifications, the server's own requests) to the client.
func (p *proxy) await(id json.RawMessage) ([]byte, error) {
	for p.up.Scan() {
		line := append([]byte(nil), p.up.Bytes()...)
		var m message
		if json.Unmarshal(line, &m) == nil && m.Method == "" && bytes.Equal(bytes.TrimSpace(m.ID), bytes.TrimSpace(id)) {
			return line, nil
		}
		p.write(line)
	}
	if err := p.up.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (p *proxy) send(v any) {
	b, _ := json.Marshal(v)
	p.write(b)
}

func (p *proxy) write(line []byte) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = p.out.Write(append(append([]byte(nil), line...), '\n'))
}
