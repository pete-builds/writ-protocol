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
// and turns a result with no tally, or one that does not verify or that
// contradicts its tally, into an error (missing_tally): the work does not count
// as done. A result that verifies reaches the client rebuilt from what the
// tally authenticates (mcpbind.Verified), never as the server sent it.
// Verified tallies are appended to -receipts.
//
// -pins and -closed add two policies argument bounds cannot express
// (policy.go): only pinned tool definitions are listed and called, and no
// argument the grant does not bound is sent. -print-pins lists a server's
// tools, writes their definitions to stderr for review and a pin file for
// them to stdout, and exits:
//
//	writ-mcp-proxy -print-pins -- writ-mcp -seed ... > pins.json
//
// The proxy reads the client and the server independently (relay.go), so a
// server may ask the client something, such as an elicitation, in the middle
// of a tool call, and the client may cancel a call, without either side
// waiting on the other.
package main

import (
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

	"writproto/keys"
	"writproto/mcpbind"
	"writproto/wire"
	"writproto/writ"
)

func main() {
	seedFile := flag.String("agent-seed-file", "", "file holding the agent's 32-byte hex seed, which signs each call")
	grantFile := flag.String("grant", "", "the grant: a writ from its root to the agent key")
	receipts := flag.String("receipts", "", "append each verified tally to this file as a JSON line")
	pinFile := flag.String("pins", "", "list and call only the tools whose definitions match this pin file")
	closed := flag.Bool("closed", false, "refuse any tool argument the grant does not bound")
	printPins := flag.Bool("print-pins", false, "write a pin file for the server's tools to stdout and exit")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("usage: writ-mcp-proxy -agent-seed-file F -grant G [-receipts R] [-pins P] [-closed] -- <mcp server command> [args]\n       writ-mcp-proxy -print-pins -- <mcp server command> [args]")
	}
	if *printPins {
		if err := printServerPins(flag.Args(), os.Stdout, os.Stderr); err != nil {
			log.Fatal(err)
		}
		return
	}
	agent, grant, err := load(*seedFile, *grantFile)
	if err != nil {
		log.Fatal(err)
	}
	var pol *policy
	if *pinFile != "" || *closed {
		pol = &policy{closed: *closed}
		if *pinFile != "" {
			if pol.pins, err = loadPins(*pinFile); err != nil {
				log.Fatal(err)
			}
		}
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
	p.pol = pol
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

// sign learns the server's key if it has not yet, and signs the client's
// tool call under the grant passed on to that key. It returns the call and
// the params to send, or the reason the call cannot go.
func (p *proxy) sign(m message) (k *writ.Call, params map[string]any, reason, msg string) {
	if err := p.probe(); err != nil {
		return nil, nil, "unreachable_server", err.Error()
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(m.Params, &in); err != nil || in == nil {
		return nil, nil, "malformed", "tools/call params are not an object"
	}
	var name string
	_ = json.Unmarshal(in["name"], &name)
	args := map[string]any{}
	if a := in["arguments"]; len(a) > 0 && string(a) != "null" {
		dec := json.NewDecoder(bytes.NewReader(a))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return nil, nil, "malformed", "arguments are not an object"
		}
	}
	if reason, msg := p.admit(name, args); reason != "" {
		return nil, nil, reason, msg
	}
	if p.child == nil {
		if p.server == "" {
			return nil, nil, "unenforced_server", "the server does not name the key it enforces under"
		}
		bnd := map[string]any{}
		for name, b := range p.grant.Bnd {
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
		}
		child, err := writ.Issue(p.agent, p.server, bnd, p.grant.Exp, p.grant)
		if err != nil {
			return nil, nil, "malformed", err.Error()
		}
		p.child = child
	}
	k, err := writ.NewCall(p.agent, []*writ.Writ{p.grant, p.child}, mcpbind.OpPrefix+name, args)
	if err != nil {
		return nil, nil, "malformed", "the tool call cannot be signed: " + err.Error()
	}
	if err := mcpbind.Ready(k, p.enforced); err != nil {
		return nil, nil, err.Error(), "the server does not advertise " + mcpbind.Extension
	}
	// The Writ call is the proxy's; everything else the client put on the
	// request, such as a progress token in _meta, goes on unchanged.
	params = mcpbind.Params(name, k)
	meta := params["_meta"].(map[string]any)
	var clientMeta map[string]json.RawMessage
	if json.Unmarshal(in["_meta"], &clientMeta) == nil {
		for key, v := range clientMeta {
			if key != mcpbind.CallKey {
				meta[key] = v
			}
		}
	}
	for key, v := range in {
		if key != "name" && key != "arguments" && key != "_meta" {
			params[key] = v
		}
	}
	return k, params, "", ""
}

// probe asks the server, once, whether it enforces the extension and which
// key it executes under. Only the sequencer calls it.
func (p *proxy) probe() error {
	if p.probed {
		return nil
	}
	r := p.openOwn()
	if r == nil {
		return errors.New("the server has exited")
	}
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id, "method": "server/discover"})
	if err := p.toServer(req); err != nil {
		p.take(r.id)
		return err
	}
	line, ok := <-r.reply
	if !ok {
		return errors.New("the server exited before answering server/discover")
	}
	var resp message
	_ = json.Unmarshal(line, &resp)
	var result map[string]any
	_ = json.Unmarshal(resp.Result, &result)
	p.enforced, p.server = mcpbind.Advertised(result)
	p.probed = true
	return nil
}

// dispatch sends one tool call, in the order the client sent its tool calls,
// and leaves a goroutine waiting for the result, so no reader ever waits on
// a tool call.
func (p *proxy) dispatch(r *request) {
	if !p.isOpen(r.id) {
		p.settle(r, "", "") // cancelled while queued, or the server exited
		return
	}
	k, params, reason, msg := p.sign(r.msg)
	if reason != "" {
		p.settle(r, reason, msg)
		return
	}
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id, "method": "tools/call", "params": params})
	if !p.isOpen(r.id) {
		p.settle(r, "", "")
		return
	}
	if err := p.toServer(req); err != nil {
		p.settle(r, "unreachable_server", err.Error())
		return
	}
	go p.finish(r, k)
}

// finish waits for a tool call's result and answers the client with it,
// rebuilt from what its tally authenticates, or with an error.
func (p *proxy) finish(r *request, k *writ.Call) {
	defer p.end()
	line, ok := <-r.reply
	if !ok {
		p.fail(r.client, "unreachable_server", "the server exited before answering")
		return
	}
	if line == nil {
		return // the client cancelled the call and expects no answer
	}
	var resp message
	_ = json.Unmarshal(line, &resp)
	if len(resp.Error) > 0 {
		p.write(withID(line, r.client)) // the server refused before signing anything
		return
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.UseNumber()
	var result map[string]any
	if err := dec.Decode(&result); err != nil {
		p.fail(r.client, "malformed", "the server's result is not an object")
		return
	}
	// The client is shown only what the tally authenticates: the result is
	// rebuilt from the verified body and the tally's st, and nothing else
	// the server sent reaches the client.
	shown, t, err := mcpbind.Verified(k, result)
	if err != nil {
		p.fail(r.client, mcpbind.ErrMissingTally.Error(), "the result carries no tally that verifies: "+err.Error())
		return
	}
	if p.receipts != nil {
		line, _ := json.Marshal(map[string]any{"call": k.Raw, "tally": t.Raw})
		p.recMu.Lock()
		_, _ = p.receipts.Write(append(line, '\n'))
		p.recMu.Unlock()
	}
	p.send(map[string]any{"jsonrpc": "2.0", "id": r.client, "result": shown})
}

// settle ends a tool call that will not get a result: the client is told
// why, unless it cancelled the call, and a call the server's exit closed is
// unreachable_server.
func (p *proxy) settle(r *request, reason, msg string) {
	defer p.end()
	if p.take(r.id) == nil {
		if line, ok := <-r.reply; ok && line == nil {
			return
		}
		reason, msg = "unreachable_server", "the server exited"
	}
	p.fail(r.client, reason, msg)
}
