package main

// Two optional policies close gaps that argument bounds leave open on MCP
// (docs/where-writ-stops.md):
//
// Pinning (-pins). MCP clients show a model whatever tool descriptions the
// server lists, and a server can change a description after it was approved,
// so a poisoned description steers the model without touching any argument.
// With pins, the proxy lists to the client only tools whose definition hashes
// to the pin approved for that name, and refuses a call to a tool that has no
// pin (unpinned_tool) or whose definition the server last listed differently
// (tool_changed). A server's notifications/tools/list_changed makes the proxy
// list again before the next call.
//
// Closed world (-closed). Spec section 7.2 leaves arguments with no bound
// unconstrained, so an argument the grant does not name, such as a bcc
// address, is a channel the grant cannot see. In closed-world mode the proxy
// refuses a call carrying any argument the grant does not bound
// (unbound_argument).
//
// Both are the proxy's own policy, applied before anything is signed. They
// are not writ bounds: a bound is compared against the call's args, so a pin
// carried as one would add an argument the tool never asked for.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"writproto/writ"
)

// toolPin is the pin of one tool definition, as tools/list carries it: the
// SHA-256, in hex, of the definition re-encoded with its object members in
// sorted order, numbers exactly as written, and no HTML escaping. Every
// member counts, so a change to the description, the schema, the title, or
// the annotations changes the pin. -print-pins writes the pins a server
// lists now.
func toolPin(def json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(def))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:]), nil
}

type policy struct {
	pins   map[string]string // tool name to its approved pin; nil when not pinning
	closed bool

	mu   sync.Mutex
	seen map[string]string // tool name to the pin of the definition last listed
}

// loadPins reads a pin file: a JSON object from tool name to pin.
func loadPins(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pins map[string]string
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("%s: no pins", path)
	}
	for name, pin := range pins {
		if s, err := hex.DecodeString(pin); err != nil || len(s) != sha256.Size {
			return nil, fmt.Errorf("%s: the pin for %q is not a SHA-256 in hex", path, name)
		}
	}
	return pins, nil
}

func (q *policy) pinning() bool { return q != nil && q.pins != nil }

// listed records the definitions in a tools/list result and returns the
// result with only the tools whose definition matches its pin. The other
// members of the result, such as nextCursor, are kept.
func (q *policy) listed(result json.RawMessage) (json.RawMessage, []string, error) {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(result, &r); err != nil || r == nil {
		return nil, nil, errors.New("the tools/list result is not an object")
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(r["tools"], &tools); err != nil {
		return nil, nil, errors.New("the tools/list result has no tools array")
	}
	kept := []json.RawMessage{}
	var dropped []string
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen == nil {
		q.seen = map[string]string{}
	}
	for _, def := range tools {
		var t struct {
			Name string `json:"name"`
		}
		pin, err := toolPin(def)
		if json.Unmarshal(def, &t) != nil || err != nil {
			dropped = append(dropped, "(unreadable)")
			continue
		}
		q.seen[t.Name] = pin
		if want, ok := q.pins[t.Name]; ok && want == pin {
			kept = append(kept, def)
			continue
		}
		dropped = append(dropped, t.Name)
	}
	r["tools"], _ = json.Marshal(kept)
	out, err := json.Marshal(r)
	return out, dropped, err
}

// changed forgets every definition seen, so the next call lists again.
func (q *policy) changed() {
	q.mu.Lock()
	q.seen = nil
	q.mu.Unlock()
}

// lastSeen is the pin of the definition last listed for name, if any.
func (q *policy) lastSeen(name string) (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	pin, ok := q.seen[name]
	return pin, ok
}

// unbound names the arguments that no application bound of the grant
// constrains (spec section 7.2), in sorted order.
func unbound(grant *writ.Writ, args map[string]any) []string {
	var out []string
	for name := range args {
		b, ok := grant.Bnd[name]
		if !ok || name == "act" || name == "hld" || name == "depth" || b.T == "count" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// admit applies the policies to one tool call before it is signed. It
// returns the reason the call may not go, or "".
func (p *proxy) admit(name string, args map[string]any) (reason, msg string) {
	if p.pol == nil {
		return "", ""
	}
	if p.pol.closed {
		if names := unbound(p.grant, args); len(names) > 0 {
			return "unbound_argument", "closed-world mode: the grant bounds no argument named " + strings.Join(names, ", ")
		}
	}
	if !p.pol.pinning() {
		return "", ""
	}
	want, ok := p.pol.pins[name]
	if !ok {
		return "unpinned_tool", "no pin approves the tool " + name
	}
	got, ok := p.pol.lastSeen(name)
	if !ok {
		if err := p.listAll(); err != nil {
			return "unreachable_server", err.Error()
		}
		got, ok = p.pol.lastSeen(name)
	}
	if !ok || got != want {
		return "tool_changed", "the server's definition of " + name + " is not the one pinned"
	}
	return "", ""
}

// listAll lists every page of the server's tools, as the proxy's own
// request, so the pins are checked against what the server lists now. Only
// the sequencer calls it.
func (p *proxy) listAll() error {
	cursor := ""
	for page := 0; page < 100; page++ {
		r := p.openOwn()
		if r == nil {
			return errors.New("the server has exited")
		}
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id, "method": "tools/list", "params": params})
		if err := p.toServer(req); err != nil {
			p.take(r.id)
			return err
		}
		line, ok := <-r.reply
		if !ok {
			return errors.New("the server exited before answering tools/list")
		}
		var resp message
		_ = json.Unmarshal(line, &resp)
		if len(resp.Error) > 0 {
			return errors.New("the server refused tools/list")
		}
		if _, _, err := p.pol.listed(resp.Result); err != nil {
			return err
		}
		var next struct {
			NextCursor string `json:"nextCursor"`
		}
		_ = json.Unmarshal(resp.Result, &next)
		if next.NextCursor == "" {
			return nil
		}
		cursor = next.NextCursor
	}
	return errors.New("the server's tools/list did not end after 100 pages")
}

// filterList rewrites a tools/list response on its way to the client.
func (p *proxy) filterList(line []byte) []byte {
	var resp map[string]json.RawMessage
	if json.Unmarshal(line, &resp) != nil || len(resp["result"]) == 0 {
		return line // an error, relayed as it is
	}
	result, dropped, err := p.pol.listed(resp["result"])
	if err != nil {
		// Show the client nothing it could not check.
		result = json.RawMessage(`{"tools":[]}`)
	}
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "writ-mcp-proxy: not listing tools with no matching pin: %s\n", strings.Join(dropped, ", "))
	}
	resp["result"] = result
	b, _ := json.Marshal(resp)
	return b
}

// printServerPins starts the server, lists its tools, writes each definition
// to review for a person to read, and writes a pin file for them to out.
// Pin only what was read: the pin approves the description a model will see.
func printServerPins(argv []string, out, review io.Writer) error {
	cmd := osexec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	ask := func(id int, method string, params any) (message, error) {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if _, err := in.Write(append(b, '\n')); err != nil {
			return message{}, err
		}
		for sc.Scan() {
			var m message
			if json.Unmarshal(sc.Bytes(), &m) == nil && m.Method == "" && string(m.ID) == strconv.Itoa(id) {
				return m, nil
			}
		}
		return message{}, errors.New("the server exited before answering " + method)
	}
	// A server on an older MCP revision lists tools only after initialize;
	// one that does not know initialize answers with an error, which is fine.
	if _, err := ask(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "writ-mcp-proxy", "version": "0.1"}}); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	_, _ = in.Write(append(b, '\n'))
	pins := map[string]string{}
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		m, err := ask(2+page, "tools/list", params)
		if err != nil {
			return err
		}
		if len(m.Error) > 0 {
			return fmt.Errorf("the server refused tools/list: %s", m.Error)
		}
		var r struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(m.Result, &r); err != nil {
			return err
		}
		for _, def := range r.Tools {
			var t struct {
				Name string `json:"name"`
			}
			pin, err := toolPin(def)
			if err != nil || json.Unmarshal(def, &t) != nil || t.Name == "" {
				return errors.New("the server listed a tool definition that cannot be read")
			}
			pins[t.Name] = pin
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, def, "", "  ")
			fmt.Fprintf(review, "%s  %s\n%s\n\n", pin, t.Name, pretty.String())
		}
		if r.NextCursor == "" {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(pins)
		}
		cursor = r.NextCursor
	}
	return errors.New("the server's tools/list did not end after 100 pages")
}
