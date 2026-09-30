package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/mcpbind"
	"writproto/writ"
)

// bound is how long any one step may take. Every wait in these tests is
// bounded by it, so a deadlock fails the test instead of hanging it.
const bound = 3 * time.Second

// liveServer is a stand-in MCP server that handles requests concurrently and
// sends requests of its own, as a real one does. Its tools:
//
//	echo      answers at once
//	ask       asks the client a question (elicitation/create) mid-call and
//	          returns the answer
//	slow      runs until the client cancels it, then sends no response
//	crash     makes the server exit before answering
//
// A request for test/hang is never answered. The server numbers its own
// requests 1, 2, 3, the same numbers a client uses, so IDs overlap.
type liveServer struct {
	srv   *mcpbind.Server
	out   io.WriteCloser
	outMu sync.Mutex
	gone  bool

	mu      sync.Mutex
	seen    []message
	replies map[string]chan message
	cancels map[string]context.CancelFunc
	seq     int
}

func newLiveServer(S *keys.Identity, root string, out io.WriteCloser) *liveServer {
	u := &liveServer{out: out, replies: map[string]chan message{}, cancels: map[string]context.CancelFunc{}}
	e := exec.New(S, nil)
	e.AcceptRoot = func(d string) bool { return d == root }
	u.srv = mcpbind.NewServer(e, map[string]mcpbind.Tool{
		"echo": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			return map[string]any{"echo": args["message"]}, false
		},
		"ask": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			r, err := u.request(ctx, "elicitation/create", map[string]any{"message": "Which account?", "requestedSchema": map[string]any{"type": "object"}})
			if err != nil {
				return map[string]any{"error": err.Error()}, true
			}
			var answer map[string]any
			dec := json.NewDecoder(bytes.NewReader(r.Result))
			dec.UseNumber()
			_ = dec.Decode(&answer)
			return map[string]any{"answer": answer}, false
		},
		"slow": func(ctx context.Context, args map[string]any) (map[string]any, bool) {
			select {
			case <-ctx.Done():
			case <-time.After(10 * bound):
			}
			return map[string]any{"stopped": true}, true
		},
	}, true)
	return u
}

func (u *liveServer) send(v any) {
	u.outMu.Lock()
	defer u.outMu.Unlock()
	if !u.gone {
		_ = json.NewEncoder(u.out).Encode(v)
	}
}

func (u *liveServer) exit() {
	u.outMu.Lock()
	defer u.outMu.Unlock()
	if !u.gone {
		u.gone = true
		_ = u.out.Close()
	}
}

// request sends the server's own request to the client and waits for the
// answer.
func (u *liveServer) request(ctx context.Context, method string, params any) (message, error) {
	u.mu.Lock()
	u.seq++
	id := json.RawMessage(fmt.Sprint(u.seq))
	ch := make(chan message, 1)
	u.replies[string(id)] = ch
	u.mu.Unlock()
	u.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	select {
	case r := <-ch:
		if len(r.Error) > 0 {
			return r, errors.New(string(r.Error))
		}
		return r, nil
	case <-ctx.Done():
		return message{}, ctx.Err()
	case <-time.After(10 * bound):
		return message{}, errors.New("the client never answered")
	}
}

func (u *liveServer) serve(in io.Reader) {
	defer u.exit()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		u.mu.Lock()
		u.seen = append(u.seen, m)
		u.mu.Unlock()
		switch {
		case m.Method == "" && len(m.ID) > 0:
			u.mu.Lock()
			ch := u.replies[string(m.ID)]
			delete(u.replies, string(m.ID))
			u.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case m.Method == "notifications/cancelled":
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			_ = json.Unmarshal(m.Params, &p)
			u.mu.Lock()
			if cancel := u.cancels[string(p.RequestID)]; cancel != nil {
				cancel()
			}
			u.mu.Unlock()
		case len(m.ID) > 0:
			go u.handle(m)
		}
	}
}

func (u *liveServer) handle(m message) {
	resp := map[string]any{"jsonrpc": "2.0", "id": m.ID}
	switch m.Method {
	case "test/hang":
		return
	case "server/discover":
		resp["result"] = map[string]any{"extensions": mcpbind.ExtensionInfo(u.srv.E.ID.DID())}
	case "tools/list":
		resp["result"] = map[string]any{"tools": []any{}}
	case "ping":
		resp["result"] = map[string]any{}
	case "tools/call":
		var p struct {
			Name string                     `json:"name"`
			Meta map[string]json.RawMessage `json:"_meta"`
		}
		_ = json.Unmarshal(m.Params, &p)
		if p.Name == "crash" {
			u.exit()
			return
		}
		if tok, ok := p.Meta["progressToken"]; ok {
			u.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progressToken": tok, "progress": 1}})
		}
		ctx, cancel := context.WithCancel(context.Background())
		u.mu.Lock()
		u.cancels[string(m.ID)] = cancel
		u.mu.Unlock()
		res, rpcErr := u.srv.CallTool(ctx, m.Params)
		canceled := ctx.Err() != nil
		cancel()
		u.mu.Lock()
		delete(u.cancels, string(m.ID))
		u.mu.Unlock()
		if canceled {
			return // MCP: no response to a request the client cancelled
		}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = res
		}
	default:
		resp["error"] = map[string]any{"code": -32601, "message": "no"}
	}
	u.send(resp)
}

// received returns every message the server has received so far.
func (u *liveServer) received() []message {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]message(nil), u.seen...)
}

// live is a proxy between a client the test drives and a liveServer.
type live struct {
	t      *testing.T
	server *liveServer
	in     *io.PipeWriter // the client's messages to the proxy
	msgs   chan map[string]any
	done   chan struct{} // closed when run returns
	closes []io.Closer
}

func startLive(t *testing.T) *live {
	t.Helper()
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{7}, 32))
	grant, err := writ.Issue(A, B.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "mcp/tools"}}, 1<<40, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientInR, clientInW := io.Pipe()
	clientOutR, clientOutW := io.Pipe()
	upInR, upInW := io.Pipe()
	upOutR, upOutW := io.Pipe()
	l := &live{t: t, in: clientInW, msgs: make(chan map[string]any, 256), done: make(chan struct{}),
		closes: []io.Closer{clientInR, clientInW, clientOutR, clientOutW, upInR, upInW, upOutR, upOutW}}
	l.server = newLiveServer(S, A.DID(), upOutW)
	go l.server.serve(upInR)
	p := newProxy(B, grant, upInW, upOutR)
	go func() {
		defer close(l.done)
		_ = p.run(clientInR, clientOutW)
	}()
	go func() {
		sc := bufio.NewScanner(clientOutR)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var m map[string]any
			dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			dec.UseNumber()
			if dec.Decode(&m) == nil {
				l.msgs <- m
			}
		}
		close(l.msgs)
	}()
	t.Cleanup(func() {
		// Unblock everything, whatever state a failed test left it in.
		for _, c := range l.closes {
			_ = c.Close()
		}
		select {
		case <-l.done:
		case <-time.After(bound):
		}
	})
	return l
}

// send writes one message as the client, failing if the proxy does not read
// it within the bound.
func (l *live) send(v any) {
	l.t.Helper()
	b, _ := json.Marshal(v)
	wrote := make(chan error, 1)
	go func() {
		_, err := l.in.Write(append(b, '\n'))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			l.t.Fatalf("writing %s: %v", b, err)
		}
	case <-time.After(bound):
		l.t.Fatalf("the proxy did not read the client's %s: it is not reading the client", b)
	}
}

// until reads what the proxy sends the client until want matches, failing
// if nothing matches within the bound. It returns the match and every
// message before it.
func (l *live) until(what string, want func(map[string]any) bool) (map[string]any, []map[string]any) {
	l.t.Helper()
	var before []map[string]any
	deadline := time.After(bound)
	for {
		select {
		case m, ok := <-l.msgs:
			if !ok {
				l.t.Fatalf("the proxy closed its output waiting for %s; before it: %v", what, before)
			}
			if want(m) {
				return m, before
			}
			before = append(before, m)
		case <-deadline:
			l.t.Fatalf("timed out waiting for %s; received meanwhile: %v", what, before)
		}
	}
}

// responses reads until the proxy has answered every request id given, in
// whatever order the answers come, and returns them by id.
func (l *live) responses(ids ...any) map[any]map[string]any {
	l.t.Helper()
	got := map[any]map[string]any{}
	for len(got) < len(ids) {
		var missing []any
		for _, id := range ids {
			if got[id] == nil {
				missing = append(missing, id)
			}
		}
		m, _ := l.until(fmt.Sprintf("answers to %v", missing), func(m map[string]any) bool {
			for _, id := range missing {
				if idIs(id)(m) {
					got[id] = m
					return true
				}
			}
			return false
		})
		_ = m
	}
	return got
}

// waitServer waits until the server has received a message matching want.
func (l *live) waitServer(what string, want func(message) bool) message {
	l.t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		for _, m := range l.server.received() {
			if want(m) {
				return m
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.t.Fatalf("the server never received %s", what)
	return message{}
}

func (l *live) waitDone(what string) {
	l.t.Helper()
	select {
	case <-l.done:
	case <-time.After(bound):
		l.t.Fatalf("the proxy did not shut down after %s", what)
	}
}

// idIs matches a response to the request with this exact id: a JSON number
// and a string with the same digits are different ids.
func idIs(id any) func(map[string]any) bool {
	want := fmt.Sprintf("%T:%v", id, id)
	if n, ok := id.(int); ok {
		want = fmt.Sprintf("%T:%v", json.Number(fmt.Sprint(n)), n)
	}
	return func(m map[string]any) bool {
		_, isRequest := m["method"]
		return !isRequest && fmt.Sprintf("%T:%v", m["id"], m["id"]) == want
	}
}

func methodIs(method string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["method"] == method }
}

func body(m map[string]any) map[string]any {
	r, _ := m["result"].(map[string]any)
	b, _ := r["structuredContent"].(map[string]any)
	return b
}

// The regression: during a tool call, the server asks the client something
// and waits for the answer. The client's answer must reach the server while
// the tool call is still open, and the call then completes with it.
func TestServerRequestDuringAToolCall(t *testing.T) {
	l := startLive(t)
	l.send(toolCall(1, "ask", map[string]any{}))
	ask, before := l.until("the server's elicitation/create", methodIs("elicitation/create"))
	for _, m := range before {
		if idIs(1)(m) {
			t.Fatalf("the tool call was answered before the server's question: %v", m)
		}
	}
	l.send(map[string]any{"jsonrpc": "2.0", "id": ask["id"], "result": map[string]any{"action": "accept", "content": map[string]any{"account": "acc_1"}}})
	res, _ := l.until("the tool call's result", idIs(1))
	answer, _ := body(res)["answer"].(map[string]any)
	if content, _ := answer["content"].(map[string]any); content["account"] != "acc_1" {
		t.Fatalf("the tool call's result: %v", res)
	}
	l.in.Close()
	l.waitDone("the client closed")
}

// While the server waits on the client, traffic keeps flowing both ways and
// every response reaches the request it answers: client ids are never
// confused with the server's, with each other, or with the proxy's own.
func TestInterleavedTraffic(t *testing.T) {
	l := startLive(t)
	l.send(toolCall(1, "ask", map[string]any{}))
	ask, _ := l.until("the server's elicitation/create", methodIs("elicitation/create"))
	l.send(map[string]any{"jsonrpc": "2.0", "id": "writ-proxy-1", "method": "tools/list"})
	l.send(map[string]any{"jsonrpc": "2.0", "id": "1", "method": "ping"})
	l.send(toolCall(2, "echo", map[string]any{"message": "meanwhile"}))
	got := l.responses("writ-proxy-1", "1", 2)
	if got["writ-proxy-1"]["result"] == nil || got["1"]["result"] == nil || body(got[2])["echo"] != "meanwhile" {
		t.Fatalf("tools/list, ping, and the second tool call: %v", got)
	}
	l.send(map[string]any{"jsonrpc": "2.0", "id": ask["id"], "result": map[string]any{"action": "decline"}})
	if m, _ := l.until("the first tool call", idIs(1)); body(m)["answer"] == nil {
		t.Fatalf("the first tool call: %v", m)
	}
	seen := map[string]bool{}
	for _, m := range l.server.received() {
		if m.Method != "" && len(m.ID) > 0 {
			if seen[string(m.ID)] {
				t.Fatalf("the server received two requests with id %s", m.ID)
			}
			seen[string(m.ID)] = true
		}
	}
	l.in.Close()
	l.waitDone("the client closed")
}

// A client's cancellation reaches the server under the id the server knows
// the request by, and the proxy keeps serving and still shuts down cleanly
// with the cancelled call never answered.
func TestCancellationReachesTheServer(t *testing.T) {
	l := startLive(t)
	l.send(toolCall(5, "slow", map[string]any{}))
	slow := l.waitServer("the slow tool call", func(m message) bool {
		return m.Method == "tools/call" && bytes.Contains(m.Params, []byte(`"name":"slow"`))
	})
	l.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 5, "reason": "the user stopped it"}})
	l.waitServer("the cancellation, under its own id for the call", func(m message) bool {
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		_ = json.Unmarshal(m.Params, &p)
		return m.Method == "notifications/cancelled" && bytes.Equal(p.RequestID, slow.ID)
	})
	l.send(toolCall(6, "echo", map[string]any{"message": "after"}))
	if m, _ := l.until("a call after the cancellation", idIs(6)); body(m)["echo"] != "after" {
		t.Fatalf("a call after the cancellation: %v", m)
	}
	l.in.Close()
	l.waitDone("the client closed with a cancelled call outstanding")
}

// A progress token the client puts on a tool call reaches the server, so the
// server's progress notifications reach the client.
func TestProgressKeepsItsToken(t *testing.T) {
	l := startLive(t)
	l.send(map[string]any{"jsonrpc": "2.0", "id": 8, "method": "tools/call",
		"params": map[string]any{"name": "echo", "arguments": map[string]any{"message": "p"}, "_meta": map[string]any{"progressToken": "tok-8"}}})
	note, _ := l.until("the progress notification", methodIs("notifications/progress"))
	if params, _ := note["params"].(map[string]any); params["progressToken"] != "tok-8" {
		t.Fatalf("progress: %v", note)
	}
	if m, _ := l.until("the tool call", idIs(8)); body(m)["echo"] != "p" {
		t.Fatalf("the tool call: %v", m)
	}
}

// The client goes away while the server is waiting for its answer. The proxy
// answers the server's request with an error on the client's behalf, the
// tool call finishes, and the proxy shuts down.
func TestClientDisconnectsDuringAServerRequest(t *testing.T) {
	l := startLive(t)
	l.send(toolCall(1, "ask", map[string]any{}))
	ask, _ := l.until("the server's elicitation/create", methodIs("elicitation/create"))
	l.in.Close()
	l.waitDone("the client disconnected mid-question")
	var askID json.RawMessage
	b, _ := json.Marshal(ask["id"])
	askID = b
	l.waitServer("an error answering its question", func(m message) bool {
		return m.Method == "" && bytes.Equal(m.ID, askID) && len(m.Error) > 0
	})
}

// The server exits with calls in flight. Every request the client has open
// is answered with an error, and the proxy shuts down.
func TestServerExitsDuringCalls(t *testing.T) {
	l := startLive(t)
	l.send(toolCall(1, "ask", map[string]any{}))
	l.until("the server's elicitation/create", methodIs("elicitation/create"))
	l.send(map[string]any{"jsonrpc": "2.0", "id": "h", "method": "test/hang"})
	l.waitServer("test/hang", func(m message) bool { return m.Method == "test/hang" })
	l.send(toolCall(3, "crash", map[string]any{}))
	for id, m := range l.responses(1, "h", 3) {
		if m["error"] == nil {
			t.Fatalf("request %v after the server exited: %v", id, m)
		}
	}
	l.waitDone("the server exited")
}
