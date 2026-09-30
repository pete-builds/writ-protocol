package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"

	"writproto/keys"
	"writproto/writ"
)

// The relay reads the client and the server independently, so either side
// may ask the other something at any time: the server an elicitation or a
// sampling request in the middle of a tool call, the client a cancellation.
// Every request the proxy sends the server, the client's and its own, goes
// under an id the proxy allocates, so the server never sees one id twice and
// no response can reach the wrong request; the client's id is put back on
// the way out. The server's requests keep their ids: the client answers
// them, and the proxy relays the answer unchanged.
//
// Tool calls are signed and sent in the order the client sent them, by one
// sequencer goroutine, and each result is awaited on its own goroutine.

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// request is one request the proxy has sent the server, or has queued to.
type request struct {
	id     json.RawMessage // the proxy's id for it
	client json.RawMessage // the client's id; nil for the proxy's own request
	// reply receives the server's response for a tool call or the proxy's
	// own request: nil when the client cancelled it, closed when the server
	// exited first. A relayed request has none: its response goes straight
	// to the client.
	reply chan []byte
	msg   message // a tool call as the client sent it
}

type proxy struct {
	agent    *keys.Identity
	grant    *writ.Writ
	receipts io.Writer
	recMu    sync.Mutex

	// What server/discover said, and the grant passed on to the server's
	// key. Only the sequencer touches these.
	child    *writ.Writ
	server   string
	enforced bool
	probed   bool

	upW   io.Writer // the server's input
	upR   io.Reader // the server's output
	upMu  sync.Mutex
	out   io.Writer // the client's input
	outMu sync.Mutex

	mu       sync.Mutex
	seq      int
	open     map[string]*request        // sent or queued, by the proxy's id
	byClient map[string]string          // the client's id to the proxy's, for cancellation
	asked    map[string]json.RawMessage // the server's requests the client has not answered
	queue    []*request                 // tool calls waiting for the sequencer
	queued   *sync.Cond
	active   int // client requests not yet answered, failed, or cancelled
	idle     *sync.Cond
	stopping bool
	// clientGone: the client closed its output, so the server's requests
	// are answered with an error on its behalf. serverGone: the server
	// closed its output, so nothing more can be sent.
	clientGone, serverGone bool
}

func newProxy(agent *keys.Identity, grant *writ.Writ, upW io.Writer, upR io.Reader) *proxy {
	p := &proxy{agent: agent, grant: grant, upW: upW, upR: upR,
		open: map[string]*request{}, byClient: map[string]string{}, asked: map[string]json.RawMessage{}}
	p.queued = sync.NewCond(&p.mu)
	p.idle = sync.NewCond(&p.mu)
	return p
}

// run relays between the client (in, out) and the server until one side
// closes. When the client closes, the requests it left open are finished,
// then the server's input is closed so that it exits. When the server
// closes, every open request is answered with an error.
func (p *proxy) run(in io.Reader, out io.Writer) error {
	p.out = out
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	sequenced := make(chan struct{})
	go func() { serverDone <- p.readServer() }()
	go func() { defer close(sequenced); p.sequence() }()
	go func() { clientDone <- p.readClient(in) }()
	var err error
	select {
	case err = <-clientDone:
		p.clientLeft()
		p.waitIdle()
		p.stop(sequenced)
		if c, ok := p.upW.(io.Closer); ok {
			_ = c.Close()
		}
		<-serverDone
	case err = <-serverDone:
		p.waitIdle()
		p.stop(sequenced)
	}
	return err
}

func (p *proxy) readClient(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			p.send(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
			continue
		}
		switch {
		case m.Method == "" && len(m.ID) > 0:
			// The client's answer to one of the server's requests.
			p.mu.Lock()
			delete(p.asked, key(m.ID))
			p.mu.Unlock()
			_ = p.toServer(line)
		case m.Method == "notifications/cancelled":
			p.cancel(m)
		case len(m.ID) == 0:
			_ = p.toServer(line)
		case m.Method == "tools/call":
			p.enqueue(m)
		default:
			p.relay(m, line)
		}
	}
	return sc.Err()
}

func (p *proxy) readServer() error {
	sc := bufio.NewScanner(p.upR)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		var m message
		if json.Unmarshal(line, &m) != nil {
			p.write(line)
			continue
		}
		switch {
		case m.Method == "" && len(m.ID) > 0:
			r := p.take(m.ID)
			switch {
			case r == nil:
				// Cancelled by the client, or never a request the proxy sent.
			case r.reply != nil:
				r.reply <- line
			default:
				p.write(withID(line, r.client))
				p.end()
			}
		case len(m.ID) > 0:
			// The server's own request: the client answers it, unless the
			// client has gone, in which case the proxy says so.
			p.mu.Lock()
			gone := p.clientGone
			if !gone {
				p.asked[key(m.ID)] = m.ID
			}
			p.mu.Unlock()
			if gone {
				_ = p.toServer(clientAway(m.ID))
				continue
			}
			p.write(line)
		default:
			p.write(line)
		}
	}
	err := sc.Err()
	if err == nil {
		err = io.EOF
	}
	p.serverExited()
	return err
}

// sequence sends queued tool calls one at a time, in order.
func (p *proxy) sequence() {
	for {
		p.mu.Lock()
		for len(p.queue) == 0 && !p.stopping {
			p.queued.Wait()
		}
		if len(p.queue) == 0 {
			p.mu.Unlock()
			return
		}
		r := p.queue[0]
		p.queue = p.queue[1:]
		p.mu.Unlock()
		p.dispatch(r)
	}
}

func (p *proxy) enqueue(m message) {
	p.mu.Lock()
	if p.serverGone {
		p.mu.Unlock()
		p.fail(m.ID, "unreachable_server", "the server has exited")
		return
	}
	r := p.register(m.ID, true)
	r.msg = m
	p.active++
	p.queue = append(p.queue, r)
	p.queued.Signal()
	p.mu.Unlock()
}

// relay sends a client request other than tools/call to the server under
// the proxy's id; readServer returns the response under the client's.
func (p *proxy) relay(m message, line []byte) {
	p.mu.Lock()
	if p.serverGone {
		p.mu.Unlock()
		p.fail(m.ID, "unreachable_server", "the server has exited")
		return
	}
	r := p.register(m.ID, false)
	p.active++
	p.mu.Unlock()
	if err := p.toServer(withID(line, r.id)); err != nil && p.take(r.id) != nil {
		p.fail(m.ID, "unreachable_server", err.Error())
		p.end()
	}
}

// cancel passes a client's notifications/cancelled on under the id the
// server knows the request by. A cancelled request gets no answer.
func (p *proxy) cancel(m message) {
	var params map[string]json.RawMessage
	if json.Unmarshal(m.Params, &params) != nil || params == nil {
		return
	}
	p.mu.Lock()
	id, ok := p.byClient[key(params["requestId"])]
	p.mu.Unlock()
	if !ok {
		return // nothing of the client's by that id is open here
	}
	r := p.take(json.RawMessage(id))
	if r == nil {
		return
	}
	params["requestId"] = r.id
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": m.Method, "params": params})
	_ = p.toServer(b)
	if r.reply != nil {
		r.reply <- nil
	} else {
		p.end()
	}
}

// register opens a request under a new id. p.mu must be held.
func (p *proxy) register(client json.RawMessage, reply bool) *request {
	p.seq++
	r := &request{id: json.RawMessage(strconv.Quote(fmt.Sprintf("writ-proxy-%d", p.seq))), client: client}
	if reply {
		r.reply = make(chan []byte, 1)
	}
	p.open[key(r.id)] = r
	if client != nil {
		p.byClient[key(client)] = key(r.id)
	}
	return r
}

// openOwn opens a request of the proxy's own, or returns nil when the
// server has exited.
func (p *proxy) openOwn() *request {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.serverGone {
		return nil
	}
	return p.register(nil, true)
}

// take closes the request open under id and returns it, or nil when it is
// not open: exactly one caller takes each request.
func (p *proxy) take(id json.RawMessage) *request {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.open[key(id)]
	if r == nil {
		return nil
	}
	delete(p.open, key(id))
	if r.client != nil && p.byClient[key(r.client)] == key(r.id) {
		delete(p.byClient, key(r.client))
	}
	return r
}

func (p *proxy) isOpen(id json.RawMessage) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.open[key(id)] != nil
}

// clientLeft answers, on the client's behalf, every request the server is
// still waiting on it for.
func (p *proxy) clientLeft() {
	p.mu.Lock()
	p.clientGone = true
	asked := p.asked
	p.asked = map[string]json.RawMessage{}
	p.mu.Unlock()
	for _, id := range asked {
		_ = p.toServer(clientAway(id))
	}
}

// serverExited closes every open request: a relayed one is answered with an
// error here, a tool call by its own goroutine.
func (p *proxy) serverExited() {
	p.mu.Lock()
	p.serverGone = true
	open := p.open
	p.open, p.byClient = map[string]*request{}, map[string]string{}
	p.mu.Unlock()
	for _, r := range open {
		if r.reply != nil {
			close(r.reply)
			continue
		}
		p.fail(r.client, "unreachable_server", "the server exited before answering")
		p.end()
	}
}

func (p *proxy) end() {
	p.mu.Lock()
	p.active--
	if p.active == 0 {
		p.idle.Broadcast()
	}
	p.mu.Unlock()
}

func (p *proxy) waitIdle() {
	p.mu.Lock()
	for p.active > 0 {
		p.idle.Wait()
	}
	p.mu.Unlock()
}

func (p *proxy) stop(sequenced chan struct{}) {
	p.mu.Lock()
	p.stopping = true
	p.queued.Broadcast()
	p.mu.Unlock()
	<-sequenced
}

func (p *proxy) toServer(line []byte) error {
	p.upMu.Lock()
	defer p.upMu.Unlock()
	_, err := p.upW.Write(append(append([]byte(nil), line...), '\n'))
	return err
}

func (p *proxy) fail(id json.RawMessage, reason, msg string) {
	p.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": "writ: " + msg, "data": map[string]any{"reason": reason}}})
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

// clientAway is the proxy's answer to a server request the client can no
// longer answer.
func clientAway(id json.RawMessage) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": "the client disconnected"}})
	return b
}

// withID returns a message with its id replaced.
func withID(line []byte, id json.RawMessage) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(line, &m) != nil {
		return line
	}
	m["id"] = id
	b, _ := json.Marshal(m)
	return b
}

func key(id json.RawMessage) string { return string(bytes.TrimSpace(id)) }
