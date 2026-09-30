package conformance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"writproto/exec"
	"writproto/jcs"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// Scenario is one executor scenario (spec section 14.1).
type Scenario struct {
	Name     string `json:"name"`
	Executor struct {
		Seed   string              `json:"seed"`
		Accept []string            `json:"accept"`
		Peers  map[string][]string `json:"peers,omitempty"`
	} `json:"executor"`
	Steps []Step `json:"steps"`
}

// Step is one step of a scenario. Call is a call object on a "call" step and
// a call identity (a JSON string) on a "finish" step.
type Step struct {
	Do       string          `json:"do"`
	Note     string          `json:"note,omitempty"`
	Now      int64           `json:"now,omitempty"`
	Peer     string          `json:"peer,omitempty"`
	Call     json.RawMessage `json:"call,omitempty"`
	Revoke   json.RawMessage `json:"revoke,omitempty"`
	App      *App            `json:"app,omitempty"`
	Signaled *bool           `json:"signaled,omitempty"`
	Expect   json.RawMessage `json:"expect"`
}

// App scripts what the application returns when the executor performs an
// operation (spec section 14.1).
type App struct {
	St   string           `json:"st"`
	Code string           `json:"code,omitempty"`
	Res  any              `json:"res,omitempty"`
	Used map[string]int64 `json:"used,omitempty"`
	Rev  *int64           `json:"rev,omitempty"`
	Hold bool             `json:"hold,omitempty"`
}

func (a *App) result() exec.Result {
	return exec.Result{St: a.St, ErrCode: a.Code, Res: a.Res, Used: a.Used, RevUntil: a.Rev}
}

// hold is an operation the application has started and not returned.
type hold struct {
	ctx     context.Context
	started chan struct{}
	outcome chan *App
	done    chan reply
}

type reply struct {
	rep *exec.Reply
	rej *writ.Error
}

// Driver runs one executor under scripted application outcomes. The
// scenario runner and the scenario generator both use it, so the corpus is
// produced by exactly the code that checks it.
type Driver struct {
	dir    string
	id     *keys.Identity
	accept map[string]bool
	peers  map[string][]string
	e      *exec.Executor

	mu      sync.Mutex
	now     int64
	app     *App
	invoked bool
	holds   map[string]*hold // call identity
}

// timeout bounds every wait on the executor so a hung implementation fails
// the step instead of the run.
const timeout = 10 * time.Second

// NewDriver starts an executor with empty stores in a fresh directory. peers
// maps each transport identity the executor holds a binding for to the keys
// that peer speaks for (spec 7.6).
func NewDriver(seedHex string, accept []string, peers map[string][]string) (*Driver, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("executor seed must be 64 hex digits")
	}
	id, err := keys.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "writ-scenario-")
	if err != nil {
		return nil, err
	}
	d := &Driver{dir: dir, id: id, accept: map[string]bool{}, peers: peers, holds: map[string]*hold{}}
	for _, a := range accept {
		d.accept[a] = true
	}
	if err := d.open(); err != nil {
		return nil, err
	}
	return d, nil
}

// Close removes the driver's store directory.
func (d *Driver) Close() { _ = os.RemoveAll(d.dir) }

func (d *Driver) open() error {
	st, err := exec.OpenFileStore(filepath.Join(d.dir, "store.json"))
	if err != nil {
		return err
	}
	e := exec.New(d.id, st)
	e.AcceptRoot = func(did string) bool { return d.accept[did] }
	e.PeerBinds = func(peer, did string) bool {
		for _, k := range d.peers[peer] {
			if k == did {
				return true
			}
		}
		return false
	}
	e.Now = func() int64 {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.now
	}
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result { return d.perform(ctx, k.ID) }
	e.Undo = func(ctx context.Context, t *writ.Tally, res any) exec.Result {
		return d.perform(ctx, callIdentity(ctx))
	}
	d.e = e
	return nil
}

type ctxKey struct{}

func callIdentity(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}

// perform is the scripted application. It records that the executor invoked
// it, so a step with no app can assert that nothing ran.
func (d *Driver) perform(ctx context.Context, callID string) exec.Result {
	d.mu.Lock()
	app := d.app
	d.invoked = true
	h := d.holds[callID]
	d.mu.Unlock()
	if app == nil {
		return exec.Result{St: "failed", ErrCode: "conformance/unscripted"}
	}
	if app.Hold && h != nil {
		h.ctx = ctx
		close(h.started)
		return (<-h.outcome).result()
	}
	return app.result()
}

// Run performs one step and returns the executor's answer as a JSON value in
// the shape of the step's expect member, or an error when the step cannot be
// run or the executor broke a rule the answer cannot show (an application
// invoked where the step forbids it, a wrong cancellation signal).
func (d *Driver) Run(s *Step) (any, error) {
	d.mu.Lock()
	d.now, d.app, d.invoked = s.Now, s.App, false
	d.mu.Unlock()
	switch s.Do {
	case "call":
		obj, err := wire.Decode(s.Call)
		if err != nil {
			return nil, fmt.Errorf("step call is not an object: %v", err)
		}
		cid, _ := wire.Hash(obj)
		ctx := context.WithValue(context.Background(), ctxKey{}, cid)
		if s.Peer != "" {
			ctx = exec.WithPeer(ctx, s.Peer)
		}
		var out any
		if s.App != nil && s.App.Hold {
			h := &hold{started: make(chan struct{}), outcome: make(chan *App, 1), done: make(chan reply, 1)}
			d.mu.Lock()
			d.holds[cid] = h
			d.mu.Unlock()
			go func() {
				rep, rej := d.e.Execute(ctx, obj)
				h.done <- reply{rep, rej}
			}()
			select {
			case <-h.started:
				out = map[string]any{"inflight": true}
			case r := <-h.done:
				out = answer(r)
			case <-time.After(timeout):
				return nil, fmt.Errorf("executor neither started the operation nor answered")
			}
		} else {
			rep, rej := d.e.Execute(ctx, obj)
			out = answer(reply{rep, rej})
		}
		if s.App == nil && d.wasInvoked() {
			return out, fmt.Errorf("the executor performed an operation for a step whose vector says nothing may run")
		}
		return out, nil
	case "revoke":
		obj, err := wire.Decode(s.Revoke)
		if err != nil {
			return nil, fmt.Errorf("step revoke is not an object: %v", err)
		}
		tallies, rej := d.e.Revoke(obj)
		if rej != nil {
			return map[string]any{"error": string(rej.Code)}, nil
		}
		arr := make([]any, 0, len(tallies))
		for _, t := range tallies {
			arr = append(arr, t)
		}
		return map[string]any{"tallies": arr}, nil
	case "finish":
		var cid string
		if err := json.Unmarshal(s.Call, &cid); err != nil {
			return nil, fmt.Errorf("finish names no call identity: %v", err)
		}
		d.mu.Lock()
		h := d.holds[cid]
		delete(d.holds, cid)
		d.mu.Unlock()
		if h == nil || s.App == nil {
			return nil, fmt.Errorf("finish for %s: no held operation, or no app", cid)
		}
		signaled := h.ctx.Err() != nil
		h.outcome <- s.App
		var out any
		select {
		case r := <-h.done:
			out = answer(r)
		case <-time.After(timeout):
			return nil, fmt.Errorf("executor did not answer after the operation returned")
		}
		if s.Signaled != nil && signaled != *s.Signaled {
			return out, fmt.Errorf("operation stop signal was %v, want %v", signaled, *s.Signaled)
		}
		return out, nil
	case "restart":
		// Operations still held are lost with the old process: their
		// goroutines stay parked and never touch the store again.
		d.mu.Lock()
		d.holds = map[string]*hold{}
		d.mu.Unlock()
		if err := d.open(); err != nil {
			return nil, err
		}
		return map[string]any{"resolved": d.e.Recover()}, nil
	}
	return nil, fmt.Errorf("unknown step %q", s.Do)
}

func (d *Driver) wasInvoked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.invoked
}

func answer(r reply) any {
	if r.rej != nil {
		return map[string]any{"error": string(r.rej.Code)}
	}
	m := map[string]any{"tally": r.rep.Tally}
	if r.rep.Res != nil {
		m["res"] = r.rep.Res
	}
	return m
}

// Canon returns the canonical form of a JSON value built by this package or
// decoded from a vector.
func Canon(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var x any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	return jcs.Marshal(x)
}

// RunScenario runs every step and returns the index of the first failing
// step (-1 when all pass) with a description.
func RunScenario(sc *Scenario) (int, string) {
	d, err := NewDriver(sc.Executor.Seed, sc.Executor.Accept, sc.Executor.Peers)
	if err != nil {
		return 0, err.Error()
	}
	defer d.Close()
	for i := range sc.Steps {
		s := &sc.Steps[i]
		got, err := d.Run(s)
		if err != nil {
			return i, err.Error()
		}
		want, err := Canon(json.RawMessage(s.Expect))
		if err != nil {
			return i, "unreadable expect: " + err.Error()
		}
		g, err := Canon(got)
		if err != nil {
			return i, "answer is not canonical JSON: " + err.Error()
		}
		if !bytes.Equal(g, want) {
			return i, describe(g, want)
		}
	}
	return -1, fmt.Sprintf("%d steps", len(sc.Steps))
}

// describe summarizes the first difference between two answers so a failure
// reads as a protocol statement, not a byte dump.
func describe(got, want []byte) string {
	sum := func(b []byte) string {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		_ = dec.Decode(&m)
		if e, ok := m["error"]; ok {
			return fmt.Sprintf("unsigned %v", e)
		}
		if t, ok := m["tally"].(map[string]any); ok {
			s := fmt.Sprintf("tally %v", t["st"])
			if e, ok := t["err"].(map[string]any); ok {
				s += fmt.Sprintf(" %v", e["code"])
			}
			return s + fmt.Sprintf(" acc %v", t["acc"])
		}
		if ts, ok := m["tallies"].([]any); ok {
			return fmt.Sprintf("%d tallies", len(ts))
		}
		for k := range m {
			return k
		}
		return string(b)
	}
	g, w := sum(got), sum(want)
	if g != w {
		return fmt.Sprintf("got %s, want %s", g, w)
	}
	return fmt.Sprintf("same outcome (%s) but different bytes:\n  got  %s\n  want %s", g, got, want)
}

// RunScenarioDir runs every scenario in dir.
func RunScenarioDir(dir string) (int, int, string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	var sb strings.Builder
	pass, fail := 0, 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fail++
			fmt.Fprintf(&sb, "FAIL %s: unreadable: %v\n", filepath.Base(f), err)
			continue
		}
		var sc Scenario
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(&sc); err != nil {
			fail++
			fmt.Fprintf(&sb, "FAIL %s: unreadable scenario: %v\n", filepath.Base(f), err)
			continue
		}
		at, detail := RunScenario(&sc)
		if at < 0 {
			pass++
			fmt.Fprintf(&sb, "ok   %-52s %s\n", sc.Name, detail)
		} else {
			fail++
			note := ""
			if at < len(sc.Steps) && sc.Steps[at].Note != "" {
				note = " (" + sc.Steps[at].Note + ")"
			}
			fmt.Fprintf(&sb, "FAIL %-52s step %d%s: %s\n", sc.Name, at+1, note, detail)
		}
	}
	return pass, fail, sb.String()
}
