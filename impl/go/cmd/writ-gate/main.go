// writ-gate enforces Writ in front of an HTTP API that has never heard of it,
// as docs/adoption.md section 2c designs it. A caller sends its ordinary
// request with the Writ call in a Writ-Call header. The gate checks that the
// request carries exactly the values the call signs, where the route's
// contract says they travel, and nothing else; runs the executor; and, only
// if the call passes, sends the API a request it rebuilds from the signed
// values alone (contract.go). The API's response comes back unchanged, with
// the gate's signed tally in a Writ-Tally header. A refusal is a signed tally
// and the API never sees the request. The API changes zero lines.
//
// Standing calls (sys/undo, sys/tallies) and revokes go to the gate's own
// section 10 endpoint, POST /writ. An undo calls the route's reverse request
// on the API, such as a cancel, with an identifier taken from the response.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"writproto/exec"
	"writproto/httpbind"
	"writproto/jcs"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// Config is the gate's mapping file.
type Config struct {
	Upstream string           `json:"upstream"`
	Routes   map[string]Route `json:"routes"`
}

// Route maps one API request onto a Writ operation, and is that request's
// contract: the request may carry nothing the route does not bind.
type Route struct {
	Method string `json:"method"`
	// Path matches the request path; a {name} segment matches any one
	// segment, and every {name} must be bound.
	Path string `json:"path"`
	// Act is the op the caller's call must name.
	Act string `json:"act"`
	// Bind maps each call argument to where the request carries it: a member
	// of the JSON request body, like "$.total_cents", or a path parameter,
	// like "{id}". The body holds exactly the bound members, the call's args
	// equal exactly these values, and the API receives only them.
	Bind map[string]string `json:"bind"`
	// Used maps each max bound to a bound body member whose integer the
	// request consumes, reported in the tally's used.
	Used    map[string]string `json:"used"`
	Reverse *Reverse          `json:"reverse"`
}

// Reverse is the API request that undoes a route's effect (spec 8.1).
type Reverse struct {
	Method string `json:"method"`
	// Path with {id}, filled from the response body at ID.
	Path string `json:"path"`
	ID   string `json:"id"`
	TTL  int64  `json:"ttl"`
}

const (
	callHeader  = "Writ-Call"
	tallyHeader = "Writ-Tally"
	maxBody     = 1 << 20
)

func main() {
	cfgPath := flag.String("config", "", "mapping file (JSON)")
	seedFile := flag.String("seed-file", "", "file holding the gate's 32-byte hex seed")
	accept := flag.String("accept", "", "comma-separated did:key roots the gate acts under")
	store := flag.String("store", "", "path of the durable store")
	audit := flag.String("audit", "", "path of the audit record")
	listen := flag.String("listen", "127.0.0.1:8090", "address to listen on")
	flag.Parse()
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("%s: %v", *cfgPath, err)
	}
	seed, err := os.ReadFile(*seedFile)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(seed)))
	if err != nil {
		log.Fatal(err)
	}
	id, err := keys.FromSeed(raw)
	if err != nil {
		log.Fatal(err)
	}
	st, err := exec.OpenFileStore(*store)
	if err != nil {
		log.Fatal(err)
	}
	e := exec.New(id, st)
	roots := map[string]bool{}
	for _, r := range strings.Split(*accept, ",") {
		if r = strings.TrimSpace(r); r != "" {
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
	e.Recover()
	g, err := newGate(cfg, e, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("writ-gate %s in front of %s on %s", id.DID(), cfg.Upstream, *listen)
	log.Fatal(http.ListenAndServe(*listen, g))
}

type gate struct {
	cfg    Config
	routes []*contract // in route name order
	e      *exec.Executor
	client *http.Client
	writ   http.Handler // the section 10 endpoint for standing calls and revokes
}

type ctxKey struct{}

// exchange carries one proxied request into the executor's handler and its
// response back out.
type exchange struct {
	route *contract
	req   *http.Request
	resp  *http.Response
	rbody []byte
}

func newGate(cfg Config, e *exec.Executor, client *http.Client) (*gate, error) {
	if cfg.Upstream == "" || len(cfg.Routes) == 0 {
		return nil, errors.New("the mapping needs an upstream and at least one route")
	}
	g := &gate{cfg: cfg, e: e, client: client}
	acts := make([]string, 0, len(cfg.Routes))
	for _, name := range sortedKeys(cfg.Routes) {
		c, err := compile(name, cfg.Routes[name])
		if err != nil {
			return nil, err
		}
		g.routes = append(g.routes, c)
		acts = append(acts, c.route.Act)
	}
	sort.Strings(acts)
	g.writ = httpbind.Handler(e, httpbind.WellKnown{V: 1, DID: e.ID.DID(), Endpoint: "/writ", Act: acts})
	e.Handle = g.forward
	e.Undo = g.reverse
	return g, nil
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/writ" || r.URL.Path == "/.well-known/writ" {
		g.writ.ServeHTTP(w, r)
		return
	}
	route, params := g.match(r.Method, r.URL.Path)
	if route == nil {
		fail(w, http.StatusNotFound, "no_route")
		return
	}
	header := r.Header.Get(callHeader)
	if header == "" {
		fail(w, http.StatusBadRequest, "missing_call")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		fail(w, http.StatusBadRequest, "malformed")
		return
	}
	obj, err := wire.Decode(raw)
	if err != nil {
		fail(w, http.StatusBadRequest, "noncanonical")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		fail(w, http.StatusBadRequest, reasonTooLarge)
		return
	}
	// What was signed and what the API receives must be the same values: the
	// request carries exactly the signed args where the contract puts them,
	// and forward sends the API a request rebuilt from those args alone.
	if op, _ := obj["op"].(string); op != route.route.Act {
		fail(w, http.StatusBadRequest, reasonMalformed)
		return
	}
	query := r.URL.RawQuery
	if r.URL.ForceQuery {
		query = "?"
	}
	args, reason := route.extract(query, params, body)
	if reason == "" && !sameJSON(obj["args"], args) {
		reason = reasonMalformed
	}
	if reason != "" {
		fail(w, http.StatusBadRequest, reason)
		return
	}
	x := &exchange{route: route, req: r}
	rep, rej := g.e.Execute(context.WithValue(r.Context(), ctxKey{}, x), obj)
	if rej != nil {
		fail(w, http.StatusBadRequest, string(rej.Code))
		return
	}
	tb, _ := json.Marshal(rep.Tally)
	if x.resp == nil {
		// Refused, or a replay answered from the call store: the API was not
		// called now, so the answer is the tally itself.
		w.Header().Set("Content-Type", httpbind.ContentType)
		_ = json.NewEncoder(w).Encode(map[string]any{"tally": rep.Tally, "res": rep.Res})
		return
	}
	for k, vs := range x.resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set(tallyHeader, base64.RawURLEncoding.EncodeToString(tb))
	w.WriteHeader(x.resp.StatusCode)
	_, _ = w.Write(x.rbody)
}

// forward is the executor's handler: it sends the request on to the API.
func (g *gate) forward(ctx context.Context, k *writ.Call) exec.Result {
	x, _ := ctx.Value(ctxKey{}).(*exchange)
	if x == nil {
		// A forward call posted to /writ carries no API request to perform.
		return exec.Result{St: "failed", ErrCode: "gate/no_request"}
	}
	method, path, body, err := x.route.target(k.Args)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/bad_request"}
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.cfg.Upstream, "/")+path, rd)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/bad_upstream"}
	}
	for k, vs := range x.req.Header {
		if dropped[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/upstream_unreachable"}
	}
	defer resp.Body.Close()
	rbody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*maxBody))
	x.resp, x.rbody = resp, rbody
	sum := sha256.Sum256(rbody)
	res := map[string]any{"status": resp.StatusCode, "body_sha256": hex.EncodeToString(sum[:])}
	r := exec.Result{Res: res, Used: x.route.used(k.Args)}
	if resp.StatusCode >= 400 {
		r.St, r.ErrCode = "failed", fmt.Sprintf("http/%d", resp.StatusCode)
		return r
	}
	if rv := x.route.route.Reverse; rv != nil {
		if id, ok := pathString(rbody, rv.ID); ok {
			res["reverse_id"] = id
			until := g.e.Now() + rv.TTL
			r.RevUntil = &until
		}
	}
	return r
}

// reverse is the executor's undo: the route's reverse request on the API.
func (g *gate) reverse(ctx context.Context, t *writ.Tally, res any) exec.Result {
	m, _ := res.(map[string]any)
	id, _ := m["reverse_id"].(string)
	var rv *Reverse
	for _, r := range g.cfg.Routes {
		if r.Act == t.Op && r.Reverse != nil {
			rv = r.Reverse
		}
	}
	if rv == nil || id == "" {
		return exec.Result{St: "failed", ErrCode: "gate/not_reversible"}
	}
	path := strings.ReplaceAll(rv.Path, "{id}", id)
	req, err := http.NewRequestWithContext(ctx, rv.Method, strings.TrimRight(g.cfg.Upstream, "/")+path, nil)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/bad_upstream"}
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/upstream_unreachable"}
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return exec.Result{St: "failed", ErrCode: fmt.Sprintf("http/%d", resp.StatusCode)}
	}
	return exec.Result{Res: map[string]any{"reversed": id, "status": resp.StatusCode}}
}

func (g *gate) match(method, path string) (*contract, map[string]string) {
	for _, c := range g.routes {
		if params, ok := c.match(method, path); ok {
			return c, params
		}
	}
	return nil, nil
}

// dropped are the request headers the gate does not forward. The Writ call
// is the gate's; the body headers describe bytes the gate replaced; and a
// method override header would turn the signed operation into another one.
var dropped = map[string]bool{
	"Writ-Call": true, "Host": true,
	"Content-Type": true, "Content-Length": true, "Content-Encoding": true, "Transfer-Encoding": true,
	"X-Http-Method-Override": true, "X-Http-Method": true, "X-Method-Override": true,
}

func pathString(body []byte, path string) (string, bool) {
	doc, ok := parse(body)
	if !ok {
		return "", false
	}
	v, ok := at(doc, path)
	if !ok {
		return "", false
	}
	switch x := v.(type) {
	case string:
		return x, x != ""
	case json.Number:
		return x.String(), true
	}
	return "", false
}

func parse(body []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

// at follows a "$.a.b" path through JSON objects.
func at(doc any, path string) (any, bool) {
	if !strings.HasPrefix(path, "$.") {
		return nil, false
	}
	cur := doc
	for _, key := range strings.Split(path[2:], ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[key]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func sameJSON(a, b any) bool {
	x, err1 := jcs.Marshal(a)
	y, err2 := jcs.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func fail(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}
