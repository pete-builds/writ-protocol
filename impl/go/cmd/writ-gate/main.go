// writ-gate enforces Writ in front of an HTTP API that has never heard of it,
// as docs/adoption.md section 2c designs it. A caller sends its ordinary
// request with the Writ call in a Writ-Call header. The gate checks that the
// call signs exactly the fields the route binds from the request body, runs
// the executor, and forwards the request, stripped of Writ, only if the call
// passes. The API's response comes back unchanged, with the gate's signed
// tally in a Writ-Tally header. A refusal is a signed tally and the API never
// sees the request. The API changes zero lines.
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

// Route maps one API request onto a Writ operation.
type Route struct {
	Method string `json:"method"`
	// Path matches the request path; a {name} segment matches any one segment.
	Path string `json:"path"`
	// Act is the op the caller's call must name.
	Act string `json:"act"`
	// Bind maps each call argument to a JSON path in the request body, like
	// "$.total_cents". The call's args must equal exactly these fields.
	Bind map[string]string `json:"bind"`
	// Used maps each max bound to the JSON path whose integer the request
	// consumes, reported in the tally's used.
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
	e      *exec.Executor
	client *http.Client
	writ   http.Handler // the section 10 endpoint for standing calls and revokes
}

type ctxKey struct{}

// exchange carries one proxied request into the executor's handler and its
// response back out.
type exchange struct {
	route *Route
	req   *http.Request
	body  []byte
	resp  *http.Response
	rbody []byte
}

func newGate(cfg Config, e *exec.Executor, client *http.Client) (*gate, error) {
	if cfg.Upstream == "" || len(cfg.Routes) == 0 {
		return nil, errors.New("the mapping needs an upstream and at least one route")
	}
	g := &gate{cfg: cfg, e: e, client: client}
	acts := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		acts = append(acts, r.Act)
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
	route := g.match(r.Method, r.URL.Path)
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
		fail(w, http.StatusBadRequest, "too_large")
		return
	}
	// What was signed and what the API receives must be the same values.
	if op, _ := obj["op"].(string); op != route.Act {
		fail(w, http.StatusBadRequest, "malformed")
		return
	}
	args, ok := extract(body, route.Bind)
	if !ok || !sameJSON(obj["args"], args) {
		fail(w, http.StatusBadRequest, "malformed")
		return
	}
	x := &exchange{route: route, req: r, body: body}
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
	req, err := http.NewRequestWithContext(ctx, x.req.Method, strings.TrimRight(g.cfg.Upstream, "/")+x.req.URL.RequestURI(), bytes.NewReader(x.body))
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "gate/bad_upstream"}
	}
	for k, vs := range x.req.Header {
		if strings.EqualFold(k, callHeader) || strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
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
	r := exec.Result{Res: res, Used: used(x.body, x.route.Used)}
	if resp.StatusCode >= 400 {
		r.St, r.ErrCode = "failed", fmt.Sprintf("http/%d", resp.StatusCode)
		return r
	}
	if rv := x.route.Reverse; rv != nil {
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

func (g *gate) match(method, path string) *Route {
	names := make([]string, 0, len(g.cfg.Routes))
	for n := range g.cfg.Routes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := g.cfg.Routes[n]
		if strings.EqualFold(r.Method, method) && pathMatches(r.Path, path) {
			return &r
		}
	}
	return nil
}

func pathMatches(pattern, path string) bool {
	p, s := strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(p) != len(s) {
		return false
	}
	for i := range p {
		if strings.HasPrefix(p[i], "{") && strings.HasSuffix(p[i], "}") {
			if s[i] == "" {
				return false
			}
		} else if p[i] != s[i] {
			return false
		}
	}
	return true
}

// extract reads each bound argument from the JSON body at its path.
func extract(body []byte, bind map[string]string) (map[string]any, bool) {
	args := map[string]any{}
	if len(bind) == 0 {
		return args, true
	}
	doc, ok := parse(body)
	if !ok {
		return nil, false
	}
	for name, path := range bind {
		v, ok := at(doc, path)
		if !ok {
			return nil, false
		}
		args[name] = v
	}
	return args, true
}

func used(body []byte, paths map[string]string) map[string]int64 {
	if len(paths) == 0 {
		return nil
	}
	doc, ok := parse(body)
	if !ok {
		return nil
	}
	out := map[string]int64{}
	for name, path := range paths {
		if v, ok := at(doc, path); ok {
			if n, ok := v.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					out[name] = i
				}
			}
		}
	}
	return out
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
