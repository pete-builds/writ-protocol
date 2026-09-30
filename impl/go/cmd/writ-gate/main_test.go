package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// orders is a legacy API that has never heard of Writ.
type orders struct {
	mu       sync.Mutex
	created  int
	canceled []string
	sawWrit  bool
}

func (o *orders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.Header.Get(callHeader) != "" {
		o.sawWrit = true
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/orders":
		o.created++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"ord_`+string(rune('0'+o.created))+`","status":"created"}`)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/cancel"):
		o.canceled = append(o.canceled, strings.Split(r.URL.Path, "/")[3])
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type fixture struct {
	api  *orders
	url  string
	A    *keys.Identity
	w    *writ.Writ
	gate string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	api := &orders{}
	up := httptest.NewServer(api)
	t.Cleanup(up.Close)
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	G, _ := keys.FromSeed(bytes.Repeat([]byte{8}, 32))
	e := exec.New(G, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	cfg := Config{Upstream: up.URL, Routes: map[string]Route{
		"create_order": {Method: "POST", Path: "/v1/orders", Act: "orders/create",
			Bind:    map[string]string{"amount": "$.total_cents", "currency": "$.currency"},
			Used:    map[string]string{"amount": "$.total_cents"},
			Reverse: &Reverse{Method: "POST", Path: "/v1/orders/{id}/cancel", ID: "$.id", TTL: 86400}},
	}}
	g, err := newGate(cfg, e, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(g)
	t.Cleanup(gs.Close)
	w, _ := writ.Issue(A, G.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "orders"},
		"amount": map[string]any{"t": "max", "v": 5000},
		"uses":   map[string]any{"t": "count", "v": 2},
	}, time.Now().Unix()+3600, nil)
	return &fixture{api: api, url: up.URL, A: A, w: w, gate: gs.URL}
}

func (f *fixture) order(t *testing.T, k *writ.Call, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.gate+"/v1/orders", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if k != nil {
		b, _ := json.Marshal(k.Raw)
		req.Header.Set(callHeader, base64.RawURLEncoding.EncodeToString(b))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (f *fixture) call(amount int, currency string) *writ.Call {
	k, _ := writ.NewCall(f.A, []*writ.Writ{f.w}, "orders/create", map[string]any{"amount": amount, "currency": currency})
	return k
}

func refusal(t *testing.T, b []byte) string {
	t.Helper()
	var out struct {
		Tally map[string]any `json:"tally"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Tally == nil {
		t.Fatalf("not a tally answer: %s", b)
	}
	if e, ok := out.Tally["err"].(map[string]any); ok {
		return e["code"].(string)
	}
	return out.Tally["st"].(string)
}

func TestGateInFrontOfALegacyAPI(t *testing.T) {
	f := setup(t)

	k1 := f.call(1200, "USD")
	resp, body := f.order(t, k1, `{"total_cents":1200,"currency":"USD","note":"unbound fields pass through"}`)
	if resp.StatusCode != http.StatusCreated || !strings.Contains(string(body), `"ord_1"`) {
		t.Fatalf("an order inside the grant: %d %s", resp.StatusCode, body)
	}
	tb, _ := base64.RawURLEncoding.DecodeString(resp.Header.Get(tallyHeader))
	tallyObj, err := wire.Decode(tb)
	if err != nil {
		t.Fatalf("no tally header: %v", err)
	}
	// The caller rebuilds the result body from the response it received, so
	// the tally also proves the response was not altered after the gate.
	sum := sha256.Sum256(body)
	res := map[string]any{"status": json.Number("201"), "body_sha256": hex.EncodeToString(sum[:]), "reverse_id": "ord_1"}
	if v, tl, err := writ.VerifyTally(f.w, k1, tallyObj, res); v != writ.Valid || tl.Used["amount"] != 1200 || tl.Rev == nil {
		t.Fatalf("the tally for the order: %v %v %+v", v, err, tl)
	}
	if f.api.sawWrit {
		t.Fatal("the API saw the Writ-Call header")
	}

	cases := []struct {
		k      *writ.Call
		body   string
		status int
		want   string
	}{
		{f.call(6000, "USD"), `{"total_cents":6000,"currency":"USD"}`, 200, "out_of_bounds"},
		{f.call(1200, "USD"), `{"total_cents":9999,"currency":"USD"}`, 400, "malformed"},
		{nil, `{"total_cents":1200,"currency":"USD"}`, 400, "missing_call"},
	}
	for _, c := range cases {
		resp, body := f.order(t, c.k, c.body)
		got := ""
		if resp.StatusCode == 200 {
			got = refusal(t, body)
		} else {
			var e struct{ Error string }
			_ = json.Unmarshal(body, &e)
			got = e.Error
		}
		if resp.StatusCode != c.status || got != c.want {
			t.Errorf("body %s: %d %s, want %d %s", c.body, resp.StatusCode, got, c.status, c.want)
		}
	}
	// A replay of the same call and body is answered from the call store.
	resp, body = f.order(t, k1, `{"total_cents":1200,"currency":"USD","note":"unbound fields pass through"}`)
	if resp.StatusCode != 200 || refusal(t, body) != "ok" {
		t.Fatalf("a replay: %d %s", resp.StatusCode, body)
	}
	// The second use, then the count runs out.
	if resp, _ := f.order(t, f.call(100, "USD"), `{"total_cents":100,"currency":"USD"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("the second order: %d", resp.StatusCode)
	}
	if _, body := f.order(t, f.call(100, "USD"), `{"total_cents":100,"currency":"USD"}`); refusal(t, body) != "count_exhausted" {
		t.Fatalf("a third order under uses 2: %s", body)
	}
	if f.api.created != 2 {
		t.Fatalf("the API created %d orders, want 2: refusals and the replay must not reach it", f.api.created)
	}

	// Undo, through the gate's own endpoint: the API's cancel is called.
	u, _ := writ.NewCall(f.A, []*writ.Writ{f.w}, "sys/undo", map[string]any{"tally": tallyObj})
	ub, _ := json.Marshal(u.Raw)
	uresp, err := http.Post(f.gate+"/writ", "application/writ+json", bytes.NewReader(ub))
	if err != nil {
		t.Fatal(err)
	}
	defer uresp.Body.Close()
	ubody, _ := io.ReadAll(uresp.Body)
	if refusal(t, ubody) != "ok" || len(f.api.canceled) != 1 || f.api.canceled[0] != "ord_1" {
		t.Fatalf("undo: %s, canceled %v", ubody, f.api.canceled)
	}
	// Unrouted requests never reach the API.
	resp, _ = http.Post(f.gate+"/v1/admin/wipe", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unrouted path: %d", resp.StatusCode)
	}
}
