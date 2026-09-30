package httpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"writproto/exec"
	"writproto/keys"
	"writproto/writ"
)

func TestRoundTrip(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	e := exec.New(B, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		return exec.Result{Res: map[string]any{"echo": k.Op}}
	}
	srv := httptest.NewServer(Handler(e, WellKnown{V: 1, DID: B.DID(), Endpoint: "/writ", Act: []string{"echo"}}))
	defer srv.Close()
	c := NewClient()
	wk, err := c.Discover(context.Background(), srv.URL)
	if err != nil || wk.DID != B.DID() {
		t.Fatal(err)
	}
	w1, _ := writ.Issue(A, B.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "echo"}}, 1<<40, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w1}, "echo/hi", nil)
	tally, res, err := c.Call(context.Background(), srv.URL+wk.Endpoint, k)
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := writ.VerifyTally(w1, k, tally, res); v != writ.Valid {
		t.Fatal(v, err)
	}
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w1})
	if _, err := c.Revoke(context.Background(), srv.URL+wk.Endpoint, rv); err != nil {
		t.Fatal(err)
	}
	// Garbage body is an unsigned 400.
	_, err = c.post(context.Background(), srv.URL+wk.Endpoint, map[string]any{"typ": "call", "v": 1})
	if re, ok := err.(*RejectedError); !ok || re.Code != writ.Malformed {
		t.Fatalf("want malformed rejection, got %v", err)
	}
}

// A request is one call or one revoke, both limited to 65536 bytes (spec
// 1.6), so a body between that and the tally limit is too_large. Before the
// 2026-09 review fix the binding accepted up to 262144 bytes of any type. A
// body nesting deeper than 64 levels is too_large before it is built.
func TestRequestLimits(t *testing.T) {
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	srv := httptest.NewServer(Handler(exec.New(B, nil), WellKnown{V: 1, DID: B.DID(), Endpoint: "/writ"}))
	defer srv.Close()
	post := func(body []byte) (int, string) {
		resp, err := http.Post(srv.URL+"/writ", ContentType, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Error
	}
	// Whitespace padding: the received bytes exceed 65536 while the
	// canonical form stays small, so only the received-length check sees it.
	padded := func(n int) []byte {
		return []byte(`{"v":1,"typ":"call",` + strings.Repeat(" ", n) + `"args":{}}`)
	}
	base := len(padded(0))
	if code, reason := post(padded(writ.MaxCallBytes + 1 - base)); code != http.StatusBadRequest || reason != string(writ.TooLarge) {
		t.Errorf("65537 received bytes: got %d %q, want 400 too_large", code, reason)
	}
	// At exactly the limit the body reaches the verifier, which finds it malformed.
	if code, reason := post(padded(writ.MaxCallBytes - base)); code != http.StatusBadRequest || reason != string(writ.Malformed) {
		t.Errorf("65536 received bytes: got %d %q, want 400 malformed", code, reason)
	}
	deep := []byte(`{"v":1,"typ":"call","args":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}`)
	if code, reason := post(deep); code != http.StatusBadRequest || reason != string(writ.TooLarge) {
		t.Errorf("70-level call: got %d %q, want 400 too_large", code, reason)
	}
}

// Spec 7.6 and 10: the binding passes the transport-authenticated peer to the
// executor, and a key-wide revoke it could not persist is a 503.
func TestPeerAndUnsavedRevoke(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	dir := t.TempDir()
	st, err := exec.OpenFileStore(dir + "/store.json")
	if err != nil {
		t.Fatal(err)
	}
	e := exec.New(B, st)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	e.PeerBinds = func(peer, did string) bool { return peer == "spiffe://a.example/agent" && did == A.DID() }
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result { return exec.Result{} }
	peerOf := func(r *http.Request) (string, bool) {
		p := r.Header.Get("X-Test-Peer")
		return p, p != ""
	}
	srv := httptest.NewServer(HandlerWithPeer(e, WellKnown{V: 1, DID: B.DID(), Endpoint: "/writ"}, peerOf))
	defer srv.Close()
	post := func(peer string, obj any) (int, map[string]any) {
		body, _ := json.Marshal(obj)
		req, _ := http.NewRequest("POST", srv.URL+"/writ", bytes.NewReader(body))
		req.Header.Set("Content-Type", ContentType)
		if peer != "" {
			req.Header.Set("X-Test-Peer", peer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code := func(out map[string]any) string {
		tl, _ := out["tally"].(map[string]any)
		e, _ := tl["err"].(map[string]any)
		c, _ := e["code"].(string)
		return c
	}
	w1, _ := writ.Issue(A, B.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "echo"}}, 1<<40, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w1}, "echo/hi", nil)
	if status, out := post("spiffe://s.example/other", k.Raw); status != 200 || code(out) != string(writ.PeerMismatch) {
		t.Fatalf("unbound peer: %d %v, want 200 and a peer_mismatch tally", status, out)
	}
	if status, out := post("spiffe://a.example/agent", k.Raw); status != 200 || code(out) != "" {
		t.Fatalf("bound peer: %d %v, want 200 and an ok tally", status, out)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rv, _ := writ.NewRevoke(A, nil)
	if status, out := post("", rv.Raw); status != http.StatusServiceUnavailable || out["error"] != exec.StoreUnavailable {
		t.Fatalf("unsaved key-wide revoke: %d %v, want 503 %s", status, out, exec.StoreUnavailable)
	}
}
