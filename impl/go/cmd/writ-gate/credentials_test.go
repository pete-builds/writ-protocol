package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"encoding/base64"
	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// lockedAPI accepts only the gate's credential and records the headers of
// every request it receives.
type lockedAPI struct {
	mu   sync.Mutex
	seen []http.Header
}

func (a *lockedAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.seen = append(a.seen, r.Header.Clone())
	a.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer gate-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/orders":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"ord_1"}`)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/cancel"):
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func credFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "creds")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // the umask may have narrowed it
		t.Fatal(err)
	}
	return p
}

func lockedGate(t *testing.T, creds http.Header) (*lockedAPI, string, *keys.Identity, *writ.Writ) {
	t.Helper()
	api := &lockedAPI{}
	up := httptest.NewServer(api)
	t.Cleanup(up.Close)
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	G, _ := keys.FromSeed(bytes.Repeat([]byte{8}, 32))
	e := exec.New(G, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	g, err := newGate(Config{Upstream: up.URL, Routes: map[string]Route{
		"create_order": {Method: "POST", Path: "/v1/orders", Act: "orders/create",
			Bind:    map[string]string{"amount": "$.total_cents"},
			Used:    map[string]string{"amount": "$.total_cents"},
			Reverse: &Reverse{Method: "POST", Path: "/v1/orders/{id}/cancel", ID: "$.id", TTL: 86400}},
	}}, e, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	g.creds = creds
	gs := httptest.NewServer(g)
	t.Cleanup(gs.Close)
	w, _ := writ.Issue(A, G.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "orders"},
		"amount": map[string]any{"t": "max", "v": 5000},
	}, time.Now().Unix()+3600, nil)
	return api, gs.URL, A, w
}

// TestGateHoldsTheAPICredential: the API sees the gate's credential and never
// a caller's, on the order and on its reversal, so a caller holds nothing that
// would let it reach the API without the gate.
func TestGateHoldsTheAPICredential(t *testing.T) {
	creds, err := loadCredentials(credFile(t, "# the orders API\nAuthorization: Bearer gate-secret\nX-Api-Key: gate-key\n", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	api, gate, A, w := lockedGate(t, creds)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "orders/create", map[string]any{"amount": 1200})
	kb, _ := json.Marshal(k.Raw)
	req, _ := http.NewRequest("POST", gate+"/v1/orders", strings.NewReader(`{"total_cents":1200}`))
	req.Header.Set(callHeader, base64.RawURLEncoding.EncodeToString(kb))
	req.Header.Set("Authorization", "Bearer caller-token")
	req.Header.Set("Proxy-Authorization", "Basic Y2FsbGVy")
	req.Header.Set("Cookie", "session=caller")
	req.Header.Set("X-Api-Key", "caller-key")
	req.Header.Set("X-Request-Id", "r1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("an order with the gate's credential: %d", resp.StatusCode)
	}
	got := api.seen[0]
	if got.Get("Authorization") != "Bearer gate-secret" || len(got.Values("Authorization")) != 1 {
		t.Errorf("Authorization at the API: %q", got.Values("Authorization"))
	}
	if got.Get("X-Api-Key") != "gate-key" || len(got.Values("X-Api-Key")) != 1 {
		t.Errorf("X-Api-Key at the API: %q", got.Values("X-Api-Key"))
	}
	if got.Get("Cookie") != "" || got.Get("Proxy-Authorization") != "" {
		t.Errorf("a caller credential reached the API: Cookie %q, Proxy-Authorization %q", got.Get("Cookie"), got.Get("Proxy-Authorization"))
	}
	if got.Get("X-Request-Id") != "r1" {
		t.Errorf("an ordinary header was not forwarded: %q", got.Get("X-Request-Id"))
	}

	// The reversal carries the gate's credential too. Before, it carried no
	// header at all, so an API that requires one refused every undo.
	tb, _ := base64.RawURLEncoding.DecodeString(resp.Header.Get(tallyHeader))
	tallyObj, _ := wire.Decode(tb)
	u, _ := writ.NewCall(A, []*writ.Writ{w}, "sys/undo", map[string]any{"tally": tallyObj})
	ub, _ := json.Marshal(u.Raw)
	uresp, err := http.Post(gate+"/writ", "application/writ+json", bytes.NewReader(ub))
	if err != nil {
		t.Fatal(err)
	}
	ubody, _ := io.ReadAll(uresp.Body)
	uresp.Body.Close()
	if refusal(t, ubody) != "ok" {
		t.Fatalf("undo with the gate's credential: %s", ubody)
	}
	if got := api.seen[1]; got.Get("Authorization") != "Bearer gate-secret" {
		t.Errorf("Authorization on the reversal: %q", got.Get("Authorization"))
	}
}

// TestGateWithoutCredentialsForwardsNone: with no credentials file, a
// caller's credential still never reaches the API.
func TestGateWithoutCredentialsForwardsNone(t *testing.T) {
	api, gate, A, w := lockedGate(t, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "orders/create", map[string]any{"amount": 1200})
	kb, _ := json.Marshal(k.Raw)
	req, _ := http.NewRequest("POST", gate+"/v1/orders", strings.NewReader(`{"total_cents":1200}`))
	req.Header.Set(callHeader, base64.RawURLEncoding.EncodeToString(kb))
	req.Header.Set("Authorization", "Bearer gate-secret") // the caller somehow has it
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := api.seen[0].Get("Authorization"); got != "" {
		t.Fatalf("the caller's Authorization reached the API: %q", got)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the API answered %d, want 401: the gate holds no credential", resp.StatusCode)
	}
}

func TestLoadCredentialsRefuses(t *testing.T) {
	cases := []struct {
		name, content string
		mode          os.FileMode
		want          string
	}{
		{"group readable", "Authorization: Bearer x\n", 0o640, "readable by other users"},
		{"world readable", "Authorization: Bearer x\n", 0o604, "readable by other users"},
		{"no colon", "Authorization Bearer x\n", 0o600, "want"},
		{"empty value", "Authorization:\n", 0o600, "want"},
		{"bad name", "Auth orization: x\n", 0o600, "want"},
		{"control character", "Authorization: a\x01b\n", 0o600, "want"},
		{"the call header", "Writ-Call: x\n", 0o600, "gate controls"},
		{"the tally header", "Writ-Tally: x\n", 0o600, "gate controls"},
		{"the host", "host: evil.example\n", 0o600, "gate controls"},
		{"a body header", "Content-Type: text/plain\n", 0o600, "gate controls"},
		{"a method override", "X-HTTP-Method-Override: DELETE\n", 0o600, "gate controls"},
		{"twice", "Authorization: a\nauthorization: b\n", 0o600, "given twice"},
		{"nothing", "# only a comment\n\n", 0o600, "no credential"},
	}
	for _, c := range cases {
		_, err := loadCredentials(credFile(t, c.content, c.mode))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
	// A symlink is refused even when its target is private, so the check of
	// the mode is a check of the file that is read.
	target := credFile(t, "Authorization: Bearer x\n", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symlink: %v", err)
	}
	h, err := loadCredentials(credFile(t, "authorization:  Bearer x \n\n# note\nX-Api-Key:k:with:colons\n", 0o600))
	if err != nil || h.Get("Authorization") != "Bearer x" || h.Get("X-Api-Key") != "k:with:colons" || len(h) != 2 {
		t.Fatalf("a valid file: %v %v", h, err)
	}
}
