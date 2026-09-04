package httpbind

import (
	"bytes"
	"context"
	"net/http/httptest"
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
