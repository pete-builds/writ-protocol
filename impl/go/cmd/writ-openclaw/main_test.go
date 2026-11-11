package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"writproto/exec"
	"writproto/httpbind"
	"writproto/keys"
	"writproto/writ"
)

// fixture is A, B with a seed file, a booking call from A, and C as a real
// payment executor over HTTP.
type fixture struct {
	k       *writ.Call
	tool    toolConfig
	charges *int
}

func setup(t *testing.T) fixture {
	t.Helper()
	A, _ := keys.Generate()
	B, _ := keys.Generate()
	C, _ := keys.Generate()
	dir := t.TempDir()
	seedFile := filepath.Join(t.TempDir(), "b.seed")
	if err := os.WriteFile(seedFile, []byte(hex.EncodeToString(B.Priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := exec.OpenFileStore("")
	ce := exec.New(C, st)
	ce.AcceptRoot = func(did string) bool { return did == A.DID() }
	charges := 0
	ce.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		n, _ := k.Args["amount"].(json.Number).Int64()
		charges++
		return exec.Result{Res: map[string]any{"charge": "ch_1"}, Used: map[string]int64{"amount": n}}
	}
	srv := httptest.NewServer(httpbind.NewHandler(ce, httpbind.WellKnown{V: 1, DID: C.DID(), Endpoint: "/writ", Act: []string{"travel/charge"}}, httpbind.Options{}))
	t.Cleanup(srv.Close)
	w1, err := writ.Issue(A, B.DID(), map[string]any{
		"act":      map[string]any{"t": "prefix", "v": "travel"},
		"amount":   map[string]any{"t": "max", "v": 60000},
		"currency": map[string]any{"t": "set", "v": []any{"USD"}},
		"uses":     map[string]any{"t": "count", "v": 1},
	}, time.Now().Unix()+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := writ.NewCall(A, []*writ.Writ{w1}, "travel/book", map[string]any{"amount": 60000, "currency": "USD", "request": "Lisbon, two nights"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "call.json"), k.Raw); err != nil {
		t.Fatal(err)
	}
	return fixture{k: k, tool: toolConfig{dir: dir, seedFile: seedFile, downstream: srv.URL, client: httpbind.NewClient()}, charges: &charges}
}

func TestChargeWithinTheWritIsPaidAndCollected(t *testing.T) {
	f := setup(t)
	text, failed := f.tool.charge(context.Background(), "58900")
	if failed || !strings.HasPrefix(text, "Charged $589.00. Receipt ") {
		t.Fatalf("%v %q", failed, text)
	}
	r := collect(f.tool.dir, f.k)
	if r.St != "ok" || r.Used["amount"] != 58900 || len(r.Sub) != 1 || len(r.Wrt) != 1 || *f.charges != 1 {
		t.Fatalf("%+v charges=%d", r, *f.charges)
	}
}

func TestChargeOverTheWritNeverReachesC(t *testing.T) {
	f := setup(t)
	text, failed := f.tool.charge(context.Background(), "70000")
	if !failed || !strings.Contains(text, "not_narrowed") {
		t.Fatalf("%v %q", failed, text)
	}
	if *f.charges != 0 {
		t.Fatalf("C charged %d time(s)", *f.charges)
	}
	if r := collect(f.tool.dir, f.k); r.St != "failed" || r.ErrCode != "app/not_paid" {
		t.Fatalf("%+v", r)
	}
}

func TestToolSpeaksMCP(t *testing.T) {
	f := setup(t)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"charge_card","arguments":{"amount_cents":12345}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"nope"}`,
	}, "\n")
	var out bytes.Buffer
	if err := serveTool(strings.NewReader(in), &out, f.tool); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 responses, one per request, got %d:\n%s", len(lines), out.String())
	}
	for i, want := range []string{`"protocolVersion":"2025-06-18"`, `"name":"charge_card"`, `Charged $123.45`, `"code":-32601`} {
		if !strings.Contains(lines[i], want) {
			t.Fatalf("response %d lacks %s: %s", i+1, want, lines[i])
		}
	}
}
