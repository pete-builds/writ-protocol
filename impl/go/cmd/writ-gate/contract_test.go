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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// ledger is a legacy API that decodes requests the way most Go services do:
// into a tagged struct with encoding/json, which matches member names without
// regard to case (Unicode simple folding) and keeps the last duplicate. It
// also does what plenty of frameworks do: a query parameter overrides the
// body, a method override header turns a POST into another verb, a quantity
// multiplies the charge, and a batch endpoint reads every JSON value in the
// body. Every charge it makes is recorded, so a test can compare what the API
// executed with what the caller signed.
type ledger struct {
	mu      sync.Mutex
	charges []charge
	seen    []seen
}

type charge struct {
	Account string
	Cents   int64
}

type seen struct {
	Method, URI, Body string
	Header            http.Header
}

type chargeReq struct {
	TotalCents int64  `json:"total_cents"`
	Currency   string `json:"currency"`
	Quantity   int64  `json:"quantity"`
}

func (l *ledger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	l.seen = append(l.seen, seen{Method: r.Method, URI: r.URL.RequestURI(), Body: string(body), Header: r.Header.Clone()})
	method := r.Method
	if o := r.Header.Get("X-HTTP-Method-Override"); o != "" {
		method = o
	}
	account, batch := "acc_default", false
	switch parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/"); {
	case method == "POST" && r.URL.Path == "/v1/charges":
	case method == "POST" && r.URL.Path == "/v1/batch":
		batch = true
	case method == "POST" && len(parts) == 4 && parts[0] == "v1" && parts[1] == "accounts" && parts[3] == "charges":
		account = parts[2]
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var made []string
	for {
		var c chargeReq
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if q := r.URL.Query().Get("total_cents"); q != "" {
			c.TotalCents, _ = strconv.ParseInt(q, 10, 64)
		}
		if c.Quantity == 0 {
			c.Quantity = 1
		}
		l.charges = append(l.charges, charge{Account: account, Cents: c.TotalCents * c.Quantity})
		made = append(made, `"ch_`+strconv.Itoa(len(l.charges))+`"`)
		if !batch {
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"id":`+made[0]+`}`)
}

func (l *ledger) snapshot() ([]charge, []seen) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]charge(nil), l.charges...), append([]seen(nil), l.seen...)
}

type ledgerFixture struct {
	api  *ledger
	A    *keys.Identity
	w    *writ.Writ
	gate string
}

// ledgerRoutes are mappings the gate has accepted since it was written, plus
// one that binds a path parameter.
func ledgerRoutes() map[string]Route {
	body := map[string]string{"amount": "$.total_cents", "currency": "$.currency"}
	used := map[string]string{"amount": "$.total_cents"}
	return map[string]Route{
		"charge": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge", Bind: body, Used: used},
		"batch":  {Method: "POST", Path: "/v1/batch", Act: "ledger/batch", Bind: body, Used: used},
		"account_charge": {Method: "POST", Path: "/v1/accounts/{acct}/charges", Act: "ledger/account",
			Bind: map[string]string{"account": "{acct}", "amount": "$.total_cents", "currency": "$.currency"}, Used: used},
	}
}

func setupLedger(t *testing.T) *ledgerFixture {
	t.Helper()
	api := &ledger{}
	up := httptest.NewServer(api)
	t.Cleanup(up.Close)
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	G, _ := keys.FromSeed(bytes.Repeat([]byte{8}, 32))
	e := exec.New(G, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	g, err := newGate(Config{Upstream: up.URL, Routes: ledgerRoutes()}, e, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(g)
	t.Cleanup(gs.Close)
	w, _ := writ.Issue(A, G.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "ledger"},
		"amount": map[string]any{"t": "max", "v": 5000},
	}, time.Now().Unix()+3600, nil)
	return &ledgerFixture{api: api, A: A, w: w, gate: gs.URL}
}

// sign signs a call for amount in USD, and for account when it is not empty.
func (f *ledgerFixture) sign(op, account string, amount int) *writ.Call {
	args := map[string]any{"amount": amount, "currency": "USD"}
	if account != "" {
		args["account"] = account
	}
	k, _ := writ.NewCall(f.A, []*writ.Writ{f.w}, op, args)
	return k
}

func (f *ledgerFixture) send(t *testing.T, k *writ.Call, uri, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.gate+uri, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for n, v := range hdr {
		req.Header.Set(n, v)
	}
	b, _ := json.Marshal(k.Raw)
	req.Header.Set(callHeader, base64.RawURLEncoding.EncodeToString(b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// An accepted request reaches the API as exactly the operation and values the
// caller signed, and the tally reports what the API executed.
func TestGateForwardsExactlyWhatWasSigned(t *testing.T) {
	cases := []struct {
		op, account, uri, wantAccount string
	}{
		{"ledger/charge", "", "/v1/charges", "acc_default"},
		{"ledger/account", "acc_1", "/v1/accounts/acc_1/charges", "acc_1"},
	}
	for _, c := range cases {
		f := setupLedger(t)
		k := f.sign(c.op, c.account, 1200)
		resp, body := f.send(t, k, c.uri, `{ "currency" : "USD", "total_cents" : 1200 }`, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: a charge inside the grant: %d %s", c.uri, resp.StatusCode, body)
		}
		charges, seen := f.api.snapshot()
		if len(charges) != 1 || charges[0] != (charge{c.wantAccount, 1200}) {
			t.Fatalf("%s: the API executed %+v, want one charge of 1200 to %s", c.uri, charges, c.wantAccount)
		}
		if s := seen[0]; s.Method != "POST" || s.URI != c.uri || s.Body != `{"currency":"USD","total_cents":1200}` ||
			s.Header.Get("Content-Type") != "application/json" || s.Header.Get(callHeader) != "" {
			t.Fatalf("%s: the API received %+v", c.uri, s)
		}
		tb, _ := base64.RawURLEncoding.DecodeString(resp.Header.Get(tallyHeader))
		tallyObj, err := wire.Decode(tb)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		res := map[string]any{"status": json.Number("201"), "body_sha256": hex.EncodeToString(sum[:])}
		v, tl, err := writ.VerifyTally(f.w, k, tallyObj, res)
		if v != writ.Valid || tl.St != "ok" || tl.Used["amount"] != charges[0].Cents {
			t.Fatalf("%s: the receipt for the charge: %v %v %+v", c.uri, v, err, tl)
		}
	}
}

// Each request is signed for 1200 under a max of 5000, and each is built so
// that a gate checking only the fields it extracts would pass it while the
// API above executes something else. None may reach the API, and none may
// earn a tally.
func TestGateRefusesAmbiguousRequests(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		account string
		uri     string
		body    string
		want    string
	}{
		{"case alias", "ledger/charge", "", "/v1/charges",
			`{"total_cents":1200,"currency":"USD","TOTAL_CENTS":9999}`, "gate/ambiguous_member"},
		{"Unicode folding alias", "ledger/charge", "", "/v1/charges",
			`{"total_cents":1200,"currency":"USD","total_cent` + "\u017f" + `":9999}`, "gate/ambiguous_member"},
		{"duplicate member", "ledger/charge", "", "/v1/charges",
			`{"total_cents":9999,"currency":"USD","total_cents":1200}`, "noncanonical"},
		{"trailing JSON", "ledger/batch", "", "/v1/batch",
			`{"total_cents":1200,"currency":"USD"}` + "\n" + `{"total_cents":9999,"currency":"USD"}`, "noncanonical"},
		{"unbound member", "ledger/charge", "", "/v1/charges",
			`{"total_cents":1200,"currency":"USD","quantity":10}`, "gate/unbound_member"},
		{"query string", "ledger/charge", "", "/v1/charges?total_cents=9999",
			`{"total_cents":1200,"currency":"USD"}`, "gate/unbound_query"},
		{"path parameter differs from the signed one", "ledger/account", "acc_1", "/v1/accounts/acc_2/charges",
			`{"total_cents":1200,"currency":"USD"}`, "malformed"},
		{"dot segment as a path parameter", "ledger/account", "..", "/v1/accounts/../charges",
			`{"total_cents":1200,"currency":"USD"}`, "malformed"},
		{"body differs from the signed args", "ledger/charge", "", "/v1/charges",
			`{"total_cents":9999,"currency":"USD"}`, "malformed"},
		{"a number the signed integer only resembles", "ledger/charge", "", "/v1/charges",
			`{"total_cents":1200.0,"currency":"USD"}`, "malformed"},
		{"not an object", "ledger/charge", "", "/v1/charges",
			`[{"total_cents":1200,"currency":"USD"}]`, "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupLedger(t)
			resp, body := f.send(t, f.sign(c.op, c.account, 1200), c.uri, c.body, nil)
			var e struct{ Error string }
			_ = json.Unmarshal(body, &e)
			charges, seen := f.api.snapshot()
			if len(seen) != 0 || len(charges) != 0 {
				tb, _ := base64.RawURLEncoding.DecodeString(resp.Header.Get(tallyHeader))
				t.Fatalf("the API received %d requests and executed %+v, and the gate answered %d with tally %s; nothing may reach it",
					len(seen), charges, resp.StatusCode, tb)
			}
			if resp.StatusCode != http.StatusBadRequest || e.Error != c.want {
				t.Fatalf("%d %s, want 400 %s", resp.StatusCode, body, c.want)
			}
		})
	}
}

// Headers that change what the API does are not forwarded: a method override
// would turn the signed POST into another operation, and a content type other
// than JSON would have the API parse the body some other way.
func TestGateDropsOperationChangingHeaders(t *testing.T) {
	f := setupLedger(t)
	resp, body := f.send(t, f.sign("ledger/charge", "", 1200), "/v1/charges", `{"total_cents":1200,"currency":"USD"}`,
		map[string]string{"X-HTTP-Method-Override": "DELETE", "Content-Type": "application/x-www-form-urlencoded", "X-Request-Id": "r1"})
	charges, seen := f.api.snapshot()
	if resp.StatusCode != http.StatusCreated || len(charges) != 1 || charges[0].Cents != 1200 {
		t.Fatalf("%d %s, charges %+v", resp.StatusCode, body, charges)
	}
	if h := seen[0].Header; h.Get("X-HTTP-Method-Override") != "" || h.Get("Content-Type") != "application/json" || h.Get("X-Request-Id") != "r1" {
		t.Fatalf("the API received headers %v", h)
	}
}

// A mapping that leaves part of a request unsigned, or binds two members an
// API could read as one, is refused when the gate starts.
func TestGateRefusesAmbiguousMappings(t *testing.T) {
	G, _ := keys.FromSeed(bytes.Repeat([]byte{8}, 32))
	bad := map[string]Route{
		"unbound path parameter": {Method: "POST", Path: "/v1/accounts/{acct}/charges", Act: "ledger/charge",
			Bind: map[string]string{"amount": "$.total_cents"}},
		"path parameter bound twice": {Method: "POST", Path: "/v1/accounts/{acct}/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "{acct}", "b": "{acct}"}},
		"unknown path parameter": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "{acct}"}},
		"members that fold together": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "$.total_cents", "b": "$.TOTAL_CENTS"}},
		"one path inside another": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "$.payment", "b": "$.payment.cents"}},
		"member bound twice": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "$.cents", "b": "$.cents"}},
		"used reads an unsigned member": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"amount": "$.cents"}, Used: map[string]string{"amount": "$.quantity"}},
		"malformed path": {Method: "POST", Path: "/v1/charges", Act: "ledger/charge",
			Bind: map[string]string{"a": "$..cents"}},
	}
	for name, r := range bad {
		if _, err := newGate(Config{Upstream: "http://127.0.0.1:1", Routes: map[string]Route{"r": r}}, exec.New(G, nil), http.DefaultClient); err == nil {
			t.Errorf("%s: the gate started", name)
		}
	}
}
