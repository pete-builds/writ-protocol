package httpbind

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/writ"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue signs a client certificate naming uris as URI subject alternative names.
func (ca *testCA) issue(t *testing.T, serial int64, uris ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "workload"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, p)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A SPIFFE SVID-style client certificate is the peer; did:key URIs in it are
// keys the CA binds to that peer; a bindings file exported from a directory
// covers workloads whose certificates name no key (spec 7.6).
func TestMTLSAndDirectoryBindings(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	C, _ := keys.FromSeed(bytes.Repeat([]byte{3}, 32))
	ca := newCA(t)
	dir := t.TempDir()
	bindingsPath := filepath.Join(dir, "bindings.json")
	writeBindings := func(m map[string][]string) {
		b, _ := json.Marshal(m)
		if err := os.WriteFile(bindingsPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeBindings(map[string][]string{"spiffe://example.org/nokey": {A.DID()}})
	bindings, err := exec.LoadBindings(bindingsPath)
	if err != nil {
		t.Fatal(err)
	}

	e := exec.New(C, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	e.PeerBinds = bindings.Binds
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result { return exec.Result{} }
	var peers []string
	e.Audit = func(a exec.AuditEntry) {
		if a.Peer != nil {
			peers = append(peers, *a.Peer)
		}
	}
	srv := httptest.NewUnstartedServer(NewHandler(e, WellKnown{V: 1, DID: C.DID(), Endpoint: "/writ"}, Options{MTLS: true}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.pool}
	srv.StartTLS()
	defer srv.Close()

	w, _ := writ.Issue(A, C.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "x"}}, 1<<40, nil)
	callAs := func(cert tls.Certificate, from *keys.Identity) string {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
		k, _ := writ.NewCall(from, []*writ.Writ{w}, "x/y", map[string]any{})
		body, _ := json.Marshal(k.Raw)
		resp, err := client.Post(srv.URL+"/writ", ContentType, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Tally map[string]any `json:"tally"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if e, ok := out.Tally["err"].(map[string]any); ok {
			return e["code"].(string)
		}
		return out.Tally["st"].(string)
	}

	certA := ca.issue(t, 2, "spiffe://example.org/booking", A.DID())
	certB := ca.issue(t, 3, "spiffe://example.org/other", B.DID())
	certNoKey := ca.issue(t, 4, "spiffe://example.org/nokey")
	if got := callAs(certA, A); got != "ok" {
		t.Fatalf("a certificate naming A's key: %s, want ok", got)
	}
	if got := callAs(certB, A); got != "peer_mismatch" {
		t.Fatalf("a certificate naming only B's key: %s, want peer_mismatch", got)
	}
	if got := callAs(certNoKey, A); got != "ok" {
		t.Fatalf("a certificate naming no key, bound to A in the directory file: %s, want ok", got)
	}
	// The directory drops the binding; the executor follows the file.
	time.Sleep(10 * time.Millisecond)
	writeBindings(map[string][]string{})
	if got := callAs(certNoKey, A); got != "peer_mismatch" {
		t.Fatalf("after the directory dropped the binding: %s, want peer_mismatch", got)
	}
	want := []string{"spiffe://example.org/booking", "spiffe://example.org/other", "spiffe://example.org/nokey", "spiffe://example.org/nokey"}
	if len(peers) != len(want) {
		t.Fatalf("audited peers %v, want %v", peers, want)
	}
	for i := range want {
		if peers[i] != want[i] {
			t.Fatalf("audited peers %v, want %v", peers, want)
		}
	}
}

// A bindings file that cannot be parsed binds nothing.
func TestBrokenBindingsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := exec.LoadBindings(path)
	if err == nil || b.Binds("spiffe://x", "did:key:z") {
		t.Fatal("a broken bindings file loaded or bound something")
	}
}

// With mTLS on, a verified connection that yields no usable peer identity has
// still authenticated someone. Every call over it fails closed at peer
// binding, which runs before replay (spec 7.6), so a captured call earns no
// stored result, and nothing runs. No fallback may stand in for the missing
// identity: not an absent peer, not the first of two, not PeerOf.
func TestMTLSFailsClosedWithoutAnIdentity(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	C, _ := keys.FromSeed(bytes.Repeat([]byte{3}, 32))
	ca := newCA(t)
	runs := 0
	var audited []*string
	newExecutor := func(binds func(peer, did string) bool) *exec.Executor {
		e := exec.New(C, nil)
		e.AcceptRoot = func(d string) bool { return d == A.DID() }
		e.PeerBinds = binds
		e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
			runs++
			return exec.Result{Res: map[string]any{"account": "4111-1111", "run": runs}}
		}
		e.Audit = func(a exec.AuditEntry) { audited = append(audited, a.Peer) }
		return e
	}
	// PeerBinds rejects every key: only a certificate that names the signer
	// as a did:key URI beside a peer identity can pass.
	e := newExecutor(func(string, string) bool { return false })
	start := func(h http.Handler, auth tls.ClientAuthType) *httptest.Server {
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = &tls.Config{ClientAuth: auth, ClientCAs: ca.pool}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	wk := WellKnown{V: 1, DID: C.DID(), Endpoint: "/writ"}
	required := start(NewHandler(e, wk, Options{MTLS: true}), tls.RequireAndVerifyClientCert)
	optional := start(NewHandler(e, wk, Options{MTLS: true}), tls.VerifyClientCertIfGiven)

	w, _ := writ.Issue(A, C.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "x"}}, 1<<40, nil)
	send := func(srv *httptest.Server, cert *tls.Certificate, k *writ.Call) (code string, res any) {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		cfg := &tls.Config{RootCAs: pool}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		body, _ := json.Marshal(k.Raw)
		resp, err := client.Post(srv.URL+"/writ", ContentType, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Tally map[string]any `json:"tally"`
			Res   any            `json:"res"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if e, ok := out.Tally["err"].(map[string]any); ok {
			return e["code"].(string), out.Res
		}
		return fmt.Sprint(out.Tally["st"]), out.Res
	}

	certA := ca.issue(t, 2, "spiffe://example.org/booking", A.DID())
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x/charge", map[string]any{})
	if code, res := send(required, &certA, k); code != "ok" || res == nil || runs != 1 {
		t.Fatalf("a certificate naming its peer and A's key: %s %v, %d runs", code, res, runs)
	}
	noURI := ca.issue(t, 3)
	keyOnly := ca.issue(t, 4, A.DID())
	twoPeers := ca.issue(t, 5, "spiffe://example.org/booking", "spiffe://example.org/other", A.DID())
	unrelated := ca.issue(t, 6, "spiffe://example.org/other", B.DID())
	cases := []struct {
		name string
		srv  *httptest.Server
		cert *tls.Certificate
	}{
		{"a certificate with no URI", required, &noURI},
		{"a certificate naming only a key", required, &keyOnly},
		{"a certificate naming two peers", required, &twoPeers},
		{"a certificate naming an unrelated peer and key", required, &unrelated},
		{"no certificate, where the server only asks for one", optional, nil},
	}
	for _, c := range cases {
		audited = nil
		// The captured call: a replay must not disclose its stored result.
		if code, res := send(c.srv, c.cert, k); code != "peer_mismatch" || res != nil {
			t.Errorf("%s, replaying the captured call: %s, result %v; want peer_mismatch and no result", c.name, code, res)
		}
		// A fresh call from A must not run.
		k2, _ := writ.NewCall(A, []*writ.Writ{w}, "x/charge", map[string]any{})
		if code, _ := send(c.srv, c.cert, k2); code != "peer_mismatch" {
			t.Errorf("%s, a fresh call: %s, want peer_mismatch", c.name, code)
		}
		if len(audited) != 2 || audited[0] == nil || audited[1] == nil {
			t.Errorf("%s: the audit record must name an authenticated peer for both calls, got %v", c.name, audited)
		}
	}
	if runs != 1 {
		t.Fatalf("%d operations ran; only the first call may run", runs)
	}

	// PeerOf is no fallback: a certificate with no identity cannot borrow the
	// peer a header or another hook reports, even one bound to A.
	trusted := newExecutor(func(p, d string) bool { return p == "spiffe://example.org/trusted" && d == A.DID() })
	fallback := start(NewHandler(trusted, wk, Options{MTLS: true, PeerOf: func(*http.Request) (string, bool) {
		return "spiffe://example.org/trusted", true
	}}), tls.RequireAndVerifyClientCert)
	k3, _ := writ.NewCall(A, []*writ.Writ{w}, "x/charge", map[string]any{})
	if code, _ := send(fallback, &noURI, k3); code != "peer_mismatch" || runs != 1 {
		t.Fatalf("a certificate with no identity, with PeerOf naming a bound peer: %s, %d runs", code, runs)
	}

	// MTLS on a server that is not serving TLS at all fails closed too.
	plain := httptest.NewServer(NewHandler(e, wk, Options{MTLS: true}))
	defer plain.Close()
	k4, _ := writ.NewCall(A, []*writ.Writ{w}, "x/charge", map[string]any{})
	body, _ := json.Marshal(k4.Raw)
	resp, err := http.Post(plain.URL+"/writ", ContentType, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Tally map[string]any `json:"tally"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if e, _ := out.Tally["err"].(map[string]any); e == nil || e["code"] != "peer_mismatch" || runs != 1 {
		t.Fatalf("MTLS without TLS: %v, %d runs", out.Tally, runs)
	}
}
