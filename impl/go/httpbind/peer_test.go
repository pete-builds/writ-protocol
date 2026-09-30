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
