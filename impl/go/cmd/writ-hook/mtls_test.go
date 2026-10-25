package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"writproto/exec"
)

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	dir  string
}

func newPKI(t *testing.T, name string) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &pki{cert: cert, key: key, dir: t.TempDir()}
	ca.write(t, "ca.pem", "CERTIFICATE", der)
	return ca
}

func (ca *pki) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(ca.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// issue signs a certificate for name with uris as URI subject alternative
// names, writes it and its key as PEM files, and returns their paths.
func (ca *pki) issue(t *testing.T, name string, server bool, uris ...string) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
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
	kb, _ := x509.MarshalECPrivateKey(key)
	return ca.write(t, name+".pem", "CERTIFICATE", der), ca.write(t, name+"-key.pem", "EC PRIVATE KEY", kb)
}

// mtlsGate is a gate serving mTLS on loopback, its CAs, and the machines'
// certificates: a and b are bound to the session's agent key in the bindings
// file, c names a peer the file does not list, and bare names none.
type mtlsGate struct {
	e        *env
	url      string
	serverCA *pki
	clients  *pki
	audit    string
}

func startMTLSGate(t *testing.T) *mtlsGate {
	t.Helper()
	e := setup(t, []string{"Read"}, "/work", 10)
	agent, err := loadKey(e.path("agent.seed"))
	if err != nil {
		t.Fatal(err)
	}
	bf := filepath.Join(t.TempDir(), "bindings.json")
	b, _ := json.Marshal(map[string][]string{"urn:writ:device:a": {agent.DID()}, "urn:writ:device:b": {agent.DID()}})
	if err := os.WriteFile(bf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	bind, err := exec.LoadBindings(bf)
	if err != nil {
		t.Fatal(err)
	}
	e.binds = bind.Binds

	g := &mtlsGate{e: e, serverCA: newPKI(t, "gate ca"), clients: newPKI(t, "device ca"), audit: e.path("audit.jsonl")}
	cert, key := g.serverCA.issue(t, "gate", true)
	cfg, err := gateTLS(cert, key, filepath.Join(g.clients.dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = e.serveTLS(ln) }()
	g.url = "https://" + ln.Addr().String()
	return g
}

// client is the hook side for a machine holding certFile and keyFile, as
// writ-hook builds it from WRIT_HOOK_GATE and the WRIT_HOOK_* variables.
func (g *mtlsGate) client(t *testing.T, certFile, keyFile string) asker {
	t.Setenv("WRIT_HOOK_CERT", certFile)
	t.Setenv("WRIT_HOOK_KEY", keyFile)
	t.Setenv("WRIT_HOOK_CA", filepath.Join(g.serverCA.dir, "ca.pem"))
	return tlsClient(g.url)
}

// device is a machine whose certificate names peer as its URIs; none for "".
func (g *mtlsGate) device(t *testing.T, name string, uris ...string) asker {
	cert, key := g.clients.issue(t, name, false, uris...)
	return g.client(t, cert, key)
}

func (g *mtlsGate) auditLines(t *testing.T) int {
	b, _ := os.ReadFile(g.audit)
	return bytes.Count(b, []byte("\n"))
}

// via runs one hook command through send and returns what it wrote. For pre
// that is the deny reason, or "" when the call was admitted.
func via(t *testing.T, send asker, where, cmd, in string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	_, err := remote(where, send, cmd, strings.NewReader(in), &out)
	if cmd != "pre" || out.Len() == 0 {
		return out.String(), err
	}
	var d struct {
		H struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if jerr := json.Unmarshal(out.Bytes(), &d); jerr != nil || d.H.Decision != "deny" {
		t.Fatalf("pre wrote %s, want nothing or a deny", out.String())
	}
	return d.H.Reason, err
}

func readIn(id, file string) string {
	return input("PreToolUse", "Read", id, map[string]any{"file_path": file})
}

func TestMTLSCallIsReceipted(t *testing.T) {
	g := startMTLSGate(t)
	a := g.device(t, "a", "urn:writ:device:a")
	if r, err := via(t, a, g.url, "pre", readIn("toolu_1", "/work/a.go")); r != "" || err != nil {
		t.Fatalf("an allowed Read over mTLS was not admitted: %q %v", r, err)
	}
	if out, err := via(t, a, g.url, "post", input("PostToolUse", "Read", "toolu_1", nil)); out != "" || err != nil {
		t.Fatalf("post over mTLS: %q %v", out, err)
	}
	if r, _ := via(t, a, g.url, "pre", readIn("toolu_2", "/etc/passwd")); !strings.HasPrefix(r, "Writ: out_of_bounds") {
		t.Fatalf("a Read outside the grant over mTLS: %q", r)
	}
	report, err := via(t, a, g.url, "receipts", "")
	if err != nil || !strings.Contains(report, "1 receipt(s) verified, 0 invalid") {
		t.Fatalf("receipts over mTLS: %v\n%s", err, report)
	}
	// The audit record names the machine each call came from (spec 9.3),
	// the receipted call as well as the refused one.
	b, _ := os.ReadFile(g.audit)
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var a struct {
			Peer    *string `json:"peer"`
			Outcome string  `json:"outcome"`
		}
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.Peer == nil || *a.Peer != "urn:writ:device:a" {
			t.Fatalf("an audit entry does not name the peer: %s", line)
		}
	}
}

// A client with no certificate, or one from a CA the gate does not trust, is
// refused by TLS itself: the call is blocked and nothing reaches the gate.
func TestMTLSRefusesNoClientCert(t *testing.T) {
	g := startMTLSGate(t)
	pool := x509.NewCertPool()
	pool.AddCert(g.serverCA.cert)
	none := askTLS(g.url, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool})
	before := g.auditLines(t)
	if r, _ := via(t, none, g.url, "pre", readIn("toolu_1", "/work/a.go")); !strings.Contains(r, "could not check this call") {
		t.Fatalf("a client with no certificate: %q", r)
	}
	if g.auditLines(t) != before {
		t.Fatal("a call with no client certificate reached the gate")
	}
}

func TestMTLSRefusesUntrustedCert(t *testing.T) {
	g := startMTLSGate(t)
	rogue := newPKI(t, "rogue ca")
	certFile, keyFile := rogue.issue(t, "rogue", false, "urn:writ:device:a")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(g.serverCA.cert)
	// A Go client sends only a certificate from a CA the server names, so
	// present this one regardless, as a hostile client would.
	send := askTLS(g.url, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }})
	before := g.auditLines(t)
	if r, _ := via(t, send, g.url, "pre", readIn("toolu_1", "/work/a.go")); !strings.Contains(r, "could not check this call") {
		t.Fatalf("a certificate from another CA naming a bound peer: %q", r)
	}
	if g.auditLines(t) != before {
		t.Fatal("a call with an untrusted certificate reached the gate")
	}
}

// A certificate the gate's CA signed still has to name one machine that the
// bindings file says speaks for the agent key (spec 7.6).
func TestMTLSPeerMustSpeakForTheKey(t *testing.T) {
	g := startMTLSGate(t)
	for name, send := range map[string]asker{
		"an unbound peer":  g.device(t, "c", "urn:writ:device:c"),
		"no peer URI":      g.device(t, "bare"),
		"only a key's URI": g.device(t, "keyonly", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
		"two peers":        g.device(t, "two", "urn:writ:device:a", "urn:writ:device:b"),
	} {
		if r, _ := via(t, send, g.url, "pre", readIn("toolu_"+fmt.Sprint(len(name)), "/work/a.go")); !strings.HasPrefix(r, "Writ: peer_mismatch") {
			t.Errorf("%s: %q, want peer_mismatch", name, r)
		}
	}
}

// pre fails closed: a gate that cannot be reached, or a machine whose
// certificate cannot be loaded, blocks the call.
func TestUnreachableMTLSGateBlocksPre(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ca := newPKI(t, "ca")
	cert, key := ca.issue(t, "a", false, "urn:writ:device:a")
	t.Setenv("WRIT_HOOK_CERT", cert)
	t.Setenv("WRIT_HOOK_KEY", key)
	t.Setenv("WRIT_HOOK_CA", filepath.Join(ca.dir, "ca.pem"))
	for name, send := range map[string]asker{
		"nothing listening": tlsClient("https://" + addr),
		"no certificate":    func() asker { t.Setenv("WRIT_HOOK_CERT", "/nonexistent.pem"); return tlsClient("https://" + addr) }(),
	} {
		r, _ := via(t, send, "https://"+addr, "pre", readIn("toolu_1", "/work/a.go"))
		if !strings.Contains(r, "could not check this call, so it is blocked") {
			t.Errorf("%s: pre gave %q, want a block", name, r)
		}
	}
}

// One machine cannot report the outcome of another's call, or recover it,
// and recover over mTLS must name its session.
func TestMTLSMachinesFinishOnlyTheirOwnCalls(t *testing.T) {
	g := startMTLSGate(t)
	a, b := g.device(t, "a", "urn:writ:device:a"), g.device(t, "b", "urn:writ:device:b")
	in := `{"hook_event_name":"PreToolUse","session_id":"sess-a","tool_name":"Read","tool_use_id":"toolu_a1","tool_input":{"file_path":"/work/a.go"}}`
	if r, err := via(t, a, g.url, "pre", in); r != "" || err != nil {
		t.Fatalf("a's Read: %q %v", r, err)
	}
	if _, err := via(t, b, g.url, "post", input("PostToolUseFailure", "Read", "toolu_a1", nil)); err == nil || !strings.Contains(err.Error(), "another machine") {
		t.Fatalf("b reported the outcome of a's call: %v", err)
	}
	if _, err := via(t, b, g.url, "recover", `{"hook_event_name":"SessionStart","session_id":"sess-a"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(g.e.pendingPath("toolu_a1")); err != nil {
		t.Fatal("b's recover, naming a's session, resolved a's call")
	}
	if _, err := via(t, b, g.url, "recover", ""); err == nil {
		t.Fatal("recover over mTLS with no session was answered")
	}
	if out, err := via(t, a, g.url, "post", input("PostToolUse", "Read", "toolu_a1", nil)); out != "" || err != nil {
		t.Fatalf("a's own post: %q %v", out, err)
	}
	report, err := via(t, a, g.url, "receipts", "")
	if err != nil || !strings.Contains(report, "1 receipt(s) verified, 0 invalid") || !strings.Contains(report, "Read                     1") {
		t.Fatalf("receipts: %v\n%s", err, report)
	}
}
