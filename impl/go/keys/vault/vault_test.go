package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// roundTrip has root grant a fresh agent, the agent call exe, and exe sign the
// receipt, then checks the grant and the receipt with the existing verifier,
// and checks that one flipped byte in either signature fails it.
func roundTrip(t *testing.T, root, exe keys.Signer) {
	t.Helper()
	agent, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	bnd := map[string]any{"act": map[string]any{"t": "prefix", "v": "claude"}}
	w, err := writ.Issue(root, agent.DID(), bnd, now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writ.VerifyChain([]*writ.Writ{w}); err != nil {
		t.Fatalf("a grant signed through Vault does not verify: %v", err)
	}
	// The agent passes the grant to the executor unchanged and calls it, as
	// writ-hook's agent does with its gate.
	pass, err := writ.Issue(agent, exe.DID(), bnd, now+3600, w)
	if err != nil {
		t.Fatal(err)
	}
	k, err := writ.NewCall(agent, []*writ.Writ{w, pass}, "claude/Read", map[string]any{"file_path": "/a"})
	if err != nil {
		t.Fatal(err)
	}
	tl, res, err := writ.NewTally(exe, writ.TallyInput{Call: k, Acc: now, St: "ok", Res: map[string]any{"ok": true}})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := writ.VerifyTally(pass, k, tl.Raw, res); v != writ.Valid {
		t.Fatalf("a receipt signed through Vault does not verify: %v %v", v, err)
	}

	// The same objects with one signature byte flipped, decoded from bytes
	// as a verifier would receive them.
	if _, err := writ.ParseWrit(tamper(t, w.Raw)); err == nil {
		t.Fatal("a grant with a tampered signature verified")
	}
	if v, _, _ := writ.VerifyTally(pass, k, tamper(t, tl.Raw), res); v == writ.Valid {
		t.Fatal("a receipt with a tampered signature verified")
	}
}

// tamper returns a copy of obj whose signature has its first byte flipped.
func tamper(t *testing.T, obj wire.Object) wire.Object {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := wire.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.B64.DecodeString(cp["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	cp["sig"] = wire.B64.EncodeToString(sig)
	return cp
}

// fakeTransit is a transit mount with the behavior a test asks for.
type fakeTransit struct {
	priv    ed25519.PrivateKey
	keyType string
	derived bool
	mode    string // "", "wrong-message", "wrong-version", "forbidden"
	signed  int
}

func newFake(t *testing.T, f *fakeTransit) Config {
	t.Helper()
	_, f.priv, _ = ed25519.GenerateKey(rand.Reader)
	if f.keyType == "" {
		f.keyType = "ed25519"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" || f.mode == "forbidden" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		var data any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/k":
			pub := f.priv.Public().(ed25519.PublicKey)
			data = map[string]any{"type": f.keyType, "derived": f.derived, "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}}}
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/k":
			var in struct {
				Input      string `json:"input"`
				KeyVersion int    `json:"key_version"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.KeyVersion != 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			msg, _ := base64.StdEncoding.DecodeString(in.Input)
			if f.mode == "wrong-message" {
				msg = append(msg, 'x')
			}
			prefix, priv := "vault:v1:", f.priv
			if f.mode == "wrong-version" {
				// A rotated key: version 2, a different key pair.
				_, priv, _ = ed25519.GenerateKey(rand.Reader)
				prefix = "vault:v2:"
			}
			f.signed++
			data = map[string]any{"signature": prefix + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), "key_version": 1}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	return Config{Addr: srv.URL, Token: "tok", Key: "k"}
}

func TestSignaturesThroughTransitVerify(t *testing.T) {
	root, err := New(context.Background(), newFake(t, &fakeTransit{}))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTransit{}
	exe, err := New(context.Background(), newFake(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if exe.DID() != keys.DIDFromPublicKey(f.priv.Public().(ed25519.PublicKey)) {
		t.Fatal("the signer's did:key is not the transit key's")
	}
	roundTrip(t, root, exe)
	if f.signed == 0 {
		t.Fatal("the receipt was not signed through transit")
	}
}

// A signature that does not verify under the pinned key never leaves the
// signer. The check is the signer's own: Issue parses what it signed, but
// NewTally and NewAck do not, so a receipt would carry a bad signature.
func TestBadSignaturesFromTransitAreRefused(t *testing.T) {
	for _, mode := range []string{"wrong-message", "wrong-version"} {
		s, err := New(context.Background(), newFake(t, &fakeTransit{mode: mode}))
		if err != nil {
			t.Fatal(err)
		}
		if sig, err := s.SignMessage([]byte("receipt")); err == nil {
			t.Fatalf("%s: the signer returned a signature that does not verify: %x", mode, sig)
		}
	}
}

func TestKeysWritCannotUseAreRefused(t *testing.T) {
	for name, f := range map[string]*fakeTransit{
		"ecdsa":   {keyType: "ecdsa-p256"},
		"derived": {derived: true},
	} {
		if _, err := New(context.Background(), newFake(t, f)); err == nil {
			t.Fatalf("%s: a key Writ cannot use was accepted", name)
		}
	}
	cfg := newFake(t, &fakeTransit{})
	cfg.Version = 2
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("a key version transit does not have was accepted")
	}
}

func TestVaultErrorsReachTheCaller(t *testing.T) {
	f := &fakeTransit{}
	s, err := New(context.Background(), newFake(t, f))
	if err != nil {
		t.Fatal(err)
	}
	f.mode = "forbidden"
	_, err = writ.Issue(s, s.DID(), map[string]any{}, time.Now().Unix()+60, nil)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("a refused sign did not fail Issue with Vault's reason: %v", err)
	}
	if _, err := New(context.Background(), Config{Addr: "http://127.0.0.1:1", Token: "tok", Key: "k"}); err == nil {
		t.Fatal("an unreachable Vault gave a signer")
	}
}

// TestRealVault runs against a real Vault server with the transit engine, such
// as `vault server -dev`: WRIT_VAULT_TEST_ADDR and WRIT_VAULT_TEST_TOKEN name it.
// It creates two fresh non-exportable Ed25519 transit keys, signs a grant and a
// receipt with them, and checks both with the existing verifier.
func TestRealVault(t *testing.T) {
	addr, token := os.Getenv("WRIT_VAULT_TEST_ADDR"), os.Getenv("WRIT_VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("WRIT_VAULT_TEST_ADDR and WRIT_VAULT_TEST_TOKEN are not set")
	}
	ctx := context.Background()
	admin := Config{Addr: addr, Token: token, Mount: "sys", Client: http.DefaultClient}
	if err := call(ctx, admin, http.MethodPost, "mounts/transit", map[string]any{"type": "transit"}, &struct{}{}); err != nil &&
		!strings.Contains(err.Error(), "already in use") {
		t.Fatal(err)
	}
	mk := func(role string) *Signer {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		name := "writ-test-" + role + "-" + hex.EncodeToString(b)
		cfg := Config{Addr: addr, Token: token, Key: name, Client: http.DefaultClient}
		err := call(ctx, Config{Addr: addr, Token: token, Mount: "transit", Client: http.DefaultClient},
			http.MethodPost, "keys/"+name, map[string]any{"type": "ed25519"}, &struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		// The private key cannot be read back out of Vault.
		var exp map[string]any
		if err := call(ctx, cfg, http.MethodGet, "export/signing-key/"+name, nil, &exp); err == nil {
			t.Fatalf("transit exported the private half of %s", name)
		}
		return s
	}
	root, gate := mk("root"), mk("gate")
	if bytes.Equal(root.PublicKey(), gate.PublicKey()) {
		t.Fatal("two transit keys share a public key")
	}
	roundTrip(t, root, gate)
}
