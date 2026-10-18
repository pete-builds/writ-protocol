// Package vault signs with an Ed25519 key held in HashiCorp Vault's transit
// secrets engine. The private key stays inside Vault: a Signer sends Vault the
// bytes to sign and gets back a signature, which it checks against the key's
// public half before handing it on, so a signature that would not verify never
// reaches the wire. It uses only the Go standard library.
//
// Writ signs only with Ed25519 (spec 1.4), so a transit key of any other type
// is refused, and so is a derived key, whose public half depends on a context
// Writ does not carry. A Signer is pinned to one version of its key: the
// did:key names that version's public key, and rotating the key in Vault does
// not change what an existing Signer signs with.
package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"writproto/keys"
)

// Config names a transit key and how to reach Vault.
type Config struct {
	Addr      string // Vault's address, such as https://vault.example.org:8200
	Token     string // a token whose policy allows read on keys/<Key> and update on sign/<Key>
	Namespace string // Vault Enterprise namespace; empty for none
	Mount     string // the transit mount; empty for "transit"
	Key       string // the transit key's name
	Version   int    // the key version to sign with; 0 for the latest when New runs
	Client    *http.Client
}

// Signer signs through one version of one transit key. It is a keys.Signer.
type Signer struct {
	cfg     Config
	version int
	pub     ed25519.PublicKey
	did     string
}

var _ keys.Signer = (*Signer)(nil)

// New reads the key's public half from Vault and returns a Signer for it.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.Addr == "" || cfg.Token == "" || cfg.Key == "" {
		return nil, errors.New("vault: Addr, Token, and Key are required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	var key struct {
		Type          string `json:"type"`
		Derived       bool   `json:"derived"`
		LatestVersion int    `json:"latest_version"`
		Keys          map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := call(ctx, cfg, http.MethodGet, "keys/"+url.PathEscape(cfg.Key), nil, &key); err != nil {
		return nil, err
	}
	if key.Type != "ed25519" {
		return nil, fmt.Errorf("vault: transit key %q is %q; Writ signs only with ed25519", cfg.Key, key.Type)
	}
	if key.Derived {
		return nil, fmt.Errorf("vault: transit key %q is derived; Writ needs one fixed public key", cfg.Key)
	}
	v := cfg.Version
	if v == 0 {
		v = key.LatestVersion
	}
	k, ok := key.Keys[strconv.Itoa(v)]
	if !ok {
		return nil, fmt.Errorf("vault: transit key %q has no version %d", cfg.Key, v)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("vault: transit key %q version %d has no usable Ed25519 public key", cfg.Key, v)
	}
	return &Signer{cfg: cfg, version: v, pub: pub, did: keys.DIDFromPublicKey(pub)}, nil
}

// DID is the did:key of the pinned key version.
func (s *Signer) DID() string { return s.did }

// PublicKey is the pinned key version's public half.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Version is the key version the Signer signs with.
func (s *Signer) Version() int { return s.version }

// SignMessage asks Vault to sign msg with the pinned key version and returns
// the signature only if it verifies under DID.
func (s *Signer) SignMessage(msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := map[string]any{"input": base64.StdEncoding.EncodeToString(msg), "key_version": s.version}
	var out struct {
		Signature string `json:"signature"`
	}
	if err := call(ctx, s.cfg, http.MethodPost, "sign/"+url.PathEscape(s.cfg.Key), req, &out); err != nil {
		return nil, err
	}
	prefix := "vault:v" + strconv.Itoa(s.version) + ":"
	b64, ok := strings.CutPrefix(out.Signature, prefix)
	if !ok {
		return nil, fmt.Errorf("vault: signature is not from key version %d", s.version)
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("vault: signature is not a 64-byte Ed25519 signature")
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return nil, fmt.Errorf("vault: the signature Vault returned does not verify under %s", s.did)
	}
	return sig, nil
}

// call makes one request to the transit mount and decodes the response's data
// member into out.
func call(ctx context.Context, cfg Config, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := strings.TrimSuffix(cfg.Addr, "/") + "/v1/" + strings.Trim(cfg.Mount, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", cfg.Token)
	if cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("vault: %v", err)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("vault: %s %s: %s %s", method, path, resp.Status, strings.Join(e.Errors, "; "))
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil || len(env.Data) == 0 {
		return fmt.Errorf("vault: %s %s: no data in the response", method, path)
	}
	return json.Unmarshal(env.Data, out)
}
