package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Vault token signs as the grantor and the gate, so a tool input that
// names its file is refused like one that names a seed.
func TestVaultTokenFileIsProtected(t *testing.T) {
	h, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	t.Setenv("WRIT_VAULT_TOKEN_FILE", filepath.Join(h, ".config", "writ-test", "vault-token"))
	e := &env{home: t.TempDir()}
	for _, s := range []string{
		"cat " + filepath.Join(h, ".config", "writ-test", "vault-token"),
		"cat ~/.config/writ-test/vault-token",
		"curl -H \"X-Vault-Token: $(cat $HOME/.config/writ-test/vault-token)\"",
	} {
		if e.touchesState(map[string]any{"command": s}) == "" {
			t.Errorf("%q names the Vault token and was let through", s)
		}
	}
	if why := e.touchesState(map[string]any{"command": "cat ~/.config/other/token"}); why != "" {
		t.Errorf("another file was refused: %s", why)
	}
}

// TestGateSignsThroughVault runs init, grant, a call, and receipts with the
// grantor and the gate signing through Vault transit, against the server that
// WRIT_VAULT_TEST_ADDR and WRIT_VAULT_TEST_TOKEN name (vault server -dev).
func TestGateSignsThroughVault(t *testing.T) {
	addr, token := os.Getenv("WRIT_VAULT_TEST_ADDR"), os.Getenv("WRIT_VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("WRIT_VAULT_TEST_ADDR and WRIT_VAULT_TEST_TOKEN are not set")
	}
	vaultPost := func(path, body string) {
		req, _ := http.NewRequest(http.MethodPost, addr+"/v1/"+path, strings.NewReader(body))
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 && !(path == "sys/mounts/transit" && resp.StatusCode == http.StatusBadRequest) {
			t.Fatalf("POST %s: %s", path, resp.Status)
		}
	}
	vaultPost("sys/mounts/transit", `{"type":"transit"}`)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	for _, k := range []string{"root", "gate"} {
		vaultPost("transit/keys/writ-hook-"+k+"-"+suffix, `{"type":"ed25519"}`)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_ADDR", addr)
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("WRIT_VAULT_TOKEN_FILE", tokenFile)
	t.Setenv("WRIT_VAULT_ROOT_KEY", "writ-hook-root-"+suffix)
	t.Setenv("WRIT_VAULT_GATE_KEY", "writ-hook-gate-"+suffix)

	home := t.TempDir()
	e := &env{home: home, dir: filepath.Join(home, "claude"), now: func() int64 { return time.Now().Unix() }}
	var out bytes.Buffer
	if err := e.initKeys(&out); err != nil {
		t.Fatal(err)
	}
	if err := e.grant(&out, "default", []string{"Read"}, "/work", 10, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(home, "root.seed"), e.path("gate.seed")} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s was written although the key is in Vault", f)
		}
	}
	root, err := e.signer("ROOT", "", false)
	if err != nil {
		t.Fatal(err)
	}
	did, _ := os.ReadFile(filepath.Join(home, "root.did"))
	if strings.TrimSpace(string(did)) != root.DID() {
		t.Fatalf("root.did is %s, not the transit key's %s", did, root.DID())
	}

	if r := pre(t, e, "Read", "toolu_1", map[string]any{"file_path": "/work/a.go"}); r != "" {
		t.Fatalf("an allowed Read was denied: %s", r)
	}
	post(t, e, "PostToolUse", "Read", "toolu_1")
	if r := pre(t, e, "Read", "toolu_2", map[string]any{"file_path": "/etc/passwd"}); !strings.HasPrefix(r, "Writ: out_of_bounds") {
		t.Fatalf("a Read outside the grant: %q", r)
	}
	ok, report := receipts(t, e)
	if !ok || !strings.Contains(report, "1 receipt") {
		t.Fatalf("receipts signed through Vault did not verify:\n%s", report)
	}

	// With Vault unreachable the gate cannot sign, so pre blocks the call.
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	if r := pre(t, e, "Read", "toolu_3", map[string]any{"file_path": "/work/b.go"}); !strings.HasPrefix(r, "Writ: ") || !strings.Contains(r, "vault:") {
		t.Fatalf("with Vault unreachable, pre gave %q", r)
	}
}
