package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startGate runs the gate on a Unix socket under /tmp, whose short path
// stays inside the 104-byte socket name limit on macOS.
func startGate(t *testing.T, e *env) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "gate.sock")
	ready := make(chan struct{})
	go func() { _ = e.serve(socket, 0o600, func() { close(ready) }) }()
	<-ready
	return socket
}

func remotePre(t *testing.T, socket, tool, id string, in map[string]any) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := remote(socket, viaSocket(socket), "pre", strings.NewReader(input("PreToolUse", tool, id, in)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return ""
	}
	var d struct {
		H struct {
			Reason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	_ = json.Unmarshal(out.Bytes(), &d)
	return d.H.Reason
}

// The hook commands reach a gate running as its own process: the same
// checks, receipts, and reports as running in place.
func TestGateOverSocket(t *testing.T) {
	proj := "/work/project"
	e := setup(t, []string{"Read"}, proj, 0)
	socket := startGate(t, e)

	if r := remotePre(t, socket, "Read", "toolu_1", map[string]any{"file_path": proj + "/a.go"}); r != "" {
		t.Fatalf("an allowed Read through the gate was denied: %s", r)
	}
	var out bytes.Buffer
	if _, err := remote(socket, viaSocket(socket), "post", strings.NewReader(input("PostToolUse", "Read", "toolu_1", nil)), &out); err != nil || out.Len() != 0 {
		t.Fatalf("post through the gate: %v %q", err, out.String())
	}
	if r := remotePre(t, socket, "Read", "toolu_2", map[string]any{"file_path": "/etc/passwd"}); !strings.HasPrefix(r, "Writ: out_of_bounds") {
		t.Fatalf("a Read outside the folder through the gate: %q", r)
	}
	out.Reset()
	ok, err := remote(socket, viaSocket(socket), "receipts", nil, &out)
	if err != nil || !ok || !strings.Contains(out.String(), "1 receipt(s) verified, 0 invalid") {
		t.Fatalf("receipts through the gate: %v %v\n%s", ok, err, out.String())
	}
	// Grants are not served: a client with the socket cannot grant itself.
	resp, err := ask(socket, request{Cmd: "grant"})
	if err != nil || !strings.Contains(resp.Error, "grants are made locally") {
		t.Fatalf("a grant over the socket: %+v %v", resp, err)
	}
}

// An unreachable gate blocks the tool call before it runs, and makes post
// report an error rather than pretend a receipt was signed.
func TestUnreachableGateFailsClosed(t *testing.T) {
	socket := filepath.Join(os.TempDir(), "no-such-writ-gate.sock")
	if r := remotePre(t, socket, "Read", "toolu_1", map[string]any{"file_path": "/a"}); !strings.Contains(r, "could not check this call, so it is blocked") {
		t.Fatalf("pre with no gate: %q", r)
	}
	var out bytes.Buffer
	if _, err := remote(socket, viaSocket(socket), "post", strings.NewReader(input("PostToolUse", "Read", "toolu_1", nil)), &out); err == nil {
		t.Fatal("post with no gate reported success")
	}
}
