package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests cover what running the gate under every session of a working
// day needs: several sessions at once, a grant that rolls over, and stores
// that stay small.

func inputAs(session, event, tool, id string, in map[string]any) string {
	b, _ := json.Marshal(map[string]any{"session_id": session, "hook_event_name": event, "tool_name": tool,
		"tool_use_id": id, "tool_input": in, "tool_response": map[string]any{"ok": true}})
	return string(b)
}

func preAs(t *testing.T, e *env, session, tool, id string, in map[string]any) {
	t.Helper()
	var out bytes.Buffer
	if err := e.hook(strings.NewReader(inputAs(session, "PreToolUse", tool, id, in)), &out, e.pre); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("%s %s denied: %s", session, id, out.String())
	}
}

func postAs(t *testing.T, e *env, session, tool, id string) {
	t.Helper()
	var out bytes.Buffer
	if err := e.hook(strings.NewReader(inputAs(session, "PostToolUse", tool, id, nil)), &out, e.post); err != nil {
		t.Fatal(err)
	}
}

func startSession(t *testing.T, e *env, session string) string {
	t.Helper()
	h, err := parseSessionStart([]byte(`{"session_id":"` + session + `","hook_event_name":"SessionStart","source":"startup"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := e.recover(&out, h); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A session starting up must not resolve a call another session is still
// running. Before sessions were recorded, recover resolved every unfinished
// call and deleted its pending file, so the running call's real outcome was
// lost and its receipt read unknown_outcome.
func TestSessionStartLeavesOtherSessionsCallsRunning(t *testing.T) {
	e := setup(t, nil, "", 0)
	preAs(t, e, "sess-a", "Bash", "toolu_long", map[string]any{"command": "make test"})

	if got := startSession(t, e, "sess-b"); !strings.Contains(got, "resolved 0") {
		t.Fatalf("session b starting: %q, want nothing resolved", got)
	}
	postAs(t, e, "sess-a", "Bash", "toolu_long")
	ok, report := receipts(t, e)
	if !ok || !strings.Contains(report, "1 receipt(s) verified, 0 invalid, 0 call(s) still unfinished") ||
		!strings.Contains(report, "ok                       1") {
		t.Fatalf("session a's call should finish ok after session b started:\n%s", report)
	}

	// Session a's own unfinished call is resolved when session a starts again.
	preAs(t, e, "sess-a", "Read", "toolu_cut", map[string]any{"file_path": "/a"})
	if got := startSession(t, e, "sess-b"); !strings.Contains(got, "resolved 0") {
		t.Fatalf("session b starting again: %q", got)
	}
	if got := startSession(t, e, "sess-a"); !strings.Contains(got, "resolved 1") {
		t.Fatalf("session a resuming: %q, want its own call resolved", got)
	}
	if _, report := receipts(t, e); !strings.Contains(report, "2 receipt(s) verified, 0 invalid, 0 call(s) still unfinished") ||
		!strings.Contains(report, "failed                   1") || !strings.Contains(report, "2 entries, every link intact") ||
		!strings.Contains(report, "0 refusal(s)") {
		t.Fatalf("after session a resumed:\n%s", report)
	}
}

// A call no session ever comes back for is resolved by whichever session
// starts once no grant could still cover it.
func TestSessionStartResolvesStaleCalls(t *testing.T) {
	e := setup(t, nil, "", 0)
	preAs(t, e, "sess-gone", "Read", "toolu_1", map[string]any{"file_path": "/a"})
	e.now = func() int64 { return t0 + int64(staleAfter/time.Second) }
	if got := startSession(t, e, "sess-new"); !strings.Contains(got, "resolved 0") {
		t.Fatalf("at exactly staleAfter: %q", got)
	}
	e.now = func() int64 { return t0 + int64(staleAfter/time.Second) + 1 }
	if got := startSession(t, e, "sess-new"); !strings.Contains(got, "resolved 1") {
		t.Fatalf("past staleAfter: %q", got)
	}
	if files, _ := filepath.Glob(filepath.Join(e.dir, "pending", "*.json")); len(files) != 0 {
		t.Fatalf("pending files left: %v", files)
	}
}

// A SessionStart input that names no session cannot be scoped, so recover
// refuses it rather than resolve every session's calls.
func TestSessionStartWithoutSessionIsRefused(t *testing.T) {
	if _, err := parseSessionStart([]byte(`{"hook_event_name":"SessionStart"}`)); err == nil {
		t.Fatal("a SessionStart input with no session_id was accepted")
	}
	if h, err := parseSessionStart([]byte("  \n")); h != nil || err != nil {
		t.Fatalf("empty input: %v %v, want a recover run by hand", h, err)
	}
}

// Over the socket, recover carries the SessionStart input to the gate.
func TestSessionStartOverSocket(t *testing.T) {
	e := setup(t, nil, "", 0)
	socket := startGate(t, e)
	preAs(t, e, "sess-a", "Read", "toolu_1", map[string]any{"file_path": "/a"})
	var out bytes.Buffer
	if _, err := remote(socket, "recover", strings.NewReader(`{"session_id":"sess-b","hook_event_name":"SessionStart"}`), &out); err != nil ||
		!strings.Contains(out.String(), "resolved 0") {
		t.Fatalf("session b over the socket: %v %q", err, out.String())
	}
	out.Reset()
	if _, err := remote(socket, "recover", strings.NewReader(`{"session_id":"sess-a","hook_event_name":"SessionStart"}`), &out); err != nil ||
		!strings.Contains(out.String(), "resolved 1") {
		t.Fatalf("session a over the socket: %v %q", err, out.String())
	}
}

// Each grant keeps its own store, so a renewed grant starts a fresh file and
// the store a hook rewrites holds one grant's calls, not every call ever.
// Receipts still covers every store.
func TestEachGrantKeepsItsOwnStore(t *testing.T) {
	e := setup(t, nil, "", 0)
	for _, id := range []string{"toolu_1", "toolu_2", "toolu_3"} {
		preAs(t, e, "s", "Glob", id, map[string]any{"pattern": "*"})
		postAs(t, e, "s", "Glob", id)
	}
	stores, _ := filepath.Glob(filepath.Join(e.dir, "stores", "*.json"))
	if len(stores) != 1 {
		t.Fatalf("%d stores after one grant, want 1", len(stores))
	}
	firstStore := stores[0]

	e.now = func() int64 { return t0 + 60 }
	var out bytes.Buffer
	if err := e.grant(&out, "default", nil, "", 0, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	preAs(t, e, "s", "Glob", "toolu_4", map[string]any{"pattern": "*"})
	postAs(t, e, "s", "Glob", "toolu_4")

	stores, _ = filepath.Glob(filepath.Join(e.dir, "stores", "*.json"))
	if len(stores) != 2 {
		t.Fatalf("%d stores after a second grant, want 2", len(stores))
	}
	for _, s := range stores {
		want := 1
		if s == firstStore {
			want = 3
		}
		b, _ := os.ReadFile(s)
		var st struct {
			Calls map[string]any `json:"calls"`
		}
		if err := json.Unmarshal(b, &st); err != nil || len(st.Calls) != want {
			t.Errorf("%s holds %d calls (%v), want %d", filepath.Base(s), len(st.Calls), err, want)
		}
	}
	if ok, report := receipts(t, e); !ok || !strings.Contains(report, "4 receipt(s) verified, 0 invalid") {
		t.Fatalf("receipts across two stores:\n%s", report)
	}
}

// A call admitted under one grant is receipted in that grant's store even
// when the grant is renewed while the tool runs.
func TestRenewalMidCallKeepsTheReceipt(t *testing.T) {
	e := setup(t, nil, "", 0)
	preAs(t, e, "s", "Bash", "toolu_1", map[string]any{"command": "sleep 5"})
	e.now = func() int64 { return t0 + 5 }
	var out bytes.Buffer
	if err := e.grant(&out, "default", nil, "", 0, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	postAs(t, e, "s", "Bash", "toolu_1")
	if ok, report := receipts(t, e); !ok || !strings.Contains(report, "1 receipt(s) verified, 0 invalid, 0 call(s) still unfinished") {
		t.Fatalf("receipts:\n%s", report)
	}
}

// With -renew-before, granting again keeps a grant that has the same bounds
// and enough time left, and signs a new one when either is not so.
func TestRenewBeforeKeepsOrRenews(t *testing.T) {
	home := t.TempDir()
	e := &env{home: home, dir: filepath.Join(home, "claude"), now: func() int64 { return t0 }}
	var out bytes.Buffer
	if err := e.initKeys(&out); err != nil {
		t.Fatal(err)
	}
	g := func(uses int64) string {
		t.Helper()
		out.Reset()
		if err := e.grant(&out, "session", nil, "", uses, 24*time.Hour, 22*time.Hour); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	idOf := func(s string) string { return strings.Fields(s)[2] }

	first := g(100)
	if !strings.HasPrefix(first, "granted") {
		t.Fatalf("first grant: %q", first)
	}
	if again := g(100); !strings.HasPrefix(again, "kept") || idOf(again) != idOf(first) {
		t.Fatalf("same bounds, 24h left: %q, want the first grant kept", again)
	}
	if changed := g(200); !strings.HasPrefix(changed, "granted") || idOf(changed) == idOf(first) {
		t.Fatalf("other bounds: %q, want a new grant", changed)
	}
	kept := g(200)
	e.now = func() int64 { return t0 + int64(2*time.Hour/time.Second) }
	if at2h := g(200); !strings.HasPrefix(at2h, "granted") || idOf(at2h) == idOf(kept) {
		t.Fatalf("22h left of 24h with renew-before 22h: %q, want a new grant", at2h)
	}
	if err := e.grant(&out, "session", nil, "", 0, time.Hour, time.Hour); err == nil {
		t.Fatal("renew-before equal to ttl was accepted")
	}
}

// The text check names this gate's own home in every form a tool input
// would spell it, and nothing else: with WRIT_HOME elsewhere, documentation
// that mentions the default ~/.writ can be edited.
func TestStateNamesFollowWritHome(t *testing.T) {
	h, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	e := &env{home: filepath.Join(h, ".local", "state", "writ-test")}
	for _, s := range []string{
		e.home + "/claude/gate.seed",
		"cat ~/.local/state/writ-test/root.seed",
		"cat $HOME/.local/state/writ-test/root.seed",
		"cat ${HOME}/.local/state/writ-test/claude/store.json",
	} {
		if e.touchesState(map[string]any{"command": s}) == "" {
			t.Errorf("%q names the gate's state and was let through", s)
		}
	}
	for _, s := range []string{"Keys live under ~/.writ by default.", "WRIT_HOME defaults to $HOME/.writ"} {
		if why := e.touchesState(map[string]any{"new_string": s}); why != "" {
			t.Errorf("%q names another home and was refused: %s", s, why)
		}
	}
	d := &env{home: filepath.Join(h, ".writ")}
	if d.touchesState(map[string]any{"command": "cat ~/.writ/root.seed"}) == "" {
		t.Error("with the default home, ~/.writ was let through")
	}
}
