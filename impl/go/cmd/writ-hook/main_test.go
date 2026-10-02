package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const t0 = int64(1790000000)

func setup(t *testing.T, tools []string, under string, uses int64) *env {
	t.Helper()
	home := t.TempDir()
	e := &env{home: home, dir: filepath.Join(home, "claude"), now: func() int64 { return t0 }}
	var out bytes.Buffer
	if err := e.initKeys(&out); err != nil {
		t.Fatal(err)
	}
	if err := e.grant(&out, "default", tools, under, uses, time.Hour); err != nil {
		t.Fatal(err)
	}
	return e
}

func input(event, tool, id string, in map[string]any) string {
	b, _ := json.Marshal(map[string]any{"hook_event_name": event, "tool_name": tool, "tool_use_id": id,
		"tool_input": in, "tool_response": map[string]any{"ok": true}})
	return string(b)
}

// pre returns "" when the call is admitted and the deny reason otherwise.
func pre(t *testing.T, e *env, tool, id string, in map[string]any) string {
	t.Helper()
	var out bytes.Buffer
	if err := e.hook(strings.NewReader(input("PreToolUse", tool, id, in)), &out, e.pre); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return ""
	}
	var d struct {
		H struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.H.Decision != "deny" {
		t.Fatalf("pre wrote %s, want nothing or a deny", out.String())
	}
	return d.H.Reason
}

func post(t *testing.T, e *env, event, tool, id string) {
	t.Helper()
	var out bytes.Buffer
	if err := e.hook(strings.NewReader(input(event, tool, id, nil)), &out, e.post); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("post wrote %s, want nothing", out.String())
	}
}

func receipts(t *testing.T, e *env) (bool, string) {
	t.Helper()
	var out bytes.Buffer
	ok, err := e.receipts(&out)
	if err != nil {
		t.Fatal(err)
	}
	return ok, out.String()
}

func TestGrantIsEnforcedAndEveryCallReceipted(t *testing.T) {
	proj := "/work/project"
	e := setup(t, []string{"Read", "Edit"}, proj, 3)

	if r := pre(t, e, "Read", "toolu_1", map[string]any{"file_path": proj + "/main.go"}); r != "" {
		t.Fatalf("a Read under the granted folder was denied: %s", r)
	}
	post(t, e, "PostToolUse", "Read", "toolu_1")

	cases := []struct {
		tool, id string
		in       map[string]any
		want     string
	}{
		{"Read", "toolu_2", map[string]any{"file_path": "/etc/passwd"}, "out_of_bounds: an argument is outside what the grant allows (files must be under /work/project); the grant allows only Read, Edit. The signer of the grant, did:key:"},
		{"Write", "toolu_3", map[string]any{"file_path": proj + "/x", "content": "hi"}, "out_of_bounds"},
		{"Bash", "toolu_4", map[string]any{"command": "ls"}, "missing_arg: this grant requires file_path on every call and a Bash call has none; the grant allows only Read, Edit"},
		{"Read", "toolu_5", map[string]any{"file_path": proj + "/../secret"}, "not a clean path"},
		{"Read", "toolu_6", map[string]any{"file_path": e.home + "/root.seed"}, "Writ's own keys"},
		{"Edit", "toolu_7", map[string]any{"file_path": proj + "/a", "tool": "x"}, `own "tool" member`},
		{"Read", "bad id!", map[string]any{"file_path": proj + "/a"}, "tool_use_id"},
	}
	for _, c := range cases {
		if r := pre(t, e, c.tool, c.id, c.in); !strings.Contains(r, c.want) {
			t.Errorf("%s %v: denied with %q, want it to name %q", c.tool, c.in, r, c.want)
		}
	}

	big := strings.Repeat("x", 200000)
	if r := pre(t, e, "Edit", "toolu_8", map[string]any{"file_path": proj + "/a", "old_string": big, "new_string": "y"}); r != "" {
		t.Fatalf("an Edit with a large input was denied: %s", r)
	}
	post(t, e, "PostToolUseFailure", "Edit", "toolu_8")
	if r := pre(t, e, "Read", "toolu_9", map[string]any{"file_path": proj + "/b"}); r != "" {
		t.Fatalf("the third call was denied: %s", r)
	}
	post(t, e, "PostToolUse", "Read", "toolu_9")
	if r := pre(t, e, "Read", "toolu_10", map[string]any{"file_path": proj + "/c"}); !strings.HasPrefix(r, "Writ: count_exhausted: ") {
		t.Fatalf("a fourth call under uses 3: %q, want count_exhausted", r)
	}

	ok, report := receipts(t, e)
	if !ok || !strings.Contains(report, "3 receipt(s) verified, 0 invalid, 0 call(s) still unfinished") ||
		!strings.Contains(report, "failed                   1") || !strings.Contains(report, "8 refusal(s)") {
		t.Fatalf("receipts:\n%s", report)
	}
	audit, _ := os.ReadFile(e.path("audit.jsonl"))
	if n := bytes.Count(audit, []byte("\n")); n != 11 {
		t.Fatalf("%d audit entries, want 11: three receipts, four refusals by the executor, four by the hook", n)
	}
	for _, code := range []string{"claude/unclean_path", "claude/protected_state", "claude/tool_member", "claude/no_tool_use_id"} {
		if !bytes.Contains(audit, []byte(`"reason":"`+code+`"`)) {
			t.Errorf("the audit record has no %s refusal", code)
		}
	}
}

// A receipt edited after signing no longer verifies, and receipts says so.
func TestTamperedReceiptIsCaught(t *testing.T) {
	e := setup(t, nil, "", 0)
	if r := pre(t, e, "Grep", "toolu_1", map[string]any{"pattern": "x"}); r != "" {
		t.Fatal(r)
	}
	post(t, e, "PostToolUse", "Grep", "toolu_1")
	if ok, report := receipts(t, e); !ok {
		t.Fatalf("an untouched receipt failed:\n%s", report)
	}
	b, _ := os.ReadFile(e.path("store.json"))
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	tampered := 0
	for _, rec := range st["calls"].(map[string]any) {
		if tl, ok := rec.(map[string]any)["tally"].(map[string]any); ok && tl["st"] == "ok" {
			tl["st"], tampered = "failed", tampered+1
		}
	}
	if tampered != 1 {
		t.Fatalf("tampered with %d tallies, want 1", tampered)
	}
	b, _ = json.Marshal(st)
	if err := os.WriteFile(e.path("store.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, report := receipts(t, e); ok || !strings.Contains(report, "INVALID receipt") {
		t.Fatalf("a tampered receipt passed:\n%s", report)
	}
}

// Claude Code runs the hooks of parallel tool calls at once. The lock keeps
// every process's write, so no admission or receipt is lost.
func TestParallelCallsLoseNothing(t *testing.T) {
	e := setup(t, nil, "", 0)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("toolu_p%d", i)
			if r := pre(t, e, "Glob", id, map[string]any{"pattern": "*.go"}); r != "" {
				t.Errorf("call %d denied: %s", i, r)
				return
			}
			post(t, e, "PostToolUse", "Glob", id)
		}(i)
	}
	wg.Wait()
	if ok, report := receipts(t, e); !ok || !strings.Contains(report, "12 receipt(s) verified, 0 invalid, 0 call(s)") {
		t.Fatalf("receipts after 12 parallel calls:\n%s", report)
	}
}

// A call admitted and never reported resolves to unknown_outcome at the next
// session start, and still verifies as a receipt.
func TestRecoverResolvesUnfinishedCalls(t *testing.T) {
	e := setup(t, nil, "", 0)
	if r := pre(t, e, "Read", "toolu_1", map[string]any{"file_path": "/a"}); r != "" {
		t.Fatal(r)
	}
	if _, report := receipts(t, e); !strings.Contains(report, "0 receipt(s) verified, 0 invalid, 1 call(s) still unfinished") {
		t.Fatalf("before recover:\n%s", report)
	}
	var out bytes.Buffer
	if err := e.recover(&out); err != nil || !strings.Contains(out.String(), "resolved 1") {
		t.Fatalf("recover: %v %s", err, out.String())
	}
	if ok, report := receipts(t, e); !ok || !strings.Contains(report, "1 receipt(s) verified") {
		t.Fatalf("after recover:\n%s", report)
	}
	post(t, e, "PostToolUse", "Read", "toolu_1") // a late report changes nothing
}

// With no grant the gate fails closed.
func TestNoGrantDeniesEverything(t *testing.T) {
	home := t.TempDir()
	e := &env{home: home, dir: filepath.Join(home, "claude"), now: func() int64 { return t0 }}
	var out bytes.Buffer
	if err := e.initKeys(&out); err != nil {
		t.Fatal(err)
	}
	if r := pre(t, e, "Read", "toolu_1", map[string]any{"file_path": "/a"}); !strings.Contains(r, "no grant") {
		t.Fatalf("with no grant: %q, want a deny naming the missing grant", r)
	}
	if err := e.grant(&out, "default", nil, "", 0, 25*time.Hour); err == nil {
		t.Fatal("a 25-hour grant was signed")
	}
}

// Several named grants: a call is checked under the grant that lists its
// tool, so a folder limit on file tools no longer shuts out search tools.
func TestNamedGrantsPerTool(t *testing.T) {
	proj := "/work/project"
	e := setup(t, []string{"Read", "Edit"}, proj, 0)
	var out bytes.Buffer
	if err := e.grant(&out, "search", []string{"Grep", "Glob"}, "", 5, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := e.grant(&out, "Bad Name", nil, "", 0, time.Hour); err == nil {
		t.Fatal("a grant name with spaces and capitals was accepted")
	}
	if r := pre(t, e, "Grep", "toolu_1", map[string]any{"pattern": "x", "path": "/anywhere"}); r != "" {
		t.Fatalf("Grep under the search grant: %s", r)
	}
	post(t, e, "PostToolUse", "Grep", "toolu_1")
	if r := pre(t, e, "Read", "toolu_2", map[string]any{"file_path": "/etc/hosts"}); !strings.HasPrefix(r, "Writ: out_of_bounds") {
		t.Fatalf("Read outside the folder: %q", r)
	}
	if r := pre(t, e, "Bash", "toolu_3", map[string]any{"command": "ls"}); !strings.HasPrefix(r, "Writ: missing_arg") {
		t.Fatalf("Bash, which no grant lists: %q", r)
	}
	if ok, report := receipts(t, e); !ok || !strings.Contains(report, "1 receipt(s) verified") {
		t.Fatalf("receipts:\n%s", report)
	}
}
