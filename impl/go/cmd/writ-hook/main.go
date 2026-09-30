// writ-hook puts Claude Code tool calls under a Writ grant. Before a tool runs
// (PreToolUse) it checks the call against the grant with the reference
// executor and blocks it with the reason when the grant does not cover it;
// after the tool runs (PostToolUse) it signs a receipt, a tally, for what ran.
// Every call and refusal lands in the audit record (spec 9.3).
//
// Keys and state live under WRIT_HOME (default ~/.writ):
//
//	root.seed, root.did    the grantor, who signs grants
//	claude/agent.seed      signs each call on the session's behalf
//	claude/gate.seed       enforces the grant and signs every receipt
//	claude/grant.json      the grant, root to agent
//	claude/store.json      the executor's stores; claude/audit.jsonl the audit record
//
// The model never holds a key and never writes a receipt: this program does,
// outside the model, which is the enforcement point spec section 12 requires.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// maxInline is the longest string argument carried in a call as is. Longer
// strings, such as file contents, are carried as their SHA-256, so a call
// stays under the 64 KB limit of spec 1.6 and the receipt still commits to
// exactly what the tool was given.
const maxInline = 1024

// maxGrant is the longest grant the grant command signs: spec 12 asks
// issuers to keep root writs short-lived and verifiers to doubt longer ones.
const maxGrant = 24 * time.Hour

var toolUseID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type env struct {
	home string // WRIT_HOME
	dir  string // WRIT_HOME/claude
	now  func() int64
}

func newEnv() *env {
	home := os.Getenv("WRIT_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			die("writ-hook: no home directory and no WRIT_HOME: %v", err)
		}
		home = filepath.Join(h, ".writ")
	}
	return &env{home: home, dir: filepath.Join(home, "claude"), now: func() int64 { return time.Now().Unix() }}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: writ-hook init | grant [flags] | pre | post | recover | receipts")
	}
	e := newEnv()
	var err error
	switch os.Args[1] {
	case "init":
		err = e.initKeys(os.Stdout)
	case "grant":
		fs := flag.NewFlagSet("grant", flag.ExitOnError)
		tools := fs.String("tools", "", "comma-separated tool names the session may use (empty for any)")
		under := fs.String("under", "", "absolute directory every file_path argument must be under")
		uses := fs.Int64("uses", 0, "most tool calls the grant allows (0 for no limit)")
		ttl := fs.Duration("ttl", 8*time.Hour, "how long the grant lasts, at most 24h")
		_ = fs.Parse(os.Args[2:])
		err = e.grant(os.Stdout, splitList(*tools), *under, *uses, *ttl)
	case "pre":
		err = e.hook(os.Stdin, os.Stdout, e.pre)
	case "post":
		err = e.hook(os.Stdin, os.Stdout, e.post)
	case "recover":
		err = e.recover(os.Stdout)
	case "receipts":
		var ok bool
		ok, err = e.receipts(os.Stdout)
		if err == nil && !ok {
			os.Exit(1)
		}
	default:
		die("writ-hook: unknown command %q", os.Args[1])
	}
	if err != nil {
		die("writ-hook: %v", err)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------- keys

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }

func loadOrCreateKey(path string) (*keys.Identity, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, err := keys.Generate()
		if err != nil {
			return nil, err
		}
		seed := hex.EncodeToString(id.Priv.Seed())
		if err := os.WriteFile(path, []byte(seed+"\n"), 0o600); err != nil {
			return nil, err
		}
		return id, nil
	}
	if err != nil {
		return nil, err
	}
	return loadKeyBytes(path, b)
}

func loadKey(path string) (*keys.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadKeyBytes(path, b)
}

func loadKeyBytes(path string, b []byte) (*keys.Identity, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return keys.FromSeed(seed)
}

func (e *env) initKeys(out io.Writer) error {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	root, err := loadOrCreateKey(filepath.Join(e.home, "root.seed"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(e.home, "root.did"), []byte(root.DID()+"\n"), 0o600); err != nil {
		return err
	}
	agent, err := loadOrCreateKey(e.path("agent.seed"))
	if err != nil {
		return err
	}
	gate, err := loadOrCreateKey(e.path("gate.seed"))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "root  %s  (signs grants)\nagent %s  (signs calls for the session)\ngate  %s  (enforces and signs receipts)\n", root.DID(), agent.DID(), gate.DID())
	return nil
}

// ---------------------------------------------------------------- grant

func (e *env) grant(out io.Writer, tools []string, under string, uses int64, ttl time.Duration) error {
	if ttl <= 0 || ttl > maxGrant {
		return fmt.Errorf("-ttl must be more than 0 and at most %s", maxGrant)
	}
	if under != "" && (!filepath.IsAbs(under) || filepath.Clean(under) != under) {
		return fmt.Errorf("-under must be a clean absolute path")
	}
	root, err := loadKey(filepath.Join(e.home, "root.seed"))
	if err != nil {
		return fmt.Errorf("no grantor key; run writ-hook init first (%v)", err)
	}
	agent, err := loadKey(e.path("agent.seed"))
	if err != nil {
		return fmt.Errorf("no agent key; run writ-hook init first (%v)", err)
	}
	bnd := map[string]any{"act": map[string]any{"t": "prefix", "v": "claude"}}
	if len(tools) > 0 {
		set := make([]any, len(tools))
		for i, t := range tools {
			set[i] = t
		}
		bnd["tool"] = map[string]any{"t": "set", "v": set}
	}
	if under != "" {
		bnd["file_path"] = map[string]any{"t": "prefix", "v": under}
	}
	if uses > 0 {
		bnd["uses"] = map[string]any{"t": "count", "v": uses}
	}
	w, err := writ.Issue(root, agent.DID(), bnd, e.now()+int64(ttl/time.Second), nil)
	if err != nil {
		return err
	}
	unlock, err := e.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := writeJSON(e.path("grant.json"), w.Raw); err != nil {
		return err
	}
	// A new grant needs a new delegation to the gate.
	if err := os.Remove(e.path("child.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(out, "granted %s until %s\n", w.ID, time.Unix(w.Exp, 0).Format(time.RFC3339))
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readWrit(path string) (*writ.Writ, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	obj, err := wire.Decode(b)
	if err != nil {
		return nil, err
	}
	return writ.ParseWrit(obj)
}

// ---------------------------------------------------------------- state

// lock serializes every hook process over the store, which each process
// reads whole and writes whole. flock works on macOS and Linux alike.
func (e *env) lock() (func(), error) {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(e.path(".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

type gate struct {
	e      *exec.Executor
	agent  *keys.Identity
	chain  []*writ.Writ
	rootID string
	audit  *exec.AuditLog
}

func (g *gate) close() { g.audit.Close() }

// openGate loads the keys, the grant, and the delegation from agent to gate,
// issuing the delegation on first use, and opens the executor over the store.
// It must run under lock.
func (e *env) openGate() (*gate, error) {
	gateID, err := loadKey(e.path("gate.seed"))
	if err != nil {
		return nil, fmt.Errorf("no gate key; run writ-hook init (%v)", err)
	}
	agent, err := loadKey(e.path("agent.seed"))
	if err != nil {
		return nil, fmt.Errorf("no agent key; run writ-hook init (%v)", err)
	}
	rootDID, err := os.ReadFile(filepath.Join(e.home, "root.did"))
	if err != nil {
		return nil, fmt.Errorf("no trusted grantor; run writ-hook init (%v)", err)
	}
	grant, err := readWrit(e.path("grant.json"))
	if err != nil {
		return nil, fmt.Errorf("no grant; run writ-hook grant (%v)", err)
	}
	child, err := readWrit(e.path("child.json"))
	if err != nil || child.Prv != grant.ID || child.Hld != gateID.DID() {
		// The agent passes the grant on to the gate unchanged: the same
		// bounds, the same expiry. Narrowing can never widen (spec 4).
		bnd := map[string]any{}
		for name, b := range grant.Bnd {
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
		}
		if child, err = writ.Issue(agent, gateID.DID(), bnd, grant.Exp, grant); err != nil {
			return nil, err
		}
		if err := writeJSON(e.path("child.json"), child.Raw); err != nil {
			return nil, err
		}
	}
	st, err := exec.OpenFileStore(e.path("store.json"))
	if err != nil {
		return nil, err
	}
	al, err := exec.OpenAuditLog(e.path("audit.jsonl"))
	if err != nil {
		return nil, err
	}
	x := exec.New(gateID, st)
	x.Now = e.now
	root := strings.TrimSpace(string(rootDID))
	x.AcceptRoot = func(did string) bool { return did == root }
	x.Audit = func(a exec.AuditEntry) {
		if err := al.Record(a); err != nil {
			fmt.Fprintf(os.Stderr, "writ-hook: audit record not written: %v\n", err)
		}
	}
	return &gate{e: x, agent: agent, chain: []*writ.Writ{grant, child}, rootID: root, audit: al}, nil
}

// ---------------------------------------------------------------- hooks

// hookInput is the part of Claude Code's hook input this program reads.
type hookInput struct {
	Event        string          `json:"hook_event_name"`
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolUseID    string          `json:"tool_use_id"`
	ToolResponse json.RawMessage `json:"tool_response"`
	Error        json.RawMessage `json:"error"`
}

func (e *env) hook(in io.Reader, out io.Writer, f func(*hookInput) (any, error)) error {
	var h hookInput
	if err := json.NewDecoder(in).Decode(&h); err != nil {
		return fmt.Errorf("hook input: %v", err)
	}
	v, err := f(&h)
	if err != nil {
		return err
	}
	if v != nil {
		return json.NewEncoder(out).Encode(v)
	}
	return nil
}

func deny(reason string) any {
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": "Writ: " + reason,
	}}
}

// pre checks the tool call against the grant (spec 7 steps 1 to 11). It
// denies with the reason on any refusal, and otherwise stays silent, so
// Claude Code's own permission rules still apply. It fails closed: Claude Code
// runs the tool when a hook errors, so an internal error becomes a deny.
func (e *env) pre(h *hookInput) (any, error) {
	v, err := e.admit(h)
	if err != nil {
		return deny("the gate could not check this call, so it is blocked: " + err.Error()), nil
	}
	return v, nil
}

func (e *env) admit(h *hookInput) (any, error) {
	if !toolUseID.MatchString(h.ToolUseID) {
		return deny("the hook input has no usable tool_use_id"), nil
	}
	args, why := e.args(h.ToolName, h.ToolInput)
	if why != "" {
		return deny(why), nil
	}
	unlock, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	g, err := e.openGate()
	if err != nil {
		return deny(err.Error()), nil
	}
	defer g.close()
	if err := os.MkdirAll(filepath.Join(e.dir, "pending"), 0o700); err != nil {
		return nil, err
	}
	k, err := writ.NewCall(g.agent, g.chain, "claude/"+h.ToolName, args)
	if err != nil {
		return deny("the tool input cannot be carried in a call: " + err.Error()), nil
	}
	rep, rej := g.e.Begin(context.Background(), k.Raw)
	switch {
	case rej != nil:
		return deny(string(rej.Code)), nil
	case rep != nil:
		code := "refused"
		if errObj, ok := rep.Tally["err"].(map[string]any); ok {
			code, _ = errObj["code"].(string)
		}
		return deny(explain(code, h.ToolName, g.chain[0], args)), nil
	}
	if err := writeJSON(e.pendingPath(h.ToolUseID), k.Raw); err != nil {
		return nil, err
	}
	return nil, nil
}

// explain turns a refusal's reason code into a sentence the model can act
// on, naming what the grant allows. The code stays first, as in the tally.
func explain(code, tool string, grant *writ.Writ, args map[string]any) string {
	allowed := "any tool"
	if b, ok := grant.Bnd["tool"]; ok && b.T == "set" {
		var names []string
		for _, v := range b.Set {
			names = append(names, strings.Trim(fmt.Sprint(v), `"`))
		}
		allowed = "only " + strings.Join(names, ", ")
	}
	why := ""
	switch code {
	case "missing_arg":
		var need []string
		for name, b := range grant.Bnd {
			if _, ok := args[name]; !ok && b.T != "count" && name != "act" && name != "hld" && name != "depth" {
				need = append(need, name)
			}
		}
		sort.Strings(need)
		why = fmt.Sprintf("this grant requires %s on every call and a %s call has none; the grant allows %s", strings.Join(need, ", "), tool, allowed)
	case "out_of_bounds":
		why = "an argument is outside what the grant allows"
		if b, ok := grant.Bnd["file_path"]; ok {
			why += fmt.Sprintf(" (files must be under %v)", b.Raw)
		}
		why += "; the grant allows " + allowed
	case "count_exhausted":
		why = "the grant's limit on the number of tool calls is used up"
	case "expired":
		why = "the grant has expired; ask for a new one"
	case "revoked":
		why = "the grant was revoked"
	case "forbidden_op":
		why = "the grant does not cover this operation; it allows " + allowed
	default:
		return code
	}
	return code + ": " + why
}

func (e *env) pendingPath(toolUse string) string {
	return filepath.Join(e.dir, "pending", toolUse+".json")
}

// post signs the receipt for a tool call pre admitted (spec 7 step 12). The
// result body commits to the tool's response by hash, not by content.
func (e *env) post(h *hookInput) (any, error) {
	if !toolUseID.MatchString(h.ToolUseID) {
		return nil, nil
	}
	unlock, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	raw, err := os.ReadFile(e.pendingPath(h.ToolUseID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // not a call this gate admitted
	}
	if err != nil {
		return nil, err
	}
	obj, err := wire.Decode(raw)
	if err != nil {
		return nil, err
	}
	g, err := e.openGate()
	if err != nil {
		return nil, err
	}
	defer g.close()
	r := exec.Result{St: "ok"}
	sum := sha256.Sum256(h.ToolResponse)
	body := map[string]any{"tool_use_id": h.ToolUseID, "response_sha256": hex.EncodeToString(sum[:])}
	if h.Event == "PostToolUseFailure" || (len(h.Error) > 0 && string(h.Error) != "null") {
		errSum := sha256.Sum256(h.Error)
		r = exec.Result{St: "failed", ErrCode: "claude/tool_failed"}
		body = map[string]any{"tool_use_id": h.ToolUseID, "error_sha256": hex.EncodeToString(errSum[:])}
	}
	r.Res = body
	if _, rej := g.e.Complete(context.Background(), obj, r); rej != nil && rej.Code != writ.Reason(exec.NotAdmitted) {
		return nil, fmt.Errorf("receipt not signed: %v", rej)
	}
	if err := os.Remove(e.pendingPath(h.ToolUseID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return nil, nil
}

// args turns a tool's input into call arguments: the input's members, with
// the tool name under "tool" so a grant can list the tools it allows. It
// refuses what a bound could be fooled by: a path with "." or ".." segments,
// and anything that names this program's own keys and state.
func (e *env) args(tool string, input json.RawMessage) (map[string]any, string) {
	if tool == "" {
		return nil, "the hook input names no tool"
	}
	args := map[string]any{}
	if len(input) > 0 && string(input) != "null" {
		dec := json.NewDecoder(bytes.NewReader(input))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return nil, "the tool input is not a JSON object"
		}
	}
	if _, clash := args["tool"]; clash {
		return nil, `the tool input has its own "tool" member, which a grant uses to name tools`
	}
	for _, name := range []string{"file_path", "notebook_path", "path"} {
		if p, ok := args[name].(string); ok && (filepath.Clean(p) != p || hasDotDot(p)) {
			return nil, fmt.Sprintf("%s %q is not a clean path; give it without . or .. segments", name, p)
		}
	}
	if why := e.touchesState(args); why != "" {
		return nil, why
	}
	for name, v := range args {
		args[name] = shrink(v)
	}
	args["tool"] = tool
	return args, ""
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// touchesState refuses any argument that names WRIT_HOME, so a tool the
// grant allows cannot read the keys or rewrite the grant, store, or audit
// record. It matches text, so a shell command that builds the path at run
// time gets past it: a grant that must hold does not allow a shell.
func (e *env) touchesState(v any) string {
	var found string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if strings.Contains(x, e.home) || strings.Contains(x, "~/.writ") || strings.Contains(x, "$HOME/.writ") {
				found = "the call names Writ's own keys and state, which no grant covers"
			}
		case map[string]any:
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(v)
	return found
}

func shrink(v any) any {
	switch x := v.(type) {
	case string:
		if len(x) > maxInline {
			sum := sha256.Sum256([]byte(x))
			return "sha256:" + hex.EncodeToString(sum[:])
		}
	case map[string]any:
		for k, y := range x {
			x[k] = shrink(y)
		}
	case []any:
		for i, y := range x {
			x[i] = shrink(y)
		}
	}
	return v
}

// ---------------------------------------------------------------- upkeep

// recover resolves calls admitted and never reported, because the tool was
// stopped or Claude Code exited, to unknown_outcome (spec 9). Run it at
// session start, when no tool call is in flight.
func (e *env) recover(out io.Writer) error {
	unlock, err := e.lock()
	if err != nil {
		return err
	}
	defer unlock()
	g, err := e.openGate()
	if err != nil {
		return err
	}
	defer g.close()
	n := g.e.Recover()
	files, _ := filepath.Glob(filepath.Join(e.dir, "pending", "*.json"))
	for _, f := range files {
		_ = os.Remove(f)
	}
	fmt.Fprintf(out, "resolved %d unfinished call(s) to unknown_outcome\n", n)
	return nil
}

// receipts verifies every receipt in the store against the chain it names,
// with the keys inside the objects and nothing else, and summarizes them.
func (e *env) receipts(out io.Writer) (bool, error) {
	unlock, err := e.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	rootDID, err := os.ReadFile(filepath.Join(e.home, "root.did"))
	if err != nil {
		return false, fmt.Errorf("no trusted grantor; run writ-hook init (%v)", err)
	}
	root := strings.TrimSpace(string(rootDID))
	st, err := exec.OpenFileStore(e.path("store.json"))
	if err != nil {
		return false, err
	}
	byOutcome := map[string]int{}
	byTool := map[string]int{}
	valid, invalid, pending := 0, 0, 0
	for _, rec := range st.Calls {
		k, err := writ.ParseCall(rec.Call)
		if err != nil {
			invalid++
			fmt.Fprintf(out, "INVALID call record: %v\n", err)
			continue
		}
		if rec.Tally == nil {
			pending++
			continue
		}
		v, t, err := writ.VerifyTally(k.Leaf(), k, rec.Tally, nil)
		if v != writ.Valid || k.Chain[0].Iss != root {
			invalid++
			fmt.Fprintf(out, "INVALID receipt for call %s (%s): %v %v\n", k.ID, k.Op, v, err)
			continue
		}
		valid++
		byOutcome[t.St]++
		byTool[strings.TrimPrefix(k.Op, "claude/")]++
	}
	fmt.Fprintf(out, "%d receipt(s) verified, %d invalid, %d call(s) still unfinished\n", valid, invalid, pending)
	for _, m := range []map[string]int{byOutcome, byTool} {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(out, "  %-24s %d\n", n, m[n])
		}
	}
	refusals := 0
	if b, err := os.ReadFile(e.path("audit.jsonl")); err == nil {
		refusals = bytes.Count(b, []byte(`"outcome":"failed"`)) + bytes.Count(b, []byte(`"outcome":"rejected"`)) - byOutcome["failed"]
	}
	fmt.Fprintf(out, "%d refusal(s) in the audit record\n", refusals)
	return invalid == 0, nil
}
