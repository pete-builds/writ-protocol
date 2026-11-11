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
//
// The grantor and the gate can sign through HashiCorp Vault's transit engine
// instead, so their private keys never leave Vault and there is no seed file
// to steal: WRIT_VAULT_ROOT_KEY and WRIT_VAULT_GATE_KEY name the Ed25519
// transit keys, VAULT_ADDR and VAULT_NAMESPACE where Vault is, VAULT_TOKEN or
// the file WRIT_VAULT_TOKEN_FILE the token, and WRIT_VAULT_MOUNT the transit
// mount (default "transit"). root.did still records the grantor's did:key.
//
//	claude/grants/*.json   the grants, root to agent, one per name
//	claude/requests/*.json refused calls the grantor could approve, by tool_use_id
//	claude/approvals/*.json one-use approvals, root to agent, checked before the grants
//	claude/stores/*.json   the executor's stores, one per grant, named by its identity
//	claude/audit.jsonl     the audit record, one for every grant
//
// A store is read and written whole on every call, so each grant keeps its
// own: a grant lasts at most a day and a renewed grant starts a fresh store,
// which keeps the file a hook rewrites as small as one grant's calls.
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
	"writproto/jcs"
	"writproto/keys"
	"writproto/keys/vault"
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

// staleAfter is how old an unfinished call must be before a session other
// than its own resolves it. A session resolves its own unfinished calls when
// it starts, since none of them can still be running; another session's may
// be, so they wait until no grant could still cover them.
const staleAfter = maxGrant

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
		die("usage: writ-hook init | grant [flags] | approve [-yes] [-ttl D] ID | serve -socket PATH | pre | post | recover | receipts")
	}
	e := newEnv()
	var err error
	// With WRIT_HOOK_SOCKET set, the hook commands go to a gate running as
	// its own process (writ-hook serve) instead of opening the state here.
	if socket := os.Getenv("WRIT_HOOK_SOCKET"); socket != "" {
		switch os.Args[1] {
		case "pre", "post", "recover", "receipts":
			var in io.Reader = os.Stdin
			if os.Args[1] == "recover" && !piped(os.Stdin) {
				in = strings.NewReader("")
			}
			ok, err := remote(socket, os.Args[1], in, os.Stdout)
			if err != nil {
				die("writ-hook: %v", err)
			}
			if os.Args[1] == "receipts" && !ok {
				os.Exit(1)
			}
			return
		}
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		socket := fs.String("socket", "", "Unix socket to listen on; the hook commands find it through WRIT_HOOK_SOCKET")
		mode := fs.Uint("mode", 0o666, "permission of the socket file, which the Claude Code user must be able to connect to")
		_ = fs.Parse(os.Args[2:])
		if *socket == "" {
			die("writ-hook serve: -socket is required")
		}
		err = e.serve(*socket, os.FileMode(*mode), func() { fmt.Fprintln(os.Stderr, "writ-hook gate listening on", *socket) })
	case "init":
		err = e.initKeys(os.Stdout)
	case "grant":
		fs := flag.NewFlagSet("grant", flag.ExitOnError)
		tools := fs.String("tools", "", "comma-separated tool names the session may use (empty for any)")
		under := fs.String("under", "", "absolute directory every file_path argument must be under")
		uses := fs.Int64("uses", 0, "most tool calls the grant allows (0 for no limit)")
		ttl := fs.Duration("ttl", 8*time.Hour, "how long the grant lasts, at most 24h")
		name := fs.String("name", "default", "the grant's name; a tool call is checked under the grant that lists its tool")
		renew := fs.Duration("renew-before", 0, "keep the grant of this name, unsigned again, while it has the same bounds and more than this left to run")
		_ = fs.Parse(os.Args[2:])
		err = e.grant(os.Stdout, *name, splitList(*tools), *under, *uses, *ttl, *renew)
	case "approve":
		fs := flag.NewFlagSet("approve", flag.ExitOnError)
		yes := fs.Bool("yes", false, "sign the approval; without it, only show what would be approved")
		ttl := fs.Duration("ttl", 30*time.Minute, "how long the approval lasts, at most 24h")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			die("usage: writ-hook approve [-yes] [-ttl D] ID, where ID is the one a refusal named")
		}
		err = e.approve(os.Stdout, fs.Arg(0), *yes, *ttl)
	case "pre":
		err = e.hook(os.Stdin, os.Stdout, e.pre)
	case "post":
		err = e.hook(os.Stdin, os.Stdout, e.post)
	case "recover":
		var h *hookInput
		if h, err = sessionStart(os.Stdin); err == nil {
			err = e.recover(os.Stdout, h)
		}
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

// signer is the grantor's key (role ROOT) or the gate's (GATE). When
// WRIT_VAULT_<role>_KEY names a transit key, it is that key in Vault and every
// signature goes through Vault; no seed file is read or written. Otherwise it
// is the seed file at path, created when create is set.
func (e *env) signer(role, path string, create bool) (keys.Signer, error) {
	name := os.Getenv("WRIT_VAULT_" + role + "_KEY")
	if name == "" {
		load := loadKey
		if create {
			load = loadOrCreateKey
		}
		id, err := load(path)
		if err != nil {
			return nil, err
		}
		return id, nil
	}
	token := os.Getenv("VAULT_TOKEN")
	if f := os.Getenv("WRIT_VAULT_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return vault.New(ctx, vault.Config{Addr: os.Getenv("VAULT_ADDR"), Token: token,
		Namespace: os.Getenv("VAULT_NAMESPACE"), Mount: os.Getenv("WRIT_VAULT_MOUNT"), Key: name})
}

func (e *env) initKeys(out io.Writer) error {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	root, err := e.signer("ROOT", filepath.Join(e.home, "root.seed"), true)
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
	gate, err := e.signer("GATE", e.path("gate.seed"), true)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "root  %s  (signs grants)\nagent %s  (signs calls for the session)\ngate  %s  (enforces and signs receipts)\n", root.DID(), agent.DID(), gate.DID())
	return nil
}

// ---------------------------------------------------------------- grant

var grantName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// grant signs a grant from the grantor to the agent key and saves it under
// name. With renew above zero, a grant already saved under name is kept when
// the same grantor signed it to the same agent with the same bounds and it
// has more than renew left to run, so the command can run at every session
// start and keep a rolling grant without signing a new one each time.
func (e *env) grant(out io.Writer, name string, tools []string, under string, uses int64, ttl, renew time.Duration) error {
	if !grantName.MatchString(name) {
		return fmt.Errorf("-name must be lowercase letters, digits, and dashes")
	}
	if ttl <= 0 || ttl > maxGrant {
		return fmt.Errorf("-ttl must be more than 0 and at most %s", maxGrant)
	}
	if renew < 0 || renew >= ttl {
		return fmt.Errorf("-renew-before must be at least 0 and less than -ttl")
	}
	if under != "" && (!filepath.IsAbs(under) || filepath.Clean(under) != under) {
		return fmt.Errorf("-under must be a clean absolute path")
	}
	root, err := e.signer("ROOT", filepath.Join(e.home, "root.seed"), false)
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
	path := filepath.Join(e.path("grants"), name+".json")
	if renew > 0 {
		if w, err := readWrit(path); err == nil && w.Iss == root.DID() && w.Hld == agent.DID() &&
			w.Exp-e.now() > int64(renew/time.Second) && sameBounds(w, bnd) {
			fmt.Fprintf(out, "kept %q %s until %s\n", name, w.ID, time.Unix(w.Exp, 0).Format(time.RFC3339))
			return nil
		}
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
	if err := os.MkdirAll(e.path("grants"), 0o700); err != nil {
		return err
	}
	if err := writeJSON(path, w.Raw); err != nil {
		return err
	}
	fmt.Fprintf(out, "granted %q %s until %s\n", name, w.ID, time.Unix(w.Exp, 0).Format(time.RFC3339))
	return nil
}

// sameBounds reports whether a saved grant carries exactly the bounds bnd
// would sign, compared in canonical form.
func sameBounds(w *writ.Writ, bnd map[string]any) bool {
	have, err := jcs.Marshal(w.Raw["bnd"])
	if err != nil {
		return false
	}
	obj, err := wire.Decode(mustJSON(map[string]any{"bnd": bnd}))
	if err != nil {
		return false
	}
	want, err := jcs.Marshal(obj["bnd"])
	return err == nil && bytes.Equal(have, want)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
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
	env    *env
	id     keys.Signer
	agent  *keys.Identity
	rootID string
	audit  *exec.AuditLog
}

func (g *gate) close() { g.audit.Close() }

// storeFor is the store of the calls made under the grant with identity id,
// which is base64url and so a safe file name.
func (e *env) storeFor(id string) string {
	return filepath.Join(e.dir, "stores", id+".json")
}

// use opens the executor over the store of the grant with identity id. It
// must run under lock.
func (g *gate) use(id string) error {
	if err := os.MkdirAll(filepath.Join(g.env.dir, "stores"), 0o700); err != nil {
		return err
	}
	st, err := exec.OpenFileStore(g.env.storeFor(id))
	if err != nil {
		return err
	}
	x := exec.New(g.id, st)
	x.Now = g.env.now
	x.AcceptRoot = func(did string) bool { return did == g.rootID }
	x.Audit = func(a exec.AuditEntry) {
		if err := g.audit.Record(a); err != nil {
			fmt.Fprintf(os.Stderr, "writ-hook: audit record not written: %v\n", err)
		}
	}
	g.e = x
	return nil
}

// openGate loads the keys and opens the audit record; use then opens the
// store of one grant. It must run under lock.
func (e *env) openGate() (*gate, error) {
	gateID, err := e.signer("GATE", e.path("gate.seed"), false)
	if err != nil {
		return nil, fmt.Errorf("the gate key could not be loaded; with none, run writ-hook init (%v)", err)
	}
	agent, err := loadKey(e.path("agent.seed"))
	if err != nil {
		return nil, fmt.Errorf("no agent key; run writ-hook init (%v)", err)
	}
	rootDID, err := os.ReadFile(filepath.Join(e.home, "root.did"))
	if err != nil {
		return nil, fmt.Errorf("no trusted grantor; run writ-hook init (%v)", err)
	}
	al, err := exec.OpenAuditLog(e.path("audit.jsonl"))
	if err != nil {
		return nil, err
	}
	return &gate{env: e, id: gateID, agent: agent, rootID: strings.TrimSpace(string(rootDID)), audit: al}, nil
}

// chainFor picks the grant a call to tool is checked under: the first, by
// name, whose tool set lists it, else the first with no tool set, else the
// first of all, which the executor then refuses with its reason. It returns
// the chain root, agent, gate, issuing the agent's delegation to the gate on
// first use: the same bounds and expiry, since narrowing never widens (spec 4).
//
// An approval the grantor signed with writ-hook approve comes first, when it
// admits exactly this call and has not expired, and the second return value
// is then its file, which admit removes once the call is admitted. Any other
// call is checked under the grants as before, so an approval never stands in
// for the grant on the calls it does not name.
func (g *gate) chainFor(tool, op string, args map[string]any) ([]*writ.Writ, string, error) {
	approvals, _ := filepath.Glob(filepath.Join(g.env.path("approvals"), "*.json"))
	sort.Strings(approvals)
	for _, f := range approvals {
		w, err := readWrit(f)
		if err != nil || w.Iss != g.rootID || w.Hld != g.agent.DID() || w.Exp <= g.env.now() || !writ.Admits(w, op, args) {
			continue
		}
		chain, err := g.withChild(w, "approval-"+filepath.Base(f))
		return chain, f, err
	}
	files, _ := filepath.Glob(filepath.Join(g.env.path("grants"), "*.json"))
	sort.Strings(files)
	var pick, open, first string
	for _, f := range files {
		w, err := readWrit(f)
		if err != nil {
			continue
		}
		if first == "" {
			first = f
		}
		b, listed := w.Bnd["tool"]
		if !listed || b.T != "set" {
			if open == "" {
				open = f
			}
			continue
		}
		for _, v := range b.Set {
			if strings.Trim(fmt.Sprint(v), `"`) == tool {
				pick = f
				break
			}
		}
		if pick != "" {
			break
		}
	}
	for _, f := range []string{pick, open, first} {
		if f == "" {
			continue
		}
		grant, err := readWrit(f)
		if err != nil {
			return nil, "", err
		}
		chain, err := g.withChild(grant, filepath.Base(f))
		return chain, "", err
	}
	return nil, "", errors.New("no grant; run writ-hook grant")
}

// withChild returns the chain root, agent, gate for grant, issuing the
// agent's delegation to the gate under children/name on first use.
func (g *gate) withChild(grant *writ.Writ, name string) ([]*writ.Writ, error) {
	childPath := filepath.Join(g.env.path("children"), name)
	child, err := readWrit(childPath)
	if err != nil || child.Prv != grant.ID || child.Hld != g.id.DID() {
		bnd := map[string]any{}
		for name, b := range grant.Bnd {
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
		}
		if child, err = writ.Issue(g.agent, g.id.DID(), bnd, grant.Exp, grant); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(g.env.path("children"), 0o700); err != nil {
			return nil, err
		}
		if err := writeJSON(childPath, child.Raw); err != nil {
			return nil, err
		}
	}
	return []*writ.Writ{grant, child}, nil
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
	SessionID    string          `json:"session_id"`
}

// pendingCall is what pre keeps for a call it admitted, until post signs its
// receipt or recover resolves it: the call, and the session that made it and
// when, so a session starting up resolves only calls that cannot be running.
type pendingCall struct {
	Session string          `json:"session"`
	At      int64           `json:"at"`
	Call    json.RawMessage `json:"call"`
}

// readPending reads a pending file. A file written before pendingCall
// existed holds the bare call, with no session and no time.
func readPending(path string) (*pendingCall, wire.Object, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var p pendingCall
	if err := json.Unmarshal(raw, &p); err != nil || len(p.Call) == 0 {
		p = pendingCall{Call: raw}
	}
	obj, err := wire.Decode(p.Call)
	if err != nil {
		return nil, nil, err
	}
	return &p, obj, nil
}

// grantOf is the identity of the grant a call was made under, which names
// the store it lives in.
func grantOf(obj wire.Object) (string, error) {
	k, err := writ.ParseCall(obj)
	if err != nil {
		return "", err
	}
	return k.Chain[0].ID, nil
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
		e.auditRefusal(h, "claude/no_tool_use_id")
		return deny("the hook input has no usable tool_use_id"), nil
	}
	args, why := e.args(h.ToolName, h.ToolInput)
	if why != "" {
		e.auditRefusal(h, adapterCode(why))
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
	chain, approval, err := g.chainFor(h.ToolName, "claude/"+h.ToolName, args)
	if err != nil {
		return deny(err.Error()), nil
	}
	if err := g.use(chain[0].ID); err != nil {
		return nil, err
	}
	k, err := writ.NewCall(g.agent, chain, "claude/"+h.ToolName, args)
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
		return deny(explain(code, h.ToolName, chain[0], args) + e.approvable(code, chain, k, h)), nil
	}
	call, err := json.Marshal(k.Raw)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(e.pendingPath(h.ToolUseID), pendingCall{Session: h.SessionID, At: e.now(), Call: call}); err != nil {
		return nil, err
	}
	// The approval is used up: its count of one is now spent at this
	// executor, and removing it keeps it from being tried for later calls.
	if approval != "" {
		if err := os.Remove(approval); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
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

// approvable says who can approve a call refused for its operation or its
// arguments, when a writ in the chain above the one that refused it would
// allow it (docs/approval.md). Approval is a one-use writ for exactly this
// call, so the model is told who to ask, not how to get around the grant.
// When the approver is the grantor, whose key this program holds, the call is
// saved under requests/ by its tool_use_id for writ-hook approve. It must run
// under lock.
func (e *env) approvable(code string, chain []*writ.Writ, k *writ.Call, h *hookInput) string {
	if code != "out_of_bounds" && code != "forbidden_op" && code != "missing_arg" {
		return ""
	}
	j := writ.ApprovalPoint(chain, k.Op, k.Args)
	if j < 0 {
		return ""
	}
	if j == 0 {
		req := approvalRequest{Tool: h.ToolName, Op: k.Op, Args: k.Args, Grant: chain[0].Raw, At: e.now()}
		if err := os.MkdirAll(e.path("requests"), 0o700); err == nil && writeJSON(e.requestPath(h.ToolUseID), req) == nil {
			return fmt.Sprintf(". The signer of the grant, %s, can approve exactly this one call by running `writ-hook approve %s` (docs/approval.md); ask the person, and do not retry until they say it is approved", chain[0].Iss, h.ToolUseID)
		}
	}
	return fmt.Sprintf(". The signer of the grant, %s, can approve exactly this one call with `writ approve` (docs/approval.md); ask the person, do not retry", chain[j].Iss)
}

// approvalRequest is a refused call the grantor could approve: what the
// person is shown, and what writ-hook approve signs a one-use writ for.
type approvalRequest struct {
	Tool  string         `json:"tool"`
	Op    string         `json:"op"`
	Args  map[string]any `json:"args"`
	Grant wire.Object    `json:"grant"`
	At    int64          `json:"at"`
}

func (e *env) requestPath(id string) string { return filepath.Join(e.path("requests"), id+".json") }

// approve shows the refused call saved under id and, with yes, signs as the
// grantor a writ for exactly that call, once (docs/approval.md), saved under
// approvals/ where the gate tries it before the grants. Like grant, it is a
// local command for the grantor, never answered over the gate's socket.
func (e *env) approve(out io.Writer, id string, yes bool, ttl time.Duration) error {
	if !toolUseID.MatchString(id) {
		return fmt.Errorf("%q is not an ID a refusal names", id)
	}
	if ttl <= 0 || ttl > maxGrant {
		return fmt.Errorf("-ttl must be more than 0 and at most %s", maxGrant)
	}
	unlock, err := e.lock()
	if err != nil {
		return err
	}
	defer unlock()
	b, err := os.ReadFile(e.requestPath(id))
	if err != nil {
		return fmt.Errorf("no refused call %s waits for approval (%v)", id, err)
	}
	// Decoded the way the protocol decodes, so integers stay integers and the
	// approval pins exactly the values the refused call carried.
	obj, err := wire.Decode(b)
	if err != nil {
		return fmt.Errorf("request %s: %v", id, err)
	}
	op, _ := obj["op"].(string)
	args, okArgs := obj["args"].(map[string]any)
	grantObj, okGrant := obj["grant"].(map[string]any)
	atNum, _ := obj["at"].(json.Number)
	at, _ := atNum.Int64()
	if op == "" || !okArgs || !okGrant {
		return fmt.Errorf("request %s is incomplete", id)
	}
	shown, _ := json.MarshalIndent(args, "  ", "  ")
	fmt.Fprintf(out, "%s, refused %s, with:\n  %s\n", op, time.Unix(at, 0).Format(time.RFC3339), shown)
	if !yes {
		fmt.Fprintf(out, "nothing signed; run again with -yes to approve exactly this call, once, for %s\n", ttl)
		return nil
	}
	root, err := loadKey(filepath.Join(e.home, "root.seed"))
	if err != nil {
		return fmt.Errorf("no grantor key; approve as the user that ran writ-hook init (%v)", err)
	}
	grant, err := writ.ParseWrit(grantObj)
	if err != nil {
		return fmt.Errorf("request %s: %v", id, err)
	}
	a, err := writ.Approve(root, nil, grant, op, args, e.now()+int64(ttl/time.Second))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.path("approvals"), 0o700); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(e.path("approvals"), id+".json"), a.Raw); err != nil {
		return err
	}
	if err := os.Remove(e.requestPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(out, "approved %s once, until %s; the same call will now run\n", a.ID, time.Unix(a.Exp, 0).Format(time.RFC3339))
	return nil
}

// auditRefusal records a call this program refuses before it reaches the
// executor, such as one that names Writ's own keys, so the audit record holds
// every refusal (spec 9.3). The call is refused whether or not this lands.
func (e *env) auditRefusal(h *hookInput, code string) {
	unlock, err := e.lock()
	if err != nil {
		return
	}
	defer unlock()
	al, err := exec.OpenAuditLog(e.path("audit.jsonl"))
	if err != nil {
		return
	}
	defer al.Close()
	_ = al.Record(exec.AuditEntry{At: e.now(), Kind: "call", Op: "claude/" + h.ToolName, Outcome: "rejected", Reason: code})
}

func adapterCode(why string) string {
	switch {
	case strings.Contains(why, "Writ's own keys"):
		return "claude/protected_state"
	case strings.Contains(why, "not a clean path"):
		return "claude/unclean_path"
	case strings.Contains(why, `own "tool" member`):
		return "claude/tool_member"
	}
	return "claude/unreadable_input"
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
	_, obj, err := readPending(e.pendingPath(h.ToolUseID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // not a call this gate admitted
	}
	if err != nil {
		return nil, err
	}
	id, err := grantOf(obj)
	if err != nil {
		return nil, err
	}
	g, err := e.openGate()
	if err != nil {
		return nil, err
	}
	defer g.close()
	if err := g.use(id); err != nil {
		return nil, err
	}
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
	names := e.stateNames()
	var found string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, n := range names {
				if strings.Contains(x, n) {
					found = "the call names Writ's own keys and state, which no grant covers"
				}
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

// stateNames are the ways a tool input names WRIT_HOME as text: the path
// itself and, when it is under the home directory, its ~ and $HOME forms.
// Only this gate's own home: text about another, such as "~/.writ" in this
// project's documentation when WRIT_HOME is elsewhere, names nothing here.
// A Vault token file is named the same way, since its token signs as the
// grantor and the gate.
func (e *env) stateNames() []string {
	paths := []string{e.home}
	if f := os.Getenv("WRIT_VAULT_TOKEN_FILE"); f != "" {
		paths = append(paths, f)
	}
	var names []string
	h, _ := os.UserHomeDir()
	for _, p := range paths {
		names = append(names, p)
		if h == "" {
			continue
		}
		if rel, ok := strings.CutPrefix(p, strings.TrimSuffix(h, "/")+"/"); ok {
			names = append(names, "~/"+rel, "$HOME/"+rel, "${HOME}/"+rel)
		}
	}
	return names
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

// sessionStart reads the SessionStart hook input recover is given on stdin.
// It returns nil when stdin is a terminal or empty: a recover run by hand.
func sessionStart(in *os.File) (*hookInput, error) {
	if !piped(in) {
		return nil, nil
	}
	b, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return parseSessionStart(b)
}

func parseSessionStart(b []byte) (*hookInput, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var h hookInput
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("hook input: %v", err)
	}
	if h.SessionID == "" {
		return nil, errors.New("the hook input names no session_id, so recover cannot tell this session's unfinished calls from another's")
	}
	return &h, nil
}

func piped(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice == 0
}

// recover resolves calls admitted and never reported, because the tool was
// stopped, the person declined it at the permission prompt, or Claude Code
// exited, to unknown_outcome (spec 9).
//
// Run at a session start (h set), it resolves that session's own unfinished
// calls, none of which can still be running, and any older than staleAfter.
// Another session's recent calls are left alone: several sessions share one
// gate, and one of them may be in the middle of a tool call. Run by hand (h
// nil), when no session is live, it resolves every unfinished call in every
// store, including one admitted by a pre that crashed before it saved its
// pending file.
func (e *env) recover(out io.Writer, h *hookInput) error {
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
	unknown := exec.Result{St: "failed", ErrCode: string(writ.UnknownOutcome)}
	n := 0
	if h == nil {
		// Each call is resolved through Complete rather than the executor's
		// Recover, which signs the tally but writes no audit entry, so the
		// audit record would hold one entry fewer than the store.
		stores, _ := filepath.Glob(filepath.Join(e.dir, "stores", "*.json"))
		for _, s := range stores {
			if err := g.use(strings.TrimSuffix(filepath.Base(s), ".json")); err != nil {
				return err
			}
			var open []wire.Object
			for _, rec := range g.e.Store.Calls {
				if rec.Tally == nil && rec.Call != nil {
					open = append(open, rec.Call)
				}
			}
			for _, obj := range open {
				if rep, rej := g.e.Complete(context.Background(), obj, unknown); rep != nil && rej == nil {
					n++
				}
			}
		}
	}
	files, _ := filepath.Glob(filepath.Join(e.dir, "pending", "*.json"))
	for _, f := range files {
		p, obj, err := readPending(f)
		if err != nil {
			continue
		}
		at := p.At
		if at == 0 { // a pending file from before sessions were recorded
			if fi, err := os.Stat(f); err == nil {
				at = fi.ModTime().Unix()
			}
		}
		if h != nil && (p.Session == "" || p.Session != h.SessionID) && e.now()-at <= int64(staleAfter/time.Second) {
			continue
		}
		id, err := grantOf(obj)
		if err != nil {
			continue
		}
		if err := g.use(id); err != nil {
			return err
		}
		// A call already final, or never admitted, has nothing to resolve;
		// Complete would only audit it a second time.
		if g.isPending(obj) {
			if _, rej := g.e.Complete(context.Background(), obj, unknown); rej != nil {
				fmt.Fprintf(out, "could not resolve %s: %v\n", filepath.Base(f), rej)
				continue
			}
			n++
		}
		_ = os.Remove(f)
	}
	fmt.Fprintf(out, "resolved %d unfinished call(s) to unknown_outcome\n", n)
	return nil
}

// isPending reports whether the store open in g holds obj's call as admitted
// and not yet final. The call store is keyed "leaf|id" (exec.FileStore).
func (g *gate) isPending(obj wire.Object) bool {
	k, err := writ.ParseCall(obj)
	if err != nil {
		return false
	}
	rec, ok := g.e.Store.Calls[k.Leaf().ID+"|"+k.CID]
	return ok && rec.Tally == nil
}

// receipts verifies every receipt in every store against the chain it names,
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
	// store.json is the single store of a gate from before stores were kept
	// per grant.
	paths, _ := filepath.Glob(filepath.Join(e.dir, "stores", "*.json"))
	if _, err := os.Stat(e.path("store.json")); err == nil {
		paths = append([]string{e.path("store.json")}, paths...)
	}
	var recs []*exec.Record
	for _, p := range paths {
		st, err := exec.OpenFileStore(p)
		if err != nil {
			return false, err
		}
		for _, rec := range st.Calls {
			recs = append(recs, rec)
		}
	}
	byOutcome := map[string]int{}
	byTool := map[string]int{}
	valid, invalid, pending := 0, 0, 0
	for _, rec := range recs {
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
	refusals, linked := 0, true
	if b, err := os.ReadFile(e.path("audit.jsonl")); err == nil {
		refusals = bytes.Count(b, []byte(`"outcome":"failed"`)) + bytes.Count(b, []byte(`"outcome":"rejected"`)) - byOutcome["failed"]
		// Each entry links to the one before it (spec 9.3), so an entry
		// edited or removed since it was written shows here.
		if rep, err := exec.VerifyAudit(bytes.NewReader(b)); err == nil {
			linked = len(rep.Breaks) == 0
			if linked {
				fmt.Fprintf(out, "audit record: %d entries, every link intact\n", rep.Entries)
			} else {
				fmt.Fprintf(out, "audit record: %d entries, links broken at line(s) %v: an entry was edited, removed, or reordered\n", rep.Entries, rep.Breaks)
			}
		}
	}
	fmt.Fprintf(out, "%d refusal(s) in the audit record\n", refusals)
	return invalid == 0 && linked, nil
}
