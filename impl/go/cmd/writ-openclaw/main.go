// writ-openclaw is agent B with a model inside. It is a Writ executor for
// travel/book: when a call arrives, it hands the request to an OpenClaw agent
// run (openclaw agent exec) whose only way to pay is a charge_card tool. That
// tool is this same program, run by OpenClaw as an MCP server over stdio
// ("writ-openclaw tool"): for each charge it narrows the writ B was given to
// one payment writ for C, calls C, and checks C's tally. The model decides
// what to charge; the writ decides what it can. When the run ends, B signs a
// tally that embeds every tally C returned.
//
// The tool runs in OpenClaw's child process, so the writs it issues and the
// tallies it receives are kept in the call's directory rather than in B's
// store: spec 7.5's crash safety for them is not provided here.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"writproto/exec"
	"writproto/httpbind"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "tool" {
		if err := serveTool(os.Stdin, os.Stdout, toolEnv()); err != nil {
			log.Fatal(err)
		}
		return
	}
	seedFile := flag.String("seed-file", "", "file holding B's 32-byte hex seed")
	host := flag.String("addr", "127.0.0.1", "listen address")
	port := flag.Int("port", 8081, "listen port")
	accept := flag.String("accept", "", "comma-separated did:key roots B acts under")
	downstream := flag.String("downstream", "", "base URL of the payment agent C")
	openclaw := flag.String("openclaw", "openclaw", "the openclaw command")
	model := flag.String("model", "anthropic/claude-haiku-5-5", "the model OpenClaw runs")
	timeout := flag.Duration("timeout", 4*time.Minute, "longest one OpenClaw run may take")
	flag.Parse()
	id, err := loadSeed(*seedFile)
	if err != nil {
		log.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	st, _ := exec.OpenFileStore("")
	e := exec.New(id, st)
	roots := map[string]bool{}
	for _, r := range strings.Split(*accept, ",") {
		if r != "" {
			roots[r] = true
		}
	}
	e.AcceptRoot = func(did string) bool { return roots[did] }
	a := &agentB{self: self, seedFile: *seedFile, downstream: *downstream, openclaw: *openclaw, model: *model, timeout: *timeout}
	e.Handle = a.book
	wk := httpbind.WellKnown{V: 1, DID: id.DID(), Endpoint: "/writ", Act: []string{"travel/book"}}
	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("booking agent %s (OpenClaw, %s) listening on %s", id.DID(), *model, addr)
	log.Fatal(http.ListenAndServe(addr, httpbind.NewHandler(e, wk, httpbind.Options{})))
}

func loadSeed(path string) (*keys.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed: %v", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != 32 {
		return nil, errors.New("seed must be 32 bytes of hex")
	}
	return keys.FromSeed(seed)
}

// ---------------------------------------------------------------- agent B

type agentB struct {
	self, seedFile, downstream, openclaw, model string
	timeout                                     time.Duration
}

// book runs one OpenClaw turn for a travel/book call and signs for what it
// paid. The request text in the call's "request" argument goes to the model
// as is: it is untrusted input, and the writ is what bounds its effect.
func (a *agentB) book(ctx context.Context, k *writ.Call) exec.Result {
	dir, err := os.MkdirTemp("", "writ-call-")
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "app/no_workdir"}
	}
	defer os.RemoveAll(dir)
	if err := writeJSON(filepath.Join(dir, "call.json"), k.Raw); err != nil {
		return exec.Result{St: "failed", ErrCode: "app/no_workdir"}
	}
	cfg := map[string]any{"mcp": map[string]any{"servers": map[string]any{"pay": map[string]any{
		"command": a.self, "args": []string{"tool"},
		"env": map[string]string{"WRIT_CALL_DIR": dir, "WRIT_SEED_FILE": a.seedFile, "WRIT_DOWNSTREAM": a.downstream},
	}}}}
	if err := writeJSON(filepath.Join(dir, "openclaw.json"), cfg); err != nil {
		return exec.Result{St: "failed", ErrCode: "app/no_workdir"}
	}
	request, _ := k.Args["request"].(string)
	task := "You are a travel booking agent. A customer sent this request:\n\n" + request +
		"\n\nBook it. The only way to pay is the charge_card tool, in US cents. " +
		"If the tool refuses a charge, report the refusal word for word and do not try other amounts. " +
		"End your reply with the receipt id, or with REFUSED."
	runCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	cmd := osexec.CommandContext(runCtx, a.openclaw, "agent", "exec", task,
		"--config", filepath.Join(dir, "openclaw.json"), "--model", a.model, "--json", "--cwd", dir)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	var env struct {
		Final   string  `json:"final"`
		CostUSD float64 `json:"costUsd"`
	}
	_ = json.Unmarshal(out.Bytes(), &env)
	log.Printf("openclaw run for call %s: err=%v cost=$%.4f final=%q", k.ID, runErr, env.CostUSD, env.Final)
	r := collect(dir, k)
	r.Res = map[string]any{"agent_reply": env.Final, "charges": len(r.Sub)}
	return r
}

// collect reads the payments the tool made during the run and turns them
// into B's result: each C tally verified under the writ B issued for it,
// embedded with that writ, and the amounts C charged as B's consumption.
func collect(dir string, k *writ.Call) exec.Result {
	r := exec.Result{St: "failed", ErrCode: "app/not_paid"}
	b, err := os.ReadFile(filepath.Join(dir, "payments.jsonl"))
	if err != nil {
		return r
	}
	var used int64
	paid := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		obj, err := wire.Decode(sc.Bytes())
		if err != nil {
			continue
		}
		w, err1 := writ.ParseWrit(asObject(obj["writ"]))
		kc, err2 := writ.ParseCall(asObject(obj["call"]))
		if err1 != nil || err2 != nil || kc.Chain[len(kc.Chain)-2].ID != k.Leaf().ID {
			continue
		}
		v, t, _ := writ.VerifyTally(w, kc, asObject(obj["tally"]), obj["res"])
		if v != writ.Valid {
			continue
		}
		r.Sub = append(r.Sub, t)
		r.Wrt = append(r.Wrt, w)
		if t.St == "ok" {
			paid = true
			used += t.Used["amount"]
		}
	}
	if paid {
		r.St, r.ErrCode = "ok", ""
		r.Used = map[string]int64{"amount": used}
	}
	return r
}

func asObject(v any) wire.Object {
	m, _ := v.(map[string]any)
	return m
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ---------------------------------------------------------------- the tool

type toolConfig struct {
	dir, seedFile, downstream string
	client                    *httpbind.Client
}

func toolEnv() toolConfig {
	return toolConfig{dir: os.Getenv("WRIT_CALL_DIR"), seedFile: os.Getenv("WRIT_SEED_FILE"),
		downstream: os.Getenv("WRIT_DOWNSTREAM"), client: httpbind.NewClient()}
}

// serveTool is a minimal MCP server over stdio with one tool, charge_card.
func serveTool(in io.Reader, out io.Writer, c toolConfig) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(m.ID) == 0 {
			continue // a notification
		}
		var result any
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(m.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-06-18"
			}
			result = map[string]any{"protocolVersion": p.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "writ-pay", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{
				"name":        "charge_card",
				"description": "Charge the customer's card through the payment processor. amount_cents is the total in US cents.",
				"inputSchema": map[string]any{"type": "object", "required": []string{"amount_cents"},
					"properties": map[string]any{"amount_cents": map[string]any{"type": "integer"}, "memo": map[string]any{"type": "string"}}},
			}}}
		case "tools/call":
			var p struct {
				Name      string `json:"name"`
				Arguments struct {
					Amount json.Number `json:"amount_cents"`
				} `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			text, failed := c.charge(context.Background(), p.Arguments.Amount)
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": failed}
		default:
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			continue
		}
		if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result}); err != nil {
			return err
		}
	}
}

// charge narrows B's writ to one payment writ for exactly this amount, sends
// the charge to C, checks C's tally, and keeps the three in the call's
// directory. It returns the text the model sees and whether it failed.
func (c toolConfig) charge(ctx context.Context, amountArg json.Number) (string, bool) {
	amount, err := amountArg.Int64()
	if err != nil || amount <= 0 {
		return "charge_card needs amount_cents, a positive whole number of cents.", true
	}
	b, err := os.ReadFile(filepath.Join(c.dir, "call.json"))
	if err != nil {
		return "no booking in progress", true
	}
	obj, err := wire.Decode(b)
	if err != nil {
		return "no booking in progress", true
	}
	k, err := writ.ParseCall(obj)
	if err != nil {
		return "no booking in progress", true
	}
	B, err := loadSeed(c.seedFile)
	if err != nil {
		return "the payment tool has no key", true
	}
	wk, err := c.client.Discover(ctx, c.downstream)
	if err != nil {
		return "the payment processor is unreachable", true
	}
	leaf := k.Leaf()
	bnd := map[string]any{}
	for name, bd := range leaf.Bnd {
		bnd[name] = map[string]any{"t": bd.T, "v": bd.Raw}
	}
	bnd["act"] = map[string]any{"t": "prefix", "v": "travel/charge"}
	bnd["amount"] = map[string]any{"t": "max", "v": amount}
	bnd["uses"] = map[string]any{"t": "count", "v": 1}
	exp := leaf.Exp
	if now := time.Now().Unix() + 900; now < exp {
		exp = now
	}
	w2, err := writ.Issue(B, wk.DID, bnd, exp, leaf)
	if err != nil {
		return "Refused by Writ before anything was sent: " + err.Error(), true
	}
	args := map[string]any{"amount": amount}
	if cur, ok := leaf.Bnd["currency"]; ok && cur.T == "set" {
		args["currency"] = "USD"
	}
	kc, err := writ.NewCall(B, append(append([]*writ.Writ{}, k.Chain...), w2), "travel/charge", args)
	if err != nil {
		return "could not build the charge: " + err.Error(), true
	}
	tally, res, err := c.client.Call(ctx, c.downstream+wk.Endpoint, kc)
	if err != nil {
		return "the payment processor did not answer: " + err.Error(), true
	}
	v, t, verr := writ.VerifyTally(w2, kc, tally, res)
	if v != writ.Valid {
		return fmt.Sprintf("the processor's receipt did not verify: %s %v", v, verr), true
	}
	line, _ := json.Marshal(map[string]any{"writ": w2.Raw, "call": kc.Raw, "tally": tally, "res": res})
	f, err := os.OpenFile(filepath.Join(c.dir, "payments.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
	if t.St != "ok" {
		code := t.St
		if t.Err != nil {
			code = t.Err.Code
		}
		return "The payment processor refused the charge: " + code, true
	}
	return fmt.Sprintf("Charged $%d.%02d. Receipt %s", amount/100, amount%100, t.ID), false
}
