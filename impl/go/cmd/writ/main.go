// writ is the command-line tool: keys, issuing and narrowing writs, sending
// calls, verifying tallies, revoking, and running the conformance corpus.
//
//	writ keygen -seed <hex32>                       print the did:key for a seed
//	writ issue -seed <hex> -hld <did> -bnd <json> -exp <unix> [-parent <writ.json>] > writ.json
//	writ call -seed <hex> -chain <writ.json,...> -op <op> -args <json> > call.json
//	writ send -endpoint <url> -call <call.json> [-out <reply.json>]
//	writ verify -writ <leaf.json> -call <call.json> -tally <tally.json> [-res <res.json>]
//	writ revoke -seed <hex> -chain <writ.json,...> > revoke.json
//	writ approve -chain <writ.json,...> -op <op> -args <json>          print who can approve a refused call
//	writ approve -seed <hex> -chain <writ.json,...> -op <op> -args <json> -exp <unix> [-at <i>] > approval.json
//	writ inspect <object.json>                       print type, identity, and signer
//	writ conformance <dir>                           run every vector, exit non-zero on failure
//	writ scenarios <dir>                             run every executor scenario, exit non-zero on failure
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"writproto/conformance"
	"writproto/httpbind"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

func identity(seedHex string) *keys.Identity {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		die("seed must be 32 bytes of hex")
	}
	id, _ := keys.FromSeed(seed)
	return id
}

func readObj(path string) wire.Object {
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	o, err := wire.Decode(b)
	if err != nil {
		die("%s: %v", path, err)
	}
	return o
}

func readChain(list string) []*writ.Writ {
	var chain []*writ.Writ
	for _, p := range strings.Split(list, ",") {
		w, err := writ.ParseWrit(readObj(p))
		if err != nil {
			die("%s: %v", p, err)
		}
		chain = append(chain, w)
	}
	return chain
}

func emit(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) < 2 {
		die("usage: writ <keygen|issue|call|send|verify|revoke|approve|inspect|conformance|scenarios> ...")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "keygen":
		seed := fs.String("seed", "", "32-byte hex seed")
		_ = fs.Parse(args)
		if *seed == "" {
			id, _ := keys.Generate()
			fmt.Println(id.DID())
			fmt.Fprintln(os.Stderr, "seed:", hex.EncodeToString(id.Priv.Seed()))
			return
		}
		fmt.Println(identity(*seed).DID())
	case "issue":
		seed := fs.String("seed", "", "issuer seed")
		hld := fs.String("hld", "", "holder did:key")
		bndJSON := fs.String("bnd", "", "bounds JSON")
		exp := fs.Int64("exp", 0, "expiry, unix seconds")
		parent := fs.String("parent", "", "parent writ file (narrowing)")
		_ = fs.Parse(args)
		var bnd map[string]any
		if err := json.Unmarshal([]byte(*bndJSON), &bnd); err != nil {
			die("bnd: %v", err)
		}
		var p *writ.Writ
		if *parent != "" {
			var err error
			if p, err = writ.ParseWrit(readObj(*parent)); err != nil {
				die("%v", err)
			}
		}
		w, err := writ.Issue(identity(*seed), *hld, bnd, *exp, p)
		if err != nil {
			die("%v", err)
		}
		emit(w.Raw)
	case "approve":
		// Approval is delegation (docs/approval.md): the issuer of the first
		// writ that refuses the call issues a one-use writ for it in that
		// writ's place, and each holder below re-issues its own writ under it
		// with -at 1 and a chain of the new writ followed by its old one.
		seed := fs.String("seed", "", "approver seed; without it, print who the approver is")
		chain := fs.String("chain", "", "comma-separated writ files, root first")
		op := fs.String("op", "", "operation of the refused call")
		argsJSON := fs.String("args", "{}", "args JSON of the refused call")
		exp := fs.Int64("exp", 0, "expiry of the approval, unix seconds")
		at := fs.Int("at", -1, "index of the writ to replace (default: the first that refuses the call)")
		_ = fs.Parse(args)
		dec := json.NewDecoder(strings.NewReader(*argsJSON))
		dec.UseNumber()
		var a map[string]any
		if err := dec.Decode(&a); err != nil {
			die("args: %v", err)
		}
		ch := readChain(*chain)
		j := *at
		if j < 0 {
			j = writ.ApprovalPoint(ch, *op, a)
		}
		if j < 0 {
			die("every writ in the chain admits this call, so its refusal was not about its operation or arguments, and approval cannot help")
		}
		if j >= len(ch) {
			die("-at %d: the chain has %d writs", j, len(ch))
		}
		if *seed == "" {
			fmt.Println(ch[j].Iss)
			fmt.Fprintf(os.Stderr, "the approver is the issuer of writ %d, printed above\n", j)
			return
		}
		var parent *writ.Writ
		if j > 0 {
			parent = ch[j-1]
		}
		w, err := writ.Approve(identity(*seed), parent, ch[j], *op, a, *exp)
		if err != nil {
			die("%v", err)
		}
		emit(w.Raw)
		if j < len(ch)-1 {
			fmt.Fprintf(os.Stderr, "this approval replaces writ %d; its holder %s re-issues writ %d under it with -at 1\n", j, ch[j].Hld, j+1)
		}
	case "call":
		seed := fs.String("seed", "", "caller seed")
		chain := fs.String("chain", "", "comma-separated writ files, root first")
		op := fs.String("op", "", "operation")
		argsJSON := fs.String("args", "{}", "args JSON")
		_ = fs.Parse(args)
		var a map[string]any
		if err := json.Unmarshal([]byte(*argsJSON), &a); err != nil {
			die("args: %v", err)
		}
		k, err := writ.NewCall(identity(*seed), readChain(*chain), *op, a)
		if err != nil {
			die("%v", err)
		}
		emit(k.Raw)
	case "send":
		endpoint := fs.String("endpoint", "", "executor endpoint URL")
		call := fs.String("call", "", "call file")
		_ = fs.Parse(args)
		obj := readObj(*call)
		k, err := writ.ParseCall(obj)
		if err != nil {
			die("%v", err)
		}
		tally, res, err := httpbind.NewClient().Call(context.Background(), *endpoint, k)
		if err != nil {
			die("%v", err)
		}
		emit(map[string]any{"tally": tally, "res": res})
	case "verify":
		wf := fs.String("writ", "", "leaf writ file")
		cf := fs.String("call", "", "call file")
		tf := fs.String("tally", "", "tally file")
		rf := fs.String("res", "", "result body file (optional)")
		_ = fs.Parse(args)
		w, err := writ.ParseWrit(readObj(*wf))
		if err != nil {
			die("writ: %v", err)
		}
		k, err := writ.ParseCall(readObj(*cf))
		if err != nil {
			die("call: %v", err)
		}
		var res any
		if *rf != "" {
			res = readObj(*rf)
		}
		v, t, err := writ.VerifyTally(w, k, readObj(*tf), res)
		out := map[string]any{"verdict": string(v)}
		if err != nil {
			out["reason"] = string(writ.CodeOf(err))
			out["detail"] = err.Error()
		}
		if t != nil {
			out["st"] = t.St
			out["executor"] = w.Hld
			out["sub"] = len(t.Sub)
		}
		emit(out)
		if v != writ.Valid {
			os.Exit(1)
		}
	case "revoke":
		seed := fs.String("seed", "", "revoker seed")
		chain := fs.String("chain", "", "comma-separated writ files, root to the revoked writ")
		_ = fs.Parse(args)
		var c []*writ.Writ
		if *chain != "" {
			c = readChain(*chain)
		}
		r, err := writ.NewRevoke(identity(*seed), c)
		if err != nil {
			die("%v", err)
		}
		emit(r.Raw)
	case "inspect":
		if len(args) != 1 {
			die("usage: writ inspect <file>")
		}
		obj := readObj(args[0])
		id, _ := wire.Hash(obj)
		typ, _ := obj["typ"].(string)
		signer := ""
		for _, k := range []string{"iss", "from"} {
			if s, ok := obj[k].(string); ok {
				signer = s
			}
		}
		emit(map[string]any{"typ": typ, "id": id, "signer": signer})
	case "conformance":
		if len(args) != 1 {
			die("usage: writ conformance <dir>")
		}
		pass, fail, report := conformance.RunDir(args[0])
		fmt.Print(report)
		fmt.Printf("%d passed, %d failed\n", pass, fail)
		if fail > 0 {
			os.Exit(1)
		}
	case "scenarios":
		if len(args) != 1 {
			die("usage: writ scenarios <dir>")
		}
		pass, fail, report := conformance.RunScenarioDir(args[0])
		fmt.Print(report)
		fmt.Printf("%d passed, %d failed\n", pass, fail)
		if fail > 0 {
			os.Exit(1)
		}
	default:
		die("unknown command %q", cmd)
	}
}
