// writ-demo is agent A. It discovers B, delegates a bounded task, verifies the
// tally tree that comes back (B's tally embedding C's), reverses C's charge
// directly, demonstrates six rejected attempts, and cancels an in-flight task
// with a revoke. Every object exchanged is written to the transcript directory.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"writproto/httpbind"
	"writproto/keys"
	"writproto/writ"
)

var out string

func save(name string, v any) {
	if out == "" {
		return
	}
	b, _ := json.MarshalIndent(v, "", " ")
	_ = os.WriteFile(filepath.Join(out, name+".json"), b, 0o644)
}

func step(format string, a ...any) { fmt.Printf("\n== "+format+"\n", a...) }
func line(format string, a ...any) { fmt.Printf("   "+format+"\n", a...) }

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func main() {
	seedHex := flag.String("seed", "0101010101010101010101010101010101010101010101010101010101010101", "A's key seed")
	bURL := flag.String("b", "http://127.0.0.1:8081", "agent B base URL")
	cURL := flag.String("c", "http://127.0.0.1:8082", "agent C base URL")
	flag.StringVar(&out, "out", "", "directory for the JSON transcript")
	flag.Parse()
	if out != "" {
		_ = os.MkdirAll(out, 0o755)
	}
	seed, _ := hex.DecodeString(*seedHex)
	A, _ := keys.FromSeed(seed)
	ctx := context.Background()
	client := httpbind.NewClient()
	now := time.Now().Unix()
	failures := 0
	expect := func(cond bool, format string, a ...any) {
		if cond {
			line("PASS "+format, a...)
		} else {
			failures++
			line("FAIL "+format, a...)
		}
	}

	step("1. Discovery: A reads B's well-known document")
	bwk, err := client.Discover(ctx, *bURL)
	if err != nil {
		fmt.Println("cannot reach B:", err)
		os.Exit(1)
	}
	cwk, err := client.Discover(ctx, *cURL)
	if err != nil {
		fmt.Println("cannot reach C:", err)
		os.Exit(1)
	}
	line("A  = %s", A.DID())
	line("B  = %s  accepts %v", bwk.DID, bwk.Act)
	line("C  = %s  accepts %v (A learned this only to send the undo; the tally names C by key)", cwk.DID, cwk.Act)

	step("2. A issues writ_1 to B: travel, at most 60000 USD, once, refundable, dates 20261015 to 20261019, 1 hour")
	w1, err := writ.Issue(A, bwk.DID, bnd(
		"act", "prefix", "travel",
		"amount", "max", 60000,
		"currency", "set", []any{"USD"},
		"uses", "count", 1,
		"fare", "set", []any{"refundable"},
		"date", "window", []any{20261015, 20261019},
	), now+3600, nil)
	if err != nil {
		panic(err)
	}
	save("writ_1", w1.Raw)
	line("writ_1 = %s", short(w1.ID))

	step("3. A calls B: travel/book")
	args := map[string]any{"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261015}
	k1, _ := writ.NewCall(A, []*writ.Writ{w1}, "travel/book", args)
	save("call_A_to_B", k1.Raw)
	tobj, res, err := client.Call(ctx, *bURL+bwk.Endpoint, k1)
	if err != nil {
		panic(err)
	}
	save("tally_B", tobj)
	save("res_B", res)

	step("4. A verifies the tally tree with nothing but writ_1, its own call, and the keys inside the objects")
	v, tB, verr := writ.VerifyTally(w1, k1, tobj, res)
	expect(v == writ.Valid && tB.St == "ok", "tally_B verdict=%s st=%s err=%v", v, tB.St, verr)
	line("B (%s) did %s, used amount=%d, reversible until %d", short(bwk.DID), tB.Op, tB.Used["amount"], *tB.Rev)
	var tC *writ.Tally
	var w2 *writ.Writ
	for _, s := range tB.Sub {
		for _, w := range tB.Wrt {
			if w.ID == s.Writ {
				tC, w2 = s, w
			}
		}
	}
	expect(tC != nil, "tally_B embeds one sub-tally and the writ it ran under")
	if tC == nil {
		os.Exit(1)
	}
	line("B narrowed writ_1 into writ_2 for %s: act=%q amount<=%d uses<=%d exp-%ds",
		short(w2.Hld), w2.Bnd["act"].Str, w2.Bnd["amount"].Int, w2.Bnd["uses"].Int, w1.Exp-w2.Exp)
	line("C (%s) did %s, used amount=%d, reversible until %d", short(w2.Hld), tC.Op, tC.Used["amount"], *tC.Rev)
	expect(w2.Hld == cwk.DID, "the executor key in writ_2 is C's key")
	expect(tC.Used["amount"] <= w2.Bnd["amount"].Int && w2.Bnd["amount"].Int <= w1.Bnd["amount"].Int, "authority only narrowed along the chain")
	line("result body: %v", res)

	step("5. A reverses C's charge directly, without B, by standing as an issuer on the chain")
	ku, _ := writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/undo", map[string]any{"tally": tC.Raw})
	save("call_A_undo_C", ku.Raw)
	uobj, ures, err := client.Call(ctx, *cURL+cwk.Endpoint, ku)
	if err != nil {
		panic(err)
	}
	save("tally_C_undo", uobj)
	uv, tU, uerr := writ.VerifyTally(w2, ku, uobj, ures)
	expect(uv == writ.Valid && tU.St == "ok", "undo tally verdict=%s st=%s err=%v res=%v", uv, tU.St, uerr, ures)
	uobj2, ures2, _ := client.Call(ctx, *cURL+cwk.Endpoint, ku)
	_, tU2, _ := writ.VerifyTally(w2, ku, uobj2, ures2)
	expect(tU2 != nil && tU2.St == "ok", "a repeated undo is idempotent (same outcome, no second refund)")

	step("6. Rejected attempts, each answered with a signed refusal naming the reason")
	// a. widening locally
	_, err = writ.Issue(A, bwk.DID, bnd("act", "prefix", "travel", "amount", "max", 65000), now+3600, w1)
	expect(writ.CodeOf(err) == writ.ChainBroken, "A cannot issue a child of writ_1 because only its holder B can: %v", writ.CodeOf(err))
	try := func(name string, url string, k *writ.Call, leaf *writ.Writ, want writ.Reason) {
		tob, r, err := client.Call(ctx, url, k)
		if err != nil {
			expect(false, "%s: transport error %v", name, err)
			return
		}
		_, t, _ := writ.VerifyTally(leaf, k, tob, r)
		got := writ.Reason("")
		if t != nil && t.Err != nil {
			got = writ.Reason(t.Err.Code)
		}
		expect(got == want, "%s: %s", name, got)
		save("refusal_"+string(want), tob)
	}
	k, _ := writ.NewCall(A, []*writ.Writ{w1}, "travel/book", map[string]any{"amount": 61000, "currency": "USD", "fare": "refundable", "date": 20261015})
	try("amount 61000 under max 60000", *bURL+bwk.Endpoint, k, w1, writ.OutOfBounds)
	k, _ = writ.NewCall(A, []*writ.Writ{w1}, "travel/book", map[string]any{"currency": "USD", "fare": "refundable", "date": 20261015})
	try("amount omitted", *bURL+bwk.Endpoint, k, w1, writ.MissingArg)
	k, _ = writ.NewCall(A, []*writ.Writ{w1}, "admin/delete", args)
	try("op admin/delete under act travel", *bURL+bwk.Endpoint, k, w1, writ.ForbiddenOp)
	k, _ = writ.NewCall(A, []*writ.Writ{w1}, "travelx", args)
	try("op travelx under act travel (segment rule)", *bURL+bwk.Endpoint, k, w1, writ.ForbiddenOp)
	k, _ = writ.NewCall(A, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1, "currency": "USD", "fare": "refundable", "date": 20261015})
	try("A calling C directly under B's leaf (only B has standing)", *cURL+cwk.Endpoint, k, w2, writ.NoStanding)
	k, _ = writ.NewCall(A, []*writ.Writ{w1}, "travel/book", args)
	try("second use of writ_1 (count 1)", *bURL+bwk.Endpoint, k, w1, writ.CountExhausted)
	S, _ := keys.FromSeed([]byte("stranger-stranger-stranger-strng"))
	ws, _ := writ.Issue(S, bwk.DID, bnd("act", "prefix", "travel"), now+3600, nil)
	k, _ = writ.NewCall(S, []*writ.Writ{ws}, "travel/book", map[string]any{})
	tob, _, _ := client.Call(ctx, *bURL+bwk.Endpoint, k)
	ts, _ := writ.ParseTally(tob, bwk.DID)
	expect(ts != nil && ts.Err != nil && ts.Err.Code == string(writ.RootNotAccepted), "a stranger's self-issued root: %v", ts.Err.Code)

	step("7. Cancellation: A revokes writ_1b while B is mid-task; B forwards the revoke to C")
	w1b, _ := writ.Issue(A, bwk.DID, bnd("act", "prefix", "travel", "amount", "max", 60000, "currency", "set", []any{"USD"},
		"uses", "count", 1, "fare", "set", []any{"refundable"}, "date", "window", []any{20261015, 20261019}), now+3600, nil)
	save("writ_1b", w1b.Raw)
	kslow, _ := writ.NewCall(A, []*writ.Writ{w1b}, "travel/book", map[string]any{"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261015, "slow": true})
	type reply struct {
		t   map[string]any
		res any
		err error
	}
	done := make(chan reply, 1)
	go func() {
		t, r, err := client.Call(ctx, *bURL+bwk.Endpoint, kslow)
		done <- reply{t, r, err}
	}()
	time.Sleep(1 * time.Second)
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w1b})
	save("revoke_1b", rv.Raw)
	pending, err := client.Revoke(ctx, *bURL+bwk.Endpoint, rv)
	expect(err == nil && len(pending) == 1, "B answered the revoke with %d pending tally(ies)", len(pending))
	rep := <-done
	expect(rep.err == nil, "the in-flight call returned")
	_, tcan, _ := writ.VerifyTally(w1b, kslow, rep.t, rep.res)
	expect(tcan != nil && tcan.St == "canceled", "the in-flight call's final tally is st=%s", tcan.St)
	save("tally_B_canceled", rep.t)
	k, _ = writ.NewCall(A, []*writ.Writ{w1b}, "travel/book", args)
	try("a new call under the revoked writ", *bURL+bwk.Endpoint, k, w1b, writ.Revoked)

	step("8. Recovery: A asks C directly what ran under writ_1 (sys/tallies)")
	kt, _ := writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})
	tobj, res, err = client.Call(ctx, *cURL+cwk.Endpoint, kt)
	if err != nil {
		panic(err)
	}
	tv, tt, _ := writ.VerifyTally(w2, kt, tobj, res)
	n := 0
	if m, ok := res.(map[string]any); ok {
		if arr, ok := m["tallies"].([]any); ok {
			n = len(arr)
		}
	}
	expect(tv == writ.Valid && tt.St == "ok" && n >= 2, "C returned %d executed tallies under writ_1 (the charge and its undo) in a signed answer", n)

	fmt.Println()
	if failures == 0 {
		fmt.Println("DEMO PASSED: every expectation held")
	} else {
		fmt.Printf("DEMO FAILED: %d expectation(s) did not hold\n", failures)
		os.Exit(1)
	}
}
