// writ-scenarios regenerates the executor scenarios (spec section 14.1) from
// fixed seeds and fixed nonces. Every step states the outcome the spec
// requires, and generation stops if this executor answers anything else, so
// the corpus records the rule and not merely what the reference happens to do.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"writproto/conformance"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

const now = int64(1788400000)

var seq int

func nonce() string {
	seq++
	return wire.B64.EncodeToString([]byte(fmt.Sprintf("scene-%010d", seq))) // 16 bytes
}

func id(n byte) *keys.Identity {
	i, _ := keys.FromSeed(bytes.Repeat([]byte{n}, 32))
	return i
}

func seedHex(n byte) string { return strings.Repeat(fmt.Sprintf("%02x", n), 32) }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

func issue(iss *keys.Identity, hld *keys.Identity, b map[string]any, exp int64, parent *writ.Writ) *writ.Writ {
	return must(writ.Issue(iss, hld.DID(), b, exp, parent))
}

func call(from *keys.Identity, chain []*writ.Writ, op string, args map[string]any) *writ.Call {
	return must(writ.NewCall(from, chain, op, args))
}

// resigned copies obj, applies f, and signs it with signer.
func resigned(obj wire.Object, signer *keys.Identity, f func(o wire.Object)) wire.Object {
	o := must(wire.Clone(obj))
	f(o)
	b, _ := json.Marshal(o)
	o = must(wire.Decode(b))
	_ = wire.Sign(o, signer)
	return o
}

func ok(res any) *conformance.App { return &conformance.App{St: "ok", Res: res} }
func i64(v int64) *int64          { return &v }

type builder struct {
	sc conformance.Scenario
	d  *conformance.Driver
}

var (
	dir   string
	count int
	A     = id(1) // root issuer
	B     = id(2) // intermediate
	C     = id(3) // the executor under test
	D     = id(4) // a second accepted root
	S     = id(9) // a stranger
)

func scenario(name string, accept ...*keys.Identity) *builder {
	b := &builder{}
	b.sc.Name = name
	b.sc.Executor.Seed = seedHex(3)
	for _, a := range accept {
		b.sc.Executor.Accept = append(b.sc.Executor.Accept, a.DID())
	}
	b.d = must(conformance.NewDriver(b.sc.Executor.Seed, b.sc.Executor.Accept))
	return b
}

// outcome names an answer the way the builder's want strings do.
func outcome(v any) string {
	m, _ := v.(map[string]any)
	switch {
	case m["error"] != nil:
		return "error:" + m["error"].(string)
	case m["inflight"] != nil:
		return "inflight"
	case m["resolved"] != nil:
		return fmt.Sprintf("resolved:%d", m["resolved"])
	case m["tallies"] != nil:
		return fmt.Sprintf("tallies:%d", len(m["tallies"].([]any)))
	case m["tally"] != nil:
		t := m["tally"].(wire.Object)
		s := t["st"].(string)
		if e, ok := t["err"].(map[string]any); ok {
			s += ":" + e["code"].(string)
		}
		if res, ok := m["res"].(map[string]any); ok {
			if ts, ok := res["tallies"].([]any); ok {
				s += fmt.Sprintf(" with %d", len(ts))
			}
		}
		return s
	}
	return fmt.Sprintf("%v", v)
}

func (b *builder) run(s conformance.Step, want string) any {
	got, err := b.d.Run(&s)
	if err != nil {
		panic(fmt.Sprintf("%s, step %d (%s): %v", b.sc.Name, len(b.sc.Steps)+1, s.Note, err))
	}
	if o := outcome(got); o != want {
		panic(fmt.Sprintf("%s, step %d (%s): executor answered %s, the spec requires %s", b.sc.Name, len(b.sc.Steps)+1, s.Note, o, want))
	}
	s.Expect = must(json.Marshal(got))
	b.sc.Steps = append(b.sc.Steps, s)
	return got
}

func tallyOf(v any) wire.Object {
	t, _ := v.(map[string]any)["tally"].(wire.Object)
	return t
}

func (b *builder) call(at int64, k *writ.Call, app *conformance.App, want, note string) wire.Object {
	return tallyOf(b.run(conformance.Step{Do: "call", Note: note, Now: at, Call: must(json.Marshal(k.Raw)), App: app}, want))
}

func (b *builder) callObj(at int64, obj wire.Object, app *conformance.App, want, note string) {
	b.run(conformance.Step{Do: "call", Note: note, Now: at, Call: must(json.Marshal(obj)), App: app}, want)
}

func (b *builder) revoke(at int64, r wire.Object, want, note string) {
	b.run(conformance.Step{Do: "revoke", Note: note, Now: at, Revoke: must(json.Marshal(r))}, want)
}

func (b *builder) finish(k *writ.Call, app *conformance.App, signaled bool, want, note string) wire.Object {
	return tallyOf(b.run(conformance.Step{Do: "finish", Note: note, Call: must(json.Marshal(k.ID)), App: app, Signaled: &signaled}, want))
}

func (b *builder) restart(want, note string) {
	b.run(conformance.Step{Do: "restart", Note: note}, want)
}

func (b *builder) write() {
	b.d.Close()
	count++
	out, _ := json.MarshalIndent(b.sc, "", " ")
	fn := fmt.Sprintf("%03d_%s.json", count, strings.NewReplacer(" ", "_", "/", "_", ",", "", ":", "").Replace(b.sc.Name))
	if err := os.WriteFile(filepath.Join(dir, fn), append(out, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// chargeChain is the running example: A lets B book travel for at most 60000
// once; B narrows to a charge of at most 58900, once, held by the executor C.
func chargeChain() (w1, w2 *writ.Writ) {
	w1 = issue(A, B, bnd("act", "prefix", "travel", "amount", "max", 60000, "uses", "count", 1), now+3600, nil)
	w2 = issue(B, C, bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w1)
	return
}

var charge = &conformance.App{St: "ok", Res: map[string]any{"charge": "ch_1"}, Used: map[string]int64{"amount": 58900}, Rev: i64(now + 86400)}
var refund = ok(map[string]any{"refund": "rf_1"})

// plainChain is A to B to C with no count, for scenarios that make many calls.
func plainChain(act string) (w1, w2 *writ.Writ) {
	w1 = issue(A, B, bnd("act", "prefix", "travel"), now+3600, nil)
	w2 = issue(B, C, bnd("act", "prefix", act), now+3600, w1)
	return
}

func undo(from *keys.Identity, chain []*writ.Writ, t wire.Object) *writ.Call {
	return call(from, chain, "sys/undo", map[string]any{"tally": t})
}

func main() {
	flag.StringVar(&dir, "out", "../../conformance/scenarios", "output directory")
	flag.Parse()
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0o755)
	writ.Nonce = nonce

	{
		b := scenario("count, replay, and root acceptance", A)
		w1, w2 := chargeChain()
		k := call(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 58900})
		b.call(now+10, k, charge, "ok", "the charge runs")
		b.call(now+20, k, nil, "ok", "a replay of the same bytes returns the stored tally and runs nothing")
		b.call(now+30, call(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1}), nil, "failed:count_exhausted", "a new call id under the same chain")
		w2b := issue(B, B, bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w1)
		w3 := issue(B, C, bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w2b)
		b.call(now+40, call(B, []*writ.Writ{w1, w2b, w3}, "travel/charge", map[string]any{"amount": 1}), nil, "failed:count_exhausted", "delegating to itself cannot reset the root's count")
		ws := issue(S, C, bnd("act", "prefix", "travel"), now+3600, nil)
		b.call(now+50, call(S, []*writ.Writ{ws}, "travel/charge", map[string]any{}), nil, "failed:root_not_accepted", "a stranger's root")
		b.call(now+60, call(A, []*writ.Writ{w1}, "travel/book", map[string]any{"amount": 1}), nil, "failed:wrong_executor", "a chain whose leaf is held by someone else")
		b.write()
	}
	{
		b := scenario("forward call checks in order", A)
		w1 := issue(A, B, bnd("act", "prefix", "travel", "amount", "max", 60000, "currency", "set", []any{"USD"}), now+3600, nil)
		w2 := issue(B, C, bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "currency", "set", []any{"USD"}), now+1800, w1)
		ch := []*writ.Writ{w1, w2}
		good := map[string]any{"amount": 58900, "currency": "USD"}
		b.call(now+10, call(A, ch, "travel/charge", good), nil, "failed:no_standing", "from is not the leaf issuer")
		b.call(now+11, call(B, ch, "travel/chargeback", good), nil, "failed:forbidden_op", "op outside act on a segment boundary")
		b.call(now+12, call(B, ch, "travel/charge", map[string]any{"currency": "USD"}), nil, "failed:missing_arg", "amount absent")
		b.call(now+13, call(B, ch, "travel/charge", map[string]any{"amount": 58901, "currency": "USD"}), nil, "failed:out_of_bounds", "one over the leaf's max")
		b.call(now+14, call(B, ch, "travel/charge", map[string]any{"amount": 99999}), nil, "failed:missing_arg", "presence is checked for every bound before any value")
		b.call(now+15, call(B, ch, "travel/charge", good), ok(map[string]any{"charge": "ch_2"}), "ok", "a call inside every bound")
		b.call(now+1800, call(B, ch, "travel/charge", good), nil, "failed:expired", "at the leaf's exp, which is exclusive")
		ws := issue(S, C, bnd("act", "prefix", "travel"), now+100, nil)
		b.call(now+200, call(S, []*writ.Writ{ws}, "travel/x", map[string]any{}), nil, "failed:expired", "expiry is step 4, before root acceptance at step 5")
		b.write()
	}
	{
		b := scenario("count rejection consumes nothing", A)
		w1 := issue(A, B, bnd("act", "prefix", "travel", "uses", "count", 2), now+3600, nil)
		w2a := issue(B, C, bnd("act", "prefix", "travel", "uses", "count", 1), now+3600, w1)
		w2b := issue(B, C, bnd("act", "prefix", "travel", "uses", "count", 2), now+3600, w1)
		k1 := call(B, []*writ.Writ{w1, w2a}, "travel/a", map[string]any{})
		b.call(now+10, k1, ok(nil), "ok", "first use of w1 and w2a")
		k2 := call(B, []*writ.Writ{w1, w2a}, "travel/a", map[string]any{})
		b.call(now+20, k2, nil, "failed:count_exhausted", "w2a is used up; w1 must not be charged for the refusal")
		b.call(now+25, k2, nil, "failed:count_exhausted", "a refusal is not stored: the retry is checked again and signed at the new time")
		b.call(now+30, call(B, []*writ.Writ{w1, w2b}, "travel/b", map[string]any{}), ok(nil), "ok", "second use of w1, which the refusal did not consume")
		b.call(now+40, call(B, []*writ.Writ{w1, w2b}, "travel/b", map[string]any{}), nil, "failed:count_exhausted", "now w1 is used up, though w2b has a use left")
		b.call(now+50, k1, nil, "ok", "replay is step 9, before count at step 10")
		b.write()
	}
	{
		b := scenario("several count bounds on one writ, the smallest holds", A)
		w := issue(A, C, bnd("act", "prefix", "x", "uses", "count", 1, "retries", "count", 10), now+3600, nil)
		b.call(now+10, call(A, []*writ.Writ{w}, "x", map[string]any{}), ok(nil), "ok", "the one use")
		for i := 0; i < 3; i++ {
			b.call(now+20+int64(i), call(A, []*writ.Writ{w}, "x", map[string]any{}), nil, "failed:count_exhausted", "uses 1 holds whatever retries allows")
		}
		b.write()
	}
	{
		b := scenario("undo standing and idempotency", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		b.call(now+20, undo(S, ch, t), nil, "failed:no_standing", "a stranger")
		b.call(now+21, undo(C, ch, t), nil, "failed:no_standing", "the executor itself is not an issuer on the chain")
		u := undo(A, ch, t)
		b.call(now+30, u, refund, "ok", "the root issuer reverses the charge without B")
		b.call(now+31, u, nil, "ok", "a replay of the undo returns its stored tally")
		b.call(now+40, undo(A, ch, t), nil, "ok", "a new undo call performs nothing and returns the reversal's body")
		b.call(now+50, undo(B, ch, t), nil, "ok", "the intermediate issuer has standing too")
		b.write()
	}
	{
		b := scenario("undo targets and bounds", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		p1, p2 := plainChain("travel")
		pc := []*writ.Writ{p1, p2}
		tNoRev := b.call(now+11, call(B, pc, "travel/hold", map[string]any{}), ok(map[string]any{"hold": "h_1"}), "ok", "an effect with no rev")
		tFailed := b.call(now+12, call(B, pc, "travel/hold", map[string]any{}), &conformance.App{St: "failed", Code: "app/sold_out"}, "failed:app/sold_out", "an effect that failed")
		b.call(now+20, undo(A, pc, tNoRev), nil, "failed:not_reversible", "rev is null")
		b.call(now+21, undo(A, pc, tFailed), nil, "failed:not_reversible", "st is not ok")
		sib := issue(B, C, bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w1)
		b.call(now+22, undo(A, []*writ.Writ{w1, sib}, t), nil, "failed:tally_mismatch", "a chain whose leaf is not the tally's writ")
		b.call(now+23, undo(A, ch, resigned(t, S, func(o wire.Object) {})), nil, "failed:not_reversible", "a tally this executor did not sign")
		b.call(now+24, call(A, ch, "sys/undo", map[string]any{"tally": "not an object"}), nil, "failed:malformed", "args.tally is not an object")
		b.call(now+86400, undo(A, ch, t), nil, "failed:not_reversible", "at rev.until, which is exclusive")
		b.write()
	}
	{
		b := scenario("a failed reversal can be retried", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		b.call(now+20, undo(A, ch, t), &conformance.App{St: "failed", Code: "app/refund_declined"}, "failed:app/refund_declined", "the reversal fails")
		b.call(now+30, undo(A, ch, t), refund, "ok", "a failed reversal consumed nothing, so a new undo runs it")
		b.call(now+40, undo(A, ch, t), nil, "ok", "and after one succeeds, later undos run nothing")
		b.write()
	}
	{
		b := scenario("standing survives expiry", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		b.call(w2.Exp, call(B, ch, "travel/charge", map[string]any{"amount": 1}), nil, "failed:expired", "forward authority ends at the leaf's exp")
		b.call(w1.Exp-1, call(B, ch, "travel/charge", map[string]any{"amount": 1}), nil, "failed:expired", "an expired leaf is not revived by a live root")
		b.call(w1.Exp+60, call(A, ch, "sys/tallies", map[string]any{"writ": w1.ID}), nil, "ok with 1", "recovery after every writ has expired")
		b.call(w1.Exp+61, call(A, ch, "sys/tallies", map[string]any{"writ": t["writ"].(string) + "x"}), nil, "failed:tally_mismatch", "a writ hash that is not in the chain")
		b.call(w1.Exp+62, call(A, ch, "sys/tallies", map[string]any{}), nil, "failed:tally_mismatch", "no writ named at all")
		b.call(w1.Exp+70, undo(A, ch, t), refund, "ok", "reversal after expiry, before rev.until")
		b.call(w1.Exp+80, undo(B, ch, t), nil, "ok", "idempotent after expiry too")
		b.write()
	}
	{
		b := scenario("standing calls still fail closed", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		late := w1.Exp + 60
		u := undo(A, ch, t)
		tampered := must(wire.Clone(u.Raw))
		tampered["args"] = map[string]any{"tally": t, "x": json.Number("1")}
		b.callObj(late, tampered, nil, "error:bad_signature", "args changed after signing: an unsigned rejection")
		b.callObj(late, resigned(u.Raw, A, func(o wire.Object) { o["chain"] = []any{w2.Raw, w1.Raw} }), nil, "failed:chain_broken", "chain out of order, re-signed")
		ws := issue(S, C, bnd("act", "prefix", "travel"), now+3600, nil)
		b.call(late, call(S, []*writ.Writ{ws}, "sys/tallies", map[string]any{"writ": ws.ID}), nil, "failed:root_not_accepted", "standing does not skip root acceptance")
		b.call(late, call(A, []*writ.Writ{w1}, "sys/tallies", map[string]any{"writ": w1.ID}), nil, "failed:wrong_executor", "nor executor identity")
		b.call(late, call(A, ch, "sys/other", map[string]any{}), nil, "failed:forbidden_op", "an undefined standing operation")
		b.write()
	}
	{
		b := scenario("revoke ends forward authority, not standing", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		b.revoke(now+20, must(writ.NewRevoke(A, []*writ.Writ{w1})).Raw, "tallies:0", "nothing is in flight")
		b.call(now+30, call(B, ch, "travel/charge", map[string]any{"amount": 1}), nil, "failed:revoked", "revocation is step 7, before count at step 10")
		b.call(now+40, undo(A, ch, t), refund, "ok", "the revoker can still reverse what completed")
		b.call(now+50, call(A, ch, "sys/tallies", map[string]any{"writ": w1.ID}), nil, "ok with 2", "and recover it, with the reversal")
		b.call(w1.Exp+1, call(B, ch, "travel/charge", map[string]any{"amount": 1}), nil, "failed:expired", "expiry is step 4, before revocation")
		b.write()
	}
	{
		b := scenario("key-wide revoke", A, D)
		w1, w2 := plainChain("travel")
		t := b.call(now+10, call(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{}), &conformance.App{St: "ok", Res: map[string]any{"charge": "ch_3"}, Rev: i64(now + 86400)}, "ok", "an effect under A's chain")
		b.revoke(now+20, must(writ.NewRevoke(A, nil)).Raw, "tallies:0", "A revokes every writ it ever issued")
		b.call(now+30, call(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{}), nil, "failed:revoked", "A's chain")
		v1 := issue(A, B, bnd("act", "prefix", "travel"), now+3600, nil)
		v2 := issue(B, C, bnd("act", "prefix", "travel"), now+3600, v1)
		b.call(now+31, call(B, []*writ.Writ{v1, v2}, "travel/x", map[string]any{}), nil, "failed:revoked", "a writ A issued after the revoke's arrival is covered too")
		d1 := issue(D, B, bnd("act", "prefix", "travel"), now+3600, nil)
		d2 := issue(B, C, bnd("act", "prefix", "travel"), now+3600, d1)
		b.call(now+32, call(B, []*writ.Writ{d1, d2}, "travel/x", map[string]any{}), ok(nil), "ok", "another root is untouched, though B is on both chains")
		b.call(now+40, undo(A, []*writ.Writ{w1, w2}, t), refund, "ok", "A keeps its standing")
		b.write()
	}
	{
		b := scenario("invalid revokes change nothing", A)
		w1, w2 := plainChain("travel")
		ch := []*writ.Writ{w1, w2}
		rv := func(target string, chain []any, iss, signer *keys.Identity) wire.Object {
			o := wire.Object{"v": 1, "typ": "revoke", "writ": target, "iss": iss.DID(), "chain": chain}
			return resigned(o, signer, func(wire.Object) {})
		}
		b.revoke(now+10, rv(w2.ID, []any{w1.Raw}, A, A), "error:chain_broken", "the chain's leaf is not the revoked writ")
		b.revoke(now+11, rv(w1.ID, []any{w1.Raw}, S, S), "error:no_standing", "a stranger revokes A's writ")
		b.revoke(now+12, rv("*", []any{w1.Raw}, A, A), "error:malformed", "a key-wide revoke carrying a chain")
		b.revoke(now+13, resigned(must(writ.NewRevoke(A, ch)).Raw, S, func(wire.Object) {}), "error:bad_signature", "signed by the wrong key")
		b.call(now+20, call(B, ch, "travel/x", map[string]any{}), ok(nil), "ok", "none of them was recorded")
		b.revoke(now+30, must(writ.NewRevoke(B, ch)).Raw, "tallies:0", "B revokes the writ it issued")
		b.call(now+40, call(B, ch, "travel/y", map[string]any{}), nil, "failed:revoked", "and that one holds")
		b.write()
	}
	{
		b := scenario("revoke stops in-flight work under its writ only", A)
		x1, x2 := plainChain("travel")
		y1, y2 := plainChain("travel")
		kx := call(B, []*writ.Writ{x1, x2}, "travel/slow", map[string]any{})
		ky := call(B, []*writ.Writ{y1, y2}, "travel/slow", map[string]any{})
		b.call(now+10, kx, &conformance.App{Hold: true}, "inflight", "x starts and keeps running")
		b.call(now+11, ky, &conformance.App{Hold: true}, "inflight", "y starts and keeps running")
		b.call(now+12, ky, nil, "pending:pending", "a replay while y runs is answered pending, with y's acc")
		b.revoke(now+13, must(writ.NewRevoke(A, []*writ.Writ{y1})).Raw, "tallies:1", "revoking y's root answers with y's pending tally")
		b.finish(kx, ok(map[string]any{"done": "x"}), false, "ok", "x was not told to stop and completes")
		b.finish(ky, &conformance.App{St: "canceled", Code: "revoked"}, true, "canceled:revoked", "y was told to stop, and stopped")
		b.call(now+20, ky, nil, "failed:revoked", "a replay after the revoke is refused at step 7, before replay at step 9; recovery is sys/tallies")
		b.call(now+21, call(B, []*writ.Writ{y1, y2}, "travel/z", map[string]any{}), nil, "failed:revoked", "new work under y is refused")
		b.call(now+22, call(A, []*writ.Writ{y1, y2}, "sys/tallies", map[string]any{"writ": y1.ID}), nil, "ok with 1", "the canceled call is recoverable; x is under another writ")
		b.write()
	}
	{
		b := scenario("revoke answers in call identity order", A)
		w1, w2 := plainChain("travel")
		k1 := call(B, []*writ.Writ{w1, w2}, "travel/slow", map[string]any{"n": 1})
		k2 := call(B, []*writ.Writ{w1, w2}, "travel/slow", map[string]any{"n": 2})
		k3 := call(B, []*writ.Writ{w1, w2}, "travel/slow", map[string]any{"n": 3})
		for i, k := range []*writ.Call{k1, k2, k3} {
			b.call(now+10+int64(i), k, &conformance.App{Hold: true}, "inflight", "one of three running calls")
		}
		b.revoke(now+20, must(writ.NewRevoke(A, nil)).Raw, "tallies:3", "all three, ordered by call identity")
		for _, k := range []*writ.Call{k1, k2, k3} {
			b.finish(k, &conformance.App{St: "canceled", Code: "revoked"}, true, "canceled:revoked", "each was told to stop")
		}
		b.write()
	}
	{
		b := scenario("revoke leaves a running undo alone", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		u := undo(A, ch, t)
		b.call(now+20, u, &conformance.App{Hold: true}, "inflight", "the reversal starts")
		b.revoke(now+21, must(writ.NewRevoke(A, []*writ.Writ{w1})).Raw, "tallies:0", "a revoke racing the reversal lists nothing")
		b.finish(u, refund, false, "ok", "the reversal was not told to stop and completes")
		b.write()
	}
	{
		b := scenario("crash while running", A)
		w1 := issue(A, B, bnd("act", "prefix", "travel", "uses", "count", 1), now+3600, nil)
		w2 := issue(B, C, bnd("act", "prefix", "travel", "uses", "count", 1), now+3600, w1)
		ch := []*writ.Writ{w1, w2}
		k := call(B, ch, "travel/slow", map[string]any{})
		b.call(now+10, k, &conformance.App{Hold: true}, "inflight", "accepted, recorded pending, running")
		b.restart("resolved:1", "the process dies mid-operation and restarts")
		b.call(now+20, k, nil, "failed:unknown_outcome", "the retry learns the outcome is unknown, at the original acc")
		b.call(now+30, call(B, ch, "travel/again", map[string]any{}), nil, "failed:count_exhausted", "the lost operation's count stays consumed")
		b.call(now+40, call(A, ch, "sys/tallies", map[string]any{"writ": w1.ID}), nil, "ok with 1", "the resolved tally is recoverable")
		b.restart("resolved:0", "a clean restart resolves nothing")
		b.call(now+50, k, nil, "failed:unknown_outcome", "the resolution itself survived the restart")
		b.write()
	}
	{
		b := scenario("crash while reversing", A)
		w1, w2 := chargeChain()
		ch := []*writ.Writ{w1, w2}
		t := b.call(now+10, call(B, ch, "travel/charge", map[string]any{"amount": 58900}), charge, "ok", "the charge")
		u := undo(A, ch, t)
		b.call(now+20, u, &conformance.App{Hold: true}, "inflight", "the reversal starts")
		b.restart("resolved:1", "the process dies mid-reversal")
		b.call(now+30, u, nil, "failed:unknown_outcome", "the undo call itself resolves to unknown")
		b.call(now+40, undo(A, ch, t), nil, "failed:unknown_outcome", "and a new undo must not reverse a second time")
		b.write()
	}
	{
		b := scenario("sys/tallies order and contents", A)
		w1, w2 := plainChain("travel")
		ch := []*writ.Writ{w1, w2}
		b.call(now+10, call(B, ch, "travel/a", map[string]any{}), ok(map[string]any{"n": 1}), "ok", "two tallies with the same acc")
		b.call(now+10, call(B, ch, "travel/b", map[string]any{}), ok(map[string]any{"n": 2}), "ok", "are ordered by identity")
		b.call(now+5, call(B, ch, "travel/c", map[string]any{}), &conformance.App{St: "failed", Code: "app/declined"}, "failed:app/declined", "an earlier acc sorts first, and a failed operation is still held")
		b.call(now+20, call(B, ch, "cars/x", map[string]any{}), nil, "failed:forbidden_op", "a forward refusal is not held")
		b.call(now+21, call(B, ch, "sys/other", map[string]any{}), nil, "failed:forbidden_op", "nor a refused standing call")
		kt := call(A, ch, "sys/tallies", map[string]any{"writ": w1.ID})
		b.call(now+30, kt, nil, "ok with 3", "three tallies, and not this call's own")
		b.call(now+40, call(B, ch, "sys/tallies", map[string]any{"writ": w2.ID}), nil, "ok with 4", "four now, the previous recovery included")
		b.call(now+50, kt, nil, "ok with 3", "a replay returns the stored answer")
		b.write()
	}

	fmt.Printf("wrote %d scenarios to %s\n", count, dir)
}
