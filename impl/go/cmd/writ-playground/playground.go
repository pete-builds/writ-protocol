// writ-playground runs the README's travel example in one process, with the
// reference executors for B and C and nothing mocked: every refusal below is
// the code an executor or the library returns. Built for js/wasm it backs the
// browser playground (main_js.go); natively it is only tested.
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// Step is one line of what happened, for the page to show.
type Step struct {
	Who  string `json:"who"`
	Text string `json:"text"`
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

// Outcome is one scenario's result. Objects holds the signed objects
// exchanged, as JSON, for anyone who wants to read them.
type Outcome struct {
	Scenario string         `json:"scenario"`
	Verdict  string         `json:"verdict"` // ok, refused, caught, same
	Headline string         `json:"headline"`
	Steps    []Step         `json:"steps"`
	Objects  map[string]any `json:"objects"`
	Charges  int            `json:"charges"`
	Refunds  int            `json:"refunds"`
}

// Scenarios lists what the page can run, in the order it shows them.
var Scenarios = []string{"honest", "widen", "overspend", "replay", "forge", "crash"}

// world is A, B, and C with their keys, and B and C as real executors over
// memory stores. B's handler narrows its writ for C and calls C directly.
type world struct {
	ctx              context.Context
	A, B, C          *keys.Identity
	bE, cE           *exec.Executor
	limit            int64
	mode             string // how B misbehaves: "", "overspend"
	w1, w2           *writ.Writ
	k1, kc           *writ.Call
	cTally           wire.Object
	cRes             any
	charges, refunds int
	out              *Outcome
}

func (w *world) step(who string, ok bool, code, format string, a ...any) {
	w.out.Steps = append(w.out.Steps, Step{Who: who, Text: fmt.Sprintf(format, a...), OK: ok, Code: code})
}

func cents(n int64) string { return fmt.Sprintf("$%d.%02d", n/100, n%100) }

func newWorld(limit int64) (*world, error) {
	w := &world{ctx: context.Background(), limit: limit, out: &Outcome{Objects: map[string]any{}}}
	var err error
	for _, id := range []**keys.Identity{&w.A, &w.B, &w.C} {
		if *id, err = keys.Generate(); err != nil {
			return nil, err
		}
	}
	accept := func(did string) bool { return did == w.A.DID() }
	cStore, _ := exec.OpenFileStore("")
	w.cE = exec.New(w.C, cStore)
	w.cE.AcceptRoot = accept
	w.cE.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		n, _ := k.Args["amount"].(interface{ Int64() (int64, error) })
		amount, _ := n.Int64()
		w.charges++
		until := w.cE.Now() + 86400
		return exec.Result{Res: map[string]any{"charge": fmt.Sprintf("ch_%04d", w.charges), "amount": amount},
			Used: map[string]int64{"amount": amount}, RevUntil: &until}
	}
	w.cE.Undo = func(ctx context.Context, t *writ.Tally, res any) exec.Result {
		w.refunds++
		m, _ := res.(map[string]any)
		return exec.Result{Res: map[string]any{"refund": fmt.Sprintf("rf_%v", m["charge"])}}
	}
	bStore, _ := exec.OpenFileStore("")
	w.bE = exec.New(w.B, bStore)
	w.bE.AcceptRoot = accept
	w.bE.Handle = w.book
	return w, nil
}

// book is B: narrow writ_1 to a payment writ for C, call C, check C's
// tally, and return a tally that embeds it.
func (w *world) book(ctx context.Context, k *writ.Call) exec.Result {
	leaf := k.Leaf()
	fare := int64(58900)
	if mx := leaf.Bnd["amount"]; mx.Int < fare {
		fare = mx.Int
	}
	bnd := map[string]any{}
	for name, b := range leaf.Bnd {
		bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
	}
	bnd["act"] = map[string]any{"t": "prefix", "v": "travel/charge"}
	bnd["amount"] = map[string]any{"t": "max", "v": fare}
	bnd["uses"] = map[string]any{"t": "count", "v": 1}
	w2, err := writ.Issue(w.B, w.C.DID(), bnd, leaf.Exp, leaf)
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "app/cannot_narrow"}
	}
	w.w2 = w2
	w.step("B", true, "", "B writes C a smaller slip, writ #2: charge card, at most %s, once.", cents(fare))
	charge := fare
	if w.mode == "overspend" {
		charge = fare + 10000
		w.step("B", false, "", "B asks C to charge %s, more than slip #2 allows.", cents(charge))
	}
	kc, err := writ.NewCall(w.B, append(append([]*writ.Writ{}, k.Chain...), w2), "travel/charge",
		map[string]any{"amount": charge, "currency": "USD"})
	if err != nil {
		return exec.Result{St: "failed", ErrCode: "app/call_build", Wrt: []*writ.Writ{w2}}
	}
	w.kc = kc
	_ = w.bE.Issued(k, w2)
	rep, rej := w.cE.Execute(ctx, kc.Raw)
	if rej != nil {
		return exec.Result{St: "failed", ErrCode: "app/payment_" + string(rej.Code), Wrt: []*writ.Writ{w2}}
	}
	v, tc, verr := writ.VerifyTally(w2, kc, rep.Tally, rep.Res)
	if v == writ.Unverifiable {
		return exec.Result{St: "failed", ErrCode: "app/unverified_payment", Wrt: []*writ.Writ{w2}}
	}
	_ = verr
	w.cTally, w.cRes = rep.Tally, rep.Res
	_ = w.bE.Received(k, tc)
	if tc.St != "ok" {
		w.step("C", false, tc.Err.Code, "C checked the whole stack and refused: %s. Nothing was charged.", tc.Err.Code)
		return exec.Result{St: "failed", ErrCode: "app/payment_" + tc.Err.Code, Sub: []*writ.Tally{tc}, Wrt: []*writ.Writ{w2}}
	}
	w.step("C", true, "", "C checked the whole stack, charged %s, and signed a receipt.", cents(charge))
	until := w.bE.Now() + 86400
	w.step("B", true, "", "B booked the trip and put C's receipt inside its own.")
	return exec.Result{Res: map[string]any{"pnr": "PNR001", "fare": fare, "payment": rep.Res},
		Used: map[string]int64{"amount": fare}, RevUntil: &until, Sub: []*writ.Tally{tc}, Wrt: []*writ.Writ{w2}}
}

// grant is A issuing writ_1 to B and asking B to book.
func (w *world) grant() (wire.Object, any, error) {
	exp := w.bE.Now() + 3600
	w1, err := writ.Issue(w.A, w.B.DID(), map[string]any{
		"act":      map[string]any{"t": "prefix", "v": "travel"},
		"amount":   map[string]any{"t": "max", "v": w.limit},
		"uses":     map[string]any{"t": "count", "v": 1},
		"currency": map[string]any{"t": "set", "v": []any{"USD"}},
	}, exp, nil)
	if err != nil {
		return nil, nil, err
	}
	w.w1 = w1
	w.step("A", true, "", "A signs B a slip, writ #1: travel, at most %s, once, for an hour.", cents(w.limit))
	k1, err := writ.NewCall(w.A, []*writ.Writ{w1}, "travel/book", map[string]any{"amount": w.limit, "currency": "USD"})
	if err != nil {
		return nil, nil, err
	}
	w.k1 = k1
	rep, rej := w.bE.Execute(w.ctx, k1.Raw)
	if rej != nil {
		return nil, nil, fmt.Errorf("B rejected the call: %s", rej.Code)
	}
	w.out.Objects["writ_1"] = w1.Raw
	if w.w2 != nil {
		w.out.Objects["writ_2"] = w.w2.Raw
	}
	w.out.Objects["tally_B"] = rep.Tally
	return rep.Tally, rep.Res, nil
}

// verify is A checking the tally tree with nothing but writ_1, its own call,
// and the keys inside the objects.
func (w *world) verify(tobj wire.Object, res any) (writ.Verdict, *writ.Tally, error) {
	return writ.VerifyTally(w.w1, w.k1, tobj, res)
}

// Play runs one scenario with A's limit in cents.
func Play(scenario string, limit int64) (*Outcome, error) {
	if limit < 1000 || limit > 1000000 {
		return nil, fmt.Errorf("limit must be between $10 and $10,000")
	}
	w, err := newWorld(limit)
	if err != nil {
		return nil, err
	}
	w.out.Scenario = scenario
	switch scenario {
	case "honest", "replay", "forge", "crash":
	case "overspend":
		w.mode = "overspend"
	case "widen":
		return w.widen()
	default:
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	tobj, res, err := w.grant()
	if err != nil {
		return nil, err
	}
	v, tB, verr := w.verify(tobj, res)
	if w.mode == "overspend" {
		w.out.Verdict, w.out.Headline = "refused", "C refused the overcharge"
		if v == writ.Valid && tB.St == "failed" {
			w.step("A", true, "", "A verified B's receipt: the booking failed, and C's signed refusal is inside it.")
		}
		return w.done(), nil
	}
	if v != writ.Valid || tB.St != "ok" {
		return nil, fmt.Errorf("honest run did not verify: %s %v", v, verr)
	}
	w.step("A", true, "", "A checked both receipts offline: who did what, under which slip. Valid.")
	switch scenario {
	case "honest":
		w.out.Verdict, w.out.Headline = "ok", "Booked, and every receipt checks out"
	case "replay":
		w.replay()
	case "forge":
		w.forge(tobj, res)
	case "crash":
		w.crash()
	}
	return w.done(), nil
}

func (w *world) done() *Outcome {
	w.out.Charges, w.out.Refunds = w.charges, w.refunds
	return w.out
}

// widen is B trying to hand C more than B was given.
func (w *world) widen() (*Outcome, error) {
	exp := w.bE.Now() + 3600
	w1, err := writ.Issue(w.A, w.B.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "travel"},
		"amount": map[string]any{"t": "max", "v": w.limit},
	}, exp, nil)
	if err != nil {
		return nil, err
	}
	w.step("A", true, "", "A signs B a slip, writ #1: travel, at most %s.", cents(w.limit))
	wider := w.limit + 10000
	w.step("B", false, "", "B tries to write C a slip for %s, more than its own.", cents(wider))
	_, err = writ.Issue(w.B, w.C.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "travel/charge"},
		"amount": map[string]any{"t": "max", "v": wider},
	}, exp, w1)
	if err == nil {
		return nil, fmt.Errorf("a wider child writ was issued")
	}
	code := ""
	if we, ok := err.(*writ.Error); ok {
		code = string(we.Code)
	}
	w.step("Writ", false, code, "Refused before anything was signed: %v", err)
	w.step("C", true, "", "C runs the same parent-and-child check on every chain it receives, so a wider slip never gets past it either.")
	w.out.Verdict, w.out.Headline = "refused", "A slip can't be bigger than the one above it"
	w.out.Objects["writ_1"] = w1.Raw
	return w.done(), nil
}

// replay sends C's call again, as a retry or an attacker would.
func (w *world) replay() {
	first := w.cTally["sig"]
	rep, rej := w.cE.Execute(w.ctx, w.kc.Raw)
	if rej != nil {
		w.step("C", false, string(rej.Code), "C rejected the repeat: %s", rej.Code)
		return
	}
	a, _ := json.Marshal(w.cTally)
	b, _ := json.Marshal(rep.Tally)
	same := string(a) == string(b) && rep.Tally["sig"] == first
	w.step("Someone", false, "", "The same charge request reaches C a second time.")
	w.step("C", same, "", "C sent back the original receipt, byte for byte (%t). Charges made: %d.", same, w.charges)
	w.out.Verdict, w.out.Headline = "same", "Same receipt, charged once"
	w.out.Objects["tally_C_repeat"] = rep.Tally
}

// forge has B rewrite C's receipt inside its own to claim a cheaper charge.
func (w *world) forge(tobj wire.Object, res any) {
	b, _ := json.Marshal(tobj)
	forged, err := wire.Decode(b)
	if err != nil {
		return
	}
	subs, _ := forged["sub"].([]any)
	if len(subs) == 0 {
		return
	}
	c, _ := subs[0].(map[string]any)
	c["used"] = map[string]any{"amount": json.Number("30000")}
	// B signs its own tally again, so its own signature holds and only C's,
	// which B cannot make, is left to catch the edit.
	delete(forged, "sig")
	if err := wire.Sign(forged, w.B); err != nil {
		return
	}
	w.step("B", false, "", "B edits C's receipt to say C charged $300.00, then re-signs its own receipt around it.")
	v, _, err := w.verify(forged, res)
	w.step("A", v != writ.Valid, string(v), "A checked the bundle: %s. %v", v, err)
	w.out.Verdict, w.out.Headline = "caught", "B can't fake C's signature"
	w.out.Objects["tally_B_forged"] = forged
}

// crash has B disappear and A undo C's charge directly.
func (w *world) crash() {
	w.bE = nil
	w.step("B", false, "", "B crashes and never comes back.")
	ku, err := writ.NewCall(w.A, []*writ.Writ{w.w1, w.w2}, "sys/undo", map[string]any{"tally": w.cTally})
	if err != nil {
		w.step("A", false, "", "A could not build the undo: %v", err)
		return
	}
	for i := 0; i < 2; i++ {
		rep, rej := w.cE.Execute(w.ctx, ku.Raw)
		if rej != nil {
			w.step("C", false, string(rej.Code), "C rejected the undo: %s", rej.Code)
			return
		}
		v, t, _ := writ.VerifyTally(w.w2, ku, rep.Tally, rep.Res)
		ok := v == writ.Valid && t.St == "ok"
		if i == 0 {
			w.step("A", true, "", "A sends C both slips and C's receipt: undo this.")
			w.step("C", ok, "", "A is on the chain, so C refunded the charge and signed for it. Refunds: %d.", w.refunds)
			w.out.Objects["tally_C_undo"] = rep.Tally
		} else {
			w.step("C", ok, "", "A asked again. Same answer, no second refund. Refunds: %d.", w.refunds)
		}
	}
	w.out.Verdict, w.out.Headline = "ok", "Refunded without B"
}
