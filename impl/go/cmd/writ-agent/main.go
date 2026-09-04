// writ-agent runs one executor over HTTP. Two application roles are built in
// for the demo: "booking" (agent B: books travel and delegates payment) and
// "payment" (agent C: charges and refunds). The protocol code is identical in
// both; only the handlers differ.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"writproto/exec"
	"writproto/httpbind"
	"writproto/keys"
	"writproto/writ"
)

func main() {
	role := flag.String("role", "payment", "booking or payment")
	seedHex := flag.String("seed", "", "32-byte hex seed for the agent key (demo only)")
	port := flag.Int("port", 8081, "listen port")
	store := flag.String("store", "", "path of the durable store (empty for memory)")
	accept := flag.String("accept", "", "comma-separated did:key roots this agent acts under")
	downstream := flag.String("downstream", "", "base URL of the payment agent (booking role)")
	flag.Parse()

	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("seed must be 32 bytes of hex")
	}
	id, _ := keys.FromSeed(seed)
	st, err := exec.OpenFileStore(*store)
	if err != nil {
		log.Fatal(err)
	}
	e := exec.New(id, st)
	roots := map[string]bool{}
	for _, r := range strings.Split(*accept, ",") {
		if r != "" {
			roots[r] = true
		}
	}
	e.AcceptRoot = func(did string) bool { return roots[did] }
	if n := e.Recover(); n > 0 {
		log.Printf("recovered %d crashed call(s) to unknown_outcome", n)
	}

	var act []string
	switch *role {
	case "payment":
		act = []string{"travel/charge"}
		installPayment(e)
	case "booking":
		act = []string{"travel/book"}
		installBooking(e, *downstream)
	default:
		log.Fatal("unknown role")
	}
	wk := httpbind.WellKnown{V: 1, DID: id.DID(), Endpoint: "/writ", Act: act}
	log.Printf("%s agent %s listening on :%d", *role, id.DID(), *port)
	fmt.Fprintln(os.Stderr, "ready")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", *port), httpbind.Handler(e, wk)))
}

// installPayment: agent C. It charges within the leaf bounds and can refund.
func installPayment(e *exec.Executor) {
	seq := 0
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		amount, _ := k.Args["amount"].(interface{ Int64() (int64, error) })
		n, _ := amount.Int64()
		seq++
		until := e.Now() + 86400
		log.Printf("charge %d %v for %s", n, k.Args["currency"], k.From[:20])
		return exec.Result{
			Res:      map[string]any{"charge": fmt.Sprintf("ch_%04d", seq), "amount": n},
			Used:     map[string]int64{"amount": n},
			RevUntil: &until,
		}
	}
	e.Undo = func(ctx context.Context, t *writ.Tally, res any) exec.Result {
		m, _ := res.(map[string]any)
		log.Printf("refund %v", m["charge"])
		return exec.Result{Res: map[string]any{"refund": fmt.Sprintf("rf_%s", m["charge"]), "of": m["charge"]}}
	}
	e.OnRevoke = func(r *writ.Revoke) { log.Printf("revoke received for %s", short(r.Writ)) }
}

// installBooking: agent B. It narrows its writ to a payment writ for C, calls
// C, verifies C's tally, books, and returns a tally embedding C's.
func installBooking(e *exec.Executor, downstream string) {
	client := httpbind.NewClient()
	var cWK *httpbind.WellKnown
	discover := func(ctx context.Context) (*httpbind.WellKnown, error) {
		if cWK != nil {
			return cWK, nil
		}
		wk, err := client.Discover(ctx, downstream)
		if err == nil {
			cWK = wk
		}
		return wk, err
	}
	seq := 0
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		fail := func(code string) exec.Result { return exec.Result{St: "failed", ErrCode: code} }
		if _, slow := k.Args["slow"]; slow {
			// Simulate long work so a revoke can arrive mid-task.
			select {
			case <-ctx.Done():
				log.Printf("canceled before delegating payment")
				return exec.Result{St: "canceled", ErrCode: string(writ.Revoked)}
			case <-time.After(3 * time.Second):
			}
		}
		wk, err := discover(ctx)
		if err != nil {
			return fail("app/payment_unreachable")
		}
		leaf := k.Leaf()
		fare := int64(58900)
		if mx := leaf.Bnd["amount"]; mx.Int < fare {
			fare = mx.Int
		}
		// Narrow: only travel/charge, only this fare, only once, shorter life.
		bnd := map[string]any{}
		for name, b := range leaf.Bnd {
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
		}
		bnd["act"] = map[string]any{"t": "prefix", "v": "travel/charge"}
		bnd["amount"] = map[string]any{"t": "max", "v": fare}
		bnd["uses"] = map[string]any{"t": "count", "v": 1}
		exp := leaf.Exp
		if e.Now()+900 < exp {
			exp = e.Now() + 900
		}
		w2, err := writ.Issue(e.ID, wk.DID, bnd, exp, leaf)
		if err != nil {
			log.Printf("refusing to issue: %v", err)
			return fail("app/cannot_narrow")
		}
		args := map[string]any{"amount": fare}
		for name := range leaf.Bnd {
			if v, ok := k.Args[name]; ok && name != "amount" {
				args[name] = v
			}
		}
		args["pnr"] = fmt.Sprintf("PNR%03d", seq+1)
		chain := append(append([]*writ.Writ{}, k.Chain...), w2)
		kc, err := writ.NewCall(e.ID, chain, "travel/charge", args)
		if err != nil {
			return fail("app/call_build")
		}
		if e.IsRevoked(k.Chain) {
			return exec.Result{St: "canceled", ErrCode: string(writ.Revoked), Wrt: []*writ.Writ{w2}}
		}
		tobj, res, err := client.Call(ctx, downstream+wk.Endpoint, kc)
		if err != nil {
			return exec.Result{St: "failed", ErrCode: string(writ.Undeliverable), Wrt: []*writ.Writ{w2}}
		}
		v, tc, verr := writ.VerifyTally(w2, kc, tobj, res)
		if v == writ.Unverifiable {
			log.Printf("payment tally unverifiable: %v", verr)
			return exec.Result{St: "failed", ErrCode: "app/unverified_payment", Wrt: []*writ.Writ{w2}}
		}
		if tc.St != "ok" {
			return exec.Result{St: "failed", ErrCode: "app/payment_" + tc.Err.Code, Sub: []*writ.Tally{tc}, Wrt: []*writ.Writ{w2}}
		}
		seq++
		until := e.Now() + 86400
		log.Printf("booked %s, paid via %s", args["pnr"], short(tc.ID))
		return exec.Result{
			Res:      map[string]any{"pnr": args["pnr"], "fare": fare, "payment": res},
			Used:     map[string]int64{"amount": fare},
			RevUntil: &until,
			Sub:      []*writ.Tally{tc},
			Wrt:      []*writ.Writ{w2},
		}
	}
	// Undo a booking: cancel it and, as issuer of the payment writ, undo the charge at C.
	e.Undo = func(ctx context.Context, t *writ.Tally, res any) exec.Result {
		wk, err := discover(ctx)
		if err != nil {
			return exec.Result{St: "failed", ErrCode: "app/payment_unreachable"}
		}
		var subs []*writ.Tally
		var wrts []*writ.Writ
		for _, tc := range t.Sub {
			for _, w := range t.Wrt {
				if w.ID == tc.Writ {
					// Reconstruct the chain C ran under: our leaf writ plus w2.
					chain := []*writ.Writ{}
					for _, rec := range e.Store.Calls {
						if rec.Tally != nil {
							if h, _ := rec.Tally["call"].(string); h == t.Call {
								kk, _ := writ.ParseCall(rec.Call)
								chain = append(chain, kk.Chain...)
							}
						}
					}
					chain = append(chain, w)
					ku, err := writ.NewCall(e.ID, chain, "sys/undo", map[string]any{"tally": tc.Raw})
					if err != nil {
						continue
					}
					uobj, ures, err := client.Call(ctx, downstream+wk.Endpoint, ku)
					if err != nil {
						continue
					}
					if _, ut, _ := writ.VerifyTally(w, ku, uobj, ures); ut != nil {
						subs = append(subs, ut)
						wrts = append(wrts, w)
					}
				}
			}
		}
		m, _ := res.(map[string]any)
		log.Printf("canceled booking %v and undid %d payment(s)", m["pnr"], len(subs))
		return exec.Result{Res: map[string]any{"canceled": m["pnr"]}, Sub: subs, Wrt: wrts}
	}
	// Forward revokes to C, best effort.
	e.OnRevoke = func(r *writ.Revoke) {
		wk, err := discover(context.Background())
		if err != nil {
			return
		}
		if _, err := client.Revoke(context.Background(), downstream+wk.Endpoint, r); err != nil {
			log.Printf("could not forward revoke: %v", err)
		} else {
			log.Printf("forwarded revoke of %s downstream", short(r.Writ))
		}
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
