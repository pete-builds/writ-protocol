package exec

import (
	"context"
	"testing"

	"writproto/keys"
	"writproto/writ"
)

// docs/approval.md: a payment over the agent's line is refused, its issuer
// approves it with a one-use writ, the executor runs it once under the
// approval like any other chain, and the tally's chain carries the approver's
// signature. The executor knows nothing of approval.
func TestApprovedPaymentRunsOnce(t *testing.T) {
	H, A := id(1), id(2)
	runs := 0
	e := newC(t, "", H, func(ctx context.Context, k *writ.Call) Result {
		runs++
		return Result{Used: map[string]int64{"amount": 500}}
	})
	w1, _ := writ.Issue(H, A.DID(), bnd("act", "prefix", "pay", "amount", "max", 100), now+3600, nil)
	w2, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "max", 100), now+1800, w1)
	args := map[string]any{"amount": 500, "pay_to": "v1"}
	if got := run(t, e, mustCall(t, A, []*writ.Writ{w1, w2}, args)); got != "failed:out_of_bounds" {
		t.Fatalf("over the line: %s", got)
	}
	j := writ.ApprovalPoint([]*writ.Writ{w1, w2}, "pay", args)
	if j != 0 || w1.Iss != H.DID() {
		t.Fatalf("approval point %d", j)
	}
	a1, err := writ.Approve(H, nil, w1, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := writ.Approve(A, a1, w2, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	approved := []*writ.Writ{a1, a2}
	k := mustCall(t, A, approved, args)
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil || tallyCode(rep) != "ok" {
		t.Fatalf("the approved payment: %v %v", rej, rep)
	}
	if v, tl, err := writ.VerifyTally(a2, k, rep.Tally, rep.Res); v != writ.Valid || tl.Used["amount"] != 500 {
		t.Fatalf("its tally: %s %v", v, err)
	}
	if got := run(t, e, mustCall(t, A, approved, args)); got != "failed:count_exhausted" {
		t.Fatalf("a second payment under the same approval: %s", got)
	}
	if runs != 1 {
		t.Fatalf("the payment ran %d times, want once", runs)
	}
}

func mustCall(t *testing.T, from *keys.Identity, chain []*writ.Writ, args map[string]any) *writ.Call {
	t.Helper()
	k, err := writ.NewCall(from, chain, "pay", args)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
