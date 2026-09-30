package exec

// Regression tests for the review dated 2026-09-29. Each asserts what the
// spec requires, and each fails against the executor before the fix.

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"writproto/wire"
	"writproto/writ"
)

// Spec 7.5 and 9: an executor persists each writ it issues before sending it
// and each sub-tally before acting on it, and a pending record resolved after
// a restart carries both. Before the fix the Go executor kept child evidence
// in memory until the final tally, so a crash after the sub-call answered
// resolved to an unknown_outcome tally with empty sub and wrt: the charge
// below it happened and the record of it was gone.
func TestCrashAfterSubTallyKeepsChildEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	A, B, D := id(1), id(2), id(4)
	e := newC(t, path, A, nil)
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000), now+1800, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/book", map[string]any{"amount": 58900})

	persisted, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.Handle = func(ctx context.Context, k *writ.Call) Result {
		wd, err := writ.Issue(e.ID, D.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900), now+900, k.Leaf())
		if err != nil {
			t.Error(err)
			return Result{St: "failed", ErrCode: "test/issue"}
		}
		if err := e.Issued(k, wd); err != nil {
			t.Error(err)
			return Result{St: "failed", ErrCode: "test/issued"}
		}
		kd, _ := writ.NewCall(e.ID, append(append([]*writ.Writ{}, k.Chain...), wd), "travel/charge", map[string]any{"amount": 58900})
		td, _, _ := writ.NewTally(D, writ.TallyInput{Call: kd, Acc: now + 12, St: "ok", Used: map[string]int64{"amount": 58900}})
		if err := e.Received(k, td); err != nil {
			t.Error(err)
			return Result{St: "failed", ErrCode: "test/received"}
		}
		close(persisted)
		<-release // the process dies here and never returns
		return Result{St: "failed", ErrCode: "test/late"}
	}
	go func() { e.Execute(context.Background(), k.Raw); close(done) }()
	t.Cleanup(func() { close(release); <-done })
	<-persisted

	// Restart: a new executor over the same store resolves the record.
	e2 := newC(t, path, A, nil)
	if n := e2.Recover(); n != 1 {
		t.Fatalf("recovered %d pending records, want 1", n)
	}
	rep, rej := e2.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	v, tl, err := writ.VerifyTally(w2, k, rep.Tally, nil)
	if v != writ.Valid {
		t.Fatalf("resolved tally is %s: %v", v, err)
	}
	if tl.Err == nil || tl.Err.Code != string(writ.UnknownOutcome) {
		t.Fatalf("want unknown_outcome, got %+v", tl.Err)
	}
	if len(tl.Wrt) != 1 || len(tl.Sub) != 1 {
		t.Fatalf("child evidence lost across the crash: %d writs, %d sub-tallies, want 1 and 1", len(tl.Wrt), len(tl.Sub))
	}
	if tl.Used["amount"] != 58900 {
		t.Fatalf("used.amount %d, want 58900 to cover the sub-tally (spec 6)", tl.Used["amount"])
	}
}

// Spec 6: used is inclusive of the subtree. An application that reports less
// than its sub-tallies consumed would sign a tally every verifier rejects, so
// the executor raises used to cover them.
func TestUsedCoversSubTallies(t *testing.T) {
	A, B, D := id(1), id(2), id(4)
	e := newC(t, "", A, nil)
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000), now+1800, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/book", map[string]any{"amount": 58900})
	e.Handle = func(ctx context.Context, k *writ.Call) Result {
		wd, _ := writ.Issue(e.ID, D.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900), now+900, k.Leaf())
		kd, _ := writ.NewCall(e.ID, append(append([]*writ.Writ{}, k.Chain...), wd), "travel/charge", map[string]any{"amount": 58900})
		td, _, _ := writ.NewTally(D, writ.TallyInput{Call: kd, Acc: now + 12, St: "ok", Used: map[string]int64{"amount": 58900}})
		// Reports only its own consumption, forgetting the charge below it.
		return Result{Used: map[string]int64{"amount": 0}, Sub: []*writ.Tally{td}, Wrt: []*writ.Writ{wd}}
	}
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	v, tl, err := writ.VerifyTally(w2, k, rep.Tally, nil)
	if v != writ.Valid {
		t.Fatalf("tally is %s: %v", v, err)
	}
	if tl.Used["amount"] != 58900 {
		t.Fatalf("used.amount %d, want 58900", tl.Used["amount"])
	}
}

// Spec 7: steps 7 to 11 of a forward call are atomic with respect to
// recording a revoke. Before the fix a revoke recorded between a call's
// revocation check and its admission found nothing in flight, and the call
// then ran to completion without being told to stop.
func TestRevokeBetweenCheckAndAdmissionStopsTheCall(t *testing.T) {
	A, B := id(1), id(2)
	var canceled atomic.Bool
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result {
		select {
		case <-ctx.Done():
			canceled.Store(true)
			return Result{St: "canceled", ErrCode: string(writ.Revoked)}
		case <-time.After(3 * time.Second):
			return Result{}
		}
	})
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel"), now+1800, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/book", map[string]any{})
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w1})

	answer := make(chan []wire.Object, 1)
	e.afterRevokeCheck = func() {
		e.afterRevokeCheck = nil
		go func() {
			pend, rej := e.Revoke(rv.Raw)
			if rej != nil {
				t.Error(rej)
			}
			answer <- pend
		}()
		// Give the revoke the whole window. A correct executor holds it
		// until this call is in flight; without the lock it records the
		// revoke, finds nothing to stop, and returns inside the window.
		select {
		case pend := <-answer:
			answer <- pend
		case <-time.After(300 * time.Millisecond):
		}
	}
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	pend := <-answer
	_, tl, _ := writ.VerifyTally(w2, k, rep.Tally, nil)
	if tl == nil {
		t.Fatal("no tally")
	}
	if len(pend) != 1 || !canceled.Load() {
		t.Fatalf("the revoke missed the call: it answered for %d calls, operation stopped=%v, call ended %s", len(pend), canceled.Load(), tl.St)
	}
	if tl.St != "canceled" {
		t.Fatalf("want canceled, got %s", tl.St)
	}
}
