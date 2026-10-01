package exec

// Regression tests for the 2026-09-23 security review. Each asserts what the
// spec requires, and each failed against the executor before the fix.

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"writproto/writ"
)

func tallyCode(rep *Reply) string {
	st, _ := rep.Tally["st"].(string)
	if st == "ok" {
		return "ok"
	}
	e, _ := rep.Tally["err"].(map[string]any)
	c, _ := e["code"].(string)
	return st + ":" + c
}

// Spec 7 step 10: a writ with several count bounds is limited by the
// smallest. Before the fix a random one of them applied on each call, which
// one run of ten calls caught about 85 percent of the time; twenty fresh
// writs make a miss negligible.
func TestTwoCountBoundsTheSmallerHolds(t *testing.T) {
	A := id(1)
	for trial := 0; trial < 20; trial++ {
		runs := 0
		e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result { runs++; return Result{} })
		w, err := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "x", "uses", "count", 1, "retries", "count", 10), now+3600, nil)
		if err != nil {
			t.Fatal(err)
		}
		var codes []string
		for i := 0; i < 10; i++ {
			k, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
			rep, rej := e.Execute(context.Background(), k.Raw)
			if rej != nil {
				t.Fatal(rej)
			}
			codes = append(codes, tallyCode(rep))
		}
		if runs != 1 {
			t.Fatalf("trial %d: writ has uses:count 1 but the executor ran %d operations under it: %v", trial, runs, codes)
		}
	}
}

// Spec 8.1: an effect is reversed at most once per tally identity. Before the
// fix two concurrent undos with different call ids both ran the reversal.
func TestConcurrentUndosReverseOnce(t *testing.T) {
	f := newStandingFixture(t)
	var refunds int32
	gate := make(chan struct{})
	f.e.Undo = func(ctx context.Context, tt *writ.Tally, res any) Result {
		atomic.AddInt32(&refunds, 1)
		<-gate
		return Result{Res: map[string]any{"refund": "rf"}}
	}
	chain := []*writ.Writ{f.w1, f.w2}
	calls := []*writ.Call{f.undoCall(f.A, chain), f.undoCall(f.B, chain)}
	codes := make([]string, len(calls))
	var wg sync.WaitGroup
	for i, u := range calls {
		wg.Add(1)
		go func(i int, u *writ.Call) {
			defer wg.Done()
			rep, rej := f.e.Execute(context.Background(), u.Raw)
			if rej != nil {
				codes[i] = "unsigned:" + string(rej.Code)
				return
			}
			codes[i] = tallyCode(rep)
		}(i, u)
	}
	time.Sleep(200 * time.Millisecond)
	close(gate)
	wg.Wait()
	if refunds != 1 {
		t.Fatalf("one ok tally was reversed %d times", refunds)
	}
	for i, c := range codes {
		if c != "ok" {
			t.Errorf("undo %d answered %s, want ok (the second is idempotent)", i, c)
		}
	}
}

// Spec 9: the call store and count store MUST survive restart. Before the
// fix a failed store write was ignored and an ok tally returned, and after a
// restart the same call executed again. Now nothing runs unrecorded.
func TestStoreWriteFailureRunsNothing(t *testing.T) {
	A := id(1)
	runs := 0
	path := filepath.Join(t.TempDir(), "no-such-dir", "store.json")
	e := newC(t, path, A, func(ctx context.Context, k *writ.Call) Result { runs++; return Result{} })
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "x", "uses", "count", 1), now+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	if got := tallyCode(rep); got != "failed:"+StoreUnavailable || runs != 0 {
		t.Fatalf("unwritable store: answer %s after %d runs, want failed:%s and no run", got, runs, StoreUnavailable)
	}
	// The refusal consumed nothing: once the store is writable the call runs.
	e.Store.path = filepath.Join(t.TempDir(), "store.json")
	rep, _ = e.Execute(context.Background(), k.Raw)
	if got := tallyCode(rep); got != "ok" || runs != 1 {
		t.Fatalf("after the store recovered: answer %s after %d runs, want ok and one run", got, runs)
	}
}

// Spec 9.1: a revoke does not withdraw standing. Before the fix a revoke
// canceled an accepted sys/undo that was already running.
func TestRevokeLeavesRunningUndoAlone(t *testing.T) {
	f := newStandingFixture(t)
	started := make(chan struct{})
	result := make(chan string, 1)
	f.e.Undo = func(ctx context.Context, tt *writ.Tally, res any) Result {
		close(started)
		select {
		case <-ctx.Done():
			return Result{St: "canceled", ErrCode: "canceled"}
		case <-time.After(time.Second):
			return Result{Res: map[string]any{"refund": "rf"}}
		}
	}
	u := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	go func() {
		rep, _ := f.e.Execute(context.Background(), u.Raw)
		result <- tallyCode(rep)
	}()
	<-started
	r, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	pend, rej := f.e.Revoke(r.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	if got := <-result; got != "ok" || len(pend.Tallies) != 0 {
		t.Fatalf("revoke touched a running sys/undo: undo answered %s, revoke listed %d pending tallies", got, len(pend.Tallies))
	}
}
