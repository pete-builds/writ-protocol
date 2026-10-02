package exec

import (
	"context"

	"path/filepath"
	"sync"
	"testing"

	"writproto/bound"
	"writproto/keys"
	"writproto/writ"
)

func amountCall(t *testing.T, from *keys.Identity, chain []*writ.Writ, amount int) *writ.Call {
	t.Helper()
	k, err := writ.NewCall(from, chain, "pay", map[string]any{"amount": amount})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func run(t *testing.T, e *Executor, k *writ.Call) string {
	t.Helper()
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	return tallyCode(rep)
}

// Spec 7.3: a total bounds the sum of one argument across every call this
// executor accepts under the writ. max alone let any number of calls each
// spend up to the limit.
func TestTotalBoundsTheRunningSum(t *testing.T) {
	A := id(1)
	runs := 0
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result { runs++; return Result{} })
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, nil)
	k1 := amountCall(t, A, []*writ.Writ{w}, 600)
	steps := []struct {
		k    *writ.Call
		want string
	}{
		{k1, "ok"},
		{k1, "ok"}, // a replay is answered from the call store and draws nothing
		{amountCall(t, A, []*writ.Writ{w}, 300), "ok"},
		{amountCall(t, A, []*writ.Writ{w}, 1001), "failed:out_of_bounds"}, // one call over the value: section 7.2
		{amountCall(t, A, []*writ.Writ{w}, 200), "failed:total_exhausted"},
		{amountCall(t, A, []*writ.Writ{w}, 100), "ok"}, // the refusal consumed nothing: exactly 1000
		{amountCall(t, A, []*writ.Writ{w}, 0), "ok"},   // zero fits in a spent total
		{amountCall(t, A, []*writ.Writ{w}, 1), "failed:total_exhausted"},
	}
	for i, s := range steps {
		if got := run(t, e, s.k); got != s.want {
			t.Fatalf("step %d: %s, want %s", i, got, s.want)
		}
	}
	if runs != 4 {
		t.Fatalf("the operation ran %d times, want 4", runs)
	}
}

// A child's total is a share that still draws on every ancestor's, so two
// children of 600 under a root of 1000 cannot both be spent, and delegating
// to oneself resets nothing.
func TestTotalDrawsOnEveryWritInTheChain(t *testing.T) {
	A, B := id(1), id(2)
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	root, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, nil)
	c1, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 600), now+3600, root)
	c2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 600), now+3600, root)
	self, _ := writ.Issue(B, B.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, root)
	c3, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, self)
	if got := run(t, e, amountCall(t, B, []*writ.Writ{root, c1}, 600)); got != "ok" {
		t.Fatalf("the first share: %s", got)
	}
	if got := run(t, e, amountCall(t, B, []*writ.Writ{root, c1}, 1)); got != "failed:total_exhausted" {
		t.Fatalf("past the first share: %s", got)
	}
	if got := run(t, e, amountCall(t, B, []*writ.Writ{root, c2}, 600)); got != "failed:total_exhausted" {
		t.Fatalf("a second share of 600 under a root of 1000: %s", got)
	}
	if got := run(t, e, amountCall(t, B, []*writ.Writ{root, c2}, 400)); got != "ok" {
		t.Fatalf("what the root has left: %s", got)
	}
	if got := run(t, e, amountCall(t, B, []*writ.Writ{root, self, c3}, 1)); got != "failed:total_exhausted" {
		t.Fatalf("delegating to oneself to reset the root: %s", got)
	}
}

// Spec 7 step 10: count is checked before total, and a refusal by either
// consumes neither.
func TestTotalAndCountRefuseTogether(t *testing.T) {
	A := id(1)
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 100, "uses", "count", 2), now+3600, nil)
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 100)); got != "ok" {
		t.Fatalf("the first call: %s", got)
	}
	// The total is spent and one use is left: total_exhausted, and the use
	// is not consumed, so a zero-amount call still runs.
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 1)); got != "failed:total_exhausted" {
		t.Fatalf("over the total: %s", got)
	}
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 0)); got != "ok" {
		t.Fatalf("the second use: %s", got)
	}
	// Both are spent: count is reported, because step 10 checks it first.
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 1)); got != "failed:count_exhausted" {
		t.Fatalf("both spent: %s", got)
	}
}

// Spec 9: the total store survives a restart.
func TestTotalSurvivesRestart(t *testing.T) {
	A := id(1)
	path := filepath.Join(t.TempDir(), "store.json")
	e := newC(t, path, A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, nil)
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 700)); got != "ok" {
		t.Fatalf("before the restart: %s", got)
	}
	e2 := newC(t, path, A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	if got := run(t, e2, amountCall(t, A, []*writ.Writ{w}, 301)); got != "failed:total_exhausted" {
		t.Fatalf("after the restart: %s", got)
	}
	if got := run(t, e2, amountCall(t, A, []*writ.Writ{w}, 300)); got != "ok" {
		t.Fatalf("the remainder after the restart: %s", got)
	}
}

// Spec 9: an executor that cannot write its stores consumes nothing.
func TestTotalStoreWriteFailureConsumesNothing(t *testing.T) {
	A := id(1)
	e := newC(t, filepath.Join(t.TempDir(), "no-such-dir", "store.json"), A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, nil)
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 1000)); got != "failed:"+StoreUnavailable {
		t.Fatalf("unwritable store: %s", got)
	}
	e.Store.path = filepath.Join(t.TempDir(), "store.json")
	if got := run(t, e, amountCall(t, A, []*writ.Writ{w}, 1000)); got != "ok" {
		t.Fatalf("after the store recovered, the whole total is left: %s", got)
	}
}

// Spec 7: two calls that share a writ with a total must not together take it
// past its value, however they interleave.
func TestConcurrentCallsNeverOverspendATotal(t *testing.T) {
	A := id(1)
	var mu sync.Mutex
	spent := 0
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result {
		n, _ := bound.Int(k.Args["amount"])
		mu.Lock()
		spent += int(n)
		mu.Unlock()
		return Result{}
	})
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "pay", "amount", "total", 1000), now+3600, nil)
	const n = 200
	calls := make([]*writ.Call, n)
	for i := range calls {
		calls[i] = amountCall(t, A, []*writ.Writ{w}, 30)
	}
	codes := make([]string, n)
	var wg sync.WaitGroup
	for i := range calls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rep, rej := e.Execute(context.Background(), calls[i].Raw)
			if rej != nil {
				codes[i] = string(rej.Code)
				return
			}
			codes[i] = tallyCode(rep)
		}(i)
	}
	wg.Wait()
	ok, exhausted := 0, 0
	for _, c := range codes {
		switch c {
		case "ok":
			ok++
		case "failed:total_exhausted":
			exhausted++
		default:
			t.Fatalf("unexpected answer %s", c)
		}
	}
	if ok != 33 || exhausted != n-33 || spent != 990 {
		t.Fatalf("%d accepted, %d refused, %d spent; want 33, %d, 990", ok, exhausted, spent, n-33)
	}
}
