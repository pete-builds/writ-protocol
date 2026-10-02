package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

func id(b byte) *keys.Identity {
	i, _ := keys.FromSeed(bytes.Repeat([]byte{b}, 32))
	return i
}

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

const now = int64(1788400000)

func newC(t *testing.T, path string, A *keys.Identity, handler Handler) *Executor {
	t.Helper()
	st, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := New(id(3), st)
	e.Now = func() int64 { return now + 10 }
	e.AcceptRoot = func(did string) bool { return did == A.DID() }
	e.Handle = handler
	return e
}

func TestExecuteCountReplayAndRoot(t *testing.T) {
	A, B := id(1), id(2)
	charges := 0
	until := now + 86400
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result {
		charges++
		return Result{Res: map[string]any{"charge": "ch_1"}, Used: map[string]int64{"amount": 58900}, RevUntil: &until}
	})
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000, "uses", "count", 1), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 58900})
	rep, rej := e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	v, tally, err := writ.VerifyTally(w2, k, rep.Tally, rep.Res)
	if v != writ.Valid || tally.St != "ok" {
		t.Fatalf("%s %v", v, err)
	}
	// Replay: same bytes, same tally, no second charge.
	rep2, _ := e.Execute(context.Background(), k.Raw)
	b1, _ := json.Marshal(rep.Tally)
	b2, _ := json.Marshal(rep2.Tally)
	if !bytes.Equal(b1, b2) || charges != 1 {
		t.Fatal("replay must return the stored tally byte for byte and not re-execute")
	}
	// New call id under the same chain: count exhausted (count 1 on both w1 and w2).
	k2, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1})
	rep3, _ := e.Execute(context.Background(), k2.Raw)
	_, t3, _ := writ.VerifyTally(w2, k2, rep3.Tally, nil)
	if t3.St != "failed" || t3.Err.Code != string(writ.CountExhausted) {
		t.Fatalf("want count_exhausted, got %+v", t3.Err)
	}
	// Self-delegation cannot reset the root count: B issues w2' to itself then to C.
	w2b, _ := writ.Issue(B, B.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w1)
	w3, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, w2b)
	k3, _ := writ.NewCall(B, []*writ.Writ{w1, w2b, w3}, "travel/charge", map[string]any{"amount": 1})
	rep4, _ := e.Execute(context.Background(), k3.Raw)
	_, t4, _ := writ.VerifyTally(w3, k3, rep4.Tally, nil)
	if t4.St != "failed" || t4.Err.Code != string(writ.CountExhausted) {
		t.Fatalf("self-delegation reset the count: %+v", t4.Err)
	}
	// Stranger root.
	S := id(9)
	ws, _ := writ.Issue(S, e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	ks, _ := writ.NewCall(S, []*writ.Writ{ws}, "travel/charge", map[string]any{})
	rep5, _ := e.Execute(context.Background(), ks.Raw)
	_, t5, _ := writ.VerifyTally(ws, ks, rep5.Tally, nil)
	if t5.Err == nil || t5.Err.Code != string(writ.RootNotAccepted) {
		t.Fatalf("want root_not_accepted, got %+v", t5.Err)
	}
	// Undo by A directly (A is an issuer on the chain), then again (idempotent), then by a stranger.
	refunds := 0
	e.Undo = func(ctx context.Context, tt *writ.Tally, res any) Result {
		refunds++
		return Result{Res: map[string]any{"refund": "rf_1"}}
	}
	ku, _ := writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/undo", map[string]any{"tally": tally.Raw})
	ru, _ := e.Execute(context.Background(), ku.Raw)
	_, tu, err := writ.VerifyTally(w2, ku, ru.Tally, ru.Res)
	if err != nil || tu.St != "ok" || refunds != 1 {
		t.Fatalf("undo: %v %+v", err, tu)
	}
	ku2, _ := writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/undo", map[string]any{"tally": tally.Raw})
	e.Execute(context.Background(), ku2.Raw)
	if refunds != 1 {
		t.Fatal("second undo must not refund twice")
	}
	ks2, _ := writ.NewCall(S, []*writ.Writ{w1, w2}, "sys/undo", map[string]any{"tally": tally.Raw})
	rs, _ := e.Execute(context.Background(), ks2.Raw)
	_, ts, _ := writ.VerifyTally(w2, ks2, rs.Tally, nil)
	if ts.Err == nil || ts.Err.Code != string(writ.NoStanding) {
		t.Fatalf("stranger undo: %+v", ts.Err)
	}
	// sys/tallies by A with only w1.
	kt, _ := writ.NewCall(A, []*writ.Writ{w1}, "sys/tallies", map[string]any{"writ": w1.ID})
	// The executor of a call is the leaf hld; A's chain [w1] has hld B, so C refuses. Use the full chain.
	rt, _ := e.Execute(context.Background(), kt.Raw)
	// A wrong_executor refusal is signed by the receiver, not the leaf holder, so
	// it is parsed with the receiver's key rather than verified under w1.
	tt, _ := writ.ParseTally(rt.Tally, e.ID.DID())
	if tt == nil || tt.Err == nil || tt.Err.Code != string(writ.WrongExecutor) {
		t.Fatalf("want wrong_executor, got %+v", tt.Err)
	}
	kt2, _ := writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})
	rt2, _ := e.Execute(context.Background(), kt2.Raw)
	_, tt2, err := writ.VerifyTally(w2, kt2, rt2.Tally, rt2.Res)
	if err != nil || tt2.St != "ok" {
		t.Fatalf("tallies: %v", err)
	}
	if n := len(rt2.Res.(map[string]any)["tallies"].([]any)); n < 3 {
		t.Fatalf("expected at least 3 tallies under w1, got %d", n)
	}
}

func TestRevokeCancelsInflightAndRestartRecovers(t *testing.T) {
	A, B := id(1), id(2)
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	started := make(chan struct{})
	e := newC(t, path, A, func(ctx context.Context, k *writ.Call) Result {
		close(started)
		select {
		case <-ctx.Done():
			return Result{St: "canceled", ErrCode: string(writ.Revoked)}
		case <-time.After(5 * time.Second):
			return Result{Res: map[string]any{"late": true}}
		}
	})
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/slow", map[string]any{})
	done := make(chan *Reply)
	go func() { r, _ := e.Execute(context.Background(), k.Raw); done <- r }()
	<-started
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w1})
	pend, rej := e.Revoke(rv.Raw)
	if rej != nil || len(pend.Tallies) != 1 {
		t.Fatalf("revoke: %v pending=%v", rej, pend)
	}
	rep := <-done
	_, tl, _ := writ.VerifyTally(w2, k, rep.Tally, nil)
	if tl.St != "canceled" {
		t.Fatalf("want canceled, got %s", tl.St)
	}
	// New calls under the revoked writ are refused.
	k2, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/x", map[string]any{})
	r2, _ := e.Execute(context.Background(), k2.Raw)
	_, t2, _ := writ.VerifyTally(w2, k2, r2.Tally, nil)
	if t2.Err == nil || t2.Err.Code != string(writ.Revoked) {
		t.Fatalf("want revoked, got %+v", t2.Err)
	}
	// Crash simulation: write a pending record by hand, reopen, recover.
	w1c, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	w2c, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, w1c)
	k3, _ := writ.NewCall(B, []*writ.Writ{w1c, w2c}, "travel/y", map[string]any{})
	if _, _, err := e.Store.admit(&Record{LeafID: w2c.ID, CID: k3.CID, Acc: now, Exp: w2c.Exp, Call: k3.Raw}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	e2 := newC(t, path, A, nil)
	if n := e2.Recover(); n != 1 {
		t.Fatalf("recovered %d, want 1", n)
	}
	if !e2.Store.isRevoked(w1.ID) {
		t.Fatal("revocation did not survive restart")
	}
	r3, _ := e2.Execute(context.Background(), k3.Raw)
	_, t3, _ := writ.VerifyTally(w2c, k3, r3.Tally, nil)
	if t3 == nil || t3.Err == nil || t3.Err.Code != string(writ.UnknownOutcome) {
		t.Fatalf("want unknown_outcome after restart, got %+v", t3.Err)
	}
	_ = wire.Object{}
}

// TestConcurrentDuplicateExecutesOnce: spec section 7 makes steps 9 and 10
// one atomic operation, so identical calls arriving together execute once.
// The others are answered from the call store: pending while the first is
// running, its final tally after.
func TestConcurrentDuplicateExecutesOnce(t *testing.T) {
	A, B := id(1), id(2)
	release := make(chan struct{})
	var mu sync.Mutex
	runs := 0
	// A file-backed store, as a real executor runs: each store write is a
	// file write, which is the window a non-atomic check-then-record leaves.
	e := newC(t, filepath.Join(t.TempDir(), "store.json"), A, func(ctx context.Context, k *writ.Call) Result {
		mu.Lock()
		runs++
		mu.Unlock()
		<-release
		return Result{Res: map[string]any{"ok": true}}
	})
	w1, _ := writ.Issue(A, B.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	w2, _ := writ.Issue(B, e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, w1)
	k, _ := writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/book", map[string]any{})
	const n = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	sts := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rep, rej := e.Execute(context.Background(), k.Raw)
			if rej != nil {
				sts <- "unsigned:" + string(rej.Code)
				return
			}
			tt, _ := writ.ParseTally(rep.Tally, e.ID.DID())
			sts <- tt.St
		}()
	}
	close(start)
	// Let the duplicates arrive while the first call is running, then release it.
	deadline := time.After(2 * time.Second)
	answered := 0
wait:
	for answered < n-1 {
		select {
		case st := <-sts:
			if st != "pending" {
				t.Errorf("a duplicate answered %q while the first call was running", st)
			}
			answered++
		case <-deadline:
			break wait
		}
	}
	close(release)
	wg.Wait()
	close(sts)
	for st := range sts {
		if st != "ok" && st != "pending" {
			t.Errorf("answer %q, want ok or pending", st)
		}
	}
	if runs != 1 {
		t.Fatalf("handler ran %d times for one call id, want 1", runs)
	}
}
