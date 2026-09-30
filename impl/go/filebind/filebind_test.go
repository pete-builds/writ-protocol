package filebind

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"writproto/exec"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

const poll = 5 * time.Millisecond

func TestCallsOverFiles(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	C, _ := keys.FromSeed(bytes.Repeat([]byte{3}, 32))
	dir := t.TempDir()
	st, err := exec.OpenFileStore(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	newExec := func(st *exec.FileStore) *exec.Executor {
		e := exec.New(C, st)
		e.AcceptRoot = func(d string) bool { return d == A.DID() }
		e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
			runs.Add(1)
			return exec.Result{Res: map[string]any{"charged": k.Args["amount"]}, Used: map[string]int64{"amount": 100}}
		}
		return e
	}
	w, _ := writ.Issue(A, C.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "pay"}, "amount": map[string]any{"t": "max", "v": 500}}, time.Now().Unix()+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "pay/charge", map[string]any{"amount": 100})

	// A call claimed before a crash, which never ran, waits in work/.
	crashed, _ := writ.NewCall(A, []*writ.Writ{w}, "pay/charge", map[string]any{"amount": 100})
	_, work, _, _ := Dirs(filepath.Join(dir, "q"))
	b, _ := json.Marshal(crashed.Raw)
	if err := os.WriteFile(filepath.Join(work, "crashed.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	q := filepath.Join(dir, "q")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = Serve(ctx, newExec(st), q, poll); close(done) }()
	ask := func(name string, obj wire.Object) map[string]any {
		t.Helper()
		if err := Send(q, name, obj); err != nil {
			t.Fatal(err)
		}
		actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer acancel()
		ans, err := Await(actx, q, name, poll)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return ans
	}
	verify := func(call *writ.Call, ans map[string]any) string {
		t.Helper()
		tb, _ := json.Marshal(ans["tally"])
		obj, err := wire.Decode(tb)
		if err != nil {
			t.Fatalf("no tally in %v", ans)
		}
		v, tl, err := writ.VerifyTally(w, call, obj, ans["res"])
		if v != writ.Valid {
			t.Fatalf("tally does not verify: %v %v", v, err)
		}
		if tl.Err != nil {
			return tl.Err.Code
		}
		return tl.St
	}

	if got := verify(k, ask("one.json", k.Raw)); got != "ok" {
		t.Fatalf("a call over files: %s", got)
	}
	if got := verify(k, ask("one-again.json", k.Raw)); got != "ok" || runs.Load() != 2 {
		t.Fatalf("a replay: %s after %d runs, want ok and 2 runs (the charge and the crashed call)", got, runs.Load())
	}
	if ans := ask("garbage.json", wire.Object{"v": 1, "typ": "note"}); ans["error"] != "wrong_type" {
		t.Fatalf("a file that is neither call nor revoke: %v", ans)
	}
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w})
	if ans := ask("revoke.json", rv.Raw); ans["tallies"] == nil {
		t.Fatalf("a revoke over files: %v", ans)
	}
	k2, _ := writ.NewCall(A, []*writ.Writ{w}, "pay/charge", map[string]any{"amount": 100})
	if got := verify(k2, ask("after-revoke.json", k2.Raw)); got != "revoked" {
		t.Fatalf("a call after the revoke: %s", got)
	}
	_, _, out, _ := Dirs(q)
	if _, err := os.Stat(filepath.Join(out, "crashed.json")); err != nil {
		t.Fatalf("the call claimed before the crash was not answered: %v", err)
	}

	// Crash again with an already-answered call left in work/: the restarted
	// executor answers it from the store and does not run it a second time.
	cancel()
	<-done
	if err := os.WriteFile(filepath.Join(work, "one-crash.json"), mustJSON(k.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	before := runs.Load()
	st2, _ := exec.OpenFileStore(filepath.Join(dir, "store.json"))
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = Serve(ctx2, newExec(st2), q, poll) }()
	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acancel()
	ans, err := Await(actx, q, "one-crash.json", poll)
	if err != nil {
		t.Fatal(err)
	}
	// The writ was revoked meanwhile, and revocation (spec 7 step 7) comes
	// before replay (step 9), so the answer is a fresh signed refusal. What
	// matters for a crash is that the charge does not run again.
	if got := verify(k, ans); got != "revoked" || runs.Load() != before {
		t.Fatalf("an answered call recovered from work/: %s, runs %d then %d", got, before, runs.Load())
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
