package exec

import (
	"context"
	"path/filepath"
	"testing"

	"writproto/writ"
)

// Spec 9: a key-wide revoke MUST survive restart. One the executor cannot
// write is still honored, is answered as an error rather than as recorded,
// and is written when the sender retries.
func TestKeyWideRevokeWriteFailure(t *testing.T) {
	A := id(1)
	good := filepath.Join(t.TempDir(), "store.json")
	e := newC(t, good, A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	e.Store.path = filepath.Join(t.TempDir(), "no-such-dir", "store.json")
	rv, _ := writ.NewRevoke(A, nil)
	if _, rej := e.Revoke(rv.Raw); rej == nil || rej.Code != writ.Reason(StoreUnavailable) {
		t.Fatalf("unwritable revoke log: got %v, want %s", rej, StoreUnavailable)
	}
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "x"), now+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
	rep, _ := e.Execute(context.Background(), k.Raw)
	if got := tallyCode(rep); got != "failed:revoked" {
		t.Fatalf("while the revoke is held only in memory: %s, want failed:revoked", got)
	}
	e.Store.path = good
	if _, rej := e.Revoke(rv.Raw); rej != nil {
		t.Fatalf("retry after the store recovered: %v", rej)
	}
	restarted := newC(t, good, A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	k2, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
	rep, _ = restarted.Execute(context.Background(), k2.Raw)
	if got := tallyCode(rep); got != "failed:revoked" {
		t.Fatalf("after restart: %s, want failed:revoked", got)
	}
}
