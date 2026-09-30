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

// A peer the transport authenticated but could not name binds nothing, even
// under a PeerBinds that binds every peer and with the signer's key attested:
// a captured call replayed over it earns no stored result (spec 7.6).
func TestUnidentifiedPeerBindsNothing(t *testing.T) {
	A := id(1)
	runs := 0
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result {
		runs++
		return Result{Res: map[string]any{"secret": "s"}}
	})
	e.PeerBinds = func(string, string) bool { return true }
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "x"), now+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
	if rep, _ := e.Execute(WithPeer(context.Background(), "spiffe://a"), k.Raw); tallyCode(rep) != "ok" || runs != 1 {
		t.Fatalf("a named peer under a PeerBinds that binds everything: %s", tallyCode(rep))
	}
	ctx := WithAttestedKeys(WithUnidentifiedPeer(context.Background(), "x509:none"), []string{A.DID()})
	rep, _ := e.Execute(ctx, k.Raw)
	if tallyCode(rep) != "failed:peer_mismatch" || rep.Res != nil {
		t.Fatalf("the captured call replayed by an unidentified peer: %s, result %v", tallyCode(rep), rep.Res)
	}
	k2, _ := writ.NewCall(A, []*writ.Writ{w}, "x", map[string]any{})
	if rep, _ := e.Execute(ctx, k2.Raw); tallyCode(rep) != "failed:peer_mismatch" || runs != 1 {
		t.Fatalf("a fresh call from an unidentified peer: %s, %d runs", tallyCode(rep), runs)
	}
}
