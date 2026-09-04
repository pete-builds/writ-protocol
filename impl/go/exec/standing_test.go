package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// standingFixture is the two-hop chain A -> B -> C(executor) with a charge
// already executed at now+10 and reversible until now+86400. The executor's
// clock is adjustable so the tests can move past exp and past rev.until.
type standingFixture struct {
	A, B    *keys.Identity
	e       *Executor
	clock   int64
	w1, w2  *writ.Writ
	k       *writ.Call
	tally   *writ.Tally
	charges int
	refunds int
}

func newStandingFixture(t *testing.T) *standingFixture {
	t.Helper()
	f := &standingFixture{A: id(1), B: id(2), clock: now + 10}
	until := now + 86400
	f.e = newC(t, "", f.A, func(ctx context.Context, k *writ.Call) Result {
		f.charges++
		return Result{Res: map[string]any{"charge": "ch_1"}, Used: map[string]int64{"amount": 58900}, RevUntil: &until}
	})
	f.e.Now = func() int64 { return f.clock }
	f.e.Undo = func(ctx context.Context, tt *writ.Tally, res any) Result {
		f.refunds++
		return Result{Res: map[string]any{"refund": "rf_1"}}
	}
	f.w1, _ = writ.Issue(f.A, f.B.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000, "uses", "count", 1), now+3600, nil)
	f.w2, _ = writ.Issue(f.B, f.e.ID.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, f.w1)
	f.k, _ = writ.NewCall(f.B, []*writ.Writ{f.w1, f.w2}, "travel/charge", map[string]any{"amount": 58900})
	rep, rej := f.e.Execute(context.Background(), f.k.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	v, tally, err := writ.VerifyTally(f.w2, f.k, rep.Tally, rep.Res)
	if v != writ.Valid || tally.St != "ok" {
		t.Fatalf("setup charge: %s %v", v, err)
	}
	f.tally = tally
	return f
}

// code returns the reason code of a signed refusal, or "" for an ok tally.
func (f *standingFixture) code(t *testing.T, k *writ.Call, rep *Reply, rej *writ.Error) string {
	t.Helper()
	if rej != nil {
		return "unsigned:" + string(rej.Code)
	}
	tt, err := writ.ParseTally(rep.Tally, f.e.ID.DID())
	if err != nil {
		t.Fatalf("reply tally does not parse under the executor key: %v", err)
	}
	if tt.Err != nil {
		return tt.Err.Code
	}
	return ""
}

func (f *standingFixture) undoCall(from *keys.Identity, chain []*writ.Writ) *writ.Call {
	k, _ := writ.NewCall(from, chain, "sys/undo", map[string]any{"tally": f.tally.Raw})
	return k
}

func TestForwardCallRejectedAfterExpiry(t *testing.T) {
	f := newStandingFixture(t)
	f.clock = f.w2.Exp // exclusive: the leaf is expired at exactly exp
	k2, _ := writ.NewCall(f.B, []*writ.Writ{f.w1, f.w2}, "travel/charge", map[string]any{"amount": 1})
	rep, rej := f.e.Execute(context.Background(), k2.Raw)
	if got := f.code(t, k2, rep, rej); got != string(writ.Expired) {
		t.Fatalf("expired forward call: want expired, got %q", got)
	}
	if f.charges != 1 {
		t.Fatal("an expired forward call must not execute")
	}
	// Expiry of the leaf never restores forward authority, even when the root is live.
	f.clock = f.w1.Exp - 1
	rep, rej = f.e.Execute(context.Background(), k2.Raw)
	if got := f.code(t, k2, rep, rej); got != string(writ.Expired) {
		t.Fatalf("leaf expired, root live: want expired, got %q", got)
	}
}

func TestUndoAfterExpiryBeforeRevUntil(t *testing.T) {
	f := newStandingFixture(t)
	f.clock = f.w1.Exp + 60 // every writ in the chain has expired
	ku := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	rep, rej := f.e.Execute(context.Background(), ku.Raw)
	if got := f.code(t, ku, rep, rej); got != "" {
		t.Fatalf("undo after expiry, before rev.until: want ok, got %q", got)
	}
	if f.refunds != 1 {
		t.Fatalf("refunds = %d, want 1", f.refunds)
	}
	// The undo tally verifies under 6.2 although acc is after the writ's exp:
	// step 5 does not apply to a standing operation.
	v, tu, err := writ.VerifyTally(f.w2, ku, rep.Tally, rep.Res)
	if v != writ.Valid || tu.St != "ok" || tu.Acc < f.w2.Exp {
		t.Fatalf("undo tally: verdict %s st %s acc %d err %v", v, tu.St, tu.Acc, err)
	}
	// Replayed undo: identical bytes return the stored tally, no second refund.
	rep2, _ := f.e.Execute(context.Background(), ku.Raw)
	b1, _ := json.Marshal(rep.Tally)
	b2, _ := json.Marshal(rep2.Tally)
	if !bytes.Equal(b1, b2) || f.refunds != 1 {
		t.Fatal("replayed undo must return the same tally and not refund twice")
	}
	// A fresh undo call for the same tally is idempotent by tally identity.
	ku2 := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	rep3, rej3 := f.e.Execute(context.Background(), ku2.Raw)
	if got := f.code(t, ku2, rep3, rej3); got != "" || f.refunds != 1 {
		t.Fatalf("second undo: code %q refunds %d", got, f.refunds)
	}
	// The intermediate issuer B has standing too, after expiry.
	kb := f.undoCall(f.B, []*writ.Writ{f.w1, f.w2})
	repb, rejb := f.e.Execute(context.Background(), kb.Raw)
	if got := f.code(t, kb, repb, rejb); got != "" || f.refunds != 1 {
		t.Fatalf("undo by intermediate after expiry: code %q refunds %d", got, f.refunds)
	}
}

func TestUndoAfterRevUntilFails(t *testing.T) {
	f := newStandingFixture(t)
	f.clock = *f.tally.Rev // exclusive: not reversible at exactly until
	ku := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	rep, rej := f.e.Execute(context.Background(), ku.Raw)
	if got := f.code(t, ku, rep, rej); got != string(writ.NotReversible) {
		t.Fatalf("undo at rev.until: want not_reversible, got %q", got)
	}
	if f.refunds != 0 {
		t.Fatal("must not refund past rev.until")
	}
}

func TestUndoAfterRevokeSucceeds(t *testing.T) {
	f := newStandingFixture(t)
	rv, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	if _, rej := f.e.Revoke(rv.Raw); rej != nil {
		t.Fatal(rej)
	}
	// Forward authority is gone.
	k2, _ := writ.NewCall(f.B, []*writ.Writ{f.w1, f.w2}, "travel/charge", map[string]any{"amount": 1})
	rep, rej := f.e.Execute(context.Background(), k2.Raw)
	if got := f.code(t, k2, rep, rej); got != string(writ.Revoked) {
		t.Fatalf("forward after revoke: want revoked, got %q", got)
	}
	// Standing survives: the revoker can still reverse what ran before the revoke.
	ku := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	rep, rej = f.e.Execute(context.Background(), ku.Raw)
	if got := f.code(t, ku, rep, rej); got != "" || f.refunds != 1 {
		t.Fatalf("undo after revoke: code %q refunds %d", got, f.refunds)
	}
	// Revoked and expired together still never restore forward authority.
	f.clock = f.w1.Exp + 1
	rep, rej = f.e.Execute(context.Background(), k2.Raw)
	if got := f.code(t, k2, rep, rej); got != string(writ.Expired) {
		t.Fatalf("forward after revoke and expiry: want expired, got %q", got)
	}
}

func TestKeyWideRevokeStopsForwardCalls(t *testing.T) {
	f := newStandingFixture(t)
	star, _ := writ.NewRevoke(f.A, nil)
	if _, rej := f.e.Revoke(star.Raw); rej != nil {
		t.Fatal(rej)
	}
	k2, _ := writ.NewCall(f.B, []*writ.Writ{f.w1, f.w2}, "travel/charge", map[string]any{"amount": 1})
	rep, rej := f.e.Execute(context.Background(), k2.Raw)
	if got := f.code(t, k2, rep, rej); got != string(writ.Revoked) {
		t.Fatalf("forward after key-wide revoke: want revoked, got %q", got)
	}
	ku := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	rep, rej = f.e.Execute(context.Background(), ku.Raw)
	if got := f.code(t, ku, rep, rej); got != "" || f.refunds != 1 {
		t.Fatalf("undo after key-wide revoke: code %q refunds %d", got, f.refunds)
	}
}

func TestTallyRecoveryAfterExpiry(t *testing.T) {
	f := newStandingFixture(t)
	f.clock = f.w1.Exp + 60
	kt, _ := writ.NewCall(f.A, []*writ.Writ{f.w1, f.w2}, "sys/tallies", map[string]any{"writ": f.w1.ID})
	rep, rej := f.e.Execute(context.Background(), kt.Raw)
	if got := f.code(t, kt, rep, rej); got != "" {
		t.Fatalf("sys/tallies after expiry: want ok, got %q", got)
	}
	v, tt, err := writ.VerifyTally(f.w2, kt, rep.Tally, rep.Res)
	if v != writ.Valid || tt.St != "ok" {
		t.Fatalf("recovery tally: %s %v", v, err)
	}
	arr, _ := rep.Res.(map[string]any)["tallies"].([]any)
	found := false
	for _, x := range arr {
		if h, _ := wire.Hash(x.(map[string]any)); h == f.tally.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("recovered %d tallies, none is the charge tally", len(arr))
	}
	// A writ hash outside the chain is a mismatch, expiry or not.
	kbad, _ := writ.NewCall(f.A, []*writ.Writ{f.w1, f.w2}, "sys/tallies", map[string]any{"writ": f.tally.ID})
	rep, rej = f.e.Execute(context.Background(), kbad.Raw)
	if got := f.code(t, kbad, rep, rej); got != string(writ.TallyMismatch) {
		t.Fatalf("sys/tallies with a non-chain hash: want tally_mismatch, got %q", got)
	}
}

// TestStandingCallsStillFailClosed: expiry and revocation are the only checks
// a standing call skips. Everything structural still fails, after expiry.
func TestStandingCallsStillFailClosed(t *testing.T) {
	f := newStandingFixture(t)
	f.clock = f.w1.Exp + 60
	S := id(9)

	// Tampered: args changed after signing. Fails at step 2 with an unsigned rejection.
	ku := f.undoCall(f.A, []*writ.Writ{f.w1, f.w2})
	tampered, _ := wire.Clone(ku.Raw)
	tampered["args"] = map[string]any{"tally": f.tally.Raw, "x": json.Number("1")}
	rep, rej := f.e.Execute(context.Background(), tampered)
	if got := f.code(t, ku, rep, rej); got != "unsigned:"+string(writ.BadSignature) {
		t.Fatalf("tampered standing call: want bad_signature, got %q", got)
	}

	// Broken chain: wrong order, re-signed by A so the signature is fine.
	broken, _ := wire.Clone(ku.Raw)
	broken["chain"] = []any{f.w2.Raw, f.w1.Raw}
	bb, _ := json.Marshal(broken)
	broken, _ = wire.Decode(bb)
	_ = wire.Sign(broken, f.A)
	rep, rej = f.e.Execute(context.Background(), broken)
	if got := f.code(t, ku, rep, rej); got != string(writ.ChainBroken) {
		t.Fatalf("broken chain: want chain_broken, got %q", got)
	}

	// Foreign root: a stranger's self-issued chain ending at this executor.
	ws, _ := writ.Issue(S, f.e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	ks, _ := writ.NewCall(S, []*writ.Writ{ws}, "sys/tallies", map[string]any{"writ": ws.ID})
	rep, rej = f.e.Execute(context.Background(), ks.Raw)
	if got := f.code(t, ks, rep, rej); got != string(writ.RootNotAccepted) {
		t.Fatalf("foreign root: want root_not_accepted, got %q", got)
	}

	// Wrong executor: chain [w1] has hld B, not this executor.
	kw, _ := writ.NewCall(f.A, []*writ.Writ{f.w1}, "sys/tallies", map[string]any{"writ": f.w1.ID})
	rep, rej = f.e.Execute(context.Background(), kw.Raw)
	if got := f.code(t, kw, rep, rej); got != string(writ.WrongExecutor) {
		t.Fatalf("wrong executor: want wrong_executor, got %q", got)
	}

	// Unauthorized: a stranger, and the executor itself, have no standing.
	for _, from := range []*keys.Identity{S, f.e.ID} {
		kn := f.undoCall(from, []*writ.Writ{f.w1, f.w2})
		rep, rej = f.e.Execute(context.Background(), kn.Raw)
		if got := f.code(t, kn, rep, rej); got != string(writ.NoStanding) {
			t.Fatalf("unauthorized undo by %s: want no_standing, got %q", from.DID()[:16], got)
		}
	}

	// Undefined sys/ operation.
	kx, _ := writ.NewCall(f.A, []*writ.Writ{f.w1, f.w2}, "sys/other", map[string]any{})
	rep, rej = f.e.Execute(context.Background(), kx.Raw)
	if got := f.code(t, kx, rep, rej); got != string(writ.ForbiddenOp) {
		t.Fatalf("undefined standing op: want forbidden_op, got %q", got)
	}

	// Chain binding: an undo under a chain whose leaf is not the tally's writ.
	w2b, _ := writ.Issue(f.B, f.e.ID.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "uses", "count", 1), now+1800, f.w1)
	kb := f.undoCall(f.A, []*writ.Writ{f.w1, w2b})
	rep, rej = f.e.Execute(context.Background(), kb.Raw)
	if got := f.code(t, kb, rep, rej); got != string(writ.TallyMismatch) {
		t.Fatalf("undo under a sibling leaf: want tally_mismatch, got %q", got)
	}

	// Tally signed by someone else: not this executor's effect.
	forged, _ := wire.Clone(f.tally.Raw)
	fb, _ := json.Marshal(forged)
	forged, _ = wire.Decode(fb)
	_ = wire.Sign(forged, S)
	kf, _ := writ.NewCall(f.A, []*writ.Writ{f.w1, f.w2}, "sys/undo", map[string]any{"tally": forged})
	rep, rej = f.e.Execute(context.Background(), kf.Raw)
	if got := f.code(t, kf, rep, rej); got != string(writ.NotReversible) {
		t.Fatalf("forged tally: want not_reversible, got %q", got)
	}
	if f.refunds != 0 || f.charges != 1 {
		t.Fatalf("nothing above may have executed: refunds %d charges %d", f.refunds, f.charges)
	}
}
