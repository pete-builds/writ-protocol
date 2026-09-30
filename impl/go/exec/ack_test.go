package exec

import (
	"context"
	"testing"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// ackFixture is an executor C under the chain A to B to C, with a clock the
// test moves.
type ackFixture struct {
	A, B   *keys.Identity
	e      *Executor
	clock  int64
	w1, w2 *writ.Writ
	chain  []any
}

func newAckFixture(t *testing.T) *ackFixture {
	f := &ackFixture{A: id(1), B: id(2), clock: now + 10}
	f.e = newC(t, "", f.A, func(ctx context.Context, k *writ.Call) Result {
		return Result{Res: map[string]any{"op": k.Op}}
	})
	f.e.Now = func() int64 { return f.clock }
	f.w1, _ = writ.Issue(f.A, f.B.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	f.w2, _ = writ.Issue(f.B, f.e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, f.w1)
	f.chain = []any{f.w1.Raw, f.w2.Raw}
	return f
}

func (f *ackFixture) call(op string) *writ.Call {
	k, _ := writ.NewCall(f.B, []*writ.Writ{f.w1, f.w2}, op, map[string]any{})
	return k
}

func (f *ackFixture) exec(t *testing.T, k *writ.Call) *Reply {
	t.Helper()
	rep, rej := f.e.Execute(context.Background(), k.Raw)
	if rej != nil {
		t.Fatalf("%s: %v", k.Op, rej)
	}
	return rep
}

func (f *ackFixture) revoke(t *testing.T, rv *writ.Revoke) *RevokeReply {
	t.Helper()
	rep, rej := f.e.Revoke(rv.Raw)
	if rej != nil {
		t.Fatalf("revoke: %v", rej)
	}
	if _, err := writ.VerifyAck(rv, rep.Ack, rep.Res); err != nil {
		t.Fatalf("the executor's own ack does not verify: %v", err)
	}
	return rep
}

// forgetful is a second executor with C's key and none of C's stores: an
// executor that lost the revoke, or ignored it, and does new work under it.
func (f *ackFixture) forgetful(t *testing.T, k *writ.Call) wire.Object {
	t.Helper()
	g := newC(t, "", f.A, f.e.Handle)
	g.Now = func() int64 { return f.clock }
	rep, rej := g.Execute(context.Background(), k.Raw)
	if rej != nil || tallyCode(rep) != "ok" {
		t.Fatalf("the forgetful executor refused: %v %v", rej, rep)
	}
	return rep.Tally
}

func check(rv *writ.Revoke, rep *RevokeReply, chain []any, tally wire.Object) writ.Reason {
	return writ.CodeOf(writ.CheckAck(rv.Raw, rep.Ack, rep.Res, chain, tally))
}

// Spec 9.4: an honest executor's ack accounts for every tally it ever signs
// for work under the revoked writ: finished before the revoke (held), in
// flight at the revoke (open, whether its pending or its final tally), and
// refused after it (no work).
func TestAckAccountsForHonestWork(t *testing.T) {
	f := newAckFixture(t)
	t1 := f.exec(t, f.call("travel/a")).Tally
	k2 := f.call("travel/b")
	if rep, _ := f.e.Begin(context.Background(), k2.Raw); rep != nil {
		t.Fatalf("Begin answered at once: %v", tallyCode(rep))
	}
	f.clock = now + 12
	p2 := f.exec(t, k2).Tally // a retry while it runs: pending
	f.clock = now + 20
	rv, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	rep := f.revoke(t, rv)
	body := rep.Res.(map[string]any)
	if n := len(body["held"].([]any)); n != 1 {
		t.Fatalf("held lists %d tallies, want the one finished before the revoke", n)
	}
	if open := body["open"].([]any); len(open) != 1 || open[0] != k2.ID {
		t.Fatalf("open is %v, want the call in flight", open)
	}
	f.clock = now + 30
	r3 := f.exec(t, f.call("travel/c"))
	if tallyCode(r3) != "failed:revoked" {
		t.Fatalf("new work after the revoke: %s", tallyCode(r3))
	}
	f2, _ := f.e.Complete(context.Background(), k2.Raw, Result{})
	for name, tl := range map[string]wire.Object{"finished before": t1, "pending at": p2, "final after running across": f2.Tally, "refused after": r3.Tally} {
		if got := check(rv, rep, f.chain, tl); got != "" {
			t.Errorf("the tally %s the revoke: %s, want accounted for", name, got)
		}
	}
}

// Spec 9.4 step 7, and the reason the ack lists work rather than only a
// time: a tally for work accepted after the revoke is caught however its acc
// is dated. This is the control for the whole mechanism: every tally here
// verifies under section 6.2, so without the ack nothing would catch it.
func TestAckCatchesWorkAfterTheRevoke(t *testing.T) {
	f := newAckFixture(t)
	k1 := f.call("travel/a")
	t1 := f.exec(t, k1).Tally
	f.clock = now + 20
	rv, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	rep := f.revoke(t, rv)

	f.clock = now + 30
	k4 := f.call("travel/after")
	late := f.forgetful(t, k4)
	if v, _, err := writ.VerifyTally(f.w2, k4, late, nil); v != writ.Valid {
		t.Fatalf("the late tally must verify under 6.2 for this test to mean anything: %v", err)
	}
	if got := check(rv, rep, f.chain, late); got != writ.Revoked {
		t.Fatalf("work accepted after the revoke: %q, want revoked", got)
	}

	// The same work with acc dated before the revoke, and before the ack's
	// only other entry.
	k5 := f.call("travel/backdated")
	back, _, _ := writ.NewTally(f.e.ID, writ.TallyInput{Call: k5, Acc: now + 5, St: "ok", Res: map[string]any{"op": "x"}})
	if v, _, err := writ.VerifyTally(f.w2, k5, back.Raw, nil); v != writ.Valid {
		t.Fatalf("the backdated tally must verify under 6.2: %v", err)
	}
	if got := check(rv, rep, f.chain, back.Raw); got != writ.Revoked {
		t.Fatalf("backdated work: %q, want revoked", got)
	}

	// A second, different final tally for a call the ack holds is not the
	// one it holds.
	other, _, _ := writ.NewTally(f.e.ID, writ.TallyInput{Call: k1, Acc: now + 10, St: "ok", Res: map[string]any{"op": "other"}})
	if got := check(rv, rep, f.chain, other.Raw); got != writ.Revoked {
		t.Fatalf("a second outcome for a held call: %q, want revoked", got)
	}
	// A pending tally for a held call is the call's history, not new work.
	pend, _, _ := writ.NewTally(f.e.ID, writ.TallyInput{Call: k1, Acc: now + 10, St: "pending", ErrCode: "pending"})
	if got := check(rv, rep, f.chain, pend.Raw); got != "" {
		t.Fatalf("a pending tally for a call that finished before the revoke: %q", got)
	}
	if got := check(rv, rep, f.chain, t1); got != "" {
		t.Fatalf("the held tally itself: %q", got)
	}
}

// Spec 9.4 step 6: an ack says nothing about a tally by another signer, a
// standing call, work under a writ the revoke does not cover, or work under
// a writ that expired before the revoke was recorded.
func TestAckSaysNothingOutsideItsReach(t *testing.T) {
	f := newAckFixture(t)
	f.clock = now + 20
	rv, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	rep := f.revoke(t, rv)
	f.clock = now + 30
	late := f.forgetful(t, f.call("travel/after"))
	if check(rv, rep, f.chain, late) != writ.Revoked {
		t.Fatal("setup: the late tally must be caught by the executor's own ack")
	}

	// Another executor's ack of the same revoke.
	other, _ := New(id(4), nil).Revoke(rv.Raw)
	if got := check(rv, other, f.chain, late); got != "" {
		t.Errorf("another signer's ack: %q", got)
	}
	// A standing call after the revoke is accepted by design (section 8).
	st := f.exec(t, f.call("sys/tallies")).Tally
	if got := check(rv, rep, f.chain, st); got != "" {
		t.Errorf("a standing call: %q", got)
	}
	// A revoke of a sibling writ does not cover this chain.
	sib, _ := writ.Issue(f.B, f.e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, f.w1)
	rs, _ := writ.NewRevoke(f.B, []*writ.Writ{f.w1, sib})
	f.clock = now + 25
	reps := f.revoke(t, rs)
	if got := check(rs, reps, f.chain, late); got != "" {
		t.Errorf("a revoke of a sibling writ: %q", got)
	}
	// A writ that expired before rcv: its tallies may have left the store.
	short, _ := writ.Issue(f.B, f.e.ID.DID(), bnd("act", "prefix", "travel"), now+15, f.w1)
	ks, _ := writ.NewCall(f.B, []*writ.Writ{f.w1, short}, "travel/s", map[string]any{})
	gone, _, _ := writ.NewTally(f.e.ID, writ.TallyInput{Call: ks, Acc: now + 12, St: "ok"})
	if got := check(rv, rep, []any{f.w1.Raw, short.Raw}, gone.Raw); got != "" {
		t.Errorf("work under a writ that expired before rcv: %q", got)
	}
}

// A key-wide revoke's ack holds every tally under a writ the key issued, and
// catches later work under any of them, including writs issued afterwards.
func TestAckOfAKeyWideRevoke(t *testing.T) {
	f := newAckFixture(t)
	k1 := f.call("travel/a")
	t1 := f.exec(t, k1).Tally
	direct, _ := writ.Issue(f.A, f.e.ID.DID(), bnd("act", "prefix", "travel"), now+3600, nil)
	kd, _ := writ.NewCall(f.A, []*writ.Writ{direct}, "travel/d", map[string]any{})
	td := f.exec(t, kd).Tally
	f.clock = now + 20
	rv, _ := writ.NewRevoke(f.B, nil)
	rep := f.revoke(t, rv)
	held := rep.Res.(map[string]any)["held"].([]any)
	if len(held) != 1 || held[0].(map[string]any)["call"] != k1.ID {
		t.Fatalf("held is %v, want only the tally under B's writ", held)
	}
	if got := check(rv, rep, f.chain, t1); got != "" {
		t.Fatalf("the held tally: %q", got)
	}
	if got := check(rv, rep, []any{direct.Raw}, td); got != "" {
		t.Fatalf("a chain with no writ B issued: %q", got)
	}
	f.clock = now + 30
	late := f.forgetful(t, f.call("travel/after"))
	if got := check(rv, rep, f.chain, late); got != writ.Revoked {
		t.Fatalf("work under B's writ after B's key-wide revoke: %q, want revoked", got)
	}
}

// Spec 9.4: an executor that forwards a revoke relays the acks it receives,
// and refuses to relay one that does not verify for that revoke.
func TestKeepAcksRelaysOnlyVerifiedAcks(t *testing.T) {
	f := newAckFixture(t)
	f.clock = now + 20
	rv, _ := writ.NewRevoke(f.A, []*writ.Writ{f.w1})
	below, rej := New(id(4), nil).Revoke(rv.Raw)
	if rej != nil {
		t.Fatal(rej)
	}
	tampered := &RevokeReply{Ack: below.Ack, Res: map[string]any{"held": []any{}, "open": []any{"x"}}}
	var keepErr, tamperErr error
	f.e.OnRevoke = func(r *writ.Revoke) {
		keepErr = f.e.KeepAcks(r, below)
		tamperErr = f.e.KeepAcks(r, tampered)
	}
	rep := f.revoke(t, rv)
	if keepErr != nil {
		t.Fatalf("a verified ack was refused: %v", keepErr)
	}
	if writ.CodeOf(tamperErr) != writ.AckMismatch {
		t.Fatalf("an ack with a substituted body: %v, want ack_mismatch", tamperErr)
	}
	if len(rep.Fwd) != 1 {
		t.Fatalf("relayed %d acks, want 1", len(rep.Fwd))
	}
	a, err := writ.VerifyAck(rv, rep.Fwd[0].Ack, rep.Fwd[0].Res)
	if err != nil || a.Iss != id(4).DID() {
		t.Fatalf("the relayed ack: %v, signer %v", err, a)
	}
	// Relayed again on a later answer to the same revoke, and not on others.
	f.e.OnRevoke = nil
	if again := f.revoke(t, rv); len(again.Fwd) != 1 {
		t.Fatalf("a later answer relayed %d acks", len(again.Fwd))
	}
	rs, _ := writ.NewRevoke(f.A, nil)
	if other := f.revoke(t, rs); len(other.Fwd) != 0 {
		t.Fatalf("another revoke's answer relayed %d acks", len(other.Fwd))
	}
}
