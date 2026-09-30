// Package exec implements a Writ executor: spec sections 7, 8, and 9. It is
// transport-independent; the httpbind package puts it behind HTTP.
package exec

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

// StoreUnavailable is the err.code of a refusal issued because the executor
// could not write its stores. It is an implementation code, namespaced as
// spec section 11 requires, and no operation runs when it is returned.
const StoreUnavailable = "exec/store_unavailable"

// Result is what an application handler returns for a forward call.
type Result struct {
	St       string // ok, failed, canceled
	ErrCode  string
	Res      any
	Used     map[string]int64
	RevUntil *int64
	Sub      []*writ.Tally
	Wrt      []*writ.Writ
}

// Handler performs a forward operation. ctx is canceled when a revoke arrives
// for any writ in the call's chain; a handler that observes ctx.Err() should
// stop and return St "canceled".
type Handler func(ctx context.Context, k *writ.Call) Result

// Undoer reverses the effect recorded by a tally this executor signed.
type Undoer func(ctx context.Context, t *writ.Tally, res any) Result

// Executor holds one identity and its stores.
type Executor struct {
	ID         *keys.Identity
	Store      *FileStore
	AcceptRoot func(did string) bool
	// PeerBinds reports whether a transport-authenticated peer speaks for a
	// key (spec 7.6). It is consulted only for calls whose context carries a
	// peer (WithPeer), and fails closed by default.
	PeerBinds func(peer, did string) bool
	Now       func() int64
	Handle    Handler
	Undo      Undoer
	// OnRevoke is called after a revoke is recorded so the application can
	// forward it to the holders of writs it issued (spec 9.1). Best effort.
	OnRevoke func(r *writ.Revoke)
	// Audit, when set, receives one entry for every call and revoke the
	// executor answers, refusals included (spec 9.3). No check consults it.
	Audit func(AuditEntry)

	// mu guards inflight and undoLocks. Execute also holds it from a forward
	// call's revocation check until the call is registered in flight, and
	// Revoke while it records a revoke and collects what is in flight, so the
	// two are atomic with respect to each other (spec 7).
	mu        sync.Mutex
	inflight  map[string]inflight // call identity
	undoLocks map[string]*undoRef // target tally identity

	// afterRevokeCheck, when set by a test, runs just after step 7 with mu
	// held, which is the window a revoke must not slip through.
	afterRevokeCheck func()
}

type inflight struct {
	call   *writ.Call
	acc    int64
	cancel context.CancelFunc
}

// New returns an executor with a real clock and a memory store.
func New(id *keys.Identity, store *FileStore) *Executor {
	if store == nil {
		store, _ = OpenFileStore("")
	}
	return &Executor{ID: id, Store: store, Now: func() int64 { return time.Now().Unix() },
		AcceptRoot: func(string) bool { return false }, PeerBinds: func(string, string) bool { return false },
		inflight:  map[string]inflight{},
		undoLocks: map[string]*undoRef{}}
}

// Recover resolves every pending call record left by a crash to a final tally
// with unknown_outcome (spec section 9), and drops revokes of writs that have
// since expired. The resolved tally carries every writ and sub-tally the
// record holds (spec 7.5), with a used that covers those sub-tallies. Call it
// once after opening the store.
func (e *Executor) Recover() int {
	_ = e.Store.purgeRevoked(e.Now())
	e.Store.mu.Lock()
	var pending []*Record
	for _, r := range e.Store.Calls {
		if r.Tally == nil && r.Call != nil {
			pending = append(pending, r)
		}
	}
	e.Store.mu.Unlock()
	n := 0
	for _, r := range pending {
		k, err := writ.ParseCall(r.Call)
		if err != nil {
			continue
		}
		wrt, sub := evidence(r, Result{})
		t, _, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: r.Acc, St: "failed", ErrCode: string(writ.UnknownOutcome),
			Used: coverSubs(k.Leaf(), nil, sub), Sub: sub, Wrt: wrt})
		if err != nil {
			continue
		}
		final := *r
		final.Tally, final.Final = t.Raw, true
		final.Wrt, final.Sub = nil, nil // the final tally carries them now
		if e.Store.finish(t.ID, &tallyRec{Tally: t.Raw, Chain: chainIDs(k), Keep: k.Leaf().Exp}, &final) == nil {
			n++
		}
	}
	return n
}

func chainIDs(k *writ.Call) []string {
	ids := make([]string, 0, len(k.Chain))
	for _, w := range k.Chain {
		ids = append(ids, w.ID)
	}
	return ids
}

type peerKey struct{}

// WithPeer returns ctx carrying the identity the transport authenticated for
// the party that delivered a call. Without it, Execute treats the transport as
// having authenticated no peer and skips the peer binding check (spec 7.6).
func WithPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, peerKey{}, peer)
}

func peerOf(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(peerKey{}).(string)
	return p, ok
}

type unidentifiedKey struct{}

// WithUnidentifiedPeer returns ctx carrying a peer the transport authenticated
// but could not name, such as a verified client certificate with no usable
// identity, under label for the audit record. It is not a transport that
// authenticated no peer: no binding and no attested key matches it, so every
// call over it fails peer binding, before replay (spec 7.6).
func WithUnidentifiedPeer(ctx context.Context, label string) context.Context {
	return context.WithValue(WithPeer(ctx, label), unidentifiedKey{}, true)
}

func unidentified(ctx context.Context) bool {
	u, _ := ctx.Value(unidentifiedKey{}).(bool)
	return u
}

type attestedKey struct{}

// WithAttestedKeys returns ctx carrying keys the transport's own credential
// binds to the peer, such as did:key URIs in a verified client certificate.
// A call from one of them passes peer binding without consulting PeerBinds:
// the credential is the binding (spec 7.6).
func WithAttestedKeys(ctx context.Context, keys []string) context.Context {
	return context.WithValue(ctx, attestedKey{}, keys)
}

func attested(ctx context.Context, did string) bool {
	keys, _ := ctx.Value(attestedKey{}).([]string)
	for _, k := range keys {
		if k == did {
			return true
		}
	}
	return false
}

// Reply is the HTTP-binding response body for a call.
type Reply struct {
	Tally wire.Object `json:"tally"`
	Res   any         `json:"res,omitempty"`
}

// execute runs spec section 7 on a decoded call object. It returns either a
// reply (always carrying a signed tally) or an unsigned rejection for failures
// before the call's signature could be verified (steps 1 and 2).
func (e *Executor) execute(ctx context.Context, obj wire.Object) (*Reply, *writ.Error) {
	return e.run(ctx, obj, false)
}

// run is section 7. When deferred is set, a forward call that passes steps 1
// to 10 is left pending at step 11 and run returns nil, nil: the operation is
// performed elsewhere and reported through complete.
func (e *Executor) run(ctx context.Context, obj wire.Object, deferred bool) (*Reply, *writ.Error) {
	k, err := writ.ParseCall(obj)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	leaf := k.Leaf()
	refuse := func(code string) (*Reply, *writ.Error) {
		t, _, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: e.Now(), St: "failed", ErrCode: code})
		if err != nil {
			return nil, &writ.Error{Code: writ.Malformed, Msg: err.Error()}
		}
		return &Reply{Tally: t.Raw}, nil
	}
	// Step 3: the chain is structurally valid and attenuates root to leaf.
	if err := writ.VerifyChain(k.Chain); err != nil {
		return refuse(string(writ.CodeOf(err)))
	}
	// Step 4, forward calls only: forward authority ends at exp. A standing
	// call is not subject to expiry (or to revocation, step 7): the signed
	// chain is historical proof that from had standing, and the time bound
	// on what a standing call may do is operation-specific (rev.until for
	// sys/undo, tally retention for sys/tallies). Skipping these steps never
	// restores forward authority, because every forward call passes them.
	if !k.Standing() {
		if err := writ.CheckExpiry(k.Chain, e.Now()); err != nil {
			return refuse(string(writ.Expired))
		}
	}
	// Steps 5 and 6: this executor acts under the root and is the leaf holder.
	if !e.AcceptRoot(k.Chain[0].Iss) {
		return refuse(string(writ.RootNotAccepted))
	}
	if leaf.Hld != e.ID.DID() {
		return refuse(string(writ.WrongExecutor))
	}
	// Steps 7 to 11 are atomic with respect to recording a revoke (spec 7):
	// mu is held from the revocation check until the call is registered in
	// flight, and Revoke holds it while it records and collects, so a revoke
	// either refuses this call at step 7 or finds it in flight and stops it.
	e.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			e.mu.Unlock()
		}
	}
	defer unlock()
	// Step 7, forward calls only: no writ in the chain is revoked, by
	// identity or by a key-wide revoke of its issuer.
	if !k.Standing() && e.IsRevoked(k.Chain) {
		return refuse(string(writ.Revoked))
	}
	if e.afterRevokeCheck != nil {
		e.afterRevokeCheck()
	}
	// Step 8 opens with peer binding, before replay, so a captured call
	// presented over another connection cannot fetch the stored result. A
	// peer the transport authenticated but could not name binds nothing.
	if peer, ok := peerOf(ctx); ok && (unidentified(ctx) || (!attested(ctx, k.From) && !e.PeerBinds(peer, k.From))) {
		return refuse(string(writ.PeerMismatch))
	}
	// Step 8, continued: standing, then the forward or standing rules.
	if k.Standing() {
		if err := writ.CheckStanding(k); err != nil {
			return refuse(string(writ.CodeOf(err)))
		}
	} else if err := writ.CheckForward(k); err != nil {
		return refuse(string(writ.CodeOf(err)))
	}
	// Steps 9 and 10, one atomic operation: replay, then count consumed against
	// every writ in the chain that carries one. A writ with several count
	// bounds is limited by the smallest. Admission records the pending entry,
	// so a concurrent duplicate sees it and cannot execute a second time.
	ids := chainIDs(k)
	bounds := map[string]int64{}
	if !k.Standing() {
		for _, w := range k.Chain {
			for _, b := range w.Bnd {
				if cur, ok := bounds[w.ID]; b.T == "count" && (!ok || b.Int < cur) {
					bounds[w.ID] = b.Int
				}
			}
		}
	}
	acc := e.Now()
	pending := &Record{LeafID: leaf.ID, CID: k.CID, Acc: acc, Exp: leaf.Exp, Call: k.Raw}
	prior, admitted, serr := e.Store.admit(pending, ids, bounds)
	if serr != nil {
		return refuse(StoreUnavailable)
	}
	if prior != nil {
		if prior.Tally != nil {
			return &Reply{Tally: prior.Tally, Res: e.resFor(prior.Tally)}, nil
		}
		// Accepted but not yet answered (concurrent duplicate or crash): pending tally.
		return e.pendingReply(k, prior.Acc), nil
	}
	if !admitted {
		return refuse(string(writ.CountExhausted))
	}
	if deferred && !k.Standing() {
		// Step 11's pending record is persisted; the operation runs elsewhere.
		return nil, nil
	}
	// Step 11: the pending record is persisted; register in flight, then
	// release mu before performing.
	cctx, cancel := context.WithCancel(ctx)
	e.inflight[k.ID] = inflight{call: k, acc: acc, cancel: cancel}
	unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.inflight, k.ID)
		e.mu.Unlock()
	}()

	var r Result
	switch k.Op {
	case "sys/undo":
		r = e.undo(cctx, k)
	case "sys/tallies":
		r = e.tallies(k)
	default:
		r = e.Handle(cctx, k)
	}
	return e.seal(k, acc, pending, r)
}

// seal is step 12 for the call k, accepted at acc under the pending record.
func (e *Executor) seal(k *writ.Call, acc int64, pending *Record, r Result) (*Reply, *writ.Error) {
	leaf := k.Leaf()
	ids := chainIDs(k)
	if r.St == "" {
		r.St = "ok"
	}
	if r.St != "ok" && r.ErrCode == "" {
		r.ErrCode = "app/failed"
	}
	// Step 12: sign, persist, return. The tally carries the evidence the
	// operation persisted through Issued and Received as well as what it
	// returned, and its used covers its sub-tallies' (spec 6, 7.5).
	rec := e.Store.pendingRecord(callKey(leaf.ID, k.CID))
	if rec == nil {
		rec = pending
	}
	wrt, sub := evidence(rec, r)
	t, res, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: acc, St: r.St, ErrCode: r.ErrCode,
		Res: r.Res, Used: coverSubs(leaf, r.Used, sub), RevUntil: r.RevUntil, Sub: sub, Wrt: wrt})
	if err != nil {
		return nil, &writ.Error{Code: writ.Malformed, Msg: "tally: " + err.Error()}
	}
	keep := leaf.Exp
	if r.RevUntil != nil && *r.RevUntil > keep {
		keep = *r.RevUntil
	}
	final := *pending
	final.Tally, final.Final = t.Raw, true
	if e.Store.finish(t.ID, &tallyRec{Tally: t.Raw, Chain: ids, Res: res, Keep: keep}, &final) != nil {
		// The operation ran but its outcome is not durable. Claiming it
		// would be a lie after a restart, when the record resolves to
		// unknown_outcome; a pending tally is the true statement.
		return e.pendingReply(k, acc), nil
	}
	return &Reply{Tally: t.Raw, Res: res}, nil
}

func (e *Executor) pendingReply(k *writ.Call, acc int64) *Reply {
	t, _, _ := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: acc, St: "pending", ErrCode: "pending"})
	return &Reply{Tally: t.Raw}
}

func (e *Executor) resFor(t wire.Object) any {
	id, _ := wire.Hash(t)
	if rec, ok := e.Store.getTally(id); ok {
		return rec.Res
	}
	return nil
}

// undoRef serializes the reversals of one target and counts who holds or
// waits for it, so the entry is dropped when the last one is done.
type undoRef struct {
	mu sync.Mutex
	n  int
}

// lockUndo takes the lock for reversals of target and returns its release.
func (e *Executor) lockUndo(target string) func() {
	e.mu.Lock()
	r := e.undoLocks[target]
	if r == nil {
		r = &undoRef{}
		e.undoLocks[target] = r
	}
	r.n++
	e.mu.Unlock()
	r.mu.Lock()
	return func() {
		r.mu.Unlock()
		e.mu.Lock()
		if r.n--; r.n == 0 {
			delete(e.undoLocks, target)
		}
		e.mu.Unlock()
	}
}

// undo implements spec 8.1. By the time it runs, Execute has established
// the chain, root, executor identity, and standing; it has deliberately not
// checked expiry or revocation of the chain. What bounds an undo in time is
// the target tally's rev.until, judged here against this executor's clock.
// Reversals of one target are serialized, and each is claimed on disk before
// it runs, so an effect is reversed at most once even across a crash.
func (e *Executor) undo(ctx context.Context, k *writ.Call) Result {
	fail := func(code writ.Reason) Result { return Result{St: "failed", ErrCode: string(code)} }
	tobj, ok := k.Args["tally"].(map[string]any)
	if !ok {
		return fail(writ.Malformed)
	}
	target, err := writ.ParseTally(tobj, e.ID.DID())
	if err != nil {
		return fail(writ.NotReversible)
	}
	if target.Writ != k.Leaf().ID {
		return fail(writ.TallyMismatch)
	}
	if target.Rev == nil || e.Now() >= *target.Rev || target.St != "ok" {
		return fail(writ.NotReversible)
	}
	rec, ok := e.Store.getTally(target.ID)
	if !ok {
		return fail(writ.NotReversible)
	}
	defer e.lockUndo(target.ID)()
	done, res, claimed := e.Store.undoState(rec)
	if done {
		// Idempotent: a later undo for the same tally performs nothing and
		// answers with the successful reversal's body.
		return Result{St: "ok", Res: res}
	}
	if claimed {
		// A reversal was claimed and never settled: the process stopped
		// while it ran. Whether the effect was reversed is unknown, and
		// store loss is never proof that nothing happened (spec 7.3).
		return fail(writ.UnknownOutcome)
	}
	if e.Undo == nil {
		return fail(writ.NotReversible)
	}
	me := callKey(k.Leaf().ID, k.CID)
	if e.Store.claimUndo(rec, me) != nil {
		return Result{St: "failed", ErrCode: StoreUnavailable}
	}
	r := e.Undo(ctx, target, rec.Res)
	r.RevUntil = nil
	ok = r.St == "" || r.St == "ok"
	e.Store.settleUndo(rec, me, ok, r.Res)
	return r
}

// tallies implements spec 8.2. It runs after chain expiry and revocation
// exactly as before them: it returns whatever the tally store still holds
// under the named writ, which is the recovery path when a caller never
// received its tally.
//
// The named writ must be one from issued or one below it. A writ above it
// would index work under sibling delegations from never issued or saw.
func (e *Executor) tallies(k *writ.Call) Result {
	id, _ := k.Args["writ"].(string)
	found, issued := false, false
	for _, w := range k.Chain {
		if w.Iss == k.From {
			issued = true
		}
		if issued && w.ID == id {
			found = true
		}
	}
	if !found {
		return Result{St: "failed", ErrCode: string(writ.TallyMismatch)}
	}
	list := e.Store.talliesUnder(id)
	arr := make([]any, 0, len(list))
	for _, t := range list {
		arr = append(arr, t)
	}
	return Result{St: "ok", Res: map[string]any{"tallies": arr}}
}

// revoke runs spec 9.1 on a decoded revoke object and returns the tallies of
// affected non-final forward calls.
func (e *Executor) revoke(obj wire.Object) ([]wire.Object, *writ.Error) {
	r, err := writ.ParseRevoke(obj)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	if err := writ.CheckRevoke(r); err != nil {
		return nil, err.(*writ.Error)
	}
	// Record and collect under mu, which Execute holds from a forward call's
	// revocation check until the call is in flight (spec 7): every forward
	// call is then either refused at step 7 or collected here.
	var hits []inflight
	e.mu.Lock()
	// A key-wide revoke MUST survive restart (spec 9). One that cannot be
	// written is still honored below, and answered as an error so the sender
	// retries. A writ's revoke is SHOULD-durable and bounded by its exp.
	var unsaved error
	if r.Writ == "*" {
		unsaved = e.Store.revoke("*:"+r.Iss, 1<<62)
	} else {
		_ = e.Store.revoke(r.Writ, r.Chain[len(r.Chain)-1].Exp)
	}
	// Cancel in-flight forward work under the revoked writ and answer with
	// pending tallies, in ascending order of call identity (spec 9.1). A
	// standing call in flight is left alone: a revoke ends forward
	// authority, not the standing to reverse or recover (spec 8).
	under := func(k *writ.Call) bool {
		for _, w := range k.Chain {
			if w.ID == r.Writ || (r.Writ == "*" && w.Iss == r.Iss) {
				return true
			}
		}
		return false
	}
	for _, f := range e.inflight {
		if !f.call.Standing() && under(f.call) {
			hits = append(hits, f)
		}
	}
	// A call Begin admitted runs outside this executor: it is answered as
	// pending, which is true, and cannot be stopped from here (spec 9.1).
	for _, rec := range e.Store.pendingRecords() {
		k, err := writ.ParseCall(rec.Call)
		if err != nil || k.Standing() || !under(k) {
			continue
		}
		if _, running := e.inflight[k.ID]; !running {
			hits = append(hits, inflight{call: k, acc: rec.Acc})
		}
	}
	e.mu.Unlock()
	sort.Slice(hits, func(i, j int) bool { return hits[i].call.ID < hits[j].call.ID })
	out := []wire.Object{}
	for _, f := range hits {
		if f.cancel != nil {
			f.cancel()
		}
		out = append(out, e.pendingReply(f.call, f.acc).Tally)
	}
	if e.OnRevoke != nil {
		e.OnRevoke(r)
	}
	if unsaved != nil {
		return nil, &writ.Error{Code: writ.Reason(StoreUnavailable), Msg: unsaved.Error()}
	}
	return out, nil
}

// Issued durably adds w, a writ this executor issued under the leaf of the
// running call k, to the call's pending record. Spec 7.5: a writ is persisted
// before it is sent to anyone, so a crash cannot lose the evidence of a
// delegation. An application that gets an error must not send w.
func (e *Executor) Issued(k *writ.Call, w *writ.Writ) error {
	if w.Iss != e.ID.DID() {
		return errors.New("exec: the writ was not issued by this executor")
	}
	if err := writ.CheckChild(w, k.Leaf()); err != nil {
		return err
	}
	return e.Store.addEvidence(callKey(k.Leaf().ID, k.CID), w.Raw, nil)
}

// Received durably adds t, a sub-tally answering a call made under a writ
// recorded by Issued, to the running call k's pending record, replacing an
// earlier tally for the same sub-call. Spec 7.5: a sub-tally is persisted
// before anything acts on its contents. An application that gets an error
// must not act on t.
func (e *Executor) Received(k *writ.Call, t *writ.Tally) error {
	return e.Store.addEvidence(callKey(k.Leaf().ID, k.CID), nil, t.Raw)
}

// evidence returns the writs and sub-tallies a tally for rec carries: those
// persisted through Issued and Received, in the order persisted, then any the
// result adds. A result tally for a sub-call already persisted replaces it,
// as a final tally supersedes a pending one (spec 6, 7.5).
func evidence(rec *Record, r Result) ([]*writ.Writ, []*writ.Tally) {
	var wrt []*writ.Writ
	seen := map[string]bool{}
	for _, o := range rec.Wrt {
		if w, err := writ.ParseWrit(o); err == nil && !seen[w.ID] {
			seen[w.ID] = true
			wrt = append(wrt, w)
		}
	}
	for _, w := range r.Wrt {
		if !seen[w.ID] {
			seen[w.ID] = true
			wrt = append(wrt, w)
		}
	}
	hld := map[string]string{}
	for _, w := range wrt {
		hld[w.ID] = w.Hld
	}
	var sub []*writ.Tally
	at := map[string]int{}
	add := func(t *writ.Tally) {
		if i, ok := at[t.Call]; ok {
			sub[i] = t
			return
		}
		at[t.Call] = len(sub)
		sub = append(sub, t)
	}
	for _, o := range rec.Sub {
		named, _ := o["writ"].(string)
		if t, err := writ.ParseTally(o, hld[named]); err == nil {
			add(t)
		}
	}
	for _, t := range r.Sub {
		add(t)
	}
	return wrt, sub
}

// coverSubs returns used raised, for every max bound of the leaf, to the sum
// of the sub-tallies' used (spec 6: used is inclusive of the subtree). An
// operation cannot have consumed less than the work it delegated reports, and
// a tally resolved after a crash, whose own outcome is unknown, reports at
// least that much.
func coverSubs(leaf *writ.Writ, used map[string]int64, sub []*writ.Tally) map[string]int64 {
	out, copied := used, false
	for name, b := range leaf.Bnd {
		if b.T != "max" {
			continue
		}
		var sum int64
		for _, s := range sub {
			sum += s.Used[name]
		}
		if sum <= used[name] {
			continue
		}
		if !copied {
			out, copied = make(map[string]int64, len(used)+1), true
			for n, v := range used {
				out[n] = v
			}
		}
		out[name] = sum
	}
	return out
}

// IsRevoked reports whether any writ in the chain is revoked in this
// executor's store, by writ identity or by a key-wide revoke of its issuer.
// Execute applies it to every forward call (spec section 7 step 7);
// application code may also call it before starting a sub-step.
func (e *Executor) IsRevoked(chain []*writ.Writ) bool {
	for _, w := range chain {
		if e.Store.isRevoked(w.ID) || e.Store.isRevoked("*:"+w.Iss) {
			return true
		}
	}
	return false
}
