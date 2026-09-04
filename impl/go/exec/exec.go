// Package exec implements a Writ executor: spec sections 7, 8, and 9. It is
// transport-independent; the httpbind package puts it behind HTTP.
package exec

import (
	"context"
	"sync"
	"time"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

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
	Now        func() int64
	Handle     Handler
	Undo       Undoer
	// OnRevoke is called after a revoke is recorded so the application can
	// forward it to the holders of writs it issued (spec 9.1). Best effort.
	OnRevoke func(r *writ.Revoke)

	mu       sync.Mutex
	inflight map[string]inflight // call identity
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
		AcceptRoot: func(string) bool { return false }, inflight: map[string]inflight{}}
}

// Recover resolves every pending call record left by a crash to a final tally
// with unknown_outcome (spec section 9). Call it once after opening the store.
func (e *Executor) Recover() int {
	e.Store.mu.Lock()
	var pending []*Record
	for _, r := range e.Store.Calls {
		if r.Tally == nil && r.Call != nil {
			pending = append(pending, r)
		}
	}
	e.Store.mu.Unlock()
	for _, r := range pending {
		k, err := writ.ParseCall(r.Call)
		if err != nil {
			continue
		}
		t, _, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: r.Acc, St: "failed", ErrCode: string(writ.UnknownOutcome)})
		if err != nil {
			continue
		}
		var ids []string
		for _, w := range k.Chain {
			ids = append(ids, w.ID)
		}
		e.Store.putTally(t.ID, &tallyRec{Tally: t.Raw, Chain: ids, Keep: k.Leaf().Exp})
		r.Tally, r.Final = t.Raw, true
		e.Store.putCall(r)
	}
	return len(pending)
}

// Reply is the HTTP-binding response body for a call.
type Reply struct {
	Tally wire.Object `json:"tally"`
	Res   any         `json:"res,omitempty"`
}

// Execute runs spec section 7 on a decoded call object. It returns either a
// reply (always carrying a signed tally) or an unsigned rejection for failures
// before the call's signature could be verified (steps 1 and 2).
func (e *Executor) Execute(ctx context.Context, obj wire.Object) (*Reply, *writ.Error) {
	k, err := writ.ParseCall(obj)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	leaf := k.Leaf()
	refuse := func(code writ.Reason, ref string) (*Reply, *writ.Error) {
		t, _, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: e.Now(), St: "failed", ErrCode: string(code), ErrRef: ref})
		if err != nil {
			return nil, &writ.Error{Code: writ.Malformed, Msg: err.Error()}
		}
		return &Reply{Tally: t.Raw}, nil
	}
	// Steps 3 to 7.
	if err := writ.VerifyChain(k.Chain); err != nil {
		return refuse(writ.CodeOf(err), "")
	}
	if err := writ.CheckExpiry(k.Chain, e.Now()); err != nil {
		return refuse(writ.Expired, "")
	}
	if !e.AcceptRoot(k.Chain[0].Iss) {
		return refuse(writ.RootNotAccepted, "")
	}
	if leaf.Hld != e.ID.DID() {
		return refuse(writ.WrongExecutor, "")
	}
	var chainIDs []string
	for _, w := range k.Chain {
		chainIDs = append(chainIDs, w.ID)
		if e.Store.isRevoked(w.ID) {
			return refuse(writ.Revoked, "")
		}
	}
	// Step 8.
	if k.Standing() {
		if err := writ.CheckStanding(k); err != nil {
			return refuse(writ.NoStanding, "")
		}
	} else if err := writ.CheckForward(k); err != nil {
		return refuse(writ.CodeOf(err), "")
	}
	// Step 9: replay.
	if rec, ok := e.Store.getCall(leaf.ID, k.CID); ok {
		if rec.Tally != nil {
			return &Reply{Tally: rec.Tally, Res: e.resFor(rec.Tally)}, nil
		}
		// Accepted but not yet answered (concurrent duplicate or crash): pending tally.
		t, _, _ := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: rec.Acc, St: "pending", ErrCode: "pending"})
		return &Reply{Tally: t.Raw}, nil
	}
	// Step 10: count, consumed against every writ in the chain.
	if !k.Standing() {
		bounds := map[string]int64{}
		for _, w := range k.Chain {
			for _, b := range w.Bnd {
				if b.T == "count" {
					bounds[w.ID] = b.Int
				}
			}
		}
		if !e.Store.consume(chainIDs, bounds) {
			return refuse(writ.CountExhausted, "")
		}
	}
	// Step 11: persist pending, then perform.
	acc := e.Now()
	e.Store.putCall(&Record{LeafID: leaf.ID, CID: k.CID, Acc: acc, Exp: leaf.Exp, Call: k.Raw})
	cctx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.inflight[k.ID] = inflight{call: k, acc: acc, cancel: cancel}
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.inflight, k.ID)
		e.mu.Unlock()
	}()

	var r Result
	switch {
	case k.Op == "sys/undo":
		r = e.undo(cctx, k)
	case k.Op == "sys/tallies":
		r = e.tallies(k)
	case k.Standing():
		r = Result{St: "failed", ErrCode: string(writ.ForbiddenOp)}
	default:
		r = e.Handle(cctx, k)
	}
	if r.St == "" {
		r.St = "ok"
	}
	if r.St != "ok" && r.ErrCode == "" {
		r.ErrCode = "app/failed"
	}
	// Step 12: sign, persist, return.
	t, res, err := writ.NewTally(e.ID, writ.TallyInput{Call: k, Acc: acc, St: r.St, ErrCode: r.ErrCode,
		Res: r.Res, Used: r.Used, RevUntil: r.RevUntil, Sub: r.Sub, Wrt: r.Wrt})
	if err != nil {
		return nil, &writ.Error{Code: writ.Malformed, Msg: "tally: " + err.Error()}
	}
	keep := leaf.Exp
	if r.RevUntil != nil && *r.RevUntil > keep {
		keep = *r.RevUntil
	}
	e.Store.putTally(t.ID, &tallyRec{Tally: t.Raw, Chain: chainIDs, Res: res, Keep: keep})
	e.Store.putCall(&Record{LeafID: leaf.ID, CID: k.CID, Acc: acc, Exp: leaf.Exp, Call: k.Raw, Tally: t.Raw, Final: true})
	return &Reply{Tally: t.Raw, Res: res}, nil
}

func (e *Executor) resFor(t wire.Object) any {
	id, _ := wire.Hash(t)
	if rec, ok := e.Store.getTally(id); ok {
		return rec.Res
	}
	return nil
}

// undo implements spec 8.1.
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
	if rec.Undone != "" {
		// Idempotent: a second undo returns the first undo's outcome.
		if prior, ok := e.Store.Calls[rec.Undone]; ok && prior.Tally != nil {
			pt, _ := writ.ParseTally(prior.Tally, e.ID.DID())
			return Result{St: pt.St, ErrCode: errCode(pt), Res: e.resFor(prior.Tally)}
		}
		return fail(writ.NotReversible)
	}
	if e.Undo == nil {
		return fail(writ.NotReversible)
	}
	r := e.Undo(ctx, target, rec.Res)
	r.RevUntil = nil
	if r.St == "" || r.St == "ok" {
		e.Store.mu.Lock()
		rec.Undone = callKey(k.Leaf().ID, k.CID)
		e.Store.flush()
		e.Store.mu.Unlock()
	}
	return r
}

func errCode(t *writ.Tally) string {
	if t.Err != nil {
		return t.Err.Code
	}
	return ""
}

// tallies implements spec 8.2.
func (e *Executor) tallies(k *writ.Call) Result {
	id, _ := k.Args["writ"].(string)
	found := false
	for _, w := range k.Chain {
		if w.ID == id {
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

// Revoke runs spec 9.1 on a decoded revoke object and returns the tallies of
// affected non-final calls.
func (e *Executor) Revoke(obj wire.Object) ([]wire.Object, *writ.Error) {
	r, err := writ.ParseRevoke(obj)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	if err := writ.CheckRevoke(r); err != nil {
		return nil, err.(*writ.Error)
	}
	if r.Writ == "*" {
		e.Store.revoke("*:"+r.Iss, 1<<62)
	} else {
		e.Store.revoke(r.Writ, r.Chain[len(r.Chain)-1].Exp)
	}
	// Cancel in-flight work under the revoked writ and answer with pending tallies.
	var out []wire.Object
	e.mu.Lock()
	for _, f := range e.inflight {
		hit := false
		for _, w := range f.call.Chain {
			if w.ID == r.Writ || (r.Writ == "*" && w.Iss == r.Iss) {
				hit = true
			}
		}
		if hit {
			f.cancel()
			t, _, _ := writ.NewTally(e.ID, writ.TallyInput{Call: f.call, Acc: f.acc, St: "pending", ErrCode: "pending"})
			out = append(out, t.Raw)
		}
	}
	e.mu.Unlock()
	if e.OnRevoke != nil {
		e.OnRevoke(r)
	}
	return out, nil
}

// IsRevoked lets application code check a chain before starting sub-steps.
func (e *Executor) IsRevoked(chain []*writ.Writ) bool {
	for _, w := range chain {
		if e.Store.isRevoked(w.ID) || e.Store.isRevoked("*:"+w.Iss) {
			return true
		}
	}
	return false
}
