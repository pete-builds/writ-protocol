package exec

import (
	"context"

	"writproto/wire"
	"writproto/writ"
)

// NotAdmitted is the implementation code Complete answers for a call Begin
// never admitted. A refused call is not stored (spec 9), so it has none.
const NotAdmitted = "exec/not_admitted"

// Begin runs section 7 steps 1 to 11 on a forward call whose operation is
// performed outside this executor, such as a tool an agent runtime runs. A
// nil reply and nil error mean the call was admitted: its pending record is
// persisted, and the caller performs the operation and reports it with
// Complete, possibly from another process over the same store. Any other
// answer is final: a refusal, an unsigned rejection, or the stored or pending
// tally of a replay. A standing call is performed here, as Execute would.
// The operation runs outside this executor, so a revoke recorded meanwhile
// neither lists nor stops it; it refuses every later call (spec 9.1).
func (e *Executor) Begin(ctx context.Context, obj wire.Object) (*Reply, *writ.Error) {
	rep, rej := e.run(ctx, obj, true)
	if (rep != nil || rej != nil) && e.Audit != nil {
		e.Audit(e.callEntry(ctx, obj, rep, rej))
	}
	return rep, rej
}

// Complete is step 12 for a call Begin admitted: it signs and persists the
// final tally for the outcome r. The call is taken from the pending record,
// not from obj, which only locates it. A call already final, answered or
// resolved after a restart, gets its stored tally back, unchanged.
func (e *Executor) Complete(ctx context.Context, obj wire.Object, r Result) (*Reply, *writ.Error) {
	rep, rej := e.complete(obj, r)
	if e.Audit != nil {
		e.Audit(e.callEntry(ctx, obj, rep, rej))
	}
	return rep, rej
}

func (e *Executor) complete(obj wire.Object, r Result) (*Reply, *writ.Error) {
	k, err := writ.ParseCall(obj)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	key := callKey(k.Leaf().ID, k.CID)
	rec := e.Store.pendingRecord(key)
	if rec == nil {
		if prior := e.Store.record(key); prior != nil && prior.Tally != nil {
			return &Reply{Tally: prior.Tally, Res: e.resFor(prior.Tally)}, nil
		}
		return nil, &writ.Error{Code: writ.Reason(NotAdmitted), Msg: "exec: no call was admitted under this leaf and id"}
	}
	admitted, err := writ.ParseCall(rec.Call)
	if err != nil {
		return nil, err.(*writ.Error)
	}
	return e.seal(admitted, rec.Acc, rec, r)
}
