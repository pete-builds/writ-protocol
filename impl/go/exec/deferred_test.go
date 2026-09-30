package exec

import (
	"context"
	"path/filepath"
	"testing"

	"writproto/writ"
)

// Begin admits without performing; Complete, from a second executor over
// the same store as a separate process would be, signs the final tally.
func TestBeginThenCompleteAcrossProcesses(t *testing.T) {
	A := id(1)
	path := filepath.Join(t.TempDir(), "store.json")
	ran := false
	e := newC(t, path, A, func(ctx context.Context, k *writ.Call) Result { ran = true; return Result{} })
	var audit []AuditEntry
	e.Audit = func(a AuditEntry) { audit = append(audit, a) }
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "tools", "uses", "count", 2), now+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "tools/read", map[string]any{})
	if rep, rej := e.Begin(context.Background(), k.Raw); rep != nil || rej != nil {
		t.Fatalf("admission answered %v %v, want nil, nil", rep, rej)
	}
	if ran || len(audit) != 0 {
		t.Fatalf("Begin performed the operation (%v) or audited an unfinished call (%d)", ran, len(audit))
	}
	// A retry while the operation runs elsewhere gets a pending tally.
	if rep, _ := e.Begin(context.Background(), k.Raw); tallyCode(rep) != "pending:pending" {
		t.Fatalf("retry while running: %s, want pending", tallyCode(rep))
	}
	second := newC(t, path, A, nil)
	rep, rej := second.Complete(context.Background(), k.Raw, Result{Res: map[string]any{"bytes": 12}})
	if rej != nil || tallyCode(rep) != "ok" {
		t.Fatalf("complete: %v %v", rej, rep)
	}
	if v, tl, err := writ.VerifyTally(w, k, rep.Tally, rep.Res); v != writ.Valid || tl.Acc != now+10 {
		t.Fatalf("the tally does not verify, or lost the acceptance time: %v %v", v, err)
	}
	again, _ := second.Complete(context.Background(), k.Raw, Result{St: "failed", ErrCode: "late/other"})
	if tallyCode(again) != "ok" {
		t.Fatalf("a second Complete changed the outcome to %s", tallyCode(again))
	}
	if rep, _ := second.Begin(context.Background(), k.Raw); tallyCode(rep) != "ok" {
		t.Fatalf("a replay after completion: %s, want the stored ok tally", tallyCode(rep))
	}
}

// Refusals are final at Begin, are audited there, and count is consumed at
// admission, so the third call under count 2 is refused before it runs.
func TestBeginRefusesAndCounts(t *testing.T) {
	A, S := id(1), id(9)
	e := newC(t, filepath.Join(t.TempDir(), "store.json"), A, nil)
	var audit []AuditEntry
	e.Audit = func(a AuditEntry) { audit = append(audit, a) }
	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "tools", "uses", "count", 2), now+3600, nil)
	for i := 0; i < 2; i++ {
		k, _ := writ.NewCall(A, []*writ.Writ{w}, "tools/read", map[string]any{})
		if rep, rej := e.Begin(context.Background(), k.Raw); rep != nil || rej != nil {
			t.Fatalf("call %d not admitted: %v %v", i, rep, rej)
		}
	}
	k3, _ := writ.NewCall(A, []*writ.Writ{w}, "tools/read", map[string]any{})
	if rep, _ := e.Begin(context.Background(), k3.Raw); tallyCode(rep) != "failed:count_exhausted" {
		t.Fatalf("third call: %s, want count_exhausted", tallyCode(rep))
	}
	kx, _ := writ.NewCall(A, []*writ.Writ{w}, "shell/run", map[string]any{})
	if rep, _ := e.Begin(context.Background(), kx.Raw); tallyCode(rep) != "failed:forbidden_op" {
		t.Fatalf("op outside act: %s", tallyCode(rep))
	}
	ws, _ := writ.Issue(S, e.ID.DID(), bnd("act", "prefix", "tools"), now+3600, nil)
	ks, _ := writ.NewCall(S, []*writ.Writ{ws}, "tools/read", map[string]any{})
	if rep, _ := e.Begin(context.Background(), ks.Raw); tallyCode(rep) != "failed:root_not_accepted" {
		t.Fatalf("stranger root: %s", tallyCode(rep))
	}
	if len(audit) != 3 || audit[0].Reason != "count_exhausted" {
		t.Fatalf("want the three refusals audited, got %+v", audit)
	}
	// A refused call is not stored (spec 9), so there is nothing to complete.
	if rep, rej := e.Complete(context.Background(), k3.Raw, Result{}); rep != nil || rej == nil || rej.Code != writ.Reason(NotAdmitted) {
		t.Fatalf("Complete of a refused call: %v %v, want %s", rep, rej, NotAdmitted)
	}
}
