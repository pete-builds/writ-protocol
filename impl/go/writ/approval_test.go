package writ

import (
	"strings"
	"testing"
)

func codeOf(err error) Reason {
	if err == nil {
		return ""
	}
	return CodeOf(err)
}

// A person (O) lets a manager (H) spend up to 10000 a payment; H gives an
// agent (A) a line of 100; A pays an executor (E) under that line.
func approvalChain(t *testing.T) (O, H, A, E interface{ DID() string }, w0, w1, w2 *Writ) {
	t.Helper()
	o, h, a, e := seedID(t, 1), seedID(t, 2), seedID(t, 3), seedID(t, 4)
	var err error
	if w0, err = Issue(o, h.DID(), bnd("act", "prefix", "pay", "amount", "max", 10000, "pay_to", "set", []any{"v1", "v2"}), now+3600, nil); err != nil {
		t.Fatal(err)
	}
	if w1, err = Issue(h, a.DID(), bnd("act", "prefix", "pay", "amount", "max", 100, "pay_to", "set", []any{"v1", "v2"}), now+3600, w0); err != nil {
		t.Fatal(err)
	}
	if w2, err = Issue(a, e.DID(), bnd("act", "prefix", "pay", "amount", "max", 100, "pay_to", "set", []any{"v1", "v2"}), now+1800, w1); err != nil {
		t.Fatal(err)
	}
	return o, h, a, e, w0, w1, w2
}

func TestApprovalPointNamesTheApprover(t *testing.T) {
	_, H, _, _, w0, w1, w2 := approvalChain(t)
	chain := []*Writ{w0, w1, w2}
	cases := []struct {
		op   string
		args map[string]any
		want int
	}{
		{"pay", map[string]any{"amount": 50, "pay_to": "v1"}, -1},     // inside the line: nothing to approve
		{"pay", map[string]any{"amount": 500, "pay_to": "v1"}, 1},     // over A's line, inside H's: H approves
		{"pay", map[string]any{"amount": 20000, "pay_to": "v1"}, 0},   // over H's too: O approves
		{"pay", map[string]any{"amount": 50, "pay_to": "v3"}, 0},      // a recipient nobody allowed
		{"refund", map[string]any{"amount": 50, "pay_to": "v1"}, 0},   // an operation nobody allowed
		{"sys/undo", map[string]any{"amount": 50, "pay_to": "v1"}, 0}, // never a forward approval
	}
	for _, c := range cases {
		if got := ApprovalPoint(chain, c.op, c.args); got != c.want {
			t.Errorf("%s %v: approval point %d, want %d", c.op, c.args, got, c.want)
		}
	}
	if j := ApprovalPoint(chain, "pay", map[string]any{"amount": 500, "pay_to": "v1"}); chain[j].Iss != H.DID() {
		t.Fatalf("the approver is %s, want H", chain[j].Iss)
	}
}

// The approval is a writ for the call, once: the same chain refuses a larger
// amount, another recipient, another memo, and another operation. A max is
// pinned as a ceiling and act as a prefix, the two places a child cannot be
// exact (spec 4 step 4, 3.1); TestApprovalCeilings records both.
func TestApprovalPinsExactlyOneCall(t *testing.T) {
	_, _, _, _, w0, w1, w2 := approvalChain(t)
	H, A := seedID(t, 2), seedID(t, 3)
	args := map[string]any{"amount": 500, "pay_to": "v1", "memo": "invoice 7"}
	j := ApprovalPoint([]*Writ{w0, w1, w2}, "pay", args)
	a1, err := Approve(H, w0, w1, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	// A carries the approval on to the executor, pinned the same way.
	a2, err := Approve(A, a1, w2, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	if j != 1 || a1.Iss != H.DID() || a1.Hld != w1.Hld || a2.Hld != w2.Hld || a1.Exp != now+600 {
		t.Fatalf("approval shape: point %d, a1 %s to %s until %d", j, a1.Iss, a1.Hld, a1.Exp)
	}
	chain := []*Writ{w0, a1, a2}
	if err := VerifyChain(chain); err != nil {
		t.Fatalf("the approved chain: %v", err)
	}
	call := func(op string, args map[string]any) error {
		k, err := NewCall(A, chain, op, args)
		if err != nil {
			t.Fatal(err)
		}
		return CheckForward(k)
	}
	if err := call("pay", args); err != nil {
		t.Fatalf("the approved call: %v", err)
	}
	for _, c := range []struct {
		op   string
		args map[string]any
		want Reason
	}{
		{"pay", map[string]any{"amount": 501, "pay_to": "v1", "memo": "invoice 7"}, OutOfBounds},
		{"pay", map[string]any{"amount": 500, "pay_to": "v2", "memo": "invoice 7"}, OutOfBounds},
		{"pay", map[string]any{"amount": 500, "pay_to": "v1", "memo": "invoice 8"}, OutOfBounds},
		{"pay", map[string]any{"amount": 500, "pay_to": "v1"}, MissingArg},
		{"refund", args, ForbiddenOp},
		{"payx", args, ForbiddenOp},
	} {
		if got := codeOf(call(c.op, c.args)); got != c.want {
			t.Errorf("%s %v under the approval: %s, want %s", c.op, c.args, got, c.want)
		}
	}
	// One use, at every executor, by the approval's own count.
	if b := a1.Bnd[ApprovalCount]; b.T != "count" || b.Int != 1 {
		t.Fatalf("the approval's use: %+v", b)
	}
}

// No one approves more than they hold, and only the issuer of the refusing
// writ approves.
func TestApprovalIsBoundedByTheApprover(t *testing.T) {
	_, _, _, _, w0, w1, _ := approvalChain(t)
	O, H, A := seedID(t, 1), seedID(t, 2), seedID(t, 3)
	over := map[string]any{"amount": 20000, "pay_to": "v1"}
	if _, err := Approve(H, w0, w1, "pay", over, now+600); codeOf(err) != NotNarrowed {
		t.Fatalf("H approving past its own 10000: %v", err)
	}
	if _, err := Approve(O, nil, w0, "pay", over, now+600); err != nil {
		t.Fatalf("O, the root issuer, approving 20000: %v", err)
	}
	in := map[string]any{"amount": 500, "pay_to": "v1"}
	if _, err := Approve(A, w0, w1, "pay", in, now+600); err == nil || !strings.Contains(err.Error(), "approver") {
		t.Fatalf("A approving its own line: %v", err)
	}
	if _, err := Approve(H, w0, w1, "pay", map[string]any{"amount": 500, "pay_to": "v1", "blob": map[string]any{}}, now+600); err == nil {
		t.Fatal("an argument that cannot be pinned must refuse the approval")
	}
	if _, err := Approve(H, w0, w1, "sys/undo", in, now+600); err == nil {
		t.Fatal("a standing operation needs no approval and must not get one")
	}
	a, err := Approve(H, w0, w1, "pay", in, now+999999)
	if err != nil || a.Exp != w0.Exp {
		t.Fatalf("an approval outliving its parent is cut to the parent's exp: %v %d", err, a.Exp)
	}
}

// TestApprovalCeilings records where an approval is looser than the call it
// names, so a change to either rule is a deliberate one: a pinned max admits
// a smaller amount, and a pinned act admits an operation below it.
func TestApprovalCeilings(t *testing.T) {
	_, _, _, _, w0, w1, w2 := approvalChain(t)
	H, A := seedID(t, 2), seedID(t, 3)
	args := map[string]any{"amount": 500, "pay_to": "v1"}
	a1, err := Approve(H, w0, w1, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Approve(A, a1, w2, "pay", args, now+600)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"pay", map[string]any{"amount": 499, "pay_to": "v1"}},
		{"pay/extra", args},
	} {
		k, err := NewCall(A, []*Writ{w0, a1, a2}, c.op, c.args)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckForward(k); err != nil {
			t.Errorf("%s %v: %v; a ceiling or a prefix should admit it", c.op, c.args, err)
		}
	}
}
