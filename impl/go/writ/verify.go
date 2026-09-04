package writ

import (
	"strings"

	"writproto/jcs"
	"writproto/wire"
)

// Verdict is the three-valued result of tally verification (spec 6.2).
type Verdict string

const (
	Valid              Verdict = "valid"
	SignedUnauthorized Verdict = "signed_unauthorized"
	Unverifiable       Verdict = "unverifiable"
)

// HashResult returns the hash of a result body's canonical form.
func HashResult(res any) (string, error) {
	c, err := jcs.Marshal(res)
	if err != nil {
		return "", err
	}
	return wire.HashBytes(c), nil
}

// VerifyTally implements spec section 6.2 for a tally T received in answer to
// call K under leaf writ W, with optional result body res (nil when absent).
// It returns the verdict and, on anything but Valid, the first failing reason.
func VerifyTally(W *Writ, K *Call, tallyObj wire.Object, res any) (Verdict, *Tally, error) {
	T, err := ParseTally(tallyObj, W.Hld)
	if err != nil {
		return Unverifiable, nil, err
	}
	if T.Call != K.ID {
		return SignedUnauthorized, T, fail(TallyMismatch, "tally names call %s, expected %s", T.Call, K.ID)
	}
	if T.Op != K.Op {
		return SignedUnauthorized, T, fail(TallyMismatch, "tally op %q, call op %q", T.Op, K.Op)
	}
	if res != nil {
		h, err := HashResult(res)
		if err != nil {
			return SignedUnauthorized, T, fail(Noncanonical, "result body: %v", err)
		}
		if T.Out != h {
			return SignedUnauthorized, T, fail(TallyMismatch, "out does not match result body")
		}
	}
	if err := verifyTree(W, T); err != nil {
		return SignedUnauthorized, T, err
	}
	return Valid, T, nil
}

// verifyTree runs steps 3, 5, 7, 8, 9, 10 of section 6.2 recursively.
func verifyTree(W *Writ, T *Tally) error {
	if T.Writ != W.ID {
		return fail(TallyMismatch, "tally names writ %s, expected %s", T.Writ, W.ID)
	}
	// Step 5 applies to forward tallies only. A standing operation (sys/) is
	// authorized by the chain as historical proof (section 7 step 4) and may
	// be accepted after the writ's exp; its time bound is operation-specific.
	if !strings.HasPrefix(T.Op, "sys/") && T.Acc >= W.Exp {
		return fail(Expired, "acc %d at or after exp %d", T.Acc, W.Exp)
	}
	for name, b := range W.Bnd {
		if b.T == "max" && T.Used[name] > b.Int {
			return fail(OutOfBounds, "used.%s %d exceeds %d", name, T.Used[name], b.Int)
		}
	}
	byID := map[string]*Writ{}
	for _, x := range T.Wrt {
		if err := CheckChild(x, W); err != nil {
			return err
		}
		byID[x.ID] = x
	}
	sums := map[string]int64{}
	for _, S := range T.Sub {
		X, ok := byID[S.Writ]
		if !ok {
			return fail(SubUnmatched, "sub-tally names writ %s absent from wrt", S.Writ)
		}
		if err := verifyTree(X, S); err != nil {
			return err
		}
		for name, n := range S.Used {
			sums[name] += n
		}
	}
	for name, b := range W.Bnd {
		if b.T == "max" && sums[name] > b.Int {
			return fail(OutOfBounds, "sum of sub used.%s %d exceeds %d", name, sums[name], b.Int)
		}
	}
	return nil
}
