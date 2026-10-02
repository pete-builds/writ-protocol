package writ

import (
	"sort"
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
// T is Unverifiable only when T itself fails section 6.1; every later failure,
// anywhere in the tree, is SignedUnauthorized. On Valid, T.Wrt and T.Sub hold
// the verified writs and sub-tallies.
func VerifyTally(W *Writ, K *Call, tallyObj wire.Object, res any) (Verdict, *Tally, error) {
	if K.Leaf().ID != W.ID {
		return Unverifiable, nil, fail(TallyMismatch, "the call's leaf writ is not the writ supplied")
	}
	T, err := ParseTally(tallyObj, W.Hld)
	if err != nil {
		return Unverifiable, nil, err
	}
	if T.Call != K.ID {
		return SignedUnauthorized, T, fail(TallyMismatch, "tally names call %s, expected %s", T.Call, K.ID)
	}
	if T.Writ != W.ID {
		return SignedUnauthorized, T, fail(TallyMismatch, "tally names writ %s, expected %s", T.Writ, W.ID)
	}
	if T.Op != K.Op {
		return SignedUnauthorized, T, fail(TallyMismatch, "tally op %q, call op %q", T.Op, K.Op)
	}
	if err := checkAcc(W, T); err != nil {
		return SignedUnauthorized, T, err
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
	if err := verifyTree(W, K.Chain, T); err != nil {
		return SignedUnauthorized, T, err
	}
	return Valid, T, nil
}

// checkAcc is section 6.2 step 5. It applies to forward tallies only. A
// standing operation (sys/) is authorized by the chain as historical proof
// (section 7 step 4) and may be accepted after the writ's exp; its time bound
// is operation-specific.
func checkAcc(W *Writ, T *Tally) error {
	if !strings.HasPrefix(T.Op, "sys/") && T.Acc >= W.Exp {
		return fail(Expired, "acc %d at or after exp %d", T.Acc, W.Exp)
	}
	return nil
}

// verifyTree runs steps 7 to 10 of section 6.2 for T, which already passed
// steps 1 to 6 or, for a sub-tally, 6.1 and steps 3 and 5. chain runs from the
// root to W and is what the depth rule of step 8 extends.
func verifyTree(W *Writ, chain []*Writ, T *Tally) error {
	for _, name := range maxNames(W) {
		if T.Used[name] > W.Bnd[name].Int {
			return fail(OutOfBounds, "used.%s %d exceeds %d", name, T.Used[name], W.Bnd[name].Int)
		}
	}
	byID := map[string]*Writ{}
	for _, o := range T.wrtRaw {
		x, err := ParseWrit(o)
		if err != nil {
			return err
		}
		if err := CheckChild(x, W); err != nil {
			return err
		}
		if err := checkDepth(extend(chain, x)); err != nil {
			return err
		}
		byID[x.ID] = x
		T.Wrt = append(T.Wrt, x)
	}
	for i, o := range T.subRaw {
		// sub_unmatched is checked before anything else about the sub-tally.
		wh, _ := o["writ"].(string)
		X, ok := byID[wh]
		if !ok {
			return fail(SubUnmatched, "sub[%d] names writ %s absent from wrt", i, wh)
		}
		S, err := ParseTally(o, X.Hld)
		if err != nil {
			return err
		}
		if err := checkAcc(X, S); err != nil {
			return err
		}
		if err := verifyTree(X, extend(chain, X), S); err != nil {
			return err
		}
		T.Sub = append(T.Sub, S)
	}
	// Step 10: used is inclusive of the subtree, so T's own used must cover
	// its sub-tallies'. With step 7 at every level, this bounds the whole
	// tree by W, however deep; summing only against W let an intermediary
	// that reported zero hide what its own sub-tallies consumed.
	for _, name := range maxNames(W) {
		var sum int64
		for _, S := range T.Sub {
			sum += S.Used[name]
		}
		if sum > T.Used[name] {
			return fail(OutOfBounds, "sum of sub used.%s %d exceeds the tally's own used %d", name, sum, T.Used[name])
		}
	}
	return nil
}

// maxNames returns the names of W's max and total bounds in canonical order:
// the bounds a tally's used reports against (spec 6, 6.2 steps 7 and 10).
func maxNames(W *Writ) []string {
	var names []string
	for name, b := range W.Bnd {
		if b.T == "max" || b.T == "total" {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return lessUTF16(names[i], names[j]) })
	return names
}

// extend returns chain followed by w without sharing chain's backing array.
func extend(chain []*Writ, w *Writ) []*Writ {
	out := make([]*Writ, 0, len(chain)+1)
	return append(append(out, chain...), w)
}
