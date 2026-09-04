package writ

import (
	"crypto/rand"
	"encoding/json"

	"writproto/keys"
	"writproto/wire"
)

func random22() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return wire.B64.EncodeToString(b)
}

// Nonce is the nonce source; tests replace it for reproducible vectors.
var Nonce = random22

// toNumber converts Go integers in a freshly built object into json.Number so
// that the object matches what Decode would produce.
func normalize(obj wire.Object) (wire.Object, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return wire.Decode(b)
}

// Issue builds and signs a writ from iss to hld. When parent is non-nil the
// writ is a child of parent and MUST narrow it; Issue refuses otherwise, so an
// implementation cannot accidentally sign a widened grant. bnd is the JSON
// shape: name to {"t": type, "v": value}.
func Issue(iss *keys.Identity, hld string, bnd map[string]any, exp int64, parent *Writ) (*Writ, error) {
	obj := wire.Object{
		"v": 1, "typ": "writ", "iss": iss.DID(), "hld": hld,
		"bnd": bnd, "exp": exp, "nnc": Nonce(),
	}
	if parent == nil {
		obj["prv"] = nil
	} else {
		obj["prv"] = parent.ID
	}
	obj, err := normalize(obj)
	if err != nil {
		return nil, err
	}
	if err := wire.Sign(obj, iss); err != nil {
		return nil, err
	}
	w, err := ParseWrit(obj)
	if err != nil {
		return nil, err
	}
	if parent != nil {
		if err := CheckChild(w, parent); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// NewCall builds and signs a call under chain.
func NewCall(from *keys.Identity, chain []*Writ, op string, args map[string]any) (*Call, error) {
	var raw []any
	for _, w := range chain {
		raw = append(raw, w.Raw)
	}
	if raw == nil {
		raw = []any{}
	}
	if args == nil {
		args = map[string]any{}
	}
	obj := wire.Object{
		"v": 1, "typ": "call", "id": Nonce(), "chain": raw,
		"from": from.DID(), "op": op, "args": args,
	}
	obj, err := normalize(obj)
	if err != nil {
		return nil, err
	}
	if err := wire.Sign(obj, from); err != nil {
		return nil, err
	}
	return ParseCall(obj)
}

// TallyInput is what an executor knows when it signs a tally.
type TallyInput struct {
	Call     *Call
	Acc      int64
	St       string
	ErrCode  string
	ErrRef   string
	Res      any // result body, nil when none
	Used     map[string]int64
	RevUntil *int64
	Sub      []*Tally
	Wrt      []*Writ
}

// NewTally builds and signs a tally as the leaf holder.
func NewTally(exe *keys.Identity, in TallyInput) (*Tally, any, error) {
	var errv any
	if in.ErrCode != "" {
		e := map[string]any{"code": in.ErrCode}
		if in.ErrRef != "" {
			e["ref"] = in.ErrRef
		}
		errv = e
	}
	var out any
	if in.Res != nil {
		h, err := HashResult(in.Res)
		if err != nil {
			return nil, nil, err
		}
		out = h
	}
	used := map[string]any{}
	for k, v := range in.Used {
		used[k] = v
	}
	var rev any
	if in.RevUntil != nil {
		rev = map[string]any{"until": *in.RevUntil}
	}
	sub := []any{}
	for _, s := range in.Sub {
		sub = append(sub, s.Raw)
	}
	wrt := []any{}
	for _, w := range in.Wrt {
		wrt = append(wrt, w.Raw)
	}
	obj := wire.Object{
		"v": 1, "typ": "tally", "call": in.Call.ID, "writ": in.Call.Leaf().ID,
		"op": in.Call.Op, "acc": in.Acc, "st": in.St, "err": errv, "out": out,
		"used": used, "rev": rev, "sub": sub, "wrt": wrt,
	}
	obj, err := normalize(obj)
	if err != nil {
		return nil, nil, err
	}
	if err := wire.Sign(obj, exe); err != nil {
		return nil, nil, err
	}
	t, err := ParseTally(obj, exe.DID())
	if err != nil {
		return nil, nil, err
	}
	return t, in.Res, nil
}

// NewRevoke builds and signs a revoke of the leaf of chain (or "*" when chain is empty).
func NewRevoke(iss *keys.Identity, chain []*Writ) (*Revoke, error) {
	raw := []any{}
	target := "*"
	for _, w := range chain {
		raw = append(raw, w.Raw)
	}
	if len(chain) > 0 {
		target = chain[len(chain)-1].ID
	}
	obj := wire.Object{"v": 1, "typ": "revoke", "writ": target, "iss": iss.DID(), "chain": raw}
	obj, err := normalize(obj)
	if err != nil {
		return nil, err
	}
	if err := wire.Sign(obj, iss); err != nil {
		return nil, err
	}
	return ParseRevoke(obj)
}

// CheckRevoke validates a parsed revoke per section 9.1.
func CheckRevoke(r *Revoke) error {
	if r.Writ == "*" {
		if len(r.Chain) != 0 {
			return fail(Malformed, "key-wide revoke must have an empty chain")
		}
		return nil
	}
	if err := VerifyChain(r.Chain); err != nil {
		return err
	}
	if r.Chain[len(r.Chain)-1].ID != r.Writ {
		return fail(TallyMismatch, "revoke names %s but chain leaf is %s", r.Writ, r.Chain[len(r.Chain)-1].ID)
	}
	if !Issuers(r.Chain)[r.Iss] {
		return fail(NoStanding, "revoker %s is not an issuer on the chain", r.Iss)
	}
	return nil
}
