// Package writ implements the Writ protocol v0.1 objects: writ, call, tally,
// revoke, their parsing, chain attenuation, tally-tree verification, and
// issuance. It depends only on the jcs, keys, bound, and wire packages.
package writ

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"writproto/bound"
	"writproto/jcs"
	"writproto/keys"
	"writproto/wire"
)

// Version is the only protocol version this package speaks.
const Version = 1

// Limits from spec section 1.6.
const (
	MaxChain       = 8
	MaxWritBytes   = 4096
	MaxCallBytes   = 65536
	MaxTallyBytes  = 262144
	MaxRevokeBytes = 65536
	MinRandom      = 22 // 16 bytes base64url
)

var b64Re = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Known member names per type, used only to decide whether a crit entry is understood.
var known = map[string]map[string]bool{
	"writ":   set("v", "typ", "iss", "hld", "bnd", "prv", "exp", "nnc", "crit", "sig"),
	"call":   set("v", "typ", "id", "chain", "from", "op", "args", "crit", "sig"),
	"tally":  set("v", "typ", "call", "writ", "op", "acc", "st", "err", "out", "used", "rev", "sub", "wrt", "crit", "sig"),
	"revoke": set("v", "typ", "writ", "iss", "chain", "crit", "sig"),
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Writ is a parsed, structurally valid writ. Signature validity is separate.
type Writ struct {
	Raw wire.Object
	ID  string // identity hash, spec 1.5
	Iss string
	Hld string
	Bnd map[string]bound.Bound
	Prv string // "" for a root
	Exp int64
	Nnc string
}

// Call is a parsed call.
type Call struct {
	Raw   wire.Object
	ID    string // identity hash
	CID   string // the id member
	Chain []*Writ
	From  string
	Op    string
	Args  map[string]any
}

// Leaf returns the last writ of the chain.
func (c *Call) Leaf() *Writ { return c.Chain[len(c.Chain)-1] }

// Standing reports whether the call is a standing (sys/) call.
func (c *Call) Standing() bool { return strings.HasPrefix(c.Op, "sys/") }

// TallyErr is the err member of a tally.
type TallyErr struct {
	Code string
	Ref  string
}

// Tally is a parsed tally.
type Tally struct {
	Raw  wire.Object
	ID   string
	Call string
	Writ string
	Op   string
	Acc  int64
	St   string
	Err  *TallyErr
	Out  string // "" when null
	Used map[string]int64
	Rev  *int64 // until, nil when null
	Sub  []*Tally
	Wrt  []*Writ
}

// Revoke is a parsed revoke.
type Revoke struct {
	Raw   wire.Object
	ID    string
	Writ  string // hash or "*"
	Iss   string
	Chain []*Writ
}

// checkHeader runs spec 6.1 steps 1 to 4 on an object: size, canonical form,
// version, type, crit. Returns the canonical bytes.
func checkHeader(obj wire.Object, typ string, maxBytes int) ([]byte, error) {
	c, err := jcs.Marshal(obj)
	if err != nil {
		return nil, fail(Noncanonical, "%v", err)
	}
	if len(c) > maxBytes {
		return nil, fail(TooLarge, "%s is %d bytes, limit %d", typ, len(c), maxBytes)
	}
	v, ok := obj["v"].(json.Number)
	if !ok || v.String() != "1" {
		if vi, ok2 := obj["v"].(int); ok2 && vi == 1 {
			// tolerated for programmatically built objects
		} else {
			return nil, fail(UnsupportedVersion, "v is %v", obj["v"])
		}
	}
	if t, _ := obj["typ"].(string); t != typ {
		return nil, fail(WrongType, "typ is %q, want %q", t, typ)
	}
	if crit, present := obj["crit"]; present {
		arr, ok := crit.([]any)
		if !ok {
			return nil, fail(Malformed, "crit must be an array")
		}
		for _, e := range arr {
			name, ok := e.(string)
			if !ok {
				return nil, fail(Malformed, "crit entries must be strings")
			}
			if !known[typ][name] {
				return nil, fail(UnsupportedCritical, "crit names %q", name)
			}
			if _, ok := obj[name]; !ok {
				return nil, fail(Malformed, "crit names absent member %q", name)
			}
		}
	}
	return c, nil
}

// BoundReason maps a bound.Parse error to its reason code.
func BoundReason(err error) Reason {
	switch {
	case errors.Is(err, bound.ErrUnknownType):
		return UnknownBound
	case errors.Is(err, bound.ErrValue):
		return Noncanonical
	default:
		return Malformed
	}
}

// checkB64 enforces spec 1.1 rule 5 on a binary member: base64url alphabet,
// no padding, and an encoding that re-encodes to itself (noncanonical
// otherwise), then the expected decoded length (malformed otherwise). want 0
// means "at least MinRandom characters".
func checkB64(name, s string, want int) error {
	raw, err := wire.B64.DecodeString(s)
	if err != nil || !b64Re.MatchString(s) || wire.B64.EncodeToString(raw) != s {
		return fail(Noncanonical, "%s is not canonical base64url", name)
	}
	if want == 0 {
		if len(raw) < 16 {
			return fail(Malformed, "%s must encode at least 16 bytes", name)
		}
		return nil
	}
	if len(raw) != want {
		return fail(Malformed, "%s must encode %d bytes", name, want)
	}
	return nil
}

func getInt(obj wire.Object, name string) (int64, bool) {
	switch x := obj[name].(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

func checkKey(did string) error {
	if _, err := keys.PublicKeyFromDID(did); err != nil {
		return fail(BadKey, "%v", err)
	}
	return nil
}

// ParseWrit validates structure (spec 6.1 steps 1 to 5) and signature (step 6).
func ParseWrit(obj wire.Object) (*Writ, error) {
	c, err := checkHeader(obj, "writ", MaxWritBytes)
	if err != nil {
		return nil, err
	}
	w := &Writ{Raw: obj, ID: wire.HashBytes(c)}
	var ok bool
	if w.Iss, ok = obj["iss"].(string); !ok {
		return nil, fail(Malformed, "iss must be a string")
	}
	if w.Hld, ok = obj["hld"].(string); !ok {
		return nil, fail(Malformed, "hld must be a string")
	}
	bnd, ok := obj["bnd"].(map[string]any)
	if !ok {
		return nil, fail(Malformed, "bnd must be an object")
	}
	w.Bnd = map[string]bound.Bound{}
	for name, v := range bnd {
		b, err := bound.Parse(v)
		if err != nil {
			return nil, fail(BoundReason(err), "bound %q: %v", name, err)
		}
		w.Bnd[name] = b
	}
	act, ok := w.Bnd["act"]
	if !ok || act.T != "prefix" {
		return nil, fail(Malformed, "bnd.act must be present with type prefix")
	}
	if h, ok := w.Bnd["hld"]; ok {
		if h.T != "set" {
			return nil, fail(Malformed, "bnd.hld must have type set")
		}
		for _, e := range h.Set {
			if e.IsInt {
				return nil, fail(Malformed, "bnd.hld elements must be keys")
			}
			if err := checkKey(e.Str); err != nil {
				return nil, err
			}
		}
	}
	if d, ok := w.Bnd["depth"]; ok && d.T != "max" {
		return nil, fail(Malformed, "bnd.depth must have type max")
	}
	prv, present := obj["prv"]
	if !present {
		return nil, fail(Malformed, "prv is required (null for a root)")
	}
	if prv != nil {
		s, ok := prv.(string)
		if !ok {
			return nil, fail(Malformed, "prv must be null or a hash")
		}
		if err := checkB64("prv", s, 32); err != nil {
			return nil, err
		}
		w.Prv = s
	}
	if w.Exp, ok = getInt(obj, "exp"); !ok {
		return nil, fail(Malformed, "exp must be an integer")
	}
	if w.Nnc, ok = obj["nnc"].(string); !ok {
		return nil, fail(Malformed, "nnc must be a string")
	}
	if err := checkB64("nnc", w.Nnc, 0); err != nil {
		return nil, err
	}
	if err := checkKey(w.Iss); err != nil {
		return nil, err
	}
	if err := checkKey(w.Hld); err != nil {
		return nil, err
	}
	if err := checkSig(obj, w.Iss); err != nil {
		return nil, err
	}
	return w, nil
}

func checkSig(obj wire.Object, signer string) error {
	s, ok := obj["sig"].(string)
	if !ok {
		return fail(Malformed, "sig must be a string")
	}
	if err := checkB64("sig", s, 64); err != nil {
		return err
	}
	if err := wire.VerifySig(obj, signer); err != nil {
		return fail(BadSignature, "%v", err)
	}
	return nil
}

// ParseChain parses every writ in an array. It does not check attenuation.
func ParseChain(v any) ([]*Writ, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fail(Malformed, "chain must be an array")
	}
	if len(arr) > MaxChain {
		return nil, fail(TooLarge, "chain has %d writs, limit %d", len(arr), MaxChain)
	}
	var chain []*Writ
	for i, e := range arr {
		obj, ok := e.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "chain[%d] is not an object", i)
		}
		w, err := ParseWrit(obj)
		if err != nil {
			return nil, err
		}
		chain = append(chain, w)
	}
	return chain, nil
}

// ParseCall validates a call's structure and signature and parses its chain
// (each writ's structure and signature, not attenuation).
func ParseCall(obj wire.Object) (*Call, error) {
	c, err := checkHeader(obj, "call", MaxCallBytes)
	if err != nil {
		return nil, err
	}
	k := &Call{Raw: obj, ID: wire.HashBytes(c)}
	var ok bool
	if k.CID, ok = obj["id"].(string); !ok {
		return nil, fail(Malformed, "id must be a string")
	}
	if err := checkB64("id", k.CID, 0); err != nil {
		return nil, err
	}
	if k.Chain, err = ParseChain(obj["chain"]); err != nil {
		return nil, err
	}
	if len(k.Chain) == 0 {
		return nil, fail(Malformed, "chain must not be empty")
	}
	if k.From, ok = obj["from"].(string); !ok {
		return nil, fail(Malformed, "from must be a string")
	}
	if k.Op, ok = obj["op"].(string); !ok {
		return nil, fail(Malformed, "op must be a string")
	}
	if k.Args, ok = obj["args"].(map[string]any); !ok {
		return nil, fail(Malformed, "args must be an object")
	}
	if err := checkKey(k.From); err != nil {
		return nil, err
	}
	if err := checkSig(obj, k.From); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseTally validates a tally's structure and its signature under signer,
// which the caller derives from the writ the tally names. Sub-tallies and
// wrt entries are parsed structurally; sub-tally signatures are verified by
// VerifyTally once their writs are known.
func ParseTally(obj wire.Object, signer string) (*Tally, error) {
	c, err := checkHeader(obj, "tally", MaxTallyBytes)
	if err != nil {
		return nil, err
	}
	t := &Tally{Raw: obj, ID: wire.HashBytes(c)}
	var ok bool
	if t.Call, ok = obj["call"].(string); !ok {
		return nil, fail(Malformed, "call must be a hash")
	}
	if err := checkB64("call", t.Call, 32); err != nil {
		return nil, err
	}
	if t.Writ, ok = obj["writ"].(string); !ok {
		return nil, fail(Malformed, "writ must be a hash")
	}
	if err := checkB64("writ", t.Writ, 32); err != nil {
		return nil, err
	}
	if t.Op, ok = obj["op"].(string); !ok {
		return nil, fail(Malformed, "op must be a string")
	}
	if t.Acc, ok = getInt(obj, "acc"); !ok {
		return nil, fail(Malformed, "acc must be an integer")
	}
	if t.St, ok = obj["st"].(string); !ok || (t.St != "ok" && t.St != "failed" && t.St != "canceled" && t.St != "pending") {
		return nil, fail(Malformed, "st must be ok, failed, canceled, or pending")
	}
	errv, present := obj["err"]
	if !present {
		return nil, fail(Malformed, "err is required (null when ok)")
	}
	if errv != nil {
		m, ok := errv.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "err must be null or an object")
		}
		code, ok := m["code"].(string)
		if !ok {
			return nil, fail(Malformed, "err.code must be a string")
		}
		t.Err = &TallyErr{Code: code}
		if ref, ok := m["ref"]; ok {
			s, ok := ref.(string)
			if !ok {
				return nil, fail(Malformed, "err.ref must be a hash")
			}
			if err := checkB64("err.ref", s, 32); err != nil {
				return nil, err
			}
			t.Err.Ref = s
		}
	}
	if t.St == "ok" && t.Err != nil {
		return nil, fail(Malformed, "err must be null when st is ok")
	}
	if t.St != "ok" && t.Err == nil {
		return nil, fail(Malformed, "err must be present when st is not ok")
	}
	out, present := obj["out"]
	if !present {
		return nil, fail(Malformed, "out is required (null when none)")
	}
	if out != nil {
		if t.Out, ok = out.(string); !ok {
			return nil, fail(Malformed, "out must be null or a hash")
		}
		if err := checkB64("out", t.Out, 32); err != nil {
			return nil, err
		}
	}
	used, ok := obj["used"].(map[string]any)
	if !ok {
		return nil, fail(Malformed, "used must be an object")
	}
	t.Used = map[string]int64{}
	for name, v := range used {
		n, ok := getInt(used, name)
		if !ok || n < 0 {
			return nil, fail(Malformed, "used.%s must be a non-negative integer (%v)", name, v)
		}
		t.Used[name] = n
	}
	rev, present := obj["rev"]
	if !present {
		return nil, fail(Malformed, "rev is required (null when not reversible)")
	}
	if rev != nil {
		m, ok := rev.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "rev must be null or an object")
		}
		until, ok := getInt(m, "until")
		if !ok {
			return nil, fail(Malformed, "rev.until must be an integer")
		}
		t.Rev = &until
	}
	if t.St == "pending" && (len(t.Used) != 0 || t.Rev != nil || t.Out != "") {
		return nil, fail(Malformed, "a pending tally has empty used, null rev, null out")
	}
	wrt, ok := obj["wrt"].([]any)
	if !ok {
		return nil, fail(Malformed, "wrt must be an array")
	}
	for i, e := range wrt {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "wrt[%d] is not an object", i)
		}
		w, err := ParseWrit(o)
		if err != nil {
			return nil, err
		}
		t.Wrt = append(t.Wrt, w)
	}
	sub, ok := obj["sub"].([]any)
	if !ok {
		return nil, fail(Malformed, "sub must be an array")
	}
	for i, e := range sub {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "sub[%d] is not an object", i)
		}
		// Signer of a sub-tally is the hld of the writ it names, which must be in wrt.
		wh, _ := o["writ"].(string)
		var signerSub string
		for _, w := range t.Wrt {
			if w.ID == wh {
				signerSub = w.Hld
			}
		}
		if signerSub == "" {
			return nil, fail(SubUnmatched, "sub[%d] names writ %s absent from wrt", i, wh)
		}
		st, err := ParseTally(o, signerSub)
		if err != nil {
			return nil, err
		}
		t.Sub = append(t.Sub, st)
	}
	if err := checkSig(obj, signer); err != nil {
		return nil, err
	}
	return t, nil
}

// ParseRevoke validates a revoke's structure and signature.
func ParseRevoke(obj wire.Object) (*Revoke, error) {
	c, err := checkHeader(obj, "revoke", MaxRevokeBytes)
	if err != nil {
		return nil, err
	}
	r := &Revoke{Raw: obj, ID: wire.HashBytes(c)}
	var ok bool
	if r.Writ, ok = obj["writ"].(string); !ok {
		return nil, fail(Malformed, "writ must be a hash or \"*\"")
	}
	if r.Writ != "*" {
		if err := checkB64("writ", r.Writ, 32); err != nil {
			return nil, err
		}
	}
	if r.Iss, ok = obj["iss"].(string); !ok {
		return nil, fail(Malformed, "iss must be a string")
	}
	if r.Chain, err = ParseChain(obj["chain"]); err != nil {
		return nil, err
	}
	if err := checkKey(r.Iss); err != nil {
		return nil, err
	}
	if err := checkSig(obj, r.Iss); err != nil {
		return nil, err
	}
	return r, nil
}
