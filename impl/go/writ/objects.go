// Package writ implements the Writ protocol v0.1 objects: writ, call, tally,
// revoke, their parsing, chain attenuation, tally-tree verification, and
// issuance. It depends only on the jcs, keys, bound, and wire packages.
package writ

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
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
	// Sub and Wrt are filled by VerifyTally (spec 6.2 steps 8 and 9) and by
	// NewTally. ParseTally, which is spec 6.1 alone, leaves them empty and
	// keeps the unverified elements in subRaw and wrtRaw.
	Sub    []*Tally
	Wrt    []*Writ
	subRaw []wire.Object
	wrtRaw []wire.Object
}

// Revoke is a parsed revoke.
type Revoke struct {
	Raw   wire.Object
	ID    string
	Writ  string // hash or "*"
	Iss   string
	Chain []*Writ
}

// checkHeader runs spec 6.1 steps 1 to 4 on an object: nesting depth and
// size, canonical form and the encoding of the object's own binary members,
// version, type, crit. Returns the canonical bytes.
func checkHeader(obj wire.Object, typ string, maxBytes int) ([]byte, error) {
	if jcs.TooDeep(obj) {
		return nil, fail(TooLarge, "%s nests deeper than %d levels", typ, jcs.MaxDepth)
	}
	c, err := jcs.Marshal(obj)
	if err != nil {
		return nil, fail(Noncanonical, "%v", err)
	}
	if len(c) > maxBytes {
		return nil, fail(TooLarge, "%s is %d bytes, limit %d", typ, len(c), maxBytes)
	}
	if err := checkBinary(obj, typ); err != nil {
		return nil, err
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
			if _, ok := e.(string); !ok {
				return nil, fail(Malformed, "crit entries must be strings")
			}
		}
		for _, e := range arr {
			name := e.(string)
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

// binaryMembers are, per type, the members spec 6.1 step 2 holds to section
// 1.1 rule 5. A tally's err.ref is checked beside them.
var binaryMembers = map[string][]string{
	"writ":   {"prv", "nnc", "sig"},
	"call":   {"id", "sig"},
	"tally":  {"call", "writ", "out", "sig"},
	"revoke": {"writ", "sig"},
}

// checkBinary runs the rule 5 part of spec 6.1 step 2: every binary member of
// the object itself whose value is a string must be canonical base64url. A
// member of another JSON type waits for step 5, and nested writs and tallies
// are checked when they pass 6.1 themselves.
func checkBinary(obj wire.Object, typ string) error {
	for _, name := range binaryMembers[typ] {
		s, ok := obj[name].(string)
		if !ok || (typ == "revoke" && name == "writ" && s == "*") {
			continue
		}
		if !canonicalB64(s) {
			return fail(Noncanonical, "%s is not canonical base64url", name)
		}
	}
	if typ == "tally" {
		if m, ok := obj["err"].(map[string]any); ok {
			if s, ok := m["ref"].(string); ok && !canonicalB64(s) {
				return fail(Noncanonical, "err.ref is not canonical base64url")
			}
		}
	}
	return nil
}

// canonicalB64 reports whether s is the one base64url encoding, without
// padding, of some non-empty byte string (spec 1.1 rule 5).
func canonicalB64(s string) bool {
	raw, err := wire.B64.DecodeString(s)
	return err == nil && b64Re.MatchString(s) && wire.B64.EncodeToString(raw) == s
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
// means "at least MinRandom characters". Step 2 has already applied the first
// half to every binary member that is a string, so at step 5 only the length
// can fail.
func checkB64(name, s string, want int) error {
	if !canonicalB64(s) {
		return fail(Noncanonical, "%s is not canonical base64url", name)
	}
	raw, _ := wire.B64.DecodeString(s)
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

// keyMember reads a member whose type is key: a string (malformed otherwise)
// that is a valid did:key (bad_key otherwise), both checked before the next
// member (spec 6.1 step 5).
func keyMember(obj wire.Object, name string) (string, error) {
	s, ok := obj[name].(string)
	if !ok {
		return "", fail(Malformed, "%s must be a string", name)
	}
	if err := checkKey(s); err != nil {
		return "", err
	}
	return s, nil
}

// parseBnd runs the spec 6.1 step 5 rules for a writ's bnd: an object, act
// present, every bound in canonical member-name order under section 3, then
// the section 3.2 rules for act, hld, and depth.
func parseBnd(v any) (map[string]bound.Bound, error) {
	bnd, ok := v.(map[string]any)
	if !ok {
		return nil, fail(Malformed, "bnd must be an object")
	}
	if _, ok := bnd["act"]; !ok {
		return nil, fail(Malformed, "bnd.act is required")
	}
	names := make([]string, 0, len(bnd))
	for name := range bnd {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return lessUTF16(names[i], names[j]) })
	out := map[string]bound.Bound{}
	for _, name := range names {
		b, err := bound.Parse(bnd[name])
		if err != nil {
			return nil, fail(BoundReason(err), "bound %q: %v", name, err)
		}
		out[name] = b
	}
	if out["act"].T != "prefix" {
		return nil, fail(Malformed, "bnd.act must have type prefix")
	}
	if h, ok := out["hld"]; ok {
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
	if d, ok := out["depth"]; ok && d.T != "max" {
		return nil, fail(Malformed, "bnd.depth must have type max")
	}
	return out, nil
}

// checkSigMember is the spec 6.1 step 5 check on sig: a string encoding 64
// bytes. verifySig is step 6.
func checkSigMember(obj wire.Object) error {
	s, ok := obj["sig"].(string)
	if !ok {
		return fail(Malformed, "sig must be a string")
	}
	return checkB64("sig", s, 64)
}

func verifySig(obj wire.Object, signer string) error {
	if err := wire.VerifySig(obj, signer); err != nil {
		return fail(BadSignature, "%v", err)
	}
	return nil
}

// ParseWrit validates structure (spec 6.1 steps 1 to 5) and signature (step 6).
// Step 5 takes the members in the order of the writ's member table.
func ParseWrit(obj wire.Object) (*Writ, error) {
	c, err := checkHeader(obj, "writ", MaxWritBytes)
	if err != nil {
		return nil, err
	}
	w := &Writ{Raw: obj, ID: wire.HashBytes(c)}
	if w.Iss, err = keyMember(obj, "iss"); err != nil {
		return nil, err
	}
	if w.Hld, err = keyMember(obj, "hld"); err != nil {
		return nil, err
	}
	if w.Bnd, err = parseBnd(obj["bnd"]); err != nil {
		return nil, err
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
	var ok bool
	if w.Exp, ok = getInt(obj, "exp"); !ok {
		return nil, fail(Malformed, "exp must be an integer")
	}
	if w.Nnc, ok = obj["nnc"].(string); !ok {
		return nil, fail(Malformed, "nnc must be a string")
	}
	if err := checkB64("nnc", w.Nnc, 0); err != nil {
		return nil, err
	}
	if err := checkSigMember(obj); err != nil {
		return nil, err
	}
	if err := verifySig(obj, w.Iss); err != nil {
		return nil, err
	}
	return w, nil
}

// ParseChain checks a chain's shape (chainShape), then parses every writ in
// array order (spec section 4, chain verification as an operation). It does
// not check attenuation or emptiness; VerifyChain does.
func ParseChain(v any) ([]*Writ, error) {
	arr, err := chainShape(v)
	if err != nil {
		return nil, err
	}
	var chain []*Writ
	for _, e := range arr {
		w, err := ParseWrit(e.(map[string]any))
		if err != nil {
			return nil, err
		}
		chain = append(chain, w)
	}
	return chain, nil
}

// chainShape is the spec 6.1 step 5 check on a call's or revoke's chain
// member: an array of at most MaxChain elements, each an object. The writs
// are verified later, after every other member (section 7 step 2, section
// 9.1 step 2).
func chainShape(v any) ([]any, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fail(Malformed, "chain must be an array")
	}
	if len(arr) > MaxChain {
		return nil, fail(TooLarge, "chain has %d writs, limit %d", len(arr), MaxChain)
	}
	for i, e := range arr {
		if _, ok := e.(map[string]any); !ok {
			return nil, fail(Malformed, "chain[%d] is not an object", i)
		}
	}
	return arr, nil
}

// objects is the spec 6.1 step 5 check on a tally's sub and wrt: an array of
// objects. Their contents are checked in section 6.2 steps 8 and 9.
func objects(obj wire.Object, name string) ([]wire.Object, error) {
	arr, ok := obj[name].([]any)
	if !ok {
		return nil, fail(Malformed, "%s must be an array", name)
	}
	out := make([]wire.Object, 0, len(arr))
	for i, e := range arr {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "%s[%d] is not an object", name, i)
		}
		out = append(out, o)
	}
	return out, nil
}

// ParseCall runs spec section 7 steps 1 and 2 on a call: its own members
// (6.1 steps 1 to 5), then every writ of its chain (6.1, in array order),
// then its signature. Attenuation is VerifyChain's.
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
	arr, err := chainShape(obj["chain"])
	if err != nil {
		return nil, err
	}
	if len(arr) == 0 {
		return nil, fail(Malformed, "chain must not be empty")
	}
	if k.From, err = keyMember(obj, "from"); err != nil {
		return nil, err
	}
	if k.Op, ok = obj["op"].(string); !ok {
		return nil, fail(Malformed, "op must be a string")
	}
	if k.Args, ok = obj["args"].(map[string]any); !ok {
		return nil, fail(Malformed, "args must be an object")
	}
	if err := checkSigMember(obj); err != nil {
		return nil, err
	}
	if k.Chain, err = ParseChain(arr); err != nil {
		return nil, err
	}
	if err := verifySig(obj, k.From); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseTally runs spec section 6.1 on a tally with signer, which the caller
// derives from the writ the tally names. sub and wrt are checked only to be
// arrays of objects; VerifyTally checks their elements (6.2 steps 8 and 9)
// after this signature.
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
	if t.St == "ok" {
		if errv != nil {
			return nil, fail(Malformed, "err must be null when st is ok")
		}
	} else {
		m, ok := errv.(map[string]any)
		if !ok {
			return nil, fail(Malformed, "err must be an object when st is not ok")
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
	if t.subRaw, err = objects(obj, "sub"); err != nil {
		return nil, err
	}
	if t.wrtRaw, err = objects(obj, "wrt"); err != nil {
		return nil, err
	}
	if t.St == "pending" && (t.Err.Code != "pending" || len(t.Used) != 0 || t.Rev != nil || t.Out != "" ||
		len(t.subRaw) != 0 || len(t.wrtRaw) != 0) {
		return nil, fail(Malformed, "a pending tally has err.code pending, empty used, sub, and wrt, and null rev and out")
	}
	if err := checkSigMember(obj); err != nil {
		return nil, err
	}
	if err := verifySig(obj, signer); err != nil {
		return nil, err
	}
	return t, nil
}

// ParseRevoke runs spec section 9.1 steps 1 to 3: the revoke's own members,
// then every writ in its chain (section 6.1), then the revoke's signature.
// That is the order of section 7 steps 1 and 2 for a call. CheckRevoke runs
// step 4.
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
	if r.Iss, err = keyMember(obj, "iss"); err != nil {
		return nil, err
	}
	arr, err := chainShape(obj["chain"])
	if err != nil {
		return nil, err
	}
	if r.Writ == "*" && len(arr) != 0 {
		return nil, fail(Malformed, "a key-wide revoke must have an empty chain")
	}
	if r.Writ != "*" && len(arr) == 0 {
		return nil, fail(Malformed, "a revoke of one writ must carry its chain")
	}
	if err := checkSigMember(obj); err != nil {
		return nil, err
	}
	if r.Chain, err = ParseChain(arr); err != nil {
		return nil, err
	}
	if err := verifySig(obj, r.Iss); err != nil {
		return nil, err
	}
	return r, nil
}
