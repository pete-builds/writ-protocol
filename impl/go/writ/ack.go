package writ

import (
	"sort"
	"strings"

	"writproto/keys"
	"writproto/wire"
)

// MaxAckBytes is the ack limit from spec section 1.6.
const MaxAckBytes = 4096

// Ack is a parsed ack: an executor's signed record of when it recorded a
// revoke and of exactly which work under the revoked writ it held at that
// moment (spec 9.4). Its body travels beside it and Out commits to it.
type Ack struct {
	Raw    wire.Object
	ID     string
	Revoke string // identity of the revoke recorded
	Iss    string // the executor that recorded it, who signs
	Rcv    int64  // when it recorded it, by its own clock
	Out    string // hash of the body's canonical form
}

// AckHeld is one element of an ack body's held list: a tally in the
// executor's tally store under the revoked writ, and the call it answers.
type AckHeld struct {
	Call  string
	Tally string
}

// AckBody builds the body an ack commits to (spec 9.4): held in ascending
// order of call identity, open in the order given, which is the order of the
// revoke's answer.
func AckBody(held []AckHeld, open []string) map[string]any {
	sorted := append([]AckHeld(nil), held...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Call < sorted[j].Call })
	h := make([]any, 0, len(sorted))
	for _, e := range sorted {
		h = append(h, map[string]any{"call": e.Call, "tally": e.Tally})
	}
	o := make([]any, 0, len(open))
	for _, c := range open {
		o = append(o, c)
	}
	return map[string]any{"held": h, "open": o}
}

// ParseAck runs spec section 6.1 on an ack. Step 5 takes the members in the
// order of the ack's member table; the signer is the ack's own iss.
func ParseAck(obj wire.Object) (*Ack, error) {
	c, err := checkHeader(obj, "ack", MaxAckBytes)
	if err != nil {
		return nil, err
	}
	a := &Ack{Raw: obj, ID: wire.HashBytes(c)}
	var ok bool
	if a.Revoke, ok = obj["revoke"].(string); !ok {
		return nil, fail(Malformed, "revoke must be a hash")
	}
	if err := checkB64("revoke", a.Revoke, 32); err != nil {
		return nil, err
	}
	if a.Iss, err = keyMember(obj, "iss"); err != nil {
		return nil, err
	}
	if a.Rcv, ok = getInt(obj, "rcv"); !ok {
		return nil, fail(Malformed, "rcv must be an integer")
	}
	if a.Out, ok = obj["out"].(string); !ok {
		return nil, fail(Malformed, "out must be a hash")
	}
	if err := checkB64("out", a.Out, 32); err != nil {
		return nil, err
	}
	if err := checkSigMember(obj); err != nil {
		return nil, err
	}
	if err := verifySig(obj, a.Iss); err != nil {
		return nil, err
	}
	return a, nil
}

// NewAck signs, as exe, an ack of the revoke whose identity is revokeID,
// recorded at rcv, committing to body (see AckBody).
func NewAck(exe *keys.Identity, revokeID string, rcv int64, body map[string]any) (*Ack, error) {
	out, err := HashResult(body)
	if err != nil {
		return nil, err
	}
	obj := wire.Object{"v": 1, "typ": "ack", "revoke": revokeID, "iss": exe.DID(), "rcv": rcv, "out": out}
	obj, err = normalize(obj)
	if err != nil {
		return nil, err
	}
	if err := wire.Sign(obj, exe); err != nil {
		return nil, err
	}
	return ParseAck(obj)
}

// VerifyAck is spec 9.4 steps 2 to 4 for a revoke r that has passed section
// 9.1: the ack passes section 6.1, names r, and commits to body, which is an
// object whose held and open are arrays.
func VerifyAck(r *Revoke, ackObj wire.Object, body any) (*Ack, error) {
	a, err := ParseAck(ackObj)
	if err != nil {
		return nil, err
	}
	if a.Revoke != r.ID {
		return nil, fail(AckMismatch, "ack names revoke %s, not %s", a.Revoke, r.ID)
	}
	h, err := HashResult(body)
	if err != nil {
		return nil, fail(Noncanonical, "ack body: %v", err)
	}
	if h != a.Out {
		return nil, fail(AckMismatch, "ack body does not hash to out")
	}
	m, ok := body.(map[string]any)
	if !ok {
		return nil, fail(Malformed, "ack body must be an object")
	}
	if _, ok := m["held"].([]any); !ok {
		return nil, fail(Malformed, "ack body held must be an array")
	}
	if _, ok := m["open"].([]any); !ok {
		return nil, fail(Malformed, "ack body open must be an array")
	}
	return a, nil
}

// CheckAck is spec 9.4 steps 1 to 7: whether the tally tallyObj, answering a
// call under chain (root to the tally's writ), is accounted for by the ack
// ackObj, with body, of the revoke revokeObj. It returns nil when the tally is
// accounted for or the ack says nothing about it, and reason revoked when the
// tally reports forward work under the revoked writ that its signer's own ack
// does not account for.
func CheckAck(revokeObj, ackObj wire.Object, body any, chain any, tallyObj wire.Object) error {
	r, err := ParseRevoke(revokeObj)
	if err != nil {
		return err
	}
	if err := CheckRevoke(r); err != nil {
		return err
	}
	a, err := VerifyAck(r, ackObj, body)
	if err != nil {
		return err
	}
	C, err := ParseChain(chain)
	if err != nil {
		return err
	}
	if err := VerifyChain(C); err != nil {
		return err
	}
	leaf := C[len(C)-1]
	T, err := ParseTally(tallyObj, leaf.Hld)
	if err != nil {
		return err
	}
	if T.Writ != leaf.ID {
		return fail(TallyMismatch, "tally names writ %s, chain ends at %s", T.Writ, leaf.ID)
	}
	if !ackSpeaksOf(r, a, C, T) {
		return nil
	}
	if accountedFor(body.(map[string]any), T) {
		return nil
	}
	return fail(Revoked, "tally for call %s reports forward work under the revoked writ that its signer's ack at %d does not account for", T.Call, a.Rcv)
}

// ackSpeaksOf is spec 9.4 step 6: the ack says something about T only when
// they have one signer, T is forward work, R covers T's chain, and T's writ
// was still unexpired at rcv, so a final T was still in the tally store.
func ackSpeaksOf(r *Revoke, a *Ack, C []*Writ, T *Tally) bool {
	leaf := C[len(C)-1]
	if a.Iss != leaf.Hld || strings.HasPrefix(T.Op, "sys/") || !reportsWork(T) {
		return false
	}
	covered := false
	for _, w := range C {
		if w.ID == r.Writ || (r.Writ == "*" && w.Iss == r.Iss) {
			covered = true
		}
	}
	return covered && leaf.Exp > a.Rcv
}

// reportsWork is spec 9.4 step 6's test that a tally reports work: a
// refusal reports none, since it is failed with nothing used or delegated.
func reportsWork(T *Tally) bool {
	if T.St == "ok" || T.St == "pending" || T.St == "canceled" {
		return true
	}
	for _, n := range T.Used {
		if n > 0 {
			return true
		}
	}
	return len(T.subRaw) > 0 || len(T.wrtRaw) > 0
}

// accountedFor is spec 9.4 step 7.
func accountedFor(body map[string]any, T *Tally) bool {
	for _, c := range body["open"].([]any) {
		if c == T.Call {
			return true
		}
	}
	for _, e := range body["held"].([]any) {
		h, _ := e.(map[string]any)
		if h == nil || h["call"] != T.Call {
			continue
		}
		if h["tally"] == T.ID || T.St == "pending" {
			return true
		}
	}
	return false
}
