// Package conformance runs the vector corpus (spec section 14) against this
// implementation. Vector format is shared with every other implementation.
package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"writproto/bound"
	"writproto/jcs"
	"writproto/wire"
	"writproto/writ"
)

// Vector is one conformance case.
type Vector struct {
	Name   string          `json:"name"`
	Op     string          `json:"op"`
	Input  json.RawMessage `json:"input"`
	Expect string          `json:"expect"`
	Reason string          `json:"reason,omitempty"`
	Now    *int64          `json:"now,omitempty"`
}

// Verdict is this implementation's answer to one vector: the rejection
// reason and its error, or "" and nil on acceptance, plus the canonical form
// when a canonicalize vector is accepted.
type Verdict struct {
	Reason    writ.Reason
	Err       error
	Canonical string
}

// Judge evaluates one vector's input. A non-nil error means the vector itself
// is unusable. Run compares a verdict with the vector's expectation; the
// differential fuzzer records it as one.
func Judge(v Vector) (Verdict, error) {
	var reason writ.Reason
	var err error
	var canonical string
	switch v.Op {
	case "canonicalize":
		var in struct{ Raw, Canonical string }
		_ = json.Unmarshal(v.Input, &in)
		c, cerr := jcs.Canonicalize([]byte(in.Raw))
		if errors.Is(cerr, jcs.ErrTooDeep) {
			reason, err = writ.TooLarge, cerr
		} else if cerr != nil {
			reason, err = writ.Noncanonical, cerr
		}
		canonical = string(c)
	case "narrows":
		in := decode(v.Input)
		child, e1 := bound.Parse(in["child"])
		parent, e2 := bound.Parse(in["parent"])
		if e1 != nil || e2 != nil {
			reason, err = parseReason(firstErr(e1, e2)), firstErr(e1, e2)
		} else if err = writ.Narrows(child, parent); err != nil {
			reason = writ.CodeOf(err)
		}
	case "satisfies":
		in := decode(v.Input)
		b, e := bound.Parse(in["bound"])
		if e != nil {
			reason, err = parseReason(e), e
		} else if err = writ.Satisfies(b, in["arg"]); err != nil {
			reason = writ.CodeOf(err)
		}
	case "verify_writ":
		in := decode(v.Input)
		obj, _ := in["writ"].(map[string]any)
		_, err = writ.ParseWrit(obj)
		reason = writ.CodeOf(err)
	case "verify_chain":
		in := decode(v.Input)
		var chain []*writ.Writ
		chain, err = writ.ParseChain(in["chain"])
		if err == nil {
			err = writ.VerifyChain(chain)
		}
		if err == nil && v.Now != nil {
			err = writ.CheckExpiry(chain, *v.Now)
		}
		reason = writ.CodeOf(err)
	case "verify_call":
		in := decode(v.Input)
		obj, _ := in["call"].(map[string]any)
		var k *writ.Call
		k, err = writ.ParseCall(obj)
		if err == nil {
			err = writ.VerifyChain(k.Chain)
		}
		// Expiry applies to forward calls only (spec section 7 step 4).
		if err == nil && v.Now != nil && !k.Standing() {
			err = writ.CheckExpiry(k.Chain, *v.Now)
		}
		if err == nil {
			if k.Standing() {
				err = writ.CheckStanding(k)
			} else {
				err = writ.CheckForward(k)
			}
		}
		reason = writ.CodeOf(err)
	case "verify_tally":
		in := decode(v.Input)
		wobj, _ := in["writ"].(map[string]any)
		cobj, _ := in["call"].(map[string]any)
		tobj, _ := in["tally"].(map[string]any)
		w, e1 := writ.ParseWrit(wobj)
		if e1 != nil {
			return Verdict{}, fmt.Errorf("vector's writ is invalid: %v", e1)
		}
		k, e2 := writ.ParseCall(cobj)
		if e2 != nil {
			return Verdict{}, fmt.Errorf("vector's call is invalid: %v", e2)
		}
		_, _, err = writ.VerifyTally(w, k, tobj, in["res"])
		reason = writ.CodeOf(err)
	case "verify_revoke":
		in := decode(v.Input)
		obj, _ := in["revoke"].(map[string]any)
		var r *writ.Revoke
		r, err = writ.ParseRevoke(obj)
		if err == nil {
			err = writ.CheckRevoke(r)
		}
		reason = writ.CodeOf(err)
	case "check_ack":
		in := decode(v.Input)
		rvo, _ := in["revoke"].(map[string]any)
		ack, _ := in["ack"].(map[string]any)
		tobj, _ := in["tally"].(map[string]any)
		err = writ.CheckAck(rvo, ack, in["res"], in["chain"], tobj)
		reason = writ.CodeOf(err)
	default:
		return Verdict{}, fmt.Errorf("unknown op %s", v.Op)
	}
	return Verdict{reason, err, canonical}, nil
}

// Run evaluates one vector and returns (pass, detail).
func Run(v Vector) (bool, string) {
	vd, herr := Judge(v)
	if herr != nil {
		return false, herr.Error()
	}
	reason, err, canonical := vd.Reason, vd.Err, vd.Canonical
	if v.Op == "canonicalize" && err == nil && v.Expect == "accept" {
		var in struct{ Canonical string }
		_ = json.Unmarshal(v.Input, &in)
		if canonical != in.Canonical {
			return false, fmt.Sprintf("canonical form %s, want %s", canonical, in.Canonical)
		}
	}
	switch v.Expect {
	case "accept":
		if err != nil {
			return false, "rejected with " + string(reason) + ": " + err.Error()
		}
		return true, "accepted"
	case "reject":
		if err == nil {
			return false, "accepted, expected rejection " + v.Reason
		}
		if string(reason) != v.Reason {
			return false, "rejected with " + string(reason) + ", expected " + v.Reason + " (" + err.Error() + ")"
		}
		return true, "rejected with " + v.Reason
	}
	return false, "bad expect"
}

func decode(raw json.RawMessage) map[string]any {
	obj, _ := wire.Decode(raw)
	return obj
}

func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func parseReason(err error) writ.Reason { return writ.BoundReason(err) }

// RunDir runs every *.json vector in dir. Returns counts and a report.
func RunDir(dir string) (int, int, string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	var sb strings.Builder
	pass, fail := 0, 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var v Vector
		if err := json.Unmarshal(b, &v); err != nil {
			fail++
			fmt.Fprintf(&sb, "FAIL %s: unreadable vector: %v\n", filepath.Base(f), err)
			continue
		}
		ok, detail := Run(v)
		if ok {
			pass++
			fmt.Fprintf(&sb, "ok   %-48s %s\n", v.Name, detail)
		} else {
			fail++
			fmt.Fprintf(&sb, "FAIL %-48s %s\n", v.Name, detail)
		}
	}
	return pass, fail, sb.String()
}
