// Package conformance runs the vector corpus (spec section 14) against this
// implementation. Vector format is shared with every other implementation.
package conformance

import (
	"encoding/json"
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

// Run evaluates one vector and returns (pass, detail).
func Run(v Vector) (bool, string) {
	var reason writ.Reason
	var err error
	switch v.Op {
	case "canonicalize":
		var in struct{ Raw, Canonical string }
		_ = json.Unmarshal(v.Input, &in)
		c, cerr := jcs.Canonicalize([]byte(in.Raw))
		if cerr != nil {
			reason, err = writ.Noncanonical, cerr
		} else if v.Expect == "accept" && string(c) != in.Canonical {
			return false, fmt.Sprintf("canonical form %s, want %s", c, in.Canonical)
		}
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
		if err == nil && v.Now != nil {
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
			return false, "vector's writ is invalid: " + e1.Error()
		}
		k, e2 := writ.ParseCall(cobj)
		if e2 != nil {
			return false, "vector's call is invalid: " + e2.Error()
		}
		_, _, err = writ.VerifyTally(w, k, tobj, in["res"])
		reason = writ.CodeOf(err)
	default:
		return false, "unknown op " + v.Op
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
