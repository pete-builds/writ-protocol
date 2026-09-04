package writ

import (
	"sort"
	"strings"
	"unicode/utf16"

	"writproto/bound"
)

// PrefixMatches implements spec section 3.1.
func PrefixMatches(p, s string) bool {
	if s == p {
		return true
	}
	if strings.HasSuffix(p, "/") && strings.HasPrefix(s, p) {
		return true
	}
	return strings.HasPrefix(s, p+"/")
}

// Narrows reports whether child narrows parent per section 3, using the
// segment rule for prefix.
func Narrows(child, parent bound.Bound) error {
	if child.T != parent.T {
		return fail(NotNarrowed, "type changed from %s to %s", parent.T, child.T)
	}
	if child.T == "prefix" {
		if !PrefixMatches(parent.Str, child.Str) {
			return fail(NotNarrowed, "prefix %q does not narrow %q", child.Str, parent.Str)
		}
		return nil
	}
	if err := bound.Narrows(child, parent); err != nil {
		return fail(NotNarrowed, "%v", err)
	}
	return nil
}

// Satisfies reports whether arg is permitted by b, using the segment rule for prefix.
func Satisfies(b bound.Bound, arg any) error {
	if b.T == "prefix" {
		s, ok := arg.(string)
		if !ok || !PrefixMatches(b.Str, s) {
			return fail(OutOfBounds, "value does not match prefix %q", b.Str)
		}
		return nil
	}
	if err := bound.Satisfies(b, arg); err != nil {
		return fail(OutOfBounds, "%v", err)
	}
	return nil
}

// CheckChild implements spec section 4 steps 1 to 5 for one adjacent pair.
func CheckChild(child, parent *Writ) error {
	if child.Iss != parent.Hld {
		return fail(ChainBroken, "child iss %s is not parent hld %s", child.Iss, parent.Hld)
	}
	if child.Prv != parent.ID {
		return fail(ChainBroken, "child prv does not name parent")
	}
	if child.Exp > parent.Exp {
		return fail(NotNarrowed, "child exp %d after parent exp %d", child.Exp, parent.Exp)
	}
	for name, pb := range parent.Bnd {
		cb, ok := child.Bnd[name]
		if !ok {
			return fail(NotNarrowed, "child drops bound %q", name)
		}
		if err := Narrows(cb, pb); err != nil {
			return fail(NotNarrowed, "bound %q: %v", name, err)
		}
	}
	if h, ok := parent.Bnd["hld"]; ok {
		found := false
		for _, e := range h.Set {
			if !e.IsInt && e.Str == child.Hld {
				found = true
			}
		}
		if !found {
			return fail(NotNarrowed, "child hld %s not in parent hld set", child.Hld)
		}
	}
	return nil
}

// VerifyChain checks that a parsed chain is a valid chain: root prv null,
// each pair attenuates, depth bounds hold over the whole chain. It does not
// check expiry, which needs a clock (see Expired).
func VerifyChain(chain []*Writ) error {
	if len(chain) == 0 {
		return fail(Malformed, "chain must not be empty")
	}
	if len(chain) > MaxChain {
		return fail(TooLarge, "chain has %d writs", len(chain))
	}
	if chain[0].Prv != "" {
		return fail(ChainBroken, "root prv is not null")
	}
	for i := 1; i < len(chain); i++ {
		if err := CheckChild(chain[i], chain[i-1]); err != nil {
			return err
		}
	}
	n := int64(len(chain))
	for i, w := range chain {
		if d, ok := w.Bnd["depth"]; ok && n-1-int64(i) > d.Int {
			return fail(NotNarrowed, "chain[%d] permits depth %d, chain has %d below it", i, d.Int, n-1-int64(i))
		}
	}
	return nil
}

// CheckExpiry reports whether any writ in the chain is expired at now.
func CheckExpiry(chain []*Writ, now int64) error {
	for _, w := range chain {
		if now >= w.Exp {
			return fail(Expired, "writ %s expired at %d, now %d", w.ID, w.Exp, now)
		}
	}
	return nil
}

// Issuers returns the set of iss keys on a chain.
func Issuers(chain []*Writ) map[string]bool {
	m := map[string]bool{}
	for _, w := range chain {
		m[w.Iss] = true
	}
	return m
}

// CheckArgs implements spec section 7.2 in two passes over the leaf's
// application bounds in canonical name order: presence of every argument
// first, then satisfaction. So missing_arg always precedes out_of_bounds and
// two implementations report the same first failure.
func CheckArgs(leaf *Writ, args map[string]any) error {
	names := make([]string, 0, len(leaf.Bnd))
	for name, b := range leaf.Bnd {
		if name == "act" || name == "hld" || name == "depth" || b.T == "count" {
			continue
		}
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return lessUTF16(names[i], names[j]) })
	for _, name := range names {
		if _, ok := args[name]; !ok {
			return fail(MissingArg, "args lacks %q", name)
		}
	}
	for _, name := range names {
		if err := Satisfies(leaf.Bnd[name], args[name]); err != nil {
			return fail(OutOfBounds, "args.%s: %v", name, err)
		}
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// CheckForward implements the forward-call rules of section 5 and section 7
// step 8: standing, op namespace, act match, and args.
func CheckForward(k *Call) error {
	leaf := k.Leaf()
	if k.From != leaf.Iss {
		return fail(NoStanding, "from %s is not the leaf issuer %s", k.From, leaf.Iss)
	}
	if k.Standing() {
		return fail(ForbiddenOp, "forward op %q is in the sys/ namespace", k.Op)
	}
	if !PrefixMatches(leaf.Bnd["act"].Str, k.Op) {
		return fail(ForbiddenOp, "op %q not matched by act %q", k.Op, leaf.Bnd["act"].Str)
	}
	return CheckArgs(leaf, k.Args)
}

// CheckStanding implements the standing-call rule: from is an issuer on the chain.
func CheckStanding(k *Call) error {
	if !Issuers(k.Chain)[k.From] {
		return fail(NoStanding, "from %s is not an issuer on the chain", k.From)
	}
	return nil
}
