package writ

import (
	"fmt"
	"sort"
	"strings"

	"writproto/bound"
	"writproto/keys"
)

// Approval is delegation, not a new object (docs/approval.md). An agent's own
// writ is its approval line: a forward call its chain refuses for its
// operation or its arguments may still be within what a writ higher up the
// chain allows, and the issuer of the first writ that refuses it holds that
// wider authority. That issuer approves by issuing a writ for exactly this
// operation and these arguments, once, in place of the one that refused. The
// approval then sits in the chain of every tally done under it, signed by
// the approver, and no executor needs to know approval exists.

// ApprovalCount is the bound name an approval writ uses for its single use
// when the writ it narrows carries no count bound of its own.
const ApprovalCount = "approval"

// Admits reports whether one writ's act and application bounds admit a
// forward call's op and args (spec 5 and 7.2). Count, total, expiry, and
// revocation need an executor's clock and stores, and are not judged here.
func Admits(w *Writ, op string, args map[string]any) bool {
	if strings.HasPrefix(op, "sys/") || !PrefixMatches(w.Bnd["act"].Str, op) {
		return false
	}
	return CheckArgs(w, args) == nil
}

// ApprovalPoint returns the index of the first writ in chain, root first,
// that does not admit op and args. Its issuer is the approver: the holder of
// the writ above it, or, for index 0, the root's own issuer. Because each
// writ narrows its parent, every writ below that index refuses too, and every
// writ above it admits. It returns -1 when every writ admits, so a refusal of
// the call was not about its operation or arguments and approval cannot help.
func ApprovalPoint(chain []*Writ, op string, args map[string]any) int {
	for i, w := range chain {
		if !Admits(w, op, args) {
			return i
		}
	}
	return -1
}

// Approve issues, as approver, the writ that replaces replaced for op and
// args: act is op, every bound is pinned to the call's value, every argument
// is pinned even where no bound named it, it may be used once, and it ends at
// exp or parent's exp, whichever is sooner. Two pins are looser than the
// call, because a child keeps its parent's bound types (spec 4 step 4): a max
// or total pinned to a value is a ceiling, so a smaller amount also passes,
// and act is a prefix, so an operation below op in its namespace also passes
// (spec 3.1). parent is the writ above
// replaced, nil when replaced is a root. The approver must be replaced's
// issuer, so it holds parent, and Issue refuses an approval that does not
// narrow parent, so no one can approve more than they hold.
//
// The holder of the approval re-issues, the same way, each writ that stood
// below replaced; in the common chain of a person, their agent, and an
// executor, that is the agent's one writ to the executor.
func Approve(approver keys.Signer, parent, replaced *Writ, op string, args map[string]any, exp int64) (*Writ, error) {
	if approver.DID() != replaced.Iss {
		return nil, fmt.Errorf("approval: %s did not issue the writ it replaces; its issuer %s is the approver", approver.DID(), replaced.Iss)
	}
	if strings.HasPrefix(op, "sys/") {
		return nil, fmt.Errorf("approval: %q is a standing operation, which needs no approval", op)
	}
	// The approval carries every bound the writ above it carries, as it
	// must (spec 4 step 4), and the shape of the writ it replaces where
	// that writ is a root and nothing is above it.
	shape := replaced.Bnd
	if parent != nil {
		shape = parent.Bnd
	}
	bnd := map[string]any{"act": map[string]any{"t": "prefix", "v": op}}
	counted := false
	for name, b := range shape {
		switch name {
		case "act":
			continue
		case "hld", "depth":
			// Who may hold a child, and how deep: the writ being replaced
			// already chose these within its parent's.
			if rb, ok := replaced.Bnd[name]; ok {
				b = rb
			}
			bnd[name] = map[string]any{"t": b.T, "v": b.Raw}
			continue
		}
		if b.T == "count" {
			bnd[name] = map[string]any{"t": "count", "v": 1}
			counted = true
			continue
		}
		arg, ok := args[name]
		if !ok {
			return nil, fmt.Errorf("approval: the call has no %q argument, which the writ above bounds", name)
		}
		v, err := pin(b.T, arg)
		if err != nil {
			return nil, fmt.Errorf("approval: argument %q: %v", name, err)
		}
		bnd[name] = map[string]any{"t": b.T, "v": v}
	}
	// Pin every remaining argument, so the approval names one action and
	// not a family of them (spec 7.2: an argument with no bound is free).
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, done := bnd[name]; done {
			continue
		}
		if name == "act" || name == "hld" || name == "depth" {
			return nil, fmt.Errorf("approval: argument %q has a reserved bound name and cannot be pinned", name)
		}
		v, err := pin("set", args[name])
		if err != nil {
			return nil, fmt.Errorf("approval: argument %q: %v", name, err)
		}
		bnd[name] = map[string]any{"t": "set", "v": v}
	}
	if !counted {
		if _, taken := bnd[ApprovalCount]; taken {
			return nil, fmt.Errorf("approval: an argument named %q leaves no name for the approval's single use", ApprovalCount)
		}
		bnd[ApprovalCount] = map[string]any{"t": "count", "v": 1}
	}
	if parent != nil && parent.Exp < exp {
		exp = parent.Exp
	}
	return Issue(approver, replaced.Hld, bnd, exp, parent)
}

// pin returns the bound value of type t that admits exactly arg.
func pin(t string, arg any) (any, error) {
	switch t {
	case "max", "total":
		n, err := bound.Int(arg)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("a %s bound needs a non-negative integer", t)
		}
		return n, nil
	case "window":
		n, err := bound.Int(arg)
		if err != nil {
			return nil, fmt.Errorf("a window bound needs an integer")
		}
		return []any{n, n}, nil
	case "prefix":
		s, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("a prefix bound needs a string")
		}
		return s, nil
	case "set":
		if s, ok := arg.(string); ok {
			return []any{s}, nil
		}
		n, err := bound.Int(arg)
		if err != nil {
			return nil, fmt.Errorf("only a string or an integer can be pinned")
		}
		return []any{n}, nil
	}
	return nil, fmt.Errorf("a %s bound cannot be pinned to an argument", t)
}
