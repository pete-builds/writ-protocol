// Package bound implements the v0.1 bound registry: five constraint types with
// fixed, mechanical comparison semantics. A bound is {"t": type, "v": value}.
//
//	type    value                    child narrows parent when         call value satisfies when
//	max     integer                  child <= parent                   arg <= v
//	count   integer                  child <= parent                   executions under leaf < v (executor state)
//	prefix  string                   child starts with parent          arg starts with v
//	set     array of string|integer  child is a subset of parent       arg is a member of v
//	window  [lo, hi] integers        parent.lo <= child.lo, child.hi <= parent.hi   lo <= arg <= hi
//
// Any other type is rejected, never ignored: a bound a verifier cannot compare
// is a bound it cannot enforce.
package bound

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Error classes, so callers can map to protocol reason codes: a shape error
// (wrong JSON type or member set) is malformed, a value error (negative max,
// inverted window, duplicate set element) is noncanonical, an unknown type is
// unknown_bound.
var (
	ErrShape       = errors.New("bound: malformed")
	ErrValue       = errors.New("bound: invalid value")
	ErrUnknownType = errors.New("bound: unknown type")
)

func shape(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrShape}, a...)...)
}
func value(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrValue}, a...)...)
}

// Bound is one parsed constraint.
type Bound struct {
	T string
	// Exactly one of the following is set, according to T.
	Int int64
	Str string
	Set []Elem
	Lo  int64
	Hi  int64
	Raw any // the original decoded value, for re-serialization
}

// Elem is a set member: a string or an integer, never both.
type Elem struct {
	IsInt bool
	Int   int64
	Str   string
}

func (e Elem) String() string {
	if e.IsInt {
		return fmt.Sprintf("%d", e.Int)
	}
	return fmt.Sprintf("%q", e.Str)
}

// Types is the closed registry for protocol version 1.
var Types = []string{"max", "count", "prefix", "set", "window"}

const maxSafe = 1<<53 - 1

// Parse decodes a bound object as produced by encoding/json with UseNumber
// (map[string]any with json.Number for numbers). It rejects unknown types,
// wrong value shapes, extra members, and non-safe integers.
func Parse(v any) (Bound, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Bound{}, shape("not an object")
	}
	if len(m) != 2 {
		return Bound{}, shape("must have exactly the members t and v")
	}
	t, ok := m["t"].(string)
	if !ok {
		return Bound{}, shape("t must be a string")
	}
	val, ok := m["v"]
	if !ok {
		return Bound{}, shape("missing v")
	}
	b := Bound{T: t, Raw: val}
	switch t {
	case "max", "count":
		n, err := toInt(val)
		if err != nil {
			return Bound{}, shape("%s: %v", t, err)
		}
		if n < 0 {
			return Bound{}, value("%s: value must be non-negative", t)
		}
		b.Int = n
	case "prefix":
		s, ok := val.(string)
		if !ok {
			return Bound{}, shape("prefix: value must be a string")
		}
		b.Str = s
	case "set":
		arr, ok := val.([]any)
		if !ok {
			return Bound{}, shape("set: value must be an array")
		}
		seen := map[string]bool{}
		for _, e := range arr {
			el, err := toElem(e)
			if err != nil {
				return Bound{}, shape("set: %v", err)
			}
			k := el.String()
			if seen[k] {
				return Bound{}, value("set: duplicate element %s", k)
			}
			seen[k] = true
			b.Set = append(b.Set, el)
		}
	case "window":
		arr, ok := val.([]any)
		if !ok || len(arr) != 2 {
			return Bound{}, shape("window: value must be [lo, hi]")
		}
		lo, err1 := toInt(arr[0])
		hi, err2 := toInt(arr[1])
		if err1 != nil || err2 != nil {
			return Bound{}, shape("window: lo and hi must be integers")
		}
		if lo > hi {
			return Bound{}, value("window: lo exceeds hi")
		}
		b.Lo, b.Hi = lo, hi
	default:
		return Bound{}, fmt.Errorf("%w %q", ErrUnknownType, t)
	}
	return b, nil
}

// Narrows reports whether child is at most as permissive as parent. Types must
// match exactly.
func Narrows(child, parent Bound) error {
	if child.T != parent.T {
		return fmt.Errorf("bound: type changed from %s to %s", parent.T, child.T)
	}
	switch child.T {
	case "max", "count":
		if child.Int > parent.Int {
			return fmt.Errorf("bound %s: child %d exceeds parent %d", child.T, child.Int, parent.Int)
		}
	case "prefix":
		if !strings.HasPrefix(child.Str, parent.Str) {
			return fmt.Errorf("bound prefix: child %q does not extend parent %q", child.Str, parent.Str)
		}
	case "set":
		for _, e := range child.Set {
			if !contains(parent.Set, e) {
				return fmt.Errorf("bound set: child element %s not in parent", e)
			}
		}
	case "window":
		if child.Lo < parent.Lo || child.Hi > parent.Hi {
			return fmt.Errorf("bound window: child [%d,%d] not inside parent [%d,%d]", child.Lo, child.Hi, parent.Lo, parent.Hi)
		}
	default:
		return fmt.Errorf("bound: unknown type %q", child.T)
	}
	return nil
}

// Satisfies reports whether a call argument value is permitted by the bound.
// count is not checked here: it is consumed by executor state, not by an
// argument value.
func Satisfies(b Bound, arg any) error {
	switch b.T {
	case "max":
		n, err := toInt(arg)
		if err != nil {
			return fmt.Errorf("bound max: argument %w", err)
		}
		if n < 0 || n > b.Int {
			return fmt.Errorf("bound max: %d exceeds %d", n, b.Int)
		}
	case "count":
		return errors.New("bound count: not satisfiable by an argument; consumed by the executor")
	case "prefix":
		s, ok := arg.(string)
		if !ok || !strings.HasPrefix(s, b.Str) {
			return fmt.Errorf("bound prefix: argument does not start with %q", b.Str)
		}
	case "set":
		el, err := toElem(arg)
		if err != nil || !contains(b.Set, el) {
			return errors.New("bound set: argument not a member")
		}
	case "window":
		n, err := toInt(arg)
		if err != nil || n < b.Lo || n > b.Hi {
			return fmt.Errorf("bound window: argument outside [%d,%d]", b.Lo, b.Hi)
		}
	default:
		return fmt.Errorf("bound: unknown type %q", b.T)
	}
	return nil
}

func contains(set []Elem, e Elem) bool {
	for _, s := range set {
		if s == e {
			return true
		}
	}
	return false
}

func toElem(v any) (Elem, error) {
	switch x := v.(type) {
	case string:
		return Elem{Str: x}, nil
	case json.Number, int, int64, float64:
		n, err := toInt(x)
		if err != nil {
			return Elem{}, err
		}
		return Elem{IsInt: true, Int: n}, nil
	}
	return Elem{}, errors.New("element must be a string or an integer")
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return 0, errors.New("must be an integer")
		}
		if n > maxSafe || n < -maxSafe {
			return 0, errors.New("integer outside the safe range")
		}
		return n, nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case float64:
		if x != float64(int64(x)) {
			return 0, errors.New("must be an integer")
		}
		return int64(x), nil
	}
	return 0, errors.New("must be an integer")
}
