package jcs

import "errors"

// MaxDepth is the nesting limit of spec section 1.1 rule 7: arrays and
// objects nest at most 64 levels, the outermost value being level 1.
const MaxDepth = 64

// ErrTooDeep is returned when a value nests deeper than MaxDepth. It maps to
// reason too_large, not noncanonical, and is found before any other rule of
// section 1.1.
var ErrTooDeep = errors.New("jcs: arrays and objects nest deeper than 64 levels")

// CheckDepth scans raw JSON text and reports ErrTooDeep when its arrays and
// objects nest deeper than MaxDepth, without building any value. Brackets
// inside strings are skipped; the scan needs no other validity, so it can run
// before every other check.
func CheckDepth(raw []byte) error {
	depth := 0
	inStr := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '[', '{':
			depth++
			if depth > MaxDepth {
				return ErrTooDeep
			}
		case ']', '}':
			depth--
		}
	}
	return nil
}

// TooDeep reports whether an already decoded value nests deeper than
// MaxDepth. It stops descending at the limit, so its cost is bounded by the
// part of the value within the limit.
func TooDeep(v any) bool { return tooDeep(v, 1) }

func tooDeep(v any, level int) bool {
	switch x := v.(type) {
	case map[string]any:
		if level > MaxDepth {
			return true
		}
		for _, e := range x {
			if tooDeep(e, level+1) {
				return true
			}
		}
	case []any:
		if level > MaxDepth {
			return true
		}
		for _, e := range x {
			if tooDeep(e, level+1) {
				return true
			}
		}
	}
	return false
}
