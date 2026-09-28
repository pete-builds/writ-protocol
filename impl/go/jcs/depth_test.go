package jcs

import (
	"errors"
	"strings"
	"testing"
)

func nest(levels int) string {
	return strings.Repeat(`{"a":[`, levels/2) + strings.Repeat("[", levels%2) + "1" +
		strings.Repeat("]", levels%2) + strings.Repeat(`]}`, levels/2)
}

// Spec section 1.1 rule 7: 64 levels pass, 65 are too_large, and brackets
// inside strings do not count.
func TestNestingLimit(t *testing.T) {
	if err := CheckDepth([]byte(nest(64))); err != nil {
		t.Fatalf("64 levels: %v", err)
	}
	if err := CheckDepth([]byte(nest(65))); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("65 levels: got %v, want ErrTooDeep", err)
	}
	if err := CheckDepth([]byte(`["` + strings.Repeat(`[{\"`, 200) + `"]`)); err != nil {
		t.Fatalf("brackets inside a string counted: %v", err)
	}
	if _, err := Canonicalize([]byte(nest(65))); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("Canonicalize at 65 levels: got %v, want ErrTooDeep", err)
	}
	// Depth is found before any other rule: a float at level 70 is too deep,
	// not noncanonical.
	deepFloat := strings.Repeat("[", 70) + "1.5" + strings.Repeat("]", 70)
	if _, err := Canonicalize([]byte(deepFloat)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("deep float: got %v, want ErrTooDeep", err)
	}
	for _, levels := range []int{64, 65} {
		var built any = 1
		for i := 0; i < levels; i++ {
			built = []any{built}
		}
		if got := TooDeep(built); got != (levels > MaxDepth) {
			t.Errorf("TooDeep at %d levels: %v", levels, got)
		}
	}
}
