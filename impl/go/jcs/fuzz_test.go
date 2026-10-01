package jcs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// FuzzCanonicalize checks that whatever Canonicalize accepts, it maps to a
// fixed point: the output is valid UTF-8, passes Strict, and canonicalizes
// to itself. The seeds are the corpus's canonicalize vectors, raw and
// canonical, so mutation starts from every edge case the vectors pin.
func FuzzCanonicalize(f *testing.F) {
	for _, s := range []string{`{}`, `[]`, `0`, `"é"`, `{"b":1,"a":[2,{"d":null,"c":true}]}`, `{"a":1,"a":2}`, `1.5`, `"\ud800"`} {
		f.Add([]byte(s))
	}
	files, _ := filepath.Glob("../../../conformance/vectors/*_canonicalize_*.json")
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var v struct {
			Input struct {
				Raw       string `json:"raw"`
				Canonical string `json:"canonical"`
			} `json:"input"`
		}
		if json.Unmarshal(b, &v) == nil {
			f.Add([]byte(v.Input.Raw))
			if v.Input.Canonical != "" {
				f.Add([]byte(v.Input.Canonical))
			}
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := Canonicalize(raw)
		if err != nil {
			return
		}
		if !utf8.Valid(out) {
			t.Fatalf("canonical form of %q is not UTF-8: %q", raw, out)
		}
		if err := Strict(out); err != nil {
			t.Fatalf("canonical form %q fails Strict: %v", out, err)
		}
		again, err := Canonicalize(out)
		if err != nil {
			t.Fatalf("canonical form %q of %q is rejected: %v", out, raw, err)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not a fixed point: %q canonicalizes to %q", out, again)
		}
	})
}
