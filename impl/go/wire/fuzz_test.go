package wire

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecode checks that an object Decode accepts and Canonical can encode
// decodes again to the same canonical bytes and the same identity, and that
// building the signing input and checking a signature never panic on it.
// The seeds are every object in the conformance corpus.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{}`, `{"typ":"writ","v":1,"sig":"AA"}`, `{"a":1,"a":2}`, `{"v":1.0}`, `[]`} {
		f.Add([]byte(s))
	}
	files, _ := filepath.Glob("../../../conformance/vectors/*.json")
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		obj, err := Decode(raw)
		if err != nil {
			return
		}
		c, err := Canonical(obj)
		if err != nil {
			return // decodable but not canonicalizable, such as a float
		}
		obj2, err := Decode(c)
		if err != nil {
			t.Fatalf("canonical form %q of an accepted object is rejected: %v", c, err)
		}
		c2, err := Canonical(obj2)
		if err != nil || !bytes.Equal(c, c2) {
			t.Fatalf("canonical form is not stable: %q then %q (%v)", c, c2, err)
		}
		h1, err1 := Hash(obj)
		h2, err2 := Hash(obj2)
		if err1 != nil || err2 != nil || h1 != h2 {
			t.Fatalf("identity changed across a round trip: %s %s (%v, %v)", h1, h2, err1, err2)
		}
		_, _ = SigningInput(obj)
		if iss, ok := obj["iss"].(string); ok {
			_ = VerifySig(obj, iss)
		}
	})
}
