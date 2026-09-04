package wire

import (
	"bytes"
	"testing"

	"writproto/keys"
)

func TestSignVerifyHash(t *testing.T) {
	id, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	obj, err := Decode([]byte(`{"v":1,"typ":"writ","b":{"y":2,"x":1},"a":[1,"s"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(obj, id); err != nil {
		t.Fatal(err)
	}
	if err := VerifySig(obj, id.DID()); err != nil {
		t.Fatal(err)
	}
	h1, _ := Hash(obj)
	if len(h1) != 43 {
		t.Fatalf("hash length %d", len(h1))
	}
	// Re-encoding with different whitespace and key order must verify and hash identically.
	c, _ := Canonical(obj)
	reordered := []byte(`{ "sig": "` + obj["sig"].(string) + `", "a":[1,"s"], "b":{"x":1,"y":2}, "typ":"writ", "v":1 }`)
	obj2, _ := Decode(reordered)
	if err := VerifySig(obj2, id.DID()); err != nil {
		t.Fatal("reordered object failed to verify:", err)
	}
	h2, _ := Hash(obj2)
	if h1 != h2 {
		t.Fatal("hash differs across equivalent encodings")
	}
	c2, _ := Canonical(obj2)
	if !bytes.Equal(c, c2) {
		t.Fatal("canonical forms differ")
	}
	// Tamper.
	obj2["v"] = 2
	if err := VerifySig(obj2, id.DID()); err == nil {
		t.Fatal("tampered object verified")
	}
	// Wrong key.
	other, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	if err := VerifySig(obj, other.DID()); err == nil {
		t.Fatal("wrong key verified")
	}
	// Signature must be base64url without padding.
	obj["sig"] = obj["sig"].(string) + "="
	if err := VerifySig(obj, id.DID()); err == nil {
		t.Fatal("padded sig accepted")
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, s := range []string{`[]`, `1`, `{"a":1} {"b":2}`, `{"a":1.5}x`, ``} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestDeterministicSignature(t *testing.T) {
	id, _ := keys.FromSeed(bytes.Repeat([]byte{3}, 32))
	a, _ := Decode([]byte(`{"k":"v"}`))
	b, _ := Decode([]byte(`{"k":"v"}`))
	_ = Sign(a, id)
	_ = Sign(b, id)
	if a["sig"] != b["sig"] {
		t.Fatal("Ed25519 signatures must be deterministic")
	}
}
