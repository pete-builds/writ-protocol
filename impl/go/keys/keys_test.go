package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestDIDRoundTrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	did := id.DID()
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("Ed25519 did:key must start with did:key:z6Mk, got %s", did)
	}
	pub, err := PublicKeyFromDID(did)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, id.Pub) {
		t.Fatal("public key did not round-trip through did:key")
	}
}

// Known vector from the W3C did:key specification example: Ed25519 public key
// 2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6 encodes as
// did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.
func TestKnownVector(t *testing.T) {
	pubHex := "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6"
	pub, _ := hex.DecodeString(pubHex)
	want := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if got := DIDFromPublicKey(pub); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	back, err := PublicKeyFromDID(want)
	if err != nil || !bytes.Equal(back, pub) {
		t.Fatalf("decode mismatch: %v", err)
	}
}

// Base58 vectors from the Bitcoin Core test suite (base58_encode_decode.json).
func TestBase58Vectors(t *testing.T) {
	cases := map[string]string{
		"":       "",
		"61":     "2g",
		"626262": "a3gV",
		"636363": "aPEr",
		"73696d706c792061206c6f6e6720737472696e67":           "2cFupjhnEsSn59qHXstmK2ffpLv2",
		"00eb15231dfceb60925886b67d065299925915aeb172c06647": "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
		"00000000000000000000":                               "1111111111",
	}
	for h, want := range cases {
		b, _ := hex.DecodeString(h)
		if got := base58Encode(b); got != want {
			t.Errorf("encode %s: got %s want %s", h, got, want)
		}
		dec, err := base58Decode(want)
		if err != nil || hex.EncodeToString(dec) != h {
			t.Errorf("decode %s: got %x err %v", want, dec, err)
		}
	}
}

func TestSignVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	id, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"a":1}`)
	sig := id.Sign(msg)
	if err := Verify(id.DID(), msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify(id.DID(), []byte(`{"a":2}`), sig); err == nil {
		t.Fatal("tampered message verified")
	}
	other, _ := Generate()
	if err := Verify(other.DID(), msg, sig); err == nil {
		t.Fatal("wrong key verified")
	}
	sig[0] ^= 1
	if err := Verify(id.DID(), msg, sig); err == nil {
		t.Fatal("tampered signature verified")
	}
}

func TestRejectsOtherDIDs(t *testing.T) {
	bad := []string{
		"did:web:example.com",
		"did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme", // secp256k1
		"did:key:z6Mk",
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooW0", // invalid char
		"",
	}
	for _, d := range bad {
		if _, err := PublicKeyFromDID(d); err == nil {
			t.Errorf("%q: expected rejection", d)
		}
	}
}

// The fourteen encodings of the eight small-order points (spec 1.3), written
// out in full rather than derived from the masked table in keys.go, so a slip
// in that table or in the masking fails here. Derived from the curve equation
// with a decoder that, like crypto/ed25519 and OpenSSL, accepts y >= p and x = 0
// with the sign bit set.
var smallOrderEncodings = []string{
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 4, y = p
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 4, y = p
	"0100000000000000000000000000000000000000000000000000000000000000", // identity
	"0100000000000000000000000000000000000000000000000000000000000080", // identity, x = -0
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // identity, y = p+1
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // identity, y = p+1, x = -0
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 2, x = -0
}

// forgedSig is R = identity, S = 0: it verifies under the identity key for
// every message, since [0]B = identity + [k]identity for any k.
var forgedSig = append([]byte{1}, make([]byte, 63)...)

func TestSmallOrderKeysRejected(t *testing.T) {
	for _, h := range smallOrderEncodings {
		pub, _ := hex.DecodeString(h)
		did := DIDFromPublicKey(pub)
		if _, err := PublicKeyFromDID(did); err == nil {
			t.Errorf("%s (%s): small-order key accepted", h, did)
		}
	}
	// The did:key from the 2026-09-30 report, accepted on 85a17fc.
	const identity = "did:key:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj"
	for _, msg := range []string{"writ/1\x00{}", "tally/1\x00anything at all"} {
		if err := Verify(identity, []byte(msg), forgedSig); err == nil {
			t.Errorf("forged signature verified under the identity key over %q", msg)
		}
	}
	// Control: the same check leaves ordinary keys and signatures alone.
	id, _ := FromSeed(bytes.Repeat([]byte{7}, 32))
	if _, err := PublicKeyFromDID(id.DID()); err != nil {
		t.Fatalf("ordinary key refused: %v", err)
	}
	if err := Verify(id.DID(), []byte("m"), id.Sign([]byte("m"))); err != nil {
		t.Fatalf("ordinary signature refused: %v", err)
	}
	if err := Verify(id.DID(), []byte("m"), forgedSig); err == nil {
		t.Fatal("forged signature verified under an ordinary key")
	}
	// A near miss of the identity encoding is not small order.
	near, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000001")
	if _, err := PublicKeyFromDID(DIDFromPublicKey(near)); err != nil {
		t.Fatalf("near miss of the identity refused: %v", err)
	}
}

// signWithIdentityR signs msg as id with r = 0, so R is the identity point:
// S = k*a mod L. A cofactorless verify accepts it, since [S]B = [k]A = R + [k]A.
func signWithIdentityR(id *Identity, msg []byte) []byte {
	h := sha512.Sum512(id.Priv.Seed())
	s := h[:32]
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	a := new(big.Int).SetBytes(reversed(s))
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	R := append([]byte{1}, make([]byte, 31)...)
	kh := sha512.Sum512(append(append(append([]byte{}, R...), id.Pub...), msg...))
	k := new(big.Int).Mod(new(big.Int).SetBytes(reversed(kh[:])), L)
	S := make([]byte, 32)
	new(big.Int).Mod(new(big.Int).Mul(k, a), L).FillBytes(S)
	return append(R, reversed(S)...)
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func TestSmallOrderRRejected(t *testing.T) {
	id, _ := FromSeed(bytes.Repeat([]byte{7}, 32))
	msg := []byte("tally/1\x00crafted by the key holder")
	sig := signWithIdentityR(id, msg)
	// Control: the signature is genuine under the cofactorless equation.
	if !ed25519.Verify(id.Pub, msg, sig) {
		t.Fatal("crafted signature does not verify under crypto/ed25519; the test proves nothing")
	}
	if err := Verify(id.DID(), msg, sig); err == nil {
		t.Fatal("signature with a small-order R accepted")
	}
}
