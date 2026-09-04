package keys

import (
	"bytes"
	"encoding/hex"
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
