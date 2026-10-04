// Package keys provides Ed25519 identities encoded as did:key identifiers and
// detached signatures over canonical bytes. It uses only the Go standard
// library. The did:key method (W3C CCG) for Ed25519 is: "did:key:z" followed by
// the base58btc encoding of the two-byte multicodec prefix 0xed 0x01 and the
// 32-byte public key. Every Ed25519 did:key therefore begins with "did:key:z6Mk".
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const didKeyPrefix = "did:key:z"

var multicodecEd25519Pub = []byte{0xed, 0x01}

// Identity is an Ed25519 key pair with its did:key identifier.
type Identity struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// Generate creates a fresh random identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Priv: priv, Pub: pub}, nil
}

// FromSeed derives a deterministic identity from a 32-byte seed. Used by tests
// and conformance vectors so signatures are reproducible.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keys: seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}, nil
}

// DID returns the did:key identifier of the public key.
func (id *Identity) DID() string { return DIDFromPublicKey(id.Pub) }

// Sign produces a detached Ed25519 signature over msg.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.Priv, msg) }

// DIDFromPublicKey encodes an Ed25519 public key as did:key.
func DIDFromPublicKey(pub ed25519.PublicKey) string {
	buf := append(append([]byte{}, multicodecEd25519Pub...), pub...)
	return didKeyPrefix + base58Encode(buf)
}

// PublicKeyFromDID parses an Ed25519 did:key. Any other DID method or key
// type is rejected: v0.1 supports exactly one algorithm to avoid agility attacks.
// So is a small-order key (spec 1.3), under which anyone can sign anything.
func PublicKeyFromDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, errors.New("keys: not a did:key with base58btc encoding")
	}
	raw, err := base58Decode(did[len(didKeyPrefix):])
	if err != nil {
		return nil, err
	}
	if len(raw) != 2+ed25519.PublicKeySize || raw[0] != 0xed || raw[1] != 0x01 {
		return nil, errors.New("keys: did:key is not an Ed25519 public key")
	}
	if isSmallOrder(raw[2:]) {
		return nil, errors.New("keys: did:key is a small-order Ed25519 point")
	}
	return ed25519.PublicKey(raw[2:]), nil
}

// Verify checks a detached signature made by the holder of did over msg. A
// signature whose R is a small-order encoding is refused (spec 1.4): only a
// signer choosing r = 0 makes one, and libsodium rejects it where
// crypto/ed25519 would accept it.
func Verify(did string, msg, sig []byte) error {
	pub, err := PublicKeyFromDID(did)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || isSmallOrder(sig[:32]) || !ed25519.Verify(pub, msg, sig) {
		return errors.New("keys: signature verification failed")
	}
	return nil
}

// smallOrder holds, with the sign bit cleared, the seven y encodings of the
// eight points of order 1, 2, 4, and 8: 0, 1, the two order-8 values, p-1, p,
// and p+1 (spec 1.3). With either sign bit they are the fourteen 32-byte
// strings crypto/ed25519 decodes to such a point, the non-canonical y >= p
// and x = 0 with the sign bit set included. libsodium's has_small_order
// table holds the same seven.
var smallOrder = [7][32]byte{
	{},
	{0x01},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// isSmallOrder reports whether a 32-byte point encoding is one of the fourteen
// that decode to a point of small order.
func isSmallOrder(enc []byte) bool {
	if len(enc) != 32 {
		return false
	}
	for _, s := range smallOrder {
		if bytes.Equal(enc[:31], s[:31]) && enc[31]&0x7f == s[31] {
			return true
		}
	}
	return false
}

const b58alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, b58alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	x := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(b58alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("keys: invalid base58 character %q", c)
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(idx)))
	}
	raw := x.Bytes()
	zeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		zeros++
	}
	return append(make([]byte, zeros), raw...), nil
}
