// Package keys provides Ed25519 identities encoded as did:key identifiers and
// detached signatures over canonical bytes. It uses only the Go standard
// library. The did:key method (W3C CCG) for Ed25519 is: "did:key:z" followed by
// the base58btc encoding of the two-byte multicodec prefix 0xed 0x01 and the
// 32-byte public key. Every Ed25519 did:key therefore begins with "did:key:z6Mk".
package keys

import (
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
	return ed25519.PublicKey(raw[2:]), nil
}

// Verify checks a detached signature made by the holder of did over msg.
func Verify(did string, msg, sig []byte) error {
	pub, err := PublicKeyFromDID(did)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return errors.New("keys: signature verification failed")
	}
	return nil
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
