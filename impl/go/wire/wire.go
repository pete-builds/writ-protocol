// Package wire implements the signed-object envelope shared by every protocol
// object: a JSON object whose "sig" member is a base64url (no padding) Ed25519
// signature over the JCS-canonical bytes of the object with "sig" removed. The
// identifier of a signed object is the base64url SHA-256 of the canonical
// bytes of the WHOLE object, sig included, so a re-signed copy with identical
// fields has a different identity.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"writproto/jcs"
	"writproto/keys"
)

// Object is a decoded JSON object. Numbers are json.Number (decode with
// UseNumber via Decode below).
type Object = map[string]any

// B64 is the one base64 alphabet the protocol uses: URL-safe, no padding.
var B64 = base64.RawURLEncoding

// Decode parses one JSON object with integer-preserving numbers and rejects
// trailing data, duplicate keys at the top level, and non-object values.
func Decode(raw []byte) (Object, error) {
	if err := jcs.Strict(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("wire: parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("wire: trailing data")
	}
	obj, ok := v.(Object)
	if !ok {
		return nil, errors.New("wire: not a JSON object")
	}
	return obj, nil
}

// Canonical returns the JCS bytes of obj.
func Canonical(obj Object) ([]byte, error) { return jcs.Marshal(obj) }

// SigningInput builds the bytes that are signed: "<typ>/<v>" 0x00 canonical(obj without sig).
func SigningInput(obj Object) ([]byte, error) {
	typ, _ := obj["typ"].(string)
	v := fmt.Sprint(obj["v"])
	unsigned := make(Object, len(obj))
	for k, val := range obj {
		if k != "sig" {
			unsigned[k] = val
		}
	}
	c, err := jcs.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(typ)+len(v)+2+len(c))
	out = append(out, typ...)
	out = append(out, '/')
	out = append(out, v...)
	out = append(out, 0)
	out = append(out, c...)
	return out, nil
}

// Sign sets obj["sig"] to the Ed25519 signature over SigningInput(obj).
func Sign(obj Object, id *keys.Identity) error {
	delete(obj, "sig")
	msg, err := SigningInput(obj)
	if err != nil {
		return err
	}
	obj["sig"] = B64.EncodeToString(id.Sign(msg))
	return nil
}

// VerifySig checks obj["sig"] against the did:key given.
func VerifySig(obj Object, did string) error {
	sigStr, ok := obj["sig"].(string)
	if !ok {
		return errors.New("wire: missing sig")
	}
	sig, err := B64.DecodeString(sigStr)
	if err != nil {
		return errors.New("wire: sig is not base64url")
	}
	msg, err := SigningInput(obj)
	if err != nil {
		return err
	}
	return keys.Verify(did, msg, sig)
}

// Hash returns the identifier of a signed object.
func Hash(obj Object) (string, error) {
	c, err := jcs.Marshal(obj)
	if err != nil {
		return "", err
	}
	return HashBytes(c), nil
}

// HashBytes returns base64url(SHA-256(b)) without padding: 43 characters.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return B64.EncodeToString(sum[:])
}

// Clone deep-copies an object by canonical round trip, which also validates it.
func Clone(obj Object) (Object, error) {
	c, err := jcs.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return Decode(c)
}
