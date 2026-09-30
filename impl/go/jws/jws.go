// Package jws is the JWS profile of spec Appendix D: a Writ object carried as
// the payload of an RFC 7515 JWS compact serialization, so tooling and
// standards bodies that expect JWS can handle Writ objects. The payload is the
// complete signed object, its own sig included, in canonical form; the JWS
// signature is a second signature over it by the same key. A Writ verifier
// ignores the envelope and checks the object as always, so the profile adds
// nothing a verifier needs and removes nothing it checks.
package jws

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"writproto/jcs"
	"writproto/keys"
	"writproto/wire"
)

var b64 = base64.RawURLEncoding

// header is the protected header. alg is fixed; there is no algorithm choice
// to attack (spec 12, "One algorithm").
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Wrap returns obj as a JWS compact serialization signed by signer, whose
// did:key becomes kid. obj must already be a signed Writ object.
func Wrap(obj wire.Object, signer *keys.Identity) (string, error) {
	typ, _ := obj["typ"].(string)
	switch typ {
	case "writ", "call", "tally", "revoke":
	default:
		return "", errors.New("jws: not a Writ object")
	}
	payload, err := jcs.Marshal(map[string]any(obj))
	if err != nil {
		return "", err
	}
	h, _ := json.Marshal(header{Alg: "EdDSA", Typ: "writ-" + typ + "+jws", Kid: signer.DID()})
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(payload)
	return input + "." + b64.EncodeToString(signer.Sign([]byte(input))), nil
}

// Unwrap verifies the JWS signature under the key its kid names and returns
// the Writ object and that key. It does not verify the object: do that with
// the Writ verifier, which is authoritative, and check that kid is the key
// that signed the object (iss for a writ or revoke, from for a call, the
// executor for a tally).
func Unwrap(compact string) (wire.Object, string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, "", errors.New("jws: not a compact serialization")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, "", errors.New("jws: header is not base64url")
	}
	var h header
	dec := json.NewDecoder(strings.NewReader(string(hb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, "", errors.New("jws: header has members outside the profile")
	}
	if h.Alg != "EdDSA" || !strings.HasPrefix(h.Typ, "writ-") || !strings.HasSuffix(h.Typ, "+jws") {
		return nil, "", errors.New("jws: alg must be EdDSA and typ writ-<type>+jws")
	}
	pub, err := keys.PublicKeyFromDID(h.Kid)
	if err != nil {
		return nil, "", errors.New("jws: kid is not an Ed25519 did:key")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, "", errors.New("jws: bad signature")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, "", errors.New("jws: payload is not base64url")
	}
	obj, err := wire.Decode(payload)
	if err != nil {
		return nil, "", err
	}
	if typ, _ := obj["typ"].(string); h.Typ != "writ-"+typ+"+jws" {
		return nil, "", errors.New("jws: typ does not match the object")
	}
	return obj, h.Kid, nil
}
