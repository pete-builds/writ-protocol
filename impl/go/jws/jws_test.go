package jws

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"writproto/exec"
	"writproto/jcs"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

func TestRoundTripKeepsTheObjectAndItsSignature(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	C, _ := keys.FromSeed(bytes.Repeat([]byte{3}, 32))
	w, _ := writ.Issue(A, C.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "x"}}, 1<<40, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x/y", map[string]any{"n": 1})
	e := exec.New(C, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	e.Handle = func(ctx context.Context, _ *writ.Call) exec.Result {
		return exec.Result{Res: map[string]any{"ok": true}}
	}
	rep, _ := e.Execute(context.Background(), k.Raw)
	for _, c := range []struct {
		obj    wire.Object
		signer *keys.Identity
	}{{w.Raw, A}, {k.Raw, A}, {rep.Tally, C}} {
		compact, err := Wrap(c.obj, c.signer)
		if err != nil {
			t.Fatal(err)
		}
		got, kid, err := Unwrap(compact)
		if err != nil || kid != c.signer.DID() {
			t.Fatalf("unwrap %s: %v %s", c.obj["typ"], err, kid)
		}
		x, _ := jcs.Marshal(map[string]any(got))
		y, _ := jcs.Marshal(map[string]any(c.obj))
		if !bytes.Equal(x, y) {
			t.Fatalf("%s: the object changed through the envelope", c.obj["typ"])
		}
	}
	// The inner object still verifies as Writ, unchanged.
	compact, _ := Wrap(rep.Tally, C)
	inner, _, _ := Unwrap(compact)
	if v, _, err := writ.VerifyTally(w, k, inner, rep.Res); v != writ.Valid {
		t.Fatalf("the unwrapped tally: %v %v", v, err)
	}
}

func TestRejects(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{9}, 32))
	w, _ := writ.Issue(A, S.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "x"}}, 1<<40, nil)
	good, _ := Wrap(w.Raw, A)
	p := strings.Split(good, ".")
	enc := func(s string) string { return b64.EncodeToString([]byte(s)) }
	tamperedPayload := b64.EncodeToString(bytes.Replace(mustDecode(p[1]), []byte(`"x"`), []byte(`"z"`), 1))
	sForged, _ := Wrap(w.Raw, S)
	cases := map[string]string{
		"payload changed after signing":   p[0] + "." + tamperedPayload + "." + p[2],
		"alg none":                        enc(`{"alg":"none","typ":"writ-writ+jws","kid":"`+A.DID()+`"}`) + "." + p[1] + ".",
		"alg HS256":                       enc(`{"alg":"HS256","typ":"writ-writ+jws","kid":"`+A.DID()+`"}`) + "." + p[1] + "." + p[2],
		"an extra header member":          enc(`{"alg":"EdDSA","typ":"writ-writ+jws","kid":"`+A.DID()+`","jku":"https://evil"}`) + "." + p[1] + "." + p[2],
		"kid swapped to another key":      strings.Split(sForged, ".")[0] + "." + p[1] + "." + p[2],
		"typ naming another type, signed": signed(A, `{"alg":"EdDSA","typ":"writ-call+jws","kid":"`+A.DID()+`"}`, p[1]),
		"two segments":                    p[0] + "." + p[1],
	}
	for name, compact := range cases {
		if _, _, err := Unwrap(compact); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Wrap(wire.Object{"typ": "note"}, A); err == nil {
		t.Error("wrapped something that is not a Writ object")
	}
}

// signed builds a compact JWS with a correct signature over any header, so a
// case is rejected by the check it names and not by a broken signature.
func signed(k *keys.Identity, header, payload string) string {
	input := b64.EncodeToString([]byte(header)) + "." + payload
	return input + "." + b64.EncodeToString(k.Sign([]byte(input)))
}

func mustDecode(s string) []byte {
	b, _ := b64.DecodeString(s)
	return b
}
