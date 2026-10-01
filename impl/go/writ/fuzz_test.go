package writ

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"writproto/keys"
	"writproto/wire"
)

// FuzzVerifyTally feeds arbitrary objects to the tally checker as the answer
// to one fixed call. Whatever it is given, it must not panic, must give the
// same verdict twice, must name a reason for anything but Valid, and may say
// Valid only for a tally that names this call and writ and carries the
// executor's signature. The seeds are real tallies: ok with a body and
// usage, failed, and refused.
func FuzzVerifyTally(f *testing.F) {
	saved := Nonce
	n := 0
	Nonce = func() string { n++; return wire.B64.EncodeToString([]byte(fmt.Sprintf("fuzz-nonce-%05d", n))) }
	defer func() { Nonce = saved }()
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	B, _ := keys.FromSeed(bytes.Repeat([]byte{2}, 32))
	W, err := Issue(A, B.DID(), map[string]any{
		"act":    map[string]any{"t": "prefix", "v": "travel"},
		"amount": map[string]any{"t": "max", "v": 60000},
		"uses":   map[string]any{"t": "count", "v": 1},
	}, 1<<40, nil)
	if err != nil {
		f.Fatal(err)
	}
	K, err := NewCall(A, []*Writ{W}, "travel/book", map[string]any{"amount": 500})
	if err != nil {
		f.Fatal(err)
	}
	seed := func(in TallyInput) {
		in.Call = K
		tl, _, err := NewTally(B, in)
		if err != nil {
			f.Fatal(err)
		}
		b, _ := json.Marshal(tl.Raw)
		f.Add(b)
	}
	seed(TallyInput{Acc: 1 << 30, St: "ok", Res: map[string]any{"booked": true}, Used: map[string]int64{"amount": 500, "uses": 1}})
	seed(TallyInput{Acc: 1 << 30, St: "failed", ErrCode: "app/sold_out"})
	seed(TallyInput{Acc: 1 << 30, St: "failed", ErrCode: "count_exhausted"})
	f.Fuzz(func(t *testing.T, raw []byte) {
		obj, err := wire.Decode(raw)
		if err != nil {
			return
		}
		v, T, err := VerifyTally(W, K, obj, nil)
		v2, _, _ := VerifyTally(W, K, obj, nil)
		if v != v2 {
			t.Fatalf("two verdicts for one tally: %s then %s", v, v2)
		}
		if v != Valid {
			if err == nil {
				t.Fatalf("verdict %s with no reason", v)
			}
			return
		}
		if T == nil || T.Call != K.ID || T.Writ != W.ID {
			t.Fatalf("valid tally does not name this call and writ: %+v", T)
		}
		if err := wire.VerifySig(obj, W.Hld); err != nil {
			t.Fatalf("valid tally without the executor's signature: %v", err)
		}
	})
}
