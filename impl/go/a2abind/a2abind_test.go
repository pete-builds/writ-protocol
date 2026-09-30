package a2abind

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"writproto/exec"
	"writproto/keys"
	"writproto/writ"
)

// An A2A exchange at the message level: the call rides in a data part (or in
// metadata), the executor answers, the tally rides back as the last artifact,
// and the client verifies it offline; a cancel carries a revoke.
func TestA2ARoundTrip(t *testing.T) {
	A, _ := keys.FromSeed(bytes.Repeat([]byte{1}, 32))
	S, _ := keys.FromSeed(bytes.Repeat([]byte{7}, 32))
	e := exec.New(S, nil)
	e.AcceptRoot = func(d string) bool { return d == A.DID() }
	e.Handle = func(ctx context.Context, k *writ.Call) exec.Result {
		return exec.Result{Res: map[string]any{"booked": k.Args["city"]}}
	}
	w, _ := writ.Issue(A, S.DID(), map[string]any{"act": map[string]any{"t": "prefix", "v": "travel"}}, 1<<40, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "travel/book", map[string]any{"city": "Ithaca"})

	for _, form := range []string{FormPart, FormMetaKV} {
		msg := map[string]any{"role": "user", "parts": []any{map[string]any{"kind": "text", "text": "book it"}}}
		if form == FormPart {
			msg["parts"] = append(msg["parts"].([]any), CallPart(k.Raw))
		} else {
			msg["metadata"] = map[string]any{CallKey: k.Raw}
		}
		msg = viaJSON(t, msg)
		obj, got, err := CallFrom(msg)
		if err != nil || got != form {
			t.Fatalf("%s: %v %s", form, err, got)
		}
		rep, rej := e.Execute(context.Background(), obj)
		if rej != nil {
			t.Fatal(rej)
		}
		task := viaJSON(t, map[string]any{"artifacts": []any{
			map[string]any{"artifactId": "a1", "parts": []any{map[string]any{"kind": "text", "text": "booked"}}},
			TallyArtifact("t1", rep.Tally),
		}})
		tallyObj, err := TallyFrom(task["artifacts"].([]any))
		if err != nil {
			t.Fatal(err)
		}
		if v, tl, err := writ.VerifyTally(w, k, tallyObj, rep.Res); v != writ.Valid || tl.St != "ok" {
			t.Fatalf("%s: tally %v %v", form, v, err)
		}
		meta, _ := StatusMetadata(tallyObj)
		if meta[TallyKey] == "" {
			t.Fatal("no tally identity for the status message")
		}
	}
	if _, _, err := CallFrom(map[string]any{"parts": []any{}}); err != ErrNoCall {
		t.Fatalf("a message with no call: %v", err)
	}
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w})
	cancel := viaJSON(t, map[string]any{"metadata": map[string]any{RevokeKey: rv.Raw}})
	obj, ok, err := RevokeFrom(cancel)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, rej := e.Revoke(obj); rej != nil {
		t.Fatal(rej)
	}
	if card := CardExtension(S.DID(), []string{"act"}, 6); card["uri"] != ExtURI {
		t.Fatal(card)
	}
}

func viaJSON(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
