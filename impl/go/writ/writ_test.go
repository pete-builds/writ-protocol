package writ

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"writproto/keys"
	"writproto/wire"
)

func seedID(t *testing.T, b byte) *keys.Identity {
	t.Helper()
	id, err := keys.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

const now = int64(1788400000)

type party struct {
	A, B, C *keys.Identity
	W1, W2  *Writ
}

func setup(t *testing.T) party {
	t.Helper()
	p := party{A: seedID(t, 1), B: seedID(t, 2), C: seedID(t, 3)}
	var err error
	p.W1, err = Issue(p.A, p.B.DID(), bnd(
		"act", "prefix", "travel",
		"amount", "max", 60000,
		"currency", "set", []any{"USD"},
		"uses", "count", 1,
		"fare", "set", []any{"refundable"},
		"date", "window", []any{20261015, 20261019},
	), now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.W2, err = Issue(p.B, p.C.DID(), bnd(
		"act", "prefix", "travel/charge",
		"amount", "max", 58900,
		"currency", "set", []any{"USD"},
		"uses", "count", 1,
		"fare", "set", []any{"refundable"},
		"date", "window", []any{20261015, 20261015},
	), now+1800, p.W1)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHappyPath(t *testing.T) {
	p := setup(t)
	if err := VerifyChain([]*Writ{p.W1, p.W2}); err != nil {
		t.Fatal(err)
	}
	// A calls B.
	kAB, err := NewCall(p.A, []*Writ{p.W1}, "travel/book",
		map[string]any{"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261015})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckForward(kAB); err != nil {
		t.Fatal(err)
	}
	// B calls C.
	kBC, err := NewCall(p.B, []*Writ{p.W1, p.W2}, "travel/charge",
		map[string]any{"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015, "pnr": "K7Q2ZD"})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckForward(kBC); err != nil {
		t.Fatal(err)
	}
	until := now + 86400
	tC, resC, err := NewTally(p.C, TallyInput{Call: kBC, Acc: now + 10, St: "ok",
		Res: map[string]any{"charge": "ch_8813"}, Used: map[string]int64{"amount": 58900}, RevUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := VerifyTally(p.W2, kBC, tC.Raw, resC); v != Valid {
		t.Fatalf("tally_C: %v %v", v, err)
	}
	tB, resB, err := NewTally(p.B, TallyInput{Call: kAB, Acc: now + 5, St: "ok",
		Res: map[string]any{"pnr": "K7Q2ZD", "charge": "ch_8813"}, Used: map[string]int64{"amount": 58900},
		RevUntil: &until, Sub: []*Tally{tC}, Wrt: []*Writ{p.W2}})
	if err != nil {
		t.Fatal(err)
	}
	v, parsed, err := VerifyTally(p.W1, kAB, tB.Raw, resB)
	if v != Valid {
		t.Fatalf("tally_B: %v %v", v, err)
	}
	if len(parsed.Sub) != 1 || parsed.Sub[0].Writ != p.W2.ID {
		t.Fatal("sub-tally not preserved")
	}
	// Round trip through bytes, as the wire would.
	raw, _ := json.Marshal(tB.Raw)
	obj, err := wire.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := VerifyTally(p.W1, kAB, obj, resB); v != Valid {
		t.Fatalf("after round trip: %v %v", v, err)
	}
}

func TestIssueRefusesWidening(t *testing.T) {
	p := setup(t)
	_, err := Issue(p.B, p.C.DID(), bnd(
		"act", "prefix", "travel/charge", "amount", "max", 65000, "currency", "set", []any{"USD"},
		"uses", "count", 1, "fare", "set", []any{"refundable"}, "date", "window", []any{20261015, 20261019},
	), now+1800, p.W1)
	if CodeOf(err) != NotNarrowed {
		t.Fatalf("want not_narrowed, got %v", err)
	}
}

// mutate re-signs a copy of w's raw object after applying f, as an attacker
// holding the signing key (or the legitimate issuer making a mistake) would.
func mutate(t *testing.T, w *Writ, signer *keys.Identity, f func(o wire.Object)) wire.Object {
	t.Helper()
	o, _ := wire.Clone(w.Raw)
	f(o)
	if signer != nil {
		o2, _ := normalize(o)
		if err := wire.Sign(o2, signer); err != nil {
			t.Fatal(err)
		}
		return o2
	}
	return o
}

func TestChainRejections(t *testing.T) {
	p := setup(t)
	D := seedID(t, 4)
	cases := []struct {
		name string
		f    func(o wire.Object)
		by   *keys.Identity
		want Reason
	}{
		{"widen max", func(o wire.Object) {
			o["bnd"].(map[string]any)["amount"] = map[string]any{"t": "max", "v": json.Number("60001")}
		}, p.B, NotNarrowed},
		{"drop bound", func(o wire.Object) { delete(o["bnd"].(map[string]any), "fare") }, p.B, NotNarrowed},
		{"retype bound", func(o wire.Object) {
			o["bnd"].(map[string]any)["amount"] = map[string]any{"t": "count", "v": json.Number("1")}
		}, p.B, NotNarrowed},
		{"unknown bound type", func(o wire.Object) { o["bnd"].(map[string]any)["x"] = map[string]any{"t": "glob", "v": "*"} }, p.B, UnknownBound},
		{"prv mismatch", func(o wire.Object) { o["prv"] = strings.Repeat("A", 43) }, p.B, ChainBroken},
		{"wrong issuer", func(o wire.Object) { o["iss"] = D.DID() }, D, ChainBroken},
		{"exp beyond parent", func(o wire.Object) { o["exp"] = json.Number("1788500000") }, p.B, NotNarrowed},
		{"prefix escapes segment", func(o wire.Object) { o["bnd"].(map[string]any)["act"] = map[string]any{"t": "prefix", "v": "travelx"} }, p.B, NotNarrowed},
		{"set widened", func(o wire.Object) {
			o["bnd"].(map[string]any)["currency"] = map[string]any{"t": "set", "v": []any{"USD", "EUR"}}
		}, p.B, NotNarrowed},
		{"window widened", func(o wire.Object) {
			o["bnd"].(map[string]any)["date"] = map[string]any{"t": "window", "v": []any{json.Number("20261014"), json.Number("20261015")}}
		}, p.B, NotNarrowed},
		{"tampered without resign", func(o wire.Object) { o["exp"] = json.Number("1788400001") }, nil, BadSignature},
		{"wrong typ", func(o wire.Object) { o["typ"] = "call" }, p.B, WrongType},
		{"wrong version", func(o wire.Object) { o["v"] = json.Number("2") }, p.B, UnsupportedVersion},
		{"unknown crit", func(o wire.Object) { o["crit"] = []any{"zap"} }, p.B, UnsupportedCritical},
		{"short nonce", func(o wire.Object) { o["nnc"] = "c2hvcnQ" }, p.B, Malformed},
		{"nonce bad length", func(o wire.Object) { o["nnc"] = "short" }, p.B, Noncanonical},
		{"bad key", func(o wire.Object) { o["hld"] = "did:web:example.com" }, p.B, BadKey},
		{"missing act", func(o wire.Object) { delete(o["bnd"].(map[string]any), "act") }, p.B, Malformed},
	}
	for _, c := range cases {
		obj := mutate(t, p.W2, c.by, c.f)
		w2, err := ParseWrit(obj)
		if err == nil {
			err = VerifyChain([]*Writ{p.W1, w2})
		}
		if CodeOf(err) != c.want {
			t.Errorf("%s: want %s, got %v", c.name, c.want, err)
		}
	}
}

func TestHldAndDepthBounds(t *testing.T) {
	p := setup(t)
	D := seedID(t, 4)
	w1, err := Issue(p.A, p.B.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{p.C.DID()}, "depth", "max", 1), now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Issue(p.B, D.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{}, "depth", "max", 0), now+3600, w1); CodeOf(err) != NotNarrowed {
		t.Fatalf("hld set: want not_narrowed, got %v", err)
	}
	w2, err := Issue(p.B, p.C.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{}, "depth", "max", 0), now+3600, w1)
	if err != nil {
		t.Fatal(err)
	}
	// Depth: w1 permits 1 below; a third link exceeds it. Build w3 under w2 with hld set [] is
	// already forbidden by hld; so relax w2's hld to test depth alone.
	w2b, _ := Issue(p.B, p.C.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{D.DID()}, "depth", "max", 1), now+3600, w1)
	if w2b != nil {
		t.Fatal("child hld set must be a subset of parent's")
	}
	_ = w2
	w1b, _ := Issue(p.A, p.B.DID(), bnd("act", "prefix", "travel", "depth", "max", 1), now+3600, nil)
	w2c, _ := Issue(p.B, p.C.DID(), bnd("act", "prefix", "travel", "depth", "max", 1), now+3600, w1b)
	w3, _ := Issue(p.C, D.DID(), bnd("act", "prefix", "travel", "depth", "max", 0), now+3600, w2c)
	if err := VerifyChain([]*Writ{w1b, w2c, w3}); CodeOf(err) != NotNarrowed {
		t.Fatalf("depth: want not_narrowed, got %v", err)
	}
}

func TestCallRejections(t *testing.T) {
	p := setup(t)
	D := seedID(t, 4)
	chain := []*Writ{p.W1, p.W2}
	good := map[string]any{"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015}
	cases := []struct {
		name string
		from *keys.Identity
		op   string
		args map[string]any
		want Reason
	}{
		{"over max", p.B, "travel/charge", map[string]any{"amount": 58901, "currency": "USD", "fare": "refundable", "date": 20261015}, OutOfBounds},
		{"missing arg", p.B, "travel/charge", map[string]any{"currency": "USD", "fare": "refundable", "date": 20261015}, MissingArg},
		{"wrong set member", p.B, "travel/charge", map[string]any{"amount": 1, "currency": "EUR", "fare": "refundable", "date": 20261015}, OutOfBounds},
		{"outside window", p.B, "travel/charge", map[string]any{"amount": 1, "currency": "USD", "fare": "refundable", "date": 20261016}, OutOfBounds},
		{"op not under act", p.B, "travel/chargeback", good, ForbiddenOp},
		{"op is sys", p.B, "sys/undo", good, ForbiddenOp},
		{"from is holder not issuer", p.C, "travel/charge", good, NoStanding},
		{"from is stranger", D, "travel/charge", good, NoStanding},
		{"ok", p.B, "travel/charge", good, ""},
		{"ok deeper op", p.B, "travel/charge/retry", good, ""},
	}
	for _, c := range cases {
		k, err := NewCall(c.from, chain, c.op, c.args)
		if err != nil {
			t.Fatal(err)
		}
		err = CheckForward(k)
		if CodeOf(err) != c.want {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

func TestTallyRejections(t *testing.T) {
	p := setup(t)
	kAB, _ := NewCall(p.A, []*Writ{p.W1}, "travel/book", map[string]any{"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261015})
	kBC, _ := NewCall(p.B, []*Writ{p.W1, p.W2}, "travel/charge", map[string]any{"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015})
	tC, _, _ := NewTally(p.C, TallyInput{Call: kBC, Acc: now + 10, St: "ok", Res: map[string]any{"charge": "x"}, Used: map[string]int64{"amount": 58900}})
	base := func() TallyInput {
		return TallyInput{Call: kAB, Acc: now + 5, St: "ok", Res: map[string]any{"pnr": "K"}, Used: map[string]int64{"amount": 58900}, Sub: []*Tally{tC}, Wrt: []*Writ{p.W2}}
	}
	check := func(name string, in TallyInput, signer *keys.Identity, res any, want Reason, wantV Verdict) {
		t.Helper()
		tb, r, err := NewTally(signer, in)
		if err != nil {
			t.Fatalf("%s: build: %v", name, err)
		}
		if res == nil {
			res = r
		}
		v, _, err := VerifyTally(p.W1, kAB, tb.Raw, res)
		if v != wantV || CodeOf(err) != want {
			t.Errorf("%s: want %s/%q, got %s/%v", name, wantV, want, v, err)
		}
	}
	check("ok", base(), p.B, nil, "", Valid)
	in := base()
	in.Acc = now + 3600
	check("acc at exp", in, p.B, nil, Expired, SignedUnauthorized)
	in = base()
	in.Used = map[string]int64{"amount": 60001}
	check("used over max", in, p.B, nil, OutOfBounds, SignedUnauthorized)
	// An honest builder refuses to sign this, so forge it by raw mutation.
	tb, _, _ := NewTally(p.B, base())
	forged, _ := wire.Clone(tb.Raw)
	forged["wrt"] = []any{}
	forged, _ = normalize(forged)
	_ = wire.Sign(forged, p.B)
	if v, _, err := VerifyTally(p.W1, kAB, forged, nil); v != Unverifiable || CodeOf(err) != SubUnmatched {
		t.Errorf("sub without wrt: got %s/%v", v, err)
	}
	check("wrong signer", base(), p.C, nil, BadSignature, Unverifiable)
	check("out mismatch", base(), p.B, map[string]any{"pnr": "Z"}, TallyMismatch, SignedUnauthorized)
	in = base()
	in.Call = kBC
	check("wrong call", in, p.B, nil, TallyMismatch, SignedUnauthorized)
	// Sub-tally over its own writ's max: build a C tally claiming 58901 used under W2 (max 58900).
	tBad, _, _ := NewTally(p.C, TallyInput{Call: kBC, Acc: now + 10, St: "ok", Used: map[string]int64{"amount": 58901}})
	in = base()
	in.Sub = []*Tally{tBad}
	check("sub used over its writ", in, p.B, nil, OutOfBounds, SignedUnauthorized)
	// Two sub-tallies whose sum exceeds W1's max: 58900 + 58900 > 60000.
	kBC2, _ := NewCall(p.B, []*Writ{p.W1, p.W2}, "travel/charge", map[string]any{"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015})
	tC2, _, _ := NewTally(p.C, TallyInput{Call: kBC2, Acc: now + 11, St: "ok", Used: map[string]int64{"amount": 58900}})
	in = base()
	in.Sub = []*Tally{tC, tC2}
	check("sum of sub exceeds parent", in, p.B, nil, OutOfBounds, SignedUnauthorized)
}

func TestRevoke(t *testing.T) {
	p := setup(t)
	r, err := NewRevoke(p.A, []*Writ{p.W1, p.W2})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRevoke(r); err != nil {
		t.Fatal(err)
	}
	r2, _ := NewRevoke(p.C, []*Writ{p.W1, p.W2})
	if CodeOf(CheckRevoke(r2)) != NoStanding {
		t.Fatal("holder must not be able to revoke its own writ from below")
	}
	star, _ := NewRevoke(p.A, nil)
	if err := CheckRevoke(star); err != nil || star.Writ != "*" {
		t.Fatal(err)
	}
}

func TestPrefixRule(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"travel", "travel", true}, {"travel", "travel/charge", true}, {"travel", "travelx", false},
		{"travel/", "travel/charge", true}, {"travel/", "travel", false},
		{"travel/charge", "travel/chargeback", false}, {"travel/charge", "travel/charge/retry", true},
		{"", "", true}, {"", "anything", false}, {"", "/x", true},
	}
	for _, c := range cases {
		if got := PrefixMatches(c.p, c.s); got != c.want {
			t.Errorf("PrefixMatches(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}
