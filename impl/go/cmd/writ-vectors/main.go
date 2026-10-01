// writ-vectors regenerates the conformance corpus (spec section 14) from fixed
// seeds and fixed nonces, so any implementation can reproduce every file.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

const now = int64(1788400000)

var (
	dir   string
	count int
	seq   int
)

func nonce() string {
	seq++
	raw := []byte(fmt.Sprintf("nonce-%010d", seq)) // 16 bytes, so the encoding is canonical
	return wire.B64.EncodeToString(raw)
}

func write(name, op string, input map[string]any, expect string, reason writ.Reason, nowOpt *int64) {
	count++
	v := map[string]any{"name": name, "op": op, "input": input, "expect": expect}
	if expect == "reject" {
		v["reason"] = string(reason)
	}
	if nowOpt != nil {
		v["now"] = *nowOpt
	}
	b, _ := json.MarshalIndent(v, "", " ")
	fn := fmt.Sprintf("%03d_%s_%s.json", count, op, strings.NewReplacer(" ", "_", "/", "_").Replace(name))
	if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
		panic(err)
	}
}

func accept(name, op string, input map[string]any) { write(name, op, input, "accept", "", nil) }
func reject(name, op string, input map[string]any, r writ.Reason) {
	write(name, op, input, "reject", r, nil)
}

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

func b(t string, v any) map[string]any { return map[string]any{"t": t, "v": v} }

func id(n byte) *keys.Identity {
	i, _ := keys.FromSeed(bytes.Repeat([]byte{n}, 32))
	return i
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// must3 is must for NewTally, which also returns the result body.
func must3(t *writ.Tally, _ any, err error) *writ.Tally {
	if err != nil {
		panic(err)
	}
	return t
}

// usedOf is a used object naming amount, or an empty one for zero.
func usedOf(amount int64) map[string]int64 {
	if amount == 0 {
		return nil
	}
	return map[string]int64{"amount": amount}
}

// resign copies a writ's raw object, applies f, and re-signs with signer
// (nil leaves the old signature in place).
func resign(w *writ.Writ, signer *keys.Identity, f func(o wire.Object)) wire.Object {
	o := must(wire.Clone(w.Raw))
	f(o)
	if signer != nil {
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, signer)
	}
	return o
}

func raws(ws ...*writ.Writ) []any {
	var out []any
	for _, w := range ws {
		out = append(out, w.Raw)
	}
	return out
}

func main() {
	flag.StringVar(&dir, "out", "../../conformance/vectors", "output directory")
	flag.Parse()
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0o755)
	writ.Nonce = nonce

	A, B, C, D, S := id(1), id(2), id(3), id(4), id(9)

	// Canonicalization.
	accept("sorted keys and whitespace", "canonicalize", map[string]any{"raw": `{ "b" : 1 , "a" : [ 2 , {"d":null,"c":true} ] }`, "canonical": `{"a":[2,{"c":true,"d":null}],"b":1}`})
	accept("utf16 key order", "canonicalize", map[string]any{"raw": "{\"\\u20ac\":1,\"\\r\":2,\"1\":3,\"\\ud83d\\ude00\":4,\"\\u00f6\":5}", "canonical": "{\"\\r\":2,\"1\":3,\"\u00f6\":5,\"\u20ac\":1,\"\U0001F600\":4}"})
	accept("string escapes", "canonicalize", map[string]any{"raw": `"a\u0041\u00e9\u0001\n\"\\\/"`, "canonical": "\"aA\u00e9\\u0001\\n\\\"\\\\/\""})
	accept("negative and zero", "canonicalize", map[string]any{"raw": `[-5,0,-0,9007199254740991]`, "canonical": `[-5,0,0,9007199254740991]`})
	reject("float", "canonicalize", map[string]any{"raw": `{"a":1.5}`}, writ.Noncanonical)
	reject("exponent", "canonicalize", map[string]any{"raw": `{"a":1e3}`}, writ.Noncanonical)
	reject("integer with fraction zero", "canonicalize", map[string]any{"raw": `{"a":1.0}`}, writ.Noncanonical)
	reject("beyond safe range", "canonicalize", map[string]any{"raw": `{"a":9007199254740992}`}, writ.Noncanonical)
	reject("duplicate key", "canonicalize", map[string]any{"raw": `{"a":1,"a":2}`}, writ.Noncanonical)
	reject("duplicate key nested", "canonicalize", map[string]any{"raw": `{"a":{"b":1,"b":2}}`}, writ.Noncanonical)
	reject("lone high surrogate", "canonicalize", map[string]any{"raw": `{"a":"\ud800"}`}, writ.Noncanonical)
	reject("lone low surrogate", "canonicalize", map[string]any{"raw": `{"a":"\udc00x"}`}, writ.Noncanonical)
	reject("trailing data", "canonicalize", map[string]any{"raw": `{"a":1} 2`}, writ.Noncanonical)

	// Bound narrowing.
	nar := func(name string, child, parent map[string]any, r writ.Reason) {
		in := map[string]any{"child": child, "parent": parent}
		if r == "" {
			accept(name, "narrows", in)
		} else {
			reject(name, "narrows", in, r)
		}
	}
	nar("max equal", b("max", 100), b("max", 100), "")
	nar("max smaller", b("max", 99), b("max", 100), "")
	nar("max larger", b("max", 101), b("max", 100), writ.NotNarrowed)
	nar("count smaller", b("count", 0), b("count", 1), "")
	nar("count larger", b("count", 2), b("count", 1), writ.NotNarrowed)
	nar("prefix deeper segment", b("prefix", "travel/charge"), b("prefix", "travel"), "")
	nar("prefix equal", b("prefix", "travel"), b("prefix", "travel"), "")
	nar("prefix under slash form", b("prefix", "travel/charge"), b("prefix", "travel/"), "")
	nar("prefix segment escape", b("prefix", "travelx"), b("prefix", "travel"), writ.NotNarrowed)
	nar("prefix shorter", b("prefix", "travel"), b("prefix", "travel/"), writ.NotNarrowed)
	nar("prefix chargeback", b("prefix", "travel/chargeback"), b("prefix", "travel/charge"), writ.NotNarrowed)
	nar("set subset", b("set", []any{"USD"}), b("set", []any{"USD", "EUR"}), "")
	nar("set empty", b("set", []any{}), b("set", []any{"USD"}), "")
	nar("set not subset", b("set", []any{"GBP"}), b("set", []any{"USD", "EUR"}), writ.NotNarrowed)
	nar("set int vs string", b("set", []any{"1"}), b("set", []any{1}), writ.NotNarrowed)
	nar("window inside", b("window", []any{5, 6}), b("window", []any{1, 10}), "")
	nar("window equal", b("window", []any{1, 10}), b("window", []any{1, 10}), "")
	nar("window low escapes", b("window", []any{0, 6}), b("window", []any{1, 10}), writ.NotNarrowed)
	nar("window high escapes", b("window", []any{5, 11}), b("window", []any{1, 10}), writ.NotNarrowed)
	nar("type changed", b("count", 1), b("max", 1), writ.NotNarrowed)
	nar("unknown type", b("glob", "*"), b("glob", "*"), writ.UnknownBound)
	nar("max negative", b("max", -1), b("max", 5), writ.Noncanonical)
	nar("window inverted", b("window", []any{10, 1}), b("window", []any{1, 10}), writ.Noncanonical)
	nar("set duplicate", b("set", []any{"a", "a"}), b("set", []any{"a"}), writ.Noncanonical)
	nar("extra member", map[string]any{"t": "max", "v": 1, "x": 1}, b("max", 1), writ.Malformed)
	nar("value wrong json type", b("max", "5"), b("max", 5), writ.Malformed)

	sat := func(name string, bd map[string]any, arg any, r writ.Reason) {
		in := map[string]any{"bound": bd, "arg": arg}
		if r == "" {
			accept(name, "satisfies", in)
		} else {
			reject(name, "satisfies", in, r)
		}
	}
	sat("max at limit", b("max", 100), 100, "")
	sat("max over", b("max", 100), 101, writ.OutOfBounds)
	sat("max negative arg", b("max", 100), -1, writ.OutOfBounds)
	sat("max string arg", b("max", 100), "100", writ.OutOfBounds)
	sat("prefix match", b("prefix", "travel"), "travel/charge", "")
	sat("prefix segment mismatch", b("prefix", "travel"), "travelx", writ.OutOfBounds)
	sat("set member", b("set", []any{"USD", "EUR"}), "EUR", "")
	sat("set case", b("set", []any{"USD"}), "usd", writ.OutOfBounds)
	sat("set int member", b("set", []any{1, 2}), 2, "")
	sat("set int as string", b("set", []any{1}), "1", writ.OutOfBounds)
	sat("window edge", b("window", []any{1, 10}), 10, "")
	sat("window over", b("window", []any{1, 10}), 11, writ.OutOfBounds)

	// Writs and chains.
	full := bnd("act", "prefix", "travel", "amount", "max", 60000, "currency", "set", []any{"USD"},
		"uses", "count", 1, "fare", "set", []any{"refundable"}, "date", "window", []any{20261015, 20261019})
	w1 := must(writ.Issue(A, B.DID(), full, now+3600, nil))
	w2 := must(writ.Issue(B, C.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900, "currency", "set", []any{"USD"},
		"uses", "count", 1, "fare", "set", []any{"refundable"}, "date", "window", []any{20261015, 20261015}), now+1800, w1))
	w3 := must(writ.Issue(C, D.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 100, "currency", "set", []any{"USD"},
		"uses", "count", 1, "fare", "set", []any{"refundable"}, "date", "window", []any{20261015, 20261015}), now+900, w2))
	accept("root writ", "verify_writ", map[string]any{"writ": w1.Raw})
	accept("child writ", "verify_writ", map[string]any{"writ": w2.Raw})
	rw := func(name string, o wire.Object, r writ.Reason) {
		reject(name, "verify_writ", map[string]any{"writ": o}, r)
	}
	rw("tampered exp", resign(w1, nil, func(o wire.Object) { o["exp"] = json.Number("1788400001") }), writ.BadSignature)
	rw("wrong signer", resign(w1, B, func(o wire.Object) {}), writ.BadSignature)
	rw("typ call", resign(w1, A, func(o wire.Object) { o["typ"] = "call" }), writ.WrongType)
	rw("version 2", resign(w1, A, func(o wire.Object) { o["v"] = json.Number("2") }), writ.UnsupportedVersion)
	rw("crit unknown", resign(w1, A, func(o wire.Object) { o["crit"] = []any{"zap"} }), writ.UnsupportedCritical)
	rw("crit names absent member", resign(w1, A, func(o wire.Object) { o["crit"] = []any{"iss"}; delete(o, "iss") }), writ.Malformed)
	rw("missing act", resign(w1, A, func(o wire.Object) { delete(o["bnd"].(map[string]any), "act") }), writ.Malformed)
	rw("act not prefix", resign(w1, A, func(o wire.Object) { o["bnd"].(map[string]any)["act"] = b("set", []any{"travel"}) }), writ.Malformed)
	rw("unknown bound type", resign(w1, A, func(o wire.Object) { o["bnd"].(map[string]any)["x"] = b("glob", "*") }), writ.UnknownBound)
	rw("short nonce", resign(w1, A, func(o wire.Object) { o["nnc"] = "tooshort" }), writ.Malformed)
	rw("padded signature", resign(w1, nil, func(o wire.Object) { o["sig"] = o["sig"].(string) + "=" }), writ.Noncanonical)
	rw("non canonical trailing bits", resign(w1, A, func(o wire.Object) { o["nnc"] = "nonce00000000000000001" }), writ.Noncanonical)
	rw("signature wrong length", resign(w1, nil, func(o wire.Object) { o["sig"] = o["sig"].(string)[:84] }), writ.Malformed)
	rw("did web holder", resign(w1, A, func(o wire.Object) { o["hld"] = "did:web:example.com" }), writ.BadKey)
	rw("secp256k1 did key", resign(w1, A, func(o wire.Object) { o["hld"] = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme" }), writ.BadKey)
	rw("prv not a hash", resign(w1, A, func(o wire.Object) { o["prv"] = "abc" }), writ.Malformed)
	rw("prv absent", resign(w1, A, func(o wire.Object) { delete(o, "prv") }), writ.Malformed)
	rw("exp string", resign(w1, A, func(o wire.Object) { o["exp"] = "1788403600" }), writ.Malformed)
	rw("hld bound with non key", resign(w1, A, func(o wire.Object) { o["bnd"].(map[string]any)["hld"] = b("set", []any{"bob"}) }), writ.BadKey)
	big := make([]any, 0, 400)
	for i := 0; i < 400; i++ {
		big = append(big, fmt.Sprintf("member-%04d", i))
	}
	rw("writ over 4096 bytes", resign(w1, A, func(o wire.Object) { o["bnd"].(map[string]any)["huge"] = b("set", big) }), writ.TooLarge)

	ch := func(name string, chain []any, r writ.Reason, nowOpt *int64) {
		in := map[string]any{"chain": chain}
		if r == "" {
			write(name, "verify_chain", in, "accept", "", nowOpt)
		} else {
			write(name, "verify_chain", in, "reject", r, nowOpt)
		}
	}
	later := now + 10
	expired := now + 3600
	ch("two links", raws(w1, w2), "", &later)
	ch("three links", raws(w1, w2, w3), "", &later)
	ch("single root", raws(w1), "", nil)
	ch("root expired", raws(w1, w2), writ.Expired, &expired)
	ch("child expired only", raws(w1, w2), writ.Expired, func() *int64 { t := now + 1800; return &t }())
	ch("wrong order", raws(w2, w1), writ.ChainBroken, nil)
	ch("root prv not null", raws(w2), writ.ChainBroken, nil)
	ch("issuer not parent holder", []any{w1.Raw, resign(w2, D, func(o wire.Object) { o["iss"] = D.DID() })}, writ.ChainBroken, nil)
	ch("prv mismatch", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["prv"] = strings.Repeat("A", 43) })}, writ.ChainBroken, nil)
	ch("child outlives parent", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["exp"] = json.Number("1788500000") })}, writ.NotNarrowed, nil)
	ch("child widens max", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["amount"] = b("max", 60001) })}, writ.NotNarrowed, nil)
	ch("child drops bound", []any{w1.Raw, resign(w2, B, func(o wire.Object) { delete(o["bnd"].(map[string]any), "fare") })}, writ.NotNarrowed, nil)
	ch("child retypes bound", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["amount"] = b("count", 1) })}, writ.NotNarrowed, nil)
	ch("child widens set", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["currency"] = b("set", []any{"USD", "EUR"}) })}, writ.NotNarrowed, nil)
	ch("child widens window", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["date"] = b("window", []any{20261014, 20261015}) })}, writ.NotNarrowed, nil)
	ch("child escapes act segment", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["act"] = b("prefix", "travelx") })}, writ.NotNarrowed, nil)
	ch("child adds bound", []any{w1.Raw, resign(w2, B, func(o wire.Object) { o["bnd"].(map[string]any)["seat"] = b("set", []any{"economy"}) })}, "", nil)
	// hld and depth.
	h1 := must(writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{C.DID()}, "depth", "max", 1), now+3600, nil))
	h2 := must(writ.Issue(B, C.DID(), bnd("act", "prefix", "travel", "hld", "set", []any{}, "depth", "max", 0), now+3600, h1))
	ch("hld set honored", raws(h1, h2), "", nil)
	ch("hld set violated", []any{h1.Raw, resign(h2, B, func(o wire.Object) { o["hld"] = D.DID() })}, writ.NotNarrowed, nil)
	d1 := must(writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "depth", "max", 1), now+3600, nil))
	d2 := must(writ.Issue(B, C.DID(), bnd("act", "prefix", "travel", "depth", "max", 1), now+3600, d1))
	d3 := must(writ.Issue(C, D.DID(), bnd("act", "prefix", "travel", "depth", "max", 0), now+3600, d2))
	ch("depth exceeded", raws(d1, d2, d3), writ.NotNarrowed, nil)
	ch("depth honored", raws(d1, d2), "", nil)
	// Nine links.
	long := []*writ.Writ{must(writ.Issue(A, A.DID(), bnd("act", "prefix", "x"), now+3600, nil))}
	for i := 0; i < 8; i++ {
		long = append(long, must(writ.Issue(A, A.DID(), bnd("act", "prefix", "x"), now+3600, long[len(long)-1])))
	}
	ch("nine links", raws(long...), writ.TooLarge, nil)
	ch("eight links", raws(long[:8]...), "", nil)
	ch("empty chain", []any{}, writ.Malformed, nil)

	// Calls.
	good := map[string]any{"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015}
	cl := func(name string, k *writ.Call, r writ.Reason) {
		in := map[string]any{"call": k.Raw}
		if r == "" {
			write(name, "verify_call", in, "accept", "", &later)
		} else {
			write(name, "verify_call", in, "reject", r, &later)
		}
	}
	cl("forward call", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good)), "")
	cl("forward call deeper op", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge/retry", good)), "")
	cl("forward call extra arg", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1, "currency": "USD", "fare": "refundable", "date": 20261015, "pnr": "X"})), "")
	cl("from is holder", must(writ.NewCall(C, []*writ.Writ{w1, w2}, "travel/charge", good)), writ.NoStanding)
	cl("from is stranger", must(writ.NewCall(S, []*writ.Writ{w1, w2}, "travel/charge", good)), writ.NoStanding)
	cl("from is root not leaf issuer", must(writ.NewCall(A, []*writ.Writ{w1, w2}, "travel/charge", good)), writ.NoStanding)
	cl("op outside act", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/book", good)), writ.ForbiddenOp)
	cl("op segment escape", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/chargeback", good)), writ.ForbiddenOp)
	sysact := must(writ.Issue(A, B.DID(), bnd("act", "prefix", "sys"), now+3600, nil))
	cl("act prefix sys does not grant standing", must(writ.NewCall(B, []*writ.Writ{sysact}, "sys/undo", map[string]any{})), writ.NoStanding)
	cl("missing amount", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"currency": "USD", "fare": "refundable", "date": 20261015})), writ.MissingArg)
	cl("amount over max", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 58901, "currency": "USD", "fare": "refundable", "date": 20261015})), writ.OutOfBounds)
	cl("currency not in set", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1, "currency": "EUR", "fare": "refundable", "date": 20261015})), writ.OutOfBounds)
	cl("date outside window", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", map[string]any{"amount": 1, "currency": "USD", "fare": "refundable", "date": 20261016})), writ.OutOfBounds)
	cl("standing call by root", must(writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})), "")
	cl("standing call by intermediate", must(writ.NewCall(B, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})), "")
	cl("standing call by holder", must(writ.NewCall(C, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})), writ.NoStanding)
	cl("call chain broken", &writ.Call{Raw: func() wire.Object {
		k := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
		o := must(wire.Clone(k.Raw))
		o["chain"] = []any{w2.Raw, w1.Raw}
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, B)
		return o
	}()}, writ.ChainBroken)
	cl("call short id", &writ.Call{Raw: func() wire.Object {
		k := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
		o := must(wire.Clone(k.Raw))
		o["id"] = "c2hvcnQ"
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, B)
		return o
	}()}, writ.Malformed)
	cl("call tampered", &writ.Call{Raw: func() wire.Object {
		k := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
		o := must(wire.Clone(k.Raw))
		o["op"] = "travel/charge/x"
		return o
	}()}, writ.BadSignature)

	// Tallies.
	kAB := must(writ.NewCall(A, []*writ.Writ{w1}, "travel/book", map[string]any{"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261015}))
	kBC := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
	until := now + 86400
	tC, resC, _ := writ.NewTally(C, writ.TallyInput{Call: kBC, Acc: now + 10, St: "ok", Res: map[string]any{"charge": "ch_0001"}, Used: map[string]int64{"amount": 58900}, RevUntil: &until})
	tB, resB, _ := writ.NewTally(B, writ.TallyInput{Call: kAB, Acc: now + 5, St: "ok", Res: map[string]any{"pnr": "PNR001"}, Used: map[string]int64{"amount": 58900}, RevUntil: &until, Sub: []*writ.Tally{tC}, Wrt: []*writ.Writ{w2}})
	tv := func(name string, w *writ.Writ, k *writ.Call, t wire.Object, res any, r writ.Reason) {
		in := map[string]any{"writ": w.Raw, "call": k.Raw, "tally": t}
		if res != nil {
			in["res"] = res
		}
		if r == "" {
			accept(name, "verify_tally", in)
		} else {
			reject(name, "verify_tally", in, r)
		}
	}
	tv("leaf tally", w2, kBC, tC.Raw, resC, "")
	tv("tally with sub tree", w1, kAB, tB.Raw, resB, "")
	tv("tally without body", w1, kAB, tB.Raw, nil, "")
	tv("tally body mismatch", w1, kAB, tB.Raw, map[string]any{"pnr": "OTHER"}, writ.TallyMismatch)
	tv("tally for other call", w2, kAB, tC.Raw, nil, writ.TallyMismatch)
	tv("tally wrong signer", w1, kAB, func() wire.Object {
		o := must(wire.Clone(tB.Raw))
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, C)
		return o
	}(), nil, writ.BadSignature)
	rt := func(f func(o wire.Object), signer *keys.Identity) wire.Object {
		o := must(wire.Clone(tB.Raw))
		f(o)
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, signer)
		return o
	}
	tv("tally acc at exp", w1, kAB, rt(func(o wire.Object) { o["acc"] = json.Number("1788403600") }, B), nil, writ.Expired)
	tv("tally used over max", w1, kAB, rt(func(o wire.Object) { o["used"] = map[string]any{"amount": json.Number("60001")} }, B), nil, writ.OutOfBounds)
	tv("tally sub without wrt", w1, kAB, rt(func(o wire.Object) { o["wrt"] = []any{} }, B), nil, writ.SubUnmatched)
	tv("tally wrong writ", w1, kAB, rt(func(o wire.Object) { o["writ"] = w2.ID }, B), nil, writ.TallyMismatch)
	tv("tally wrong op", w1, kAB, rt(func(o wire.Object) { o["op"] = "travel/other" }, B), nil, writ.TallyMismatch)
	tv("tally pending with used", w1, kAB, rt(func(o wire.Object) {
		o["st"] = "pending"
		o["err"] = map[string]any{"code": "pending"}
	}, B), nil, writ.Malformed)
	tv("tally ok with err", w1, kAB, rt(func(o wire.Object) { o["err"] = map[string]any{"code": "x"} }, B), nil, writ.Malformed)
	tv("tally failed without err", w1, kAB, rt(func(o wire.Object) { o["st"] = "failed" }, B), nil, writ.Malformed)
	tv("tally typ writ", w1, kAB, rt(func(o wire.Object) { o["typ"] = "writ" }, B), nil, writ.WrongType)
	tv("tally missing sub", w1, kAB, rt(func(o wire.Object) { delete(o, "sub") }, B), nil, writ.Malformed)
	tBad, _, _ := writ.NewTally(C, writ.TallyInput{Call: kBC, Acc: now + 10, St: "ok", Used: map[string]int64{"amount": 58901}})
	tv("sub tally over its writ max", w1, kAB, rt(func(o wire.Object) { o["sub"] = []any{tBad.Raw} }, B), nil, writ.OutOfBounds)
	kBC2 := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
	tC2, _, _ := writ.NewTally(C, writ.TallyInput{Call: kBC2, Acc: now + 11, St: "ok", Used: map[string]int64{"amount": 58900}})
	tv("sum of sub exceeds parent max", w1, kAB, rt(func(o wire.Object) { o["sub"] = []any{tC.Raw, tC2.Raw} }, B), nil, writ.OutOfBounds)
	tv("sub tally wrong signer", w1, kAB, rt(func(o wire.Object) {
		o2 := must(wire.Clone(tC.Raw))
		bb, _ := json.Marshal(o2)
		o2 = must(wire.Decode(bb))
		_ = wire.Sign(o2, D)
		o["sub"] = []any{o2}
	}, B), nil, writ.BadSignature)
	tv("sub tally acc after its exp", w1, kAB, rt(func(o wire.Object) {
		o2 := must(wire.Clone(tC.Raw))
		o2["acc"] = json.Number("1788401800")
		bb, _ := json.Marshal(o2)
		o2 = must(wire.Decode(bb))
		_ = wire.Sign(o2, C)
		o["sub"] = []any{o2}
	}, B), nil, writ.Expired)
	tFailed, _, _ := writ.NewTally(C, writ.TallyInput{Call: kBC, Acc: now + 10, St: "failed", ErrCode: "out_of_bounds"})
	tv("failed tally", w2, kBC, tFailed.Raw, nil, "")
	tPend, _, _ := writ.NewTally(C, writ.TallyInput{Call: kBC, Acc: now + 10, St: "pending", ErrCode: "pending"})
	tv("pending tally", w2, kBC, tPend.Raw, nil, "")

	// Standing operations after expiry (spec section 7 steps 4 and 7, 6.2 step 5).
	// Forward authority ends at exp; standing survives it, so the same chain
	// that is rejected for a forward call is accepted for a standing one.
	leafExpired := w2.Exp
	rootExpired := w1.Exp + 60
	write("forward call at leaf exp", "verify_call", map[string]any{"call": kBC.Raw}, "reject", writ.Expired, &leafExpired)
	write("forward call after root exp", "verify_call", map[string]any{"call": kBC.Raw}, "reject", writ.Expired, &rootExpired)
	kUndo := must(writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/undo", map[string]any{"tally": tC.Raw}))
	write("standing undo after leaf exp", "verify_call", map[string]any{"call": kUndo.Raw}, "accept", "", &leafExpired)
	kTal := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID}))
	write("standing tallies after root exp", "verify_call", map[string]any{"call": kTal.Raw}, "accept", "", &rootExpired)
	write("standing call by holder after exp", "verify_call", map[string]any{"call": must(writ.NewCall(C, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w1.ID})).Raw}, "reject", writ.NoStanding, &rootExpired)
	tUndo, resUndo, _ := writ.NewTally(C, writ.TallyInput{Call: kUndo, Acc: w1.Exp + 60, St: "ok", Res: map[string]any{"refund": "rf_0001"}})
	tv("undo tally acc after exp", w2, kUndo, tUndo.Raw, resUndo, "")
	tLate, _, _ := writ.NewTally(C, writ.TallyInput{Call: kBC, Acc: w2.Exp, St: "ok", Used: map[string]int64{"amount": 58900}})
	tv("forward tally acc at leaf exp", w2, kBC, tLate.Raw, nil, writ.Expired)

	// Revokes (spec section 9.1), in the section's check order: the revoke's
	// own members, every writ in its chain, its signature, then the chain,
	// the leaf, and standing. Appended last so earlier files keep their bytes.
	rv := func(target string, chain []any, iss string, signer *keys.Identity) wire.Object {
		if chain == nil {
			chain = []any{}
		}
		o := wire.Object{"v": 1, "typ": "revoke", "writ": target, "iss": iss, "chain": chain}
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		_ = wire.Sign(o, signer)
		return o
	}
	rvv := func(name string, r wire.Object, reason writ.Reason) {
		expect := "accept"
		if reason != "" {
			expect = "reject"
		}
		write(name, "verify_revoke", map[string]any{"revoke": r}, expect, reason, nil)
	}
	rvv("revoke root by its issuer", must(writ.NewRevoke(A, []*writ.Writ{w1})).Raw, "")
	rvv("revoke leaf by the root issuer", must(writ.NewRevoke(A, []*writ.Writ{w1, w2})).Raw, "")
	rvv("revoke leaf by its issuer", must(writ.NewRevoke(B, []*writ.Writ{w1, w2})).Raw, "")
	rvv("key-wide revoke", must(writ.NewRevoke(A, nil)).Raw, "")
	write("revoke after expiry", "verify_revoke", map[string]any{"revoke": must(writ.NewRevoke(A, []*writ.Writ{w1})).Raw}, "accept", "", &rootExpired)
	rvv("revoke by the leaf holder", rv(w2.ID, raws(w1, w2), C.DID(), C), writ.NoStanding)
	rvv("revoke by a stranger", rv(w1.ID, raws(w1), S.DID(), S), writ.NoStanding)
	rvv("revoke leaf mismatch", rv(w2.ID, raws(w1), A.DID(), A), writ.ChainBroken)
	rvv("revoke chain out of order", rv(w1.ID, raws(w2, w1), A.DID(), A), writ.ChainBroken)
	rvv("key-wide revoke with a chain", rv("*", raws(w1), A.DID(), A), writ.Malformed)
	rvv("revoke of one writ without a chain", rv(w1.ID, nil, A.DID(), A), writ.Malformed)
	rvv("revoke wrong signer", func() wire.Object { o := rv(w1.ID, raws(w1), A.DID(), A); _ = wire.Sign(o, S); return o }(), writ.BadSignature)
	rvv("revoke iss not a key", rv(w1.ID, raws(w1), "did:web:a.example", A), writ.BadKey)
	rvv("revoke writ not a hash", rv("w1", raws(w1), A.DID(), A), writ.Noncanonical)
	rvv("revoke typ call", func() wire.Object {
		o := rv(w1.ID, raws(w1), A.DID(), A)
		o["typ"] = "call"
		_ = wire.Sign(o, A)
		return o
	}(), writ.WrongType)
	nine := []*writ.Writ{w1}
	for len(nine) < 9 {
		parent := nine[len(nine)-1]
		nine = append(nine, must(writ.Issue(B, B.DID(), parent.Raw["bnd"].(map[string]any), parent.Exp, parent)))
	}
	rvv("revoke chain of nine", rv(nine[8].ID, raws(nine...), A.DID(), A), writ.TooLarge)
	// First-failure order across the four steps.
	rvv("key-wide with chain and wrong signer is malformed first", func() wire.Object {
		o := rv("*", raws(w1), A.DID(), A)
		_ = wire.Sign(o, S)
		return o
	}(), writ.Malformed)
	badWrit := resign(w1, A, func(o wire.Object) { o["exp"] = "soon" })
	rvv("bad writ in chain before revoke signature", func() wire.Object {
		o := rv(w1.ID, []any{badWrit}, A.DID(), A)
		_ = wire.Sign(o, S)
		return o
	}(), writ.Malformed)
	rvv("wrong signer before leaf mismatch", func() wire.Object {
		o := rv(w2.ID, raws(w1), A.DID(), A)
		_ = wire.Sign(o, S)
		return o
	}(), writ.BadSignature)
	rvv("leaf mismatch before standing", rv(w2.ID, raws(w1), S.DID(), S), writ.ChainBroken)

	// A standing call whose sys/ operation section 8 does not define.
	write("standing call undefined operation", "verify_call", map[string]any{"call": must(writ.NewCall(A, []*writ.Writ{w1, w2}, "sys/other", map[string]any{})).Raw}, "reject", writ.ForbiddenOp, nil)
	write("standing call by a stranger to an undefined operation", "verify_call", map[string]any{"call": must(writ.NewCall(S, []*writ.Writ{w1, w2}, "sys/other", map[string]any{})).Raw}, "reject", writ.NoStanding, nil)

	// First-failure order, as pinned on 2026-09-28 (spec sections 1.1, 3,
	// 6.1, 6.2, 7, 9.1, and 14). Each vector carries two faults and the
	// pinned order decides which one is reported, so a verifier checking in
	// any other order fails it. The differential fuzzer found each question.
	re := func(o wire.Object, signer *keys.Identity) wire.Object {
		bb, _ := json.Marshal(o)
		o = must(wire.Decode(bb))
		if signer != nil {
			_ = wire.Sign(o, signer)
		}
		return o
	}
	expectOf := func(r writ.Reason) string {
		if r == "" {
			return "accept"
		}
		return "reject"
	}

	// Section 3: one bound, and the narrows vector's operands.
	nar("child before parent", b("max", "5"), b("max", -1), writ.Malformed)
	nar("members before type", map[string]any{"t": "glob", "v": 1, "x": 1}, b("max", 1), writ.Malformed)
	nar("type before value type", b("glob", "5"), b("max", 1), writ.UnknownBound)
	nar("set elements in array order", b("set", []any{"a", "a", map[string]any{}}), b("set", []any{"a"}), writ.Noncanonical)
	nar("window shape before order", b("window", []any{10, 1, 5}), b("window", []any{1, 10}), writ.Malformed)

	// Section 1.1 rule 7: nesting is found before every other rule.
	accept("nesting at the limit", "canonicalize", map[string]any{"raw": strings.Repeat("[", 64) + strings.Repeat("]", 64), "canonical": strings.Repeat("[", 64) + strings.Repeat("]", 64)})
	reject("nesting over the limit", "canonicalize", map[string]any{"raw": strings.Repeat("[", 65) + strings.Repeat("]", 65)}, writ.TooLarge)
	reject("nesting before number rules", "canonicalize", map[string]any{"raw": strings.Repeat("[", 65) + "1.5" + strings.Repeat("]", 65)}, writ.TooLarge)
	nested := func(levels int, leaf any) any {
		v := leaf
		for i := 0; i < levels; i++ {
			v = []any{v}
		}
		return v
	}
	// The writ is level 1 and its member x level 2, so 63 arrays reach 64.
	accept("writ nesting at the limit", "verify_writ", map[string]any{"writ": resign(w1, A, func(o wire.Object) { o["x"] = nested(63, json.Number("1")) })})
	rw("writ nesting over the limit", resign(w1, A, func(o wire.Object) { o["x"] = nested(64, json.Number("1")) }), writ.TooLarge)
	rw("writ nesting before number rules", resign(w1, nil, func(o wire.Object) { o["x"] = nested(70, json.Number("1.5")) }), writ.TooLarge)

	// Section 6.1 steps 2 to 4.
	rw("binary encoding before version", resign(w1, A, func(o wire.Object) { o["v"] = json.Number("2"); o["nnc"] = "nonce00000000000000001" }), writ.Noncanonical)
	rw("non string binary member waits for step 5", resign(w1, A, func(o wire.Object) { o["v"] = json.Number("2"); o["nnc"] = json.Number("7") }), writ.UnsupportedVersion)
	rw("empty binary member", resign(w1, A, func(o wire.Object) { o["nnc"] = "" }), writ.Noncanonical)
	rw("crit array type before names", resign(w1, A, func(o wire.Object) { o["crit"] = []any{"zap", json.Number("5")} }), writ.Malformed)
	rw("crit names in array order", resign(w1, A, func(o wire.Object) { o["crit"] = []any{"zap", "prv"}; delete(o, "prv") }), writ.UnsupportedCritical)

	// Section 6.1 step 5 on a writ: member-table order, each member whole.
	rw("iss key before bnd", resign(w1, A, func(o wire.Object) {
		o["iss"] = "did:web:a.example"
		delete(o["bnd"].(map[string]any), "act")
	}), writ.BadKey)
	rw("hld key before exp", resign(w1, A, func(o wire.Object) { o["hld"] = "did:web:b.example"; o["exp"] = "soon" }), writ.BadKey)
	rw("act presence before bounds", resign(w1, A, func(o wire.Object) {
		m := o["bnd"].(map[string]any)
		delete(m, "act")
		m["x"] = b("glob", "*")
	}), writ.Malformed)
	rw("bounds in canonical name order", resign(w1, A, func(o wire.Object) {
		m := o["bnd"].(map[string]any)
		m["a"] = b("glob", "*")
		for _, n := range []string{"b", "c", "d", "e"} {
			m[n] = b("max", -1)
		}
	}), writ.UnknownBound)
	rw("bound order is utf16 order", resign(w1, A, func(o wire.Object) {
		m := o["bnd"].(map[string]any)
		m["\U0001F600"] = b("glob", "*")
		m["\uFF61"] = b("max", -1)
	}), writ.UnknownBound)
	rw("section 3 before section 3.2", resign(w1, A, func(o wire.Object) {
		m := o["bnd"].(map[string]any)
		m["act"] = b("set", []any{"travel"})
		m["zzz"] = b("glob", "*")
	}), writ.UnknownBound)

	// Section 7 steps 1 and 2 on a call: its own members, then its chain's
	// writs, then its signature.
	kOrd := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good))
	rc := func(f func(o wire.Object), signer *keys.Identity) wire.Object {
		o := must(wire.Clone(kOrd.Raw))
		f(o)
		return re(o, signer)
	}
	cv := func(name string, o wire.Object, r writ.Reason) {
		write(name, "verify_call", map[string]any{"call": o}, expectOf(r), r, nil)
	}
	tamperedW2 := resign(w2, nil, func(o wire.Object) { o["exp"] = json.Number("1788401799") })
	malformedW2 := resign(w2, B, func(o wire.Object) { o["exp"] = "soon" })
	cv("from key before args", rc(func(o wire.Object) { o["from"] = "did:web:b.example"; o["args"] = "none" }, B), writ.BadKey)
	cv("own members before chain writs", rc(func(o wire.Object) { o["chain"] = []any{w1.Raw, tamperedW2}; o["op"] = json.Number("7") }, B), writ.Malformed)
	cv("sig member before chain writs", rc(func(o wire.Object) { o["chain"] = []any{w1.Raw, tamperedW2}; o["sig"] = strings.Repeat("A", 84) }, nil), writ.Malformed)
	cv("chain writs before call signature", rc(func(o wire.Object) { o["chain"] = []any{w1.Raw, malformedW2} }, S), writ.Malformed)
	cv("id before chain length", rc(func(o wire.Object) { o["id"] = "c2hvcnQ"; o["chain"] = raws(nine...) }, B), writ.Malformed)
	cv("version before chain length", rc(func(o wire.Object) { o["v"] = json.Number("2"); o["chain"] = raws(nine...) }, B), writ.UnsupportedVersion)
	cv("chain length before element type", rc(func(o wire.Object) {
		c := raws(nine...)
		c[3] = "x"
		o["chain"] = c
	}, B), writ.TooLarge)

	// Section 6.2: a tally's own 6.1, then steps 2 to 6, then wrt, then sub.
	tv("tally signature before wrt contents", w1, kAB, rt(func(o wire.Object) { o["wrt"] = []any{malformedW2} }, C), nil, writ.BadSignature)
	tv("tally signature before sub_unmatched", w1, kAB, rt(func(o wire.Object) { o["wrt"] = []any{} }, C), nil, writ.BadSignature)
	tv("op before wrt contents", w1, kAB, rt(func(o wire.Object) { o["wrt"] = []any{malformedW2}; o["op"] = "travel/other" }, B), nil, writ.TallyMismatch)
	tv("acc before body", w1, kAB, rt(func(o wire.Object) { o["acc"] = json.Number("1788403600") }, B), map[string]any{"pnr": "OTHER"}, writ.Expired)
	tv("wrt before sub", w1, kAB, rt(func(o wire.Object) { o["wrt"] = []any{malformedW2} }, B), nil, writ.Malformed)
	tv("sub_unmatched before the sub tally", w1, kAB, rt(func(o wire.Object) { o["sub"] = []any{map[string]any{"writ": "zzz"}} }, B), nil, writ.SubUnmatched)
	dz := must(writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "depth", "max", 0), now+3600, nil))
	dzc := must(writ.Issue(B, C.DID(), bnd("act", "prefix", "travel", "depth", "max", 0), now+1800, dz))
	kDz := must(writ.NewCall(A, []*writ.Writ{dz}, "travel/book", map[string]any{}))
	tDz, _, _ := writ.NewTally(B, writ.TallyInput{Call: kDz, Acc: now + 5, St: "ok", Wrt: []*writ.Writ{dzc}})
	tv("depth applies to wrt", dz, kDz, tDz.Raw, nil, writ.NotNarrowed)
	d1w := must(writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "depth", "max", 1), now+3600, nil))
	d1c := must(writ.Issue(B, C.DID(), bnd("act", "prefix", "travel", "depth", "max", 0), now+1800, d1w))
	kD1 := must(writ.NewCall(A, []*writ.Writ{d1w}, "travel/book", map[string]any{}))
	tD1, _, _ := writ.NewTally(B, writ.TallyInput{Call: kD1, Acc: now + 5, St: "ok", Wrt: []*writ.Writ{d1c}})
	tv("depth honored in wrt", d1w, kD1, tD1.Raw, nil, "")
	rtp := func(f func(o wire.Object)) wire.Object {
		o := must(wire.Clone(tPend.Raw))
		f(o)
		return re(o, C)
	}
	tv("pending tally with another err code", w2, kBC, rtp(func(o wire.Object) { o["err"] = map[string]any{"code": "busy"} }), nil, writ.Malformed)
	tv("pending tally with wrt", w2, kBC, rtp(func(o wire.Object) { o["wrt"] = []any{w3.Raw} }), nil, writ.Malformed)

	// Section 4 as an operation: every element is an object before any writ
	// is verified; a sub-tally whose writ member is not a string names no
	// writ in wrt.
	ch("elements before writs", []any{resign(w1, nil, func(o wire.Object) { o["exp"] = json.Number("1788403601") }), "x"}, writ.Malformed, nil)
	tv("sub writ member not a string", w1, kAB, rt(func(o wire.Object) { o["sub"] = []any{map[string]any{"writ": map[string]any{}}} }, B), nil, writ.SubUnmatched)

	// Section 9.1 step 1: members in table order, iss before chain.
	rvv("iss before chain length", rv(nine[8].ID, raws(nine...), "did:web:a.example", A), writ.BadKey)

	// Section 6.2 step 10: used is inclusive of the subtree, so every tally's
	// used covers its sub-tallies'. The first vector is the 2026-09-29 review's
	// reproduction: two branches two levels deep each charge
	// 58900 under a root max of 60000, the intermediaries report nothing, and
	// the old rule, which summed immediate sub-tallies against the writ,
	// accepted it.
	E, F := id(5), id(6)
	narrowAll := func(parent *writ.Writ, iss *keys.Identity, hld string, exp int64) *writ.Writ {
		nb := map[string]any{}
		for name, pb := range parent.Bnd {
			nb[name] = map[string]any{"t": pb.T, "v": pb.Raw}
		}
		return must(writ.Issue(iss, hld, nb, exp, parent))
	}
	args := func(amount int) map[string]any {
		return map[string]any{"amount": amount, "currency": "USD", "fare": "refundable", "date": 20261015}
	}
	type branch struct {
		mid, leaf       *keys.Identity
		midUsed, charge int64
	}
	tree := func(branches []branch, rootUsed int64) wire.Object {
		var subs []*writ.Tally
		var wrts []*writ.Writ
		for i, br := range branches {
			wc := narrowAll(w1, B, br.mid.DID(), now+1800)
			kc := must(writ.NewCall(B, []*writ.Writ{w1, wc}, "travel/book", args(int(br.charge))))
			wd := narrowAll(wc, br.mid, br.leaf.DID(), now+900)
			kd := must(writ.NewCall(br.mid, []*writ.Writ{w1, wc, wd}, "travel/charge", args(int(br.charge))))
			td := must3(writ.NewTally(br.leaf, writ.TallyInput{Call: kd, Acc: now + 20 + int64(i), St: "ok", Used: usedOf(br.charge)}))
			tc := must3(writ.NewTally(br.mid, writ.TallyInput{Call: kc, Acc: now + 15 + int64(i), St: "ok", Used: usedOf(br.midUsed), Sub: []*writ.Tally{td}, Wrt: []*writ.Writ{wd}}))
			subs, wrts = append(subs, tc), append(wrts, wc)
		}
		return must3(writ.NewTally(B, writ.TallyInput{Call: kAB, Acc: now + 5, St: "ok", Used: usedOf(rootUsed), Sub: subs, Wrt: wrts})).Raw
	}
	tv("nested intermediaries report nothing", w1, kAB, tree([]branch{{C, D, 0, 58900}, {E, F, 0, 58900}}, 0), nil, writ.OutOfBounds)
	tv("nested fan out rolled up past the root max", w1, kAB, tree([]branch{{C, D, 58900, 58900}, {E, F, 58900, 58900}}, 117800), nil, writ.OutOfBounds)
	tv("branching tree within the root max", w1, kAB, tree([]branch{{C, D, 20000, 20000}, {E, F, 30500, 30000}}, 51000), nil, "")
	tv("own used below its sub tally", w1, kAB, rt(func(o wire.Object) { o["used"] = map[string]any{} }, B), nil, writ.OutOfBounds)

	// Section 9.4: checking a tally against its signer's ack of a revoke. A
	// revokes w1; C acked it at now+10, holding one finished call and one in
	// flight. Every tally below verifies under section 6.2; the ack is what
	// tells work accepted before the revoke from work accepted after it,
	// whatever the tally's acc says.
	ackChain := raws(w1, w2)
	rvA := must(writ.NewRevoke(A, []*writ.Writ{w1}))
	callC := func() *writ.Call { return must(writ.NewCall(B, []*writ.Writ{w1, w2}, "travel/charge", good)) }
	kHeld, kOpen := callC(), callC()
	tHeld := must3(writ.NewTally(C, writ.TallyInput{Call: kHeld, Acc: now + 5, St: "ok", Used: usedOf(58900), Res: map[string]any{"charge": "ch_1"}}))
	ackBody := writ.AckBody([]writ.AckHeld{{Call: kHeld.ID, Tally: tHeld.ID}}, []string{kOpen.ID})
	ackC := must(writ.NewAck(C, rvA.ID, now+10, ackBody))
	ca := func(name string, rvo, ack wire.Object, body any, chain []any, t wire.Object, r writ.Reason) {
		write(name, "check_ack", map[string]any{"revoke": rvo, "ack": ack, "res": body, "chain": chain, "tally": t}, expectOf(r), r, nil)
	}
	tally := func(k *writ.Call, acc int64, st, code string) wire.Object {
		return must3(writ.NewTally(C, writ.TallyInput{Call: k, Acc: acc, St: st, ErrCode: code})).Raw
	}
	ca("held tally", rvA.Raw, ackC.Raw, ackBody, ackChain, tHeld.Raw, "")
	ca("pending tally of a held call", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(kHeld, now+5, "pending", "pending"), "")
	ca("pending tally of an open call", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(kOpen, now+6, "pending", "pending"), "")
	ca("final tally of an open call", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(kOpen, now+6, "canceled", "revoked"), "")
	ca("work accepted after the revoke", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(callC(), now+20, "ok", ""), writ.Revoked)
	ca("work after the revoke with acc backdated", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(callC(), now+1, "ok", ""), writ.Revoked)
	ca("a second outcome for a held call", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(kHeld, now+5, "ok", ""), writ.Revoked)
	ca("failed work that consumed", rvA.Raw, ackC.Raw, ackBody, ackChain,
		must3(writ.NewTally(C, writ.TallyInput{Call: callC(), Acc: now + 20, St: "failed", ErrCode: "app/declined", Used: usedOf(1)})).Raw, writ.Revoked)
	ca("a refusal after the revoke reports no work", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(callC(), now+20, "failed", "revoked"), "")
	kSys := must(writ.NewCall(B, []*writ.Writ{w1, w2}, "sys/tallies", map[string]any{"writ": w2.ID}))
	ca("a standing call is not forward work", rvA.Raw, ackC.Raw, ackBody, ackChain, tally(kSys, now+20, "ok", ""), "")
	ca("an ack by another signer says nothing", rvA.Raw, must(writ.NewAck(D, rvA.ID, now+10, ackBody)).Raw, ackBody, ackChain, tally(callC(), now+20, "ok", ""), "")
	wSib := narrowAll(w1, B, C.DID(), now+1800)
	rvSib := must(writ.NewRevoke(B, []*writ.Writ{w1, wSib}))
	ca("a revoke of a sibling writ does not cover the chain", rvSib.Raw, must(writ.NewAck(C, rvSib.ID, now+10, ackBody)).Raw, ackBody, ackChain, tally(callC(), now+20, "ok", ""), "")
	wShort := narrowAll(w1, B, C.DID(), now+8)
	kShort := must(writ.NewCall(B, []*writ.Writ{w1, wShort}, "travel/charge", good))
	ca("a writ that expired before rcv", rvA.Raw, ackC.Raw, ackBody, raws(w1, wShort), tally(kShort, now+7, "ok", ""), "")
	rvB := must(writ.NewRevoke(B, nil))
	ackB := must(writ.NewAck(C, rvB.ID, now+10, ackBody))
	ca("key-wide revoke covers the writ the key issued", rvB.Raw, ackB.Raw, ackBody, ackChain, tally(callC(), now+20, "ok", ""), writ.Revoked)
	wDirect := must(writ.Issue(A, C.DID(), bnd("act", "prefix", "travel"), now+3600, nil))
	kDirect := must(writ.NewCall(A, []*writ.Writ{wDirect}, "travel/x", map[string]any{}))
	ca("key-wide revoke of a key absent from the chain", rvB.Raw, ackB.Raw, ackBody, raws(wDirect), tally(kDirect, now+20, "ok", ""), "")
	late := tally(callC(), now+20, "ok", "")
	ca("ack of another revoke", rvA.Raw, ackB.Raw, ackBody, ackChain, late, writ.AckMismatch)
	ca("body substituted", rvA.Raw, ackC.Raw, writ.AckBody([]writ.AckHeld{{Call: kHeld.ID, Tally: tHeld.ID}}, []string{kOpen.ID, must(wire.Hash(late))}), ackChain, late, writ.AckMismatch)
	ca("no body", rvA.Raw, ackC.Raw, nil, ackChain, late, writ.AckMismatch)
	badBody := map[string]any{"held": map[string]any{}, "open": []any{}}
	ca("held not an array", rvA.Raw, must(writ.NewAck(C, rvA.ID, now+10, badBody)).Raw, badBody, ackChain, late, writ.Malformed)
	ra := func(f func(o wire.Object), signer *keys.Identity) wire.Object {
		o := must(wire.Clone(ackC.Raw))
		f(o)
		return re(o, signer)
	}
	ca("ack typ tally", rvA.Raw, ra(func(o wire.Object) { o["typ"] = "tally" }, C), ackBody, ackChain, late, writ.WrongType)
	ca("ack rcv not an integer", rvA.Raw, ra(func(o wire.Object) { o["rcv"] = "soon" }, C), ackBody, ackChain, late, writ.Malformed)
	ca("ack signed by another key", rvA.Raw, ra(func(o wire.Object) {}, D), ackBody, ackChain, late, writ.BadSignature)
	ca("ack revoke member before iss", rvA.Raw, ra(func(o wire.Object) { o["revoke"] = "c2hvcnQ"; o["iss"] = "did:web:c.example" }, C), ackBody, ackChain, late, writ.Malformed)
	ca("revoke before ack", rv(w1.ID, raws(w1), A.DID(), S), ra(func(o wire.Object) { o["typ"] = "tally" }, C), ackBody, ackChain, late, writ.BadSignature)
	ca("ack before chain", rvA.Raw, ackB.Raw, ackBody, raws(w2), late, writ.AckMismatch)
	ca("chain before tally", rvA.Raw, ackC.Raw, ackBody, raws(w2), late, writ.ChainBroken)
	ca("tally signed by someone other than the leaf holder", rvA.Raw, ackC.Raw, ackBody, ackChain, must3(writ.NewTally(D, writ.TallyInput{Call: callC(), Acc: now + 20, St: "ok"})).Raw, writ.BadSignature)
	ca("tally for another writ", rvA.Raw, ackC.Raw, ackBody, ackChain, must3(writ.NewTally(C, writ.TallyInput{Call: must(writ.NewCall(A, []*writ.Writ{w1}, "travel/book", good)), Acc: now + 20, St: "ok"})).Raw, writ.TallyMismatch)

	fmt.Printf("wrote %d vectors to %s\n", count, dir)
}
