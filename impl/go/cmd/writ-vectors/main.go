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

	fmt.Printf("wrote %d vectors to %s\n", count, dir)
}
