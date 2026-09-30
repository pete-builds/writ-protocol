// writ-fuzz is the differential fuzzer. It mutates valid protocol objects,
// bounds, and JSON texts from a seed, judges each result with this verifier,
// and writes it as a conformance vector (spec section 14) whose expectation is
// that verdict. Another implementation that runs the directory with its own
// conformance runner then fails on exactly the inputs where the two disagree.
//
// Hand-written vectors only find the cases their author thought of. The
// mutations here combine faults, so they also test the normative first-failure
// order, and most mutated objects are re-signed by the right key so the input
// reaches the checks after the signature. The same seed yields the same files.
//
//	writ-fuzz -seed 1 -n 4000 -out /tmp/writ-fuzz
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"writproto/conformance"
	"writproto/keys"
	"writproto/wire"
	"writproto/writ"
)

const now = int64(1788400000)

var (
	r    *rand.Rand
	ids  = map[string]*keys.Identity{}
	A    = id(1)
	B    = id(2)
	C    = id(3)
	D    = id(4)
	S    = id(9)
	seq  int
	base struct {
		w1, w2, v1, v2, v3      *writ.Writ
		kFwd, kFwd3, kAB, kUndo *writ.Call
		kTal                    *writ.Call
		tC, tB                  wire.Object
		resC, resB              any
		rv1, rv2, rvStar        wire.Object
		exps                    []int64
		// Section 9.4: C's ack of rv1, and tallies for check_ack to judge.
		ack          wire.Object
		ackBody      map[string]any
		ackTallies   []wire.Object
		kOpen, kLate *writ.Call
		boundsSeen   []any
	}
)

func id(n byte) *keys.Identity {
	i, _ := keys.FromSeed(bytes.Repeat([]byte{n}, 32))
	ids[i.DID()] = i
	return i
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func nonce() string {
	seq++
	return wire.B64.EncodeToString([]byte(fmt.Sprintf("fuzzn-%010d", seq)))
}

func bnd(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 3 {
		m[kv[i].(string)] = map[string]any{"t": kv[i+1], "v": kv[i+2]}
	}
	return m
}

func n(v int64) json.Number { return json.Number(fmt.Sprint(v)) }

func pick[T any](xs ...T) T { return xs[r.IntN(len(xs))] }

func chance(p float64) bool { return r.Float64() < p }

// clone deep-copies a JSON value through encoding, keeping json.Number.
func clone(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		panic(err)
	}
	return out
}

func setup() {
	writ.Nonce = nonce
	base.w1 = must(writ.Issue(A, B.DID(), bnd(
		"act", "prefix", "travel",
		"amount", "max", 60000,
		"currency", "set", []any{"USD"},
		"date", "window", []any{20261015, 20261019},
		"fare", "set", []any{"refundable", 2},
		"uses", "count", 1,
		"hld", "set", []any{C.DID(), D.DID()},
		"depth", "max", 2,
	), now+3600, nil))
	base.w2 = must(writ.Issue(B, C.DID(), bnd(
		"act", "prefix", "travel/charge",
		"amount", "max", 58900,
		"currency", "set", []any{"USD"},
		"date", "window", []any{20261015, 20261016},
		"fare", "set", []any{"refundable"},
		"uses", "count", 1,
		"hld", "set", []any{},
		"depth", "max", 0,
	), now+1800, base.w1))
	base.v1 = must(writ.Issue(A, B.DID(), bnd("act", "prefix", "travel", "amount", "max", 60000), now+3600, nil))
	base.v2 = must(writ.Issue(B, D.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58900), now+2400, base.v1))
	base.v3 = must(writ.Issue(D, C.DID(), bnd("act", "prefix", "travel/charge", "amount", "max", 58000, "note", "prefix", "a/"), now+1200, base.v2))
	args := map[string]any{"amount": 58900, "currency": "USD", "date": 20261015, "fare": "refundable", "pnr": "K7Q2ZD"}
	base.kFwd = must(writ.NewCall(B, []*writ.Writ{base.w1, base.w2}, "travel/charge", args))
	base.kFwd3 = must(writ.NewCall(D, []*writ.Writ{base.v1, base.v2, base.v3}, "travel/charge/retry", map[string]any{"amount": 58000, "note": "a/b"}))
	base.kAB = must(writ.NewCall(A, []*writ.Writ{base.w1}, "travel/book", map[string]any{"amount": 58900, "currency": "USD", "date": 20261016, "fare": 2}))
	until := now + 86400
	base.resC = map[string]any{"charge": "ch_8813"}
	tC, _, _ := writ.NewTally(C, writ.TallyInput{Call: base.kFwd, Acc: now + 15, St: "ok", Res: base.resC, Used: map[string]int64{"amount": 58900}, RevUntil: &until})
	base.tC = tC.Raw
	base.resB = map[string]any{"booking": "bk_1", "pnr": "K7Q2ZD"}
	tB, _, _ := writ.NewTally(B, writ.TallyInput{Call: base.kAB, Acc: now + 12, St: "ok", Res: base.resB, Used: map[string]int64{"amount": 58900}, Sub: []*writ.Tally{tC}, Wrt: []*writ.Writ{base.w2}})
	base.tB = tB.Raw
	base.kUndo = must(writ.NewCall(A, []*writ.Writ{base.w1, base.w2}, "sys/undo", map[string]any{"tally": base.tC}))
	base.kTal = must(writ.NewCall(B, []*writ.Writ{base.w1, base.w2}, "sys/tallies", map[string]any{"writ": base.w1.ID}))
	base.rv1 = must(writ.NewRevoke(A, []*writ.Writ{base.w1})).Raw
	base.rv2 = must(writ.NewRevoke(B, []*writ.Writ{base.w1, base.w2})).Raw
	base.rvStar = must(writ.NewRevoke(A, nil)).Raw
	base.exps = []int64{now, base.w2.Exp - 1, base.w2.Exp, base.w1.Exp, base.v3.Exp, now + 1790}
	base.kOpen = must(writ.NewCall(B, []*writ.Writ{base.w1, base.w2}, "travel/charge", args))
	base.kLate = must(writ.NewCall(B, []*writ.Writ{base.w1, base.w2}, "travel/charge", args))
	rv1ID, _ := wire.Hash(base.rv1)
	base.ackBody = writ.AckBody([]writ.AckHeld{{Call: base.kFwd.ID, Tally: tC.ID}}, []string{base.kOpen.ID})
	base.ack = must(writ.NewAck(C, rv1ID, now+20, base.ackBody)).Raw
	tally := func(k *writ.Call, acc int64, st, code string) wire.Object {
		t, _, _ := writ.NewTally(C, writ.TallyInput{Call: k, Acc: acc, St: st, ErrCode: code})
		return t.Raw
	}
	base.ackTallies = []wire.Object{base.tC, tally(base.kFwd, now+15, "pending", "pending"), tally(base.kOpen, now+18, "pending", "pending"),
		tally(base.kLate, now+30, "ok", ""), tally(base.kLate, now+5, "ok", ""), tally(base.kLate, now+30, "failed", "revoked"),
		tally(base.kTal, now+30, "ok", "")}
	for _, w := range []*writ.Writ{base.w1, base.w2, base.v3} {
		for _, b := range w.Raw["bnd"].(map[string]any) {
			base.boundsSeen = append(base.boundsSeen, b)
		}
	}
	sort.Slice(base.boundsSeen, func(i, j int) bool {
		bi, _ := json.Marshal(base.boundsSeen[i])
		bj, _ := json.Marshal(base.boundsSeen[j])
		return string(bi) < string(bj)
	})
}

// ------------------------------------------------------------ JSON paths

type step struct {
	key string
	idx int
	arr bool
}

func paths(v any, prefix []step, out *[][]step, depth int) {
	if depth > 6 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := append(append([]step{}, prefix...), step{key: k})
			*out = append(*out, p)
			paths(x[k], p, out, depth+1)
		}
	case []any:
		for i := range x {
			p := append(append([]step{}, prefix...), step{idx: i, arr: true})
			*out = append(*out, p)
			paths(x[i], p, out, depth+1)
		}
	}
}

func get(v any, p []step) any {
	for _, s := range p {
		switch x := v.(type) {
		case map[string]any:
			v = x[s.key]
		case []any:
			v = x[s.idx]
		default:
			return nil
		}
	}
	return v
}

var deleted = &struct{}{}

// set returns root with the value at p replaced by nv (deleted removes it).
func set(root any, p []step, nv any) any {
	if len(p) == 0 {
		return nv
	}
	s := p[0]
	switch x := root.(type) {
	case map[string]any:
		if len(p) == 1 && nv == any(deleted) {
			delete(x, s.key)
			return x
		}
		x[s.key] = set(x[s.key], p[1:], nv)
		return x
	case []any:
		if len(p) == 1 && nv == any(deleted) {
			return append(append([]any{}, x[:s.idx]...), x[s.idx+1:]...)
		}
		x[s.idx] = set(x[s.idx], p[1:], nv)
		return x
	}
	return root
}

func describe(p []step) string {
	var sb strings.Builder
	for _, s := range p {
		if s.arr {
			fmt.Fprintf(&sb, "[%d]", s.idx)
		} else {
			sb.WriteString("." + s.key)
		}
	}
	return sb.String()
}

// ------------------------------------------------------------ values

func deep(levels int) any {
	var v any = json.Number("1")
	for i := 0; i < levels; i++ {
		v = []any{v}
	}
	return v
}

func someHash() string {
	return wire.HashBytes([]byte(fmt.Sprint("fuzz-hash-", r.IntN(4))))
}

func interesting() any {
	switch r.IntN(32) {
	case 0:
		return nil
	case 1:
		return pick(true, false)
	case 2:
		return json.Number("0")
	case 3:
		return json.Number("-1")
	case 4:
		return json.Number("9007199254740991")
	case 5:
		return json.Number("9007199254740992")
	case 6:
		return json.Number("-0")
	case 7:
		return json.Number("1.5")
	case 8:
		return json.Number("1e3")
	case 9:
		return ""
	case 10:
		return "x"
	case 11:
		return strings.Repeat("a", pick(3000, 70000))
	case 12:
		return []any{}
	case 13:
		return map[string]any{}
	case 14:
		return someHash()
	case 15:
		return someHash() + "="
	case 16:
		h := someHash()
		return h[:42] + "B" // non-zero trailing bits
	case 17:
		return S.DID()
	case 18:
		return "did:key:z6MkBad"
	case 19:
		return pick("sys/undo", "sys/tallies", "sys/other")
	case 20:
		return pick("travel", "travel/", "travel/charge", "travel/chargeback", "travel/charge/x", "")
	case 21:
		return "e\u0301"
	case 22:
		return deep(70)
	case 23:
		return deep(12)
	case 24:
		return []any{json.Number("1"), "1"}
	case 25:
		return randBound()
	case 26:
		return pick(A.DID(), B.DID(), C.DID(), D.DID())
	case 27:
		return "*"
	case 28:
		return n(pick(now, base.w2.Exp, base.w2.Exp-1, base.w1.Exp, base.w1.Exp+1))
	case 29:
		return json.Number("-9007199254740992")
	case 30:
		return wire.B64.EncodeToString([]byte("short"))
	default:
		return map[string]any{"code": pick("x", "pending", "unknown_outcome")}
	}
}

var boundTypes = []string{"max", "count", "prefix", "set", "window", "bogus"}

func randBound() any {
	t := pick(boundTypes...)
	var v any
	switch t {
	case "max", "count":
		v = pick[any](n(0), n(1), n(58900), n(60000), n(-1), json.Number("9007199254740991"), json.Number("1.5"), "7")
	case "prefix":
		v = pick[any]("travel", "travel/", "travel/charge", "", "trave", "travel/charge/x", "sys/", "a/", n(1))
	case "set":
		pool := []any{"USD", "EUR", n(1), "1", "refundable", n(2), C.DID()}
		arr := []any{}
		for i := r.IntN(4); i > 0; i-- {
			arr = append(arr, pick(pool...))
		}
		v = arr
		if chance(0.1) {
			v = "USD"
		}
	case "window":
		lo, hi := pick(int64(20261015), 20261016, 0, -5), pick(int64(20261019), 20261016, 20261014, 0)
		v = pick[any]([]any{n(lo), n(hi)}, []any{n(hi), n(lo)}, []any{n(lo)}, []any{n(lo), n(hi), n(1)}, "x")
	default:
		v = n(1)
	}
	b := map[string]any{"t": t, "v": v}
	switch r.IntN(12) {
	case 0:
		b["x"] = n(1)
	case 1:
		delete(b, "v")
	case 2:
		delete(b, "t")
	}
	return b
}

// relatedBound returns a bound shaped like one the base objects carry, with
// its value nudged, so narrows and satisfies meet near-miss pairs often.
func relatedBound(b any) any {
	m, ok := clone(b).(map[string]any)
	if !ok {
		return randBound()
	}
	switch v := m["v"].(type) {
	case json.Number:
		i, _ := v.Int64()
		m["v"] = n(i + pick[int64](-1, 0, 1, -i-1))
	case []any:
		switch r.IntN(4) {
		case 0:
			if len(v) > 0 {
				m["v"] = v[:len(v)-1]
			}
		case 1:
			m["v"] = append(v, pick[any]("EUR", n(3), "USD"))
		case 2:
			if len(v) == 2 {
				a, ok1 := v[0].(json.Number)
				b, ok2 := v[1].(json.Number)
				if ok1 && ok2 {
					lo, _ := a.Int64()
					hi, _ := b.Int64()
					m["v"] = []any{n(lo + pick[int64](-1, 0, 1)), n(hi + pick[int64](-1, 0, 1))}
				}
			}
		default:
		}
	case string:
		m["v"] = pick(v, v+"/", v+"/x", strings.TrimSuffix(v, "/"), v[:len(v)/2])
	}
	return m
}

func argFor(b any) any {
	m, _ := b.(map[string]any)
	switch v := m["v"].(type) {
	case json.Number:
		i, _ := v.Int64()
		return n(i + pick[int64](-1, 0, 1, -i, -i-1))
	case []any:
		if len(v) > 0 && chance(0.6) {
			return pick(v...)
		}
		if len(v) == 2 {
			return pick[any](v[0], v[1], n(20261014), n(20261020))
		}
	case string:
		return pick(v, v+"/x", v+"x", "")
	}
	return interesting()
}

// ------------------------------------------------------------ mutation

var memberNames = []string{"x", "crit", "zz", "sig", "v", "typ", "act", "é", "A"}

// mutate applies one random mutation somewhere in v and returns the result
// with a short description.
func mutate(v any) (any, string) {
	var ps [][]step
	paths(v, nil, &ps, 0)
	if len(ps) == 0 {
		return interesting(), "replace root"
	}
	p := ps[r.IntN(len(ps))]
	cur := get(v, p)
	where := describe(p)
	switch r.IntN(10) {
	case 0, 1, 2, 3:
		return set(v, p, interesting()), "replace " + where
	case 4, 5, 6:
		switch x := cur.(type) {
		case string:
			var nv string
			switch r.IntN(4) {
			case 0:
				nv = x + pick("x", "/", "=", "A")
			case 1:
				if len(x) > 0 {
					nv = x[:len(x)-1]
				}
			case 2:
				nv = strings.ToUpper(x)
			default:
				nv = "sys/" + x
			}
			return set(v, p, nv), "edit " + where
		case json.Number:
			i, err := x.Int64()
			if err != nil {
				return set(v, p, n(1)), "edit " + where
			}
			return set(v, p, n(i+pick[int64](1, -1, -i, i*1000))), "nudge " + where
		case bool:
			return set(v, p, !x), "flip " + where
		case map[string]any:
			if chance(0.5) || len(x) == 0 {
				x[pick(memberNames...)] = interesting()
				return v, "add member in " + where
			}
			ks := make([]string, 0, len(x))
			for k := range x {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			delete(x, pick(ks...))
			return v, "drop member in " + where
		case []any:
			switch r.IntN(4) {
			case 0:
				if len(x) > 0 {
					return set(v, p, append(x, clone(x[r.IntN(len(x))]))), "duplicate element in " + where
				}
			case 1:
				if len(x) > 1 {
					i, j := r.IntN(len(x)), r.IntN(len(x))
					x[i], x[j] = x[j], x[i]
					return v, "swap elements in " + where
				}
			case 2:
				if len(x) > 0 {
					return set(v, p, x[:len(x)-1]), "truncate " + where
				}
			}
			return set(v, p, append(x, interesting())), "append to " + where
		}
		return set(v, p, interesting()), "replace " + where
	case 7, 8:
		return set(v, p, deleted), "delete " + where
	default:
		parent := p[:len(p)-1]
		if m, ok := get(v, parent).(map[string]any); ok {
			m[pick(memberNames...)] = interesting()
			return v, "add member beside " + where
		}
		return set(v, p, interesting()), "replace " + where
	}
}

// mutateBounds rewrites one bound of a writ-shaped object.
func mutateBounds(o map[string]any) string {
	b, ok := o["bnd"].(map[string]any)
	if !ok {
		return "bnd not an object"
	}
	names := make([]string, 0, len(b))
	for k := range b {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		b["act"] = randBound()
		return "set bound act"
	}
	switch r.IntN(6) {
	case 0:
		name := pick(names...)
		delete(b, name)
		return "drop bound " + name
	case 1:
		name := pick("amount", "zz", "hld", "depth", "extra", "act", "a")
		b[name] = randBound()
		return "set bound " + name
	case 2:
		name := pick(names...)
		if m, ok := b[name].(map[string]any); ok {
			m["t"] = pick(boundTypes...)
		}
		return "retype bound " + name
	default:
		name := pick(names...)
		b[name] = relatedBound(b[name])
		return "nudge bound " + name
	}
}

func mutateN(v any, bounds bool) (any, []string) {
	var desc []string
	for i := 1 + r.IntN(3); i > 0; i-- {
		if m, ok := v.(map[string]any); ok && bounds && chance(0.4) {
			desc = append(desc, mutateBounds(m))
			continue
		}
		var d string
		v, d = mutate(v)
		desc = append(desc, d)
	}
	return v, desc
}

// resign signs o with the key its signer member names when this program
// holds that key, else with fallback. It leaves o alone when o cannot be
// signed at all (a non-integer number, a bad v).
func resign(o any, fallback *keys.Identity) {
	m, ok := o.(map[string]any)
	if !ok || m == nil {
		return
	}
	signer := fallback
	typ, _ := m["typ"].(string)
	member := map[string]string{"writ": "iss", "call": "from", "revoke": "iss", "ack": "iss"}[typ]
	if s, ok := m[member].(string); ok && ids[s] != nil {
		signer = ids[s]
	}
	_ = wire.Sign(m, signer)
}

// relink repairs prv links after chain[i] changed, re-signing each child.
func relink(chain []any, i int) {
	for j := i + 1; j < len(chain); j++ {
		parent, ok1 := chain[j-1].(map[string]any)
		child, ok2 := chain[j].(map[string]any)
		if !ok1 || !ok2 {
			return
		}
		h, err := wire.Hash(parent)
		if err != nil {
			return
		}
		child["prv"] = h
		resign(child, B)
	}
}

func chainOf(ws ...*writ.Writ) []any {
	out := []any{}
	for _, w := range ws {
		out = append(out, clone(w.Raw))
	}
	return out
}

func mutateChain(chain []any) ([]any, []string) {
	if chance(0.2) {
		switch r.IntN(5) {
		case 0:
			if len(chain) > 1 {
				chain[0], chain[1] = chain[1], chain[0]
				return chain, []string{"swap chain[0] and chain[1]"}
			}
		case 1:
			return chain[:len(chain)-1], []string{"drop the leaf"}
		case 2:
			for len(chain) < 9 {
				chain = append(chain, clone(chain[len(chain)-1]))
			}
			return chain, []string{"extend to nine"}
		case 3:
			return append(chain, clone(chain[0])), []string{"repeat the root at the end"}
		default:
			chain[r.IntN(len(chain))] = interesting()
			return chain, []string{"replace a writ with a non-writ"}
		}
	}
	i := r.IntN(len(chain))
	v, desc := mutateN(chain[i], true)
	chain[i] = v
	if chance(0.8) {
		resign(chain[i], A)
	}
	if chance(0.7) {
		relink(chain, i)
		desc = append(desc, "relinked")
	}
	for k := range desc {
		desc[k] = fmt.Sprintf("chain[%d]: %s", i, desc[k])
	}
	return chain, desc
}

// ------------------------------------------------------------ JSON texts

var (
	numTokens = []string{"0", "-0", "1", "-1", "10", "1.0", "1.5", "1e3", "1E3", "1e-3", "01", "-01", "+1",
		"9007199254740991", "-9007199254740991", "9007199254740992", "-9007199254740992",
		"123456789012345678901234567890", "0.0", "-0.0", "1.", ".5", "0x10"}
	strTokens = []string{`"a"`, `""`, `"\u0000"`, `"\u001f"`, "\"\x01\"", `"😀"`, `"\ud800"`, `"\udc00"`,
		`"\ud800\ud800"`, `"\udc00\ud800"`, `"\/"`, `"\b\f\n\r\t"`, `"é"`, `"😀"`, `"é"`, `"€"`, `"a\"b"`,
		`"\x"`, `"\u12"`, `"é"`, "\"e\u0301\"", `"\u2028"`, "\"\u2028\""}
	keyTokens = []string{`"a"`, `"b"`, `"€"`, `"\r"`, `"1"`, `"😀"`, `"ö"`, `"A"`, `""`, `"a"`}
	wsTokens  = []string{"", "", "", " ", "\t", "\n", "\r", "\u00a0", "\u2028"}
	litTokens = []string{"true", "false", "null", "nul", "TRUE", "True"}
)

func ws() string { return pick(wsTokens...) }

func text(d int) string {
	k := r.IntN(10)
	if d > 5 && k > 5 {
		k = r.IntN(6)
	}
	switch {
	case k < 3:
		return pick(numTokens...)
	case k < 5:
		return pick(strTokens...)
	case k < 6:
		return pick(litTokens...)
	case k < 8:
		var parts []string
		for i := r.IntN(4); i > 0; i-- {
			parts = append(parts, ws()+text(d+1)+ws())
		}
		tail := ""
		if chance(0.05) {
			tail = ","
		}
		return "[" + strings.Join(parts, ",") + tail + "]"
	default:
		var parts []string
		keys := map[string]bool{}
		for i := r.IntN(4); i > 0; i-- {
			key := pick(keyTokens...)
			if keys[key] && chance(0.7) {
				continue
			}
			keys[key] = true
			parts = append(parts, ws()+key+ws()+":"+ws()+text(d+1)+ws())
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
}

func rawText() (string, string) {
	t := text(0)
	switch r.IntN(20) {
	case 0:
		return "\ufeff" + t, "bom"
	case 1:
		return t + " " + text(3), "trailing data"
	case 2:
		return strings.Repeat("[", 70) + t + strings.Repeat("]", 70), "nested 70"
	case 3:
		return strings.Repeat("[", 30) + t + strings.Repeat("]", 30), "nested 30"
	case 4:
		return ws() + t + ws(), "surrounding whitespace"
	}
	return t, "grammar"
}

// ------------------------------------------------------------ vectors

type vec struct {
	op    string
	input map[string]any
	now   *int64
	desc  []string
}

func maybeNow(p float64) *int64 {
	if !chance(p) {
		return nil
	}
	t := pick(base.exps...)
	return &t
}

func gen() vec {
	switch k := r.IntN(108); {
	case k >= 100:
		return genCheckAck()
	case k < 14:
		raw, d := rawText()
		return vec{op: "canonicalize", input: map[string]any{"raw": raw}, desc: []string{d}}
	case k < 23:
		var child, parent any
		if chance(0.6) {
			parent = clone(pick(base.boundsSeen...))
			child = relatedBound(parent)
		} else {
			child, parent = randBound(), randBound()
		}
		return vec{op: "narrows", input: map[string]any{"child": child, "parent": parent}, desc: []string{"bound pair"}}
	case k < 30:
		b := clone(pick(base.boundsSeen...))
		if chance(0.3) {
			b = randBound()
		}
		// Spec section 14: satisfies never takes a count bound, whose
		// "argument satisfies" rule section 3 leaves undefined.
		if m, ok := b.(map[string]any); ok && m["t"] == "count" {
			m["t"] = "max"
		}
		return vec{op: "satisfies", input: map[string]any{"bound": b, "arg": argFor(b)}, desc: []string{"bound and argument"}}
	case k < 44:
		w := pick(base.w1, base.w2, base.v3)
		o, desc := mutateN(clone(w.Raw), true)
		if chance(0.8) {
			resign(o, ids[w.Iss])
		}
		return vec{op: "verify_writ", input: map[string]any{"writ": o}, desc: desc}
	case k < 55:
		chain := pick(chainOf(base.w1, base.w2), chainOf(base.v1, base.v2, base.v3))
		chain, desc := mutateChain(chain)
		return vec{op: "verify_chain", input: map[string]any{"chain": chain}, now: maybeNow(0.5), desc: desc}
	case k < 73:
		k := pick(base.kFwd, base.kFwd3, base.kAB, base.kUndo, base.kTal)
		o := clone(k.Raw).(map[string]any)
		var desc []string
		switch r.IntN(4) {
		case 0:
			ch, d := mutateChain(o["chain"].([]any))
			o["chain"], desc = ch, d
		case 1:
			o["op"] = pick[any]("travel/charge", "travel/chargeback", "travel/charge/x", "travel", "sys/undo",
				"sys/tallies", "sys/other", "SYS/undo", "", "travel//charge", "travel/book", "sys/")
			desc = []string{fmt.Sprintf("op %v", o["op"])}
		case 2:
			args, _ := o["args"].(map[string]any)
			leaf := k.Leaf().Raw["bnd"].(map[string]any)
			names := make([]string, 0, len(leaf))
			for name := range leaf {
				names = append(names, name)
			}
			sort.Strings(names)
			name := pick(names...)
			if chance(0.3) {
				delete(args, name)
				desc = []string{"drop arg " + name}
			} else {
				args[name] = argFor(leaf[name])
				desc = []string{"arg " + name}
			}
			if chance(0.3) {
				var more []string
				o["args"], more = mutateN(args, false)
				desc = append(desc, more...)
			}
		default:
			var v any
			v, desc = mutateN(o, false)
			o, _ = v.(map[string]any)
		}
		if chance(0.8) {
			resign(o, B)
		}
		return vec{op: "verify_call", input: map[string]any{"call": o}, now: maybeNow(0.4), desc: desc}
	case k < 88:
		type pair struct {
			w      *writ.Writ
			k      *writ.Call
			t      wire.Object
			res    any
			signer *keys.Identity
		}
		p := pick(pair{base.w2, base.kFwd, base.tC, base.resC, C}, pair{base.w1, base.kAB, base.tB, base.resB, B})
		t := clone(p.t).(map[string]any)
		var desc []string
		switch {
		case p.signer == B && chance(0.3):
			sub := t["sub"].([]any)
			s, d := mutateN(sub[0], false)
			if chance(0.8) {
				resign(s, C)
			}
			sub[0] = s
			for _, x := range d {
				desc = append(desc, "sub[0]: "+x)
			}
		case chance(0.5):
			member := pick("acc", "st", "err", "out", "used", "rev", "sub", "wrt", "call", "writ", "op")
			var v any
			switch member {
			case "acc":
				v = n(pick(p.w.Exp-1, p.w.Exp, p.w.Exp+1, 0, now))
			case "st":
				v = pick("ok", "failed", "canceled", "pending", "done")
			case "err":
				v = pick[any](nil, map[string]any{"code": "x"}, map[string]any{"code": "pending"}, map[string]any{"code": n(1)},
					map[string]any{"code": "x", "ref": someHash()}, map[string]any{"code": "x", "ref": "bad"})
			case "used":
				v = pick[any](map[string]any{}, map[string]any{"amount": n(58900)}, map[string]any{"amount": n(60001)},
					map[string]any{"amount": n(-1)}, map[string]any{"zz": n(5)})
			case "rev":
				v = pick[any](nil, map[string]any{"until": n(now + 10)}, map[string]any{"until": "x"}, map[string]any{})
			default:
				v = interesting()
			}
			t[member] = v
			desc = []string{"tally." + member}
		default:
			var v any
			v, desc = mutateN(t, false)
			t, _ = v.(map[string]any)
		}
		if chance(0.8) {
			resign(t, p.signer)
		}
		in := map[string]any{"writ": clone(p.w.Raw), "call": clone(p.k.Raw), "tally": t}
		switch r.IntN(6) {
		case 0:
			desc = append(desc, "no body")
		case 1:
			in["res"] = interesting()
			desc = append(desc, "other body")
		default:
			in["res"] = clone(p.res)
		}
		return vec{op: "verify_tally", input: in, now: maybeNow(0.2), desc: desc}
	default:
		o := clone(pick(base.rv1, base.rv2, base.rvStar)).(map[string]any)
		var desc []string
		if chance(0.5) {
			member := pick("writ", "chain", "iss")
			switch member {
			case "writ":
				o["writ"] = pick[any]("*", base.w1.ID, base.w2.ID, someHash(), "x")
			case "chain":
				o["chain"] = pick(chainOf(), chainOf(base.w1), chainOf(base.w1, base.w2), chainOf(base.w2, base.w1), chainOf(base.w2))
			default:
				o["iss"] = pick(A.DID(), B.DID(), C.DID(), S.DID(), "did:key:z6MkBad")
			}
			desc = []string{"revoke." + member}
		} else {
			var v any
			v, desc = mutateN(o, false)
			o, _ = v.(map[string]any)
		}
		if chance(0.8) {
			resign(o, A)
		}
		return vec{op: "verify_revoke", input: map[string]any{"revoke": o}, desc: desc}
	}
}

// genCheckAck mutates one input of a section 9.4 check: the revoke, the ack,
// its body, the chain, or the tally. A changed body is usually re-committed
// by re-signing the ack over it, so the input reaches steps 5 to 7.
func genCheckAck() vec {
	ack := clone(base.ack).(map[string]any)
	var body any = clone(base.ackBody)
	chain := chainOf(base.w1, base.w2)
	rv := clone(pick(base.rv1, base.rv1, base.rv1, base.rv2, base.rvStar))
	tally := clone(pick(base.ackTallies...))
	var desc []string
	recommit := func() {
		if h, err := writ.HashResult(body); err == nil {
			ack["out"] = h
		}
		resign(ack, C)
	}
	switch pick("ack", "ack", "body", "body", "chain", "tally", "tally", "revoke", "none") {
	case "ack":
		if chance(0.5) {
			member := pick("revoke", "iss", "rcv", "out", "typ", "v")
			switch member {
			case "rcv":
				ack["rcv"] = pick[any](n(now), n(now+1799), n(now+1800), n(now+40), "soon")
			case "iss":
				ack["iss"] = pick(C.DID(), D.DID(), B.DID(), "did:key:z6MkBad")
			default:
				ack[member] = interesting()
			}
			desc = []string{"ack." + member}
		} else {
			var v any
			v, desc = mutateN(ack, false)
			ack, _ = v.(map[string]any)
		}
		if chance(0.8) {
			resign(ack, C)
		}
	case "body":
		b, _ := body.(map[string]any)
		switch r.IntN(4) {
		case 0:
			b["open"] = append(b["open"].([]any), pick[any](base.kLate.ID, base.kFwd.ID, 7))
			desc = []string{"body.open gains an entry"}
		case 1:
			b["held"] = []any{}
			desc = []string{"body.held emptied"}
		case 2:
			b["held"] = append(b["held"].([]any), map[string]any{"call": base.kLate.ID, "tally": pick[any](someHash(), nil)})
			desc = []string{"body.held gains a call"}
		default:
			var v any
			v, desc = mutateN(b, false)
			body = v
		}
		if chance(0.7) {
			recommit()
			desc = append(desc, "ack re-signed over it")
		}
	case "chain":
		chain, desc = mutateChain(chain)
	case "tally":
		var v any
		v, desc = mutateN(tally, false)
		tally = v
		if chance(0.8) {
			resign(tally, C)
		}
	case "revoke":
		var v any
		v, desc = mutateN(rv, false)
		rv = v
		if chance(0.8) {
			resign(rv, A)
		}
	default:
		desc = []string{"unmutated"}
	}
	in := map[string]any{"revoke": rv, "ack": ack, "chain": chain, "tally": tally}
	if !chance(0.05) {
		in["res"] = body
	} else {
		desc = append(desc, "no body")
	}
	return vec{op: "check_ack", input: in, desc: desc}
}

func main() {
	var seed uint64
	var count int
	var dir string
	flag.Uint64Var(&seed, "seed", 1, "random seed; the same seed yields the same files")
	flag.IntVar(&count, "n", 2000, "number of vectors")
	flag.StringVar(&dir, "out", "", "output directory (replaced)")
	flag.Parse()
	if dir == "" {
		fmt.Fprintln(os.Stderr, "usage: writ-fuzz -seed <n> -n <count> -out <dir>")
		os.Exit(2)
	}
	setup()
	r = rand.New(rand.NewPCG(seed, 0x57726974))
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	tally := map[string]int{}
	written, skipped := 0, 0
	for i := 0; written < count; i++ {
		g := gen()
		in, err := json.Marshal(g.input)
		if err != nil {
			skipped++
			continue
		}
		v := conformance.Vector{Op: g.op, Input: in, Now: g.now}
		vd, herr := conformance.Judge(v)
		if herr != nil {
			skipped++
			continue
		}
		out := map[string]any{"name": fmt.Sprintf("fuzz %d/%d %s: %s", seed, i, g.op, strings.Join(g.desc, "; ")), "op": g.op, "input": g.input}
		if vd.Err == nil {
			out["expect"] = "accept"
			if g.op == "canonicalize" {
				g.input["canonical"] = vd.Canonical
			}
			tally[g.op+" accept"]++
		} else {
			out["expect"] = "reject"
			out["reason"] = string(vd.Reason)
			tally[g.op+" "+string(vd.Reason)]++
		}
		if g.now != nil {
			out["now"] = *g.now
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(out); err != nil {
			skipped++
			continue
		}
		written++
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%05d_%s.json", written, g.op)), buf.Bytes(), 0o644); err != nil {
			panic(err)
		}
	}
	keys := make([]string, 0, len(tally))
	for k := range tally {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%6d  %s\n", tally[k], k)
	}
	fmt.Printf("wrote %d vectors (seed %d, %d generated inputs skipped) to %s\n", written, seed, skipped, dir)
}
