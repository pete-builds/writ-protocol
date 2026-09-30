package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"writproto/jcs"
)

// A route's request contract. The call signs its args; the contract says
// where in the request each one travels, and that nothing else does. The gate
// refuses a request that carries anything the contract does not name, or that
// an API could read two ways, and it never forwards the caller's bytes: it
// rebuilds the request from the signed args, so the API receives exactly the
// operation and the values that were authorized (docs/writ-gate.md).

// Reasons the gate refuses a request before the executor sees it, with status
// 400. The first two are the spec's own reason codes; the rest are the gate's.
const (
	reasonMalformed    = "malformed"    // the request does not carry what the call signed
	reasonNoncanonical = "noncanonical" // the body is not one strict JSON value (duplicates, trailing data)
	reasonAmbiguous    = "gate/ambiguous_member"
	reasonUnbound      = "gate/unbound_member"
	reasonQuery        = "gate/unbound_query"
	reasonTooLarge     = "too_large"
)

// contract is a Route compiled and checked when the gate starts.
type contract struct {
	name   string
	route  Route
	method string
	segs   []string          // the path pattern, split on "/"
	params map[string]string // path parameter name to the argument it carries
	body   *member           // the body's members; nil when the route takes no body
	usedOf map[string]string // max bound name to the argument whose value it consumes
}

// member is one object member of the body the contract names: a bound
// argument, or an object holding further members.
type member struct {
	arg  string
	kids map[string]*member
}

func compile(name string, r Route) (*contract, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("route %s: "+format, append([]any{name}, a...)...)
	}
	if r.Method == "" || r.Act == "" || !strings.HasPrefix(r.Path, "/") {
		return nil, bad("needs a method, an act, and a path starting with /")
	}
	c := &contract{name: name, route: r, method: strings.ToUpper(r.Method),
		segs: strings.Split(strings.Trim(r.Path, "/"), "/"), params: map[string]string{}, usedOf: map[string]string{}}
	declared := map[string]bool{}
	for _, s := range c.segs {
		if p, ok := paramName(s); ok {
			if p == "" || declared[p] {
				return nil, bad("path parameter {%s} is empty or repeated", p)
			}
			declared[p] = true
		}
	}
	bodyArg := map[string]string{} // body path to argument
	for _, arg := range sortedKeys(r.Bind) {
		src := r.Bind[arg]
		if p, ok := paramName(src); ok {
			if !declared[p] {
				return nil, bad("%s binds {%s}, which the path does not have", arg, p)
			}
			if prev, ok := c.params[p]; ok {
				return nil, bad("{%s} is bound to both %s and %s", p, prev, arg)
			}
			c.params[p] = arg
			continue
		}
		keys, err := bodyPath(src)
		if err != nil {
			return nil, bad("%s: %v", arg, err)
		}
		if c.body == nil {
			c.body = &member{kids: map[string]*member{}}
		}
		if err := c.body.add(keys, arg); err != nil {
			return nil, bad("%s at %s: %v", arg, src, err)
		}
		bodyArg[src] = arg
	}
	for p := range declared {
		if _, ok := c.params[p]; !ok {
			return nil, bad("path parameter {%s} is not bound, so a caller could send the call to any value of it", p)
		}
	}
	for bound, src := range r.Used {
		arg, ok := bodyArg[src]
		if !ok {
			return nil, bad("used.%s reads %s, which is not a bound body member, so the tally would report an unsigned value", bound, src)
		}
		c.usedOf[bound] = arg
	}
	return c, nil
}

func paramName(s string) (string, bool) {
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) >= 2 {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// bodyPath splits "$.a.b" into its member names.
func bodyPath(src string) ([]string, error) {
	if !strings.HasPrefix(src, "$.") {
		return nil, errors.New(`a body path starts with "$." and a path parameter is written {name}`)
	}
	keys := strings.Split(src[2:], ".")
	for _, k := range keys {
		if k == "" {
			return nil, errors.New("a body path has no empty member names")
		}
	}
	return keys, nil
}

// add places a bound argument at keys. Two bound members may not be the same
// member, one may not lie inside another, and no two members of one object
// may be names an API could fold into one.
func (m *member) add(keys []string, arg string) error {
	for i, k := range keys {
		if m.arg != "" {
			return errors.New("it lies inside another bound member")
		}
		next, ok := m.kids[k]
		if !ok {
			for other := range m.kids {
				if foldKey(other) == foldKey(k) {
					return fmt.Errorf("%q and %q differ only in case, so an API could read one as the other", other, k)
				}
			}
			next = &member{kids: map[string]*member{}}
			m.kids[k] = next
		}
		if i == len(keys)-1 && (next.arg != "" || len(next.kids) > 0) {
			return errors.New("that member is already bound, or holds bound members")
		}
		m = next
	}
	m.arg = arg
	return nil
}

// match reports whether path fits the route and, if so, the value of each
// path parameter.
func (c *contract) match(method, path string) (map[string]string, bool) {
	if !strings.EqualFold(method, c.method) {
		return nil, false
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) != len(c.segs) {
		return nil, false
	}
	vals := map[string]string{}
	for i, p := range c.segs {
		if name, ok := paramName(p); ok {
			if segs[i] == "" {
				return nil, false
			}
			vals[name] = segs[i]
		} else if p != segs[i] {
			return nil, false
		}
	}
	return vals, true
}

// extract reads the arguments a request carries, refusing anything the
// contract does not name. What it returns must then equal the call's args.
func (c *contract) extract(query string, params map[string]string, body []byte) (map[string]any, string) {
	if query != "" {
		return nil, reasonQuery
	}
	args := map[string]any{}
	for p, v := range params {
		// A dot segment names a different resource once the API normalizes the
		// path; no signed value may be one.
		if v == "." || v == ".." {
			return nil, reasonMalformed
		}
		args[c.params[p]] = v
	}
	if c.body == nil {
		if len(body) != 0 {
			return nil, reasonUnbound
		}
		return args, ""
	}
	doc, reason := strictObject(body)
	if reason != "" {
		return nil, reason
	}
	if ambiguous(doc) {
		return nil, reasonAmbiguous
	}
	if reason := c.body.read(doc, args); reason != "" {
		return nil, reason
	}
	return args, ""
}

// strictObject parses a body that is exactly one JSON object, with no
// duplicate member at any depth, no unpaired surrogate, no invalid UTF-8,
// and nothing after it but whitespace.
func strictObject(body []byte) (map[string]any, string) {
	if jcs.CheckDepth(body) != nil {
		return nil, reasonTooLarge
	}
	if jcs.Strict(body) != nil {
		return nil, reasonNoncanonical
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, reasonNoncanonical
	}
	for _, b := range body[dec.InputOffset():] {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return nil, reasonNoncanonical
		}
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, reasonMalformed
	}
	return obj, ""
}

// ambiguous reports whether any object in v has two member names that are
// equal under Unicode simple case folding, which is how encoding/json and
// other case-insensitive decoders match names to fields.
func ambiguous(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		seen := make(map[string]bool, len(x))
		for k, e := range x {
			f := foldKey(k)
			if seen[f] || ambiguous(e) {
				return true
			}
			seen[f] = true
		}
	case []any:
		for _, e := range x {
			if ambiguous(e) {
				return true
			}
		}
	}
	return false
}

// foldKey maps s to one representative of its case-folding class: each rune
// becomes the smallest rune in its simple folding orbit, so two strings have
// the same key exactly when strings.EqualFold reports them equal.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

// read walks one object of the body against the contract.
func (m *member) read(obj map[string]any, args map[string]any) string {
	for k := range obj {
		if m.kids[k] == nil {
			return reasonUnbound
		}
	}
	for k, kid := range m.kids {
		v, ok := obj[k]
		if !ok {
			return reasonMalformed
		}
		if kid.arg != "" {
			args[kid.arg] = v
			continue
		}
		inner, ok := v.(map[string]any)
		if !ok {
			return reasonMalformed
		}
		if reason := kid.read(inner, args); reason != "" {
			return reason
		}
	}
	return ""
}

// target rebuilds the request the API receives from the signed args alone:
// the route's method, its path with each parameter filled in, and a body in
// canonical form holding each bound member once.
func (c *contract) target(args map[string]any) (method, path string, body []byte, err error) {
	segs := make([]string, len(c.segs))
	for i, s := range c.segs {
		segs[i] = s
		if p, ok := paramName(s); ok {
			v, ok := args[c.params[p]].(string)
			if !ok {
				return "", "", nil, fmt.Errorf("path parameter %s is not a signed string", p)
			}
			segs[i] = url.PathEscape(v)
		}
	}
	path = "/" + strings.Join(segs, "/")
	if c.body != nil {
		body, err = jcs.Marshal(c.body.build(args))
	}
	return c.method, path, body, err
}

func (m *member) build(args map[string]any) map[string]any {
	out := make(map[string]any, len(m.kids))
	for k, kid := range m.kids {
		if kid.arg != "" {
			out[k] = args[kid.arg]
		} else {
			out[k] = kid.build(args)
		}
	}
	return out
}

// used reports, for each max bound the route names, the signed integer the
// request consumes.
func (c *contract) used(args map[string]any) map[string]int64 {
	if len(c.usedOf) == 0 {
		return nil
	}
	out := map[string]int64{}
	for name, arg := range c.usedOf {
		if n, ok := args[arg].(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				out[name] = i
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
