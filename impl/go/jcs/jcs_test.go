package jcs

import (
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{}`, `{}`},
		{`[]`, `[]`},
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{ "z" : [ 1 , 2 , {"y":null,"x":true} ] , "a":"s" }`, `{"a":"s","z":[1,2,{"x":true,"y":null}]}`},
		// RFC 8785 section 3.2.3 key ordering example (UTF-16 code unit order).
		{"{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}",
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
		// String escaping: only quote, backslash, and controls; non-ASCII literal.
		{`"a\u0041\u00e9\u0001\n\"\\\/"`, "\"aA\u00e9\\u0001\\n\\\"\\\\/\""},
		{`-0`, `0`},
		{`"\ud83d\ude00"`, "\"\U0001F600\""},
		{`{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`},
		{`9007199254740991`, `9007199254740991`},
	}
	for _, c := range cases {
		got, err := Canonicalize([]byte(c.in))
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.in, got, c.want)
		}
	}
}

func TestRejects(t *testing.T) {
	bad := []string{
		`1.5`, `1e3`, `1.0`, `9007199254740992`, `-9007199254740992`,
		`{"a":1} x`, `{"a":1.0}`, `[1,2`,
		`{"a":1,"a":2}`, `{"a":{"b":1,"c":2,"b":3}}`, `[{"k":1,"k":1}]`,
		`"\ud800"`, `"\udc00"`, `"\ud800\u0041"`, `{"\udfff":1}`,
		"\"\xff\"",
	}
	for _, b := range bad {
		if _, err := Canonicalize([]byte(b)); err == nil {
			t.Errorf("%q: expected error, got none", b)
		}
	}
}

func TestIdempotent(t *testing.T) {
	in := `{"k":[{"b":2,"a":1},"x",null,true]}`
	once, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent: %s vs %s", once, twice)
	}
	if strings.ContainsAny(string(once), " \n\t") {
		t.Fatalf("whitespace in output: %s", once)
	}
}
