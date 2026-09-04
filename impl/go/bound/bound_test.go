package bound

import (
	"bytes"
	"encoding/json"
	"testing"
)

func parse(t *testing.T, s string) Bound {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	b, err := Parse(v)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return b
}

func arg(s string) any {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	_ = dec.Decode(&v)
	return v
}

func TestNarrows(t *testing.T) {
	ok := [][2]string{
		{`{"t":"max","v":100}`, `{"t":"max","v":100}`},
		{`{"t":"max","v":99}`, `{"t":"max","v":100}`},
		{`{"t":"count","v":0}`, `{"t":"count","v":1}`},
		{`{"t":"prefix","v":"travel/charge"}`, `{"t":"prefix","v":"travel/"}`},
		{`{"t":"prefix","v":""}`, `{"t":"prefix","v":""}`},
		{`{"t":"set","v":["USD"]}`, `{"t":"set","v":["USD","EUR"]}`},
		{`{"t":"set","v":[]}`, `{"t":"set","v":["USD"]}`},
		{`{"t":"set","v":[1]}`, `{"t":"set","v":[1,2]}`},
		{`{"t":"window","v":[5,6]}`, `{"t":"window","v":[1,10]}`},
		{`{"t":"window","v":[1,10]}`, `{"t":"window","v":[1,10]}`},
	}
	for _, c := range ok {
		if err := Narrows(parse(t, c[0]), parse(t, c[1])); err != nil {
			t.Errorf("%s under %s: unexpected %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{
		{`{"t":"max","v":101}`, `{"t":"max","v":100}`},
		{`{"t":"count","v":2}`, `{"t":"count","v":1}`},
		{`{"t":"prefix","v":"travel"}`, `{"t":"prefix","v":"travel/"}`},
		{`{"t":"prefix","v":"admin/"}`, `{"t":"prefix","v":"travel/"}`},
		{`{"t":"set","v":["GBP"]}`, `{"t":"set","v":["USD","EUR"]}`},
		{`{"t":"set","v":["1"]}`, `{"t":"set","v":[1]}`}, // string "1" is not integer 1
		{`{"t":"window","v":[0,6]}`, `{"t":"window","v":[1,10]}`},
		{`{"t":"window","v":[5,11]}`, `{"t":"window","v":[1,10]}`},
		{`{"t":"count","v":1}`, `{"t":"max","v":1}`}, // type change
	}
	for _, c := range bad {
		if err := Narrows(parse(t, c[0]), parse(t, c[1])); err == nil {
			t.Errorf("%s under %s: expected rejection", c[0], c[1])
		}
	}
}

func TestSatisfies(t *testing.T) {
	ok := [][2]string{
		{`{"t":"max","v":100}`, `100`},
		{`{"t":"max","v":100}`, `0`},
		{`{"t":"prefix","v":"travel/"}`, `"travel/charge"`},
		{`{"t":"set","v":["USD","EUR"]}`, `"EUR"`},
		{`{"t":"set","v":[1,2]}`, `2`},
		{`{"t":"window","v":[1,10]}`, `10`},
	}
	for _, c := range ok {
		if err := Satisfies(parse(t, c[0]), arg(c[1])); err != nil {
			t.Errorf("%s satisfies %s: unexpected %v", c[1], c[0], err)
		}
	}
	bad := [][2]string{
		{`{"t":"max","v":100}`, `101`},
		{`{"t":"max","v":100}`, `-1`},
		{`{"t":"max","v":100}`, `"100"`},
		{`{"t":"max","v":100}`, `1.5`},
		{`{"t":"prefix","v":"travel/"}`, `"admin/charge"`},
		{`{"t":"set","v":["USD"]}`, `"usd"`},
		{`{"t":"set","v":[1]}`, `"1"`},
		{`{"t":"window","v":[1,10]}`, `11`},
		{`{"t":"count","v":1}`, `1`},
	}
	for _, c := range bad {
		if err := Satisfies(parse(t, c[0]), arg(c[1])); err == nil {
			t.Errorf("%s satisfies %s: expected rejection", c[1], c[0])
		}
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		`{"t":"glob","v":"*"}`,
		`{"t":"max","v":"100"}`,
		`{"t":"max","v":1.5}`,
		`{"t":"max","v":-1}`,
		`{"t":"max","v":9007199254740992}`,
		`{"t":"prefix","v":1}`,
		`{"t":"set","v":"USD"}`,
		`{"t":"set","v":["USD","USD"]}`,
		`{"t":"set","v":[true]}`,
		`{"t":"window","v":[10,1]}`,
		`{"t":"window","v":[1]}`,
		`{"t":"max","v":1,"x":2}`,
		`{"v":1}`,
		`[]`,
	}
	for _, s := range bad {
		dec := json.NewDecoder(bytes.NewReader([]byte(s)))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(v); err == nil {
			t.Errorf("%s: expected rejection", s)
		}
	}
}
