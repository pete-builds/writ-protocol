// Package jcs implements the JSON Canonicalization Scheme (RFC 8785) with one
// deliberate restriction from the protocol spec: numbers MUST be integers in
// the IEEE-754 safe-integer range [-(2^53-1), 2^53-1]. Floating-point values
// are rejected. This removes the only genuinely hard part of RFC 8785
// (ES6 number formatting) and keeps the canonical form implementable from the
// spec text alone in any language.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is 2^53-1, the largest integer exactly representable in
// IEEE-754 binary64. Every protocol implementation, in any language, can
// round-trip integers in this range without loss.
const MaxSafeInteger = 1<<53 - 1

var intLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ErrNotInteger is returned when a number is not a safe integer.
var ErrNotInteger = errors.New("jcs: numbers must be integers within +/- 2^53-1")

// ErrInvalidUTF8 is returned when a string is not valid UTF-8.
var ErrInvalidUTF8 = errors.New("jcs: string is not valid UTF-8")

// Canonicalize parses raw JSON and returns its canonical serialization.
func Canonicalize(raw []byte) ([]byte, error) {
	if err := Strict(raw); err != nil {
		return nil, err
	}
	r := bytes.NewReader(raw)
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: parse: %w", err)
	}
	// Reject trailing garbage after the single top-level value.
	rest, _ := io.ReadAll(io.MultiReader(dec.Buffered(), r))
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("jcs: trailing data after JSON value")
	}
	return Marshal(v)
}

// Marshal canonicalizes an already-decoded value. Accepts the types produced by
// encoding/json with UseNumber (map[string]any, []any, string, json.Number,
// bool, nil) plus Go integer types and encoding/json.Marshaler-free structs
// via a round trip through encoding/json.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeString(buf, x)
	case json.Number:
		s := x.String()
		if !intLiteral.MatchString(s) {
			return ErrNotInteger
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > MaxSafeInteger || n < -MaxSafeInteger {
			return ErrNotInteger
		}
		if s == "-0" {
			s = "0" // RFC 8785: ES6 Number.prototype.toString(-0) is "0"
		}
		buf.WriteString(s)
	case int:
		return writeInt(buf, int64(x))
	case int64:
		return writeInt(buf, x)
	case int32:
		return writeInt(buf, int64(x))
	case uint64:
		if x > MaxSafeInteger {
			return ErrNotInteger
		}
		return writeInt(buf, int64(x))
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > MaxSafeInteger {
			return ErrNotInteger
		}
		return writeInt(buf, int64(x))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := write(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// Structs and other types: round-trip through encoding/json.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		c, err := Canonicalize(b)
		if err != nil {
			return err
		}
		buf.Write(c)
	}
	return nil
}

func writeInt(buf *bytes.Buffer, n int64) error {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return ErrNotInteger
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// lessUTF16 orders strings by their UTF-16 code unit sequence, as RFC 8785
// section 3.2.3 requires.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString serializes per RFC 8785 section 3.2.2.2: escape only
// quotation mark, reverse solidus, and control characters U+0000..U+001F.
// Everything else, including non-ASCII, is emitted as literal UTF-8.
func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
