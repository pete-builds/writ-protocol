package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// ErrDuplicateKey is returned when an object repeats a member name at any depth.
var ErrDuplicateKey = errors.New("jcs: duplicate object key")

// ErrLoneSurrogate is returned when a string escape encodes an unpaired UTF-16
// surrogate, which encoding/json would silently replace with U+FFFD.
var ErrLoneSurrogate = errors.New("jcs: lone surrogate escape in string")

// Strict rejects inputs that encoding/json would accept with silent
// alteration: duplicate keys (last one wins) and lone surrogate escapes
// (replaced by U+FFFD). Two implementations must never sign different bytes
// for what they both call the same object, so these are hard errors.
func Strict(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrInvalidUTF8
	}
	if err := scanSurrogates(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return checkDuplicates(dec)
}

// checkDuplicates walks the token stream and tracks member names per object.
func checkDuplicates(dec *json.Decoder) error {
	type frame struct {
		isObject  bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("jcs: parse: %w", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if top != nil && top.isObject {
					top.expectKey = true
				}
				stack = append(stack, &frame{isObject: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				if top != nil && top.isObject {
					top.expectKey = true
				}
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		default:
			if top != nil && top.isObject {
				if top.expectKey {
					k := t.(string)
					if top.keys[k] {
						return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
					}
					top.keys[k] = true
					top.expectKey = false
				} else {
					top.expectKey = true
				}
			}
		}
	}
}

// scanSurrogates finds \uXXXX escapes inside strings and rejects unpaired
// surrogates. It tracks string boundaries so escapes outside strings are not
// possible to misread.
func scanSurrogates(raw []byte) error {
	inStr := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inStr {
			if c == '"' {
				inStr = true
			}
			continue
		}
		switch c {
		case '"':
			inStr = false
		case '\\':
			if i+1 >= len(raw) {
				return errors.New("jcs: truncated escape")
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			hi, ok := hex4(raw, i+2)
			if !ok {
				return errors.New("jcs: malformed \\u escape")
			}
			i += 5
			switch {
			case hi >= 0xD800 && hi <= 0xDBFF:
				if i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
					lo, ok := hex4(raw, i+3)
					if ok && lo >= 0xDC00 && lo <= 0xDFFF {
						i += 6
						continue
					}
				}
				return ErrLoneSurrogate
			case hi >= 0xDC00 && hi <= 0xDFFF:
				return ErrLoneSurrogate
			}
		}
	}
	return nil
}

func hex4(b []byte, at int) (int, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	n := 0
	for _, c := range b[at : at+4] {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n |= int(c - '0')
		case c >= 'a' && c <= 'f':
			n |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}
