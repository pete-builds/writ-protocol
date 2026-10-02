package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// The gate, not its callers, holds the API's credential. A caller that holds
// a credential the API accepts can send its request to the API directly, and
// nothing the gate checks then applies: no bound, no count, no tally. So the
// gate never forwards a caller's credential headers, and sends the API the
// credential it was configured with, on forward requests and reversals alike.

// callerCredentials are the headers the gate never forwards from a caller,
// whatever the credentials file names. A deployment whose API reads a key from
// another header, such as X-Api-Key, names that header in the file, which
// drops the caller's copy too.
var callerCredentials = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Cookie": true,
}

// loadCredentials reads the headers the gate adds to every request it sends
// the API: one "Name: value" per line, blank lines and lines starting with #
// ignored. The file holds a secret, so a file any other user can read, or one
// that is not a regular file, is refused, as are a header the gate itself
// controls, a malformed line, and a name given twice.
func loadCredentials(path string) (http.Header, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: readable by other users (mode %04o); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !headerName(name) || !headerValue(value) {
			return nil, fmt.Errorf("%s line %d: want \"Name: value\"", path, n)
		}
		name = http.CanonicalHeaderKey(name)
		if dropped[name] || name == tallyHeader {
			return nil, fmt.Errorf("%s line %d: %s is a header the gate controls", path, n, name)
		}
		if h.Get(name) != "" {
			return nil, fmt.Errorf("%s line %d: %s given twice", path, n, name)
		}
		h.Set(name, value)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, fmt.Errorf("%s: no credential in it", path)
	}
	return h, nil
}

// forwarded reports whether a caller's request header reaches the API.
func (g *gate) forwarded(name string) bool {
	name = http.CanonicalHeaderKey(name)
	return !dropped[name] && !callerCredentials[name] && g.creds.Get(name) == ""
}

// authorize adds the gate's own credential to a request bound for the API.
func (g *gate) authorize(req *http.Request) {
	for name, vs := range g.creds {
		req.Header[name] = append([]string(nil), vs...)
	}
}

// headerName reports whether s is an RFC 9110 field name: one or more token
// characters.
func headerName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// headerValue reports whether s is a non-empty field value with no control
// character, so no line break can smuggle a second header in.
func headerValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}
