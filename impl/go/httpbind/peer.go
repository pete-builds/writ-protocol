package httpbind

import (
	"net/http"
	"strings"
)

// ClientCert reads the peer from a verified mTLS client certificate: the
// first URI subject alternative name that is not a did:key, which for a
// SPIFFE X.509-SVID is its SPIFFE ID. Every did:key URI in the same
// certificate is a key the certificate authority binds to that peer (spec
// 7.6). An SVID carries exactly one URI, so its keys come from a bindings
// file instead; a private CA can put both in one certificate. ok is false
// when the connection carries no verified client certificate.
func ClientCert(r *http.Request) (peer string, keys []string, ok bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", nil, false
	}
	for _, u := range r.TLS.VerifiedChains[0][0].URIs {
		s := u.String()
		if strings.HasPrefix(s, "did:key:") {
			keys = append(keys, s)
		} else if peer == "" {
			peer = s
		}
	}
	if peer == "" {
		return "", nil, false
	}
	return peer, keys, true
}
