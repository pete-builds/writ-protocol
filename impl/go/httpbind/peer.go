package httpbind

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"writproto/exec"
)

// ClientCert reads the peer from a verified mTLS client certificate: its one
// URI subject alternative name that is not a did:key, which for a SPIFFE
// X.509-SVID is its SPIFFE ID. Every did:key URI in the same certificate is a
// key the certificate authority binds to that peer (spec 7.6). An SVID
// carries exactly one URI, so its keys come from a bindings file instead; a
// private CA can put both in one certificate. ok is false when the connection
// carries no verified client certificate, or one that does not name exactly
// one peer: no URI but did:key URIs, or two peers, is no usable identity.
func ClientCert(r *http.Request) (peer string, keys []string, ok bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", nil, false
	}
	peers := 0
	for _, u := range r.TLS.VerifiedChains[0][0].URIs {
		s := u.String()
		if strings.HasPrefix(s, "did:key:") {
			keys = append(keys, s)
		} else if s != "" {
			peers++
			peer = s
		}
	}
	if peers != 1 {
		return "", nil, false
	}
	return peer, keys, true
}

// MTLSContext carries the peer of a request served over mTLS into ctx, by the
// rules of spec 7.6: the verified client certificate's one URI that is not a
// did:key is the peer, and its did:key URIs are keys the CA vouches it speaks
// for. A request without a verified certificate naming exactly one peer
// carries an unidentified peer, so the executor refuses every call over it
// before replay (exec.WithUnidentifiedPeer). It returns the peer, or for an
// unidentified one its audit label, and whether the peer was identified.
func MTLSContext(ctx context.Context, r *http.Request) (context.Context, string, bool) {
	if p, keys, ok := ClientCert(r); ok {
		return exec.WithAttestedKeys(exec.WithPeer(ctx, p), keys), p, true
	}
	label := unidentifiedLabel(r)
	return exec.WithUnidentifiedPeer(ctx, label), label, false
}

// unidentifiedLabel names, for the audit record, a connection that mTLS
// authenticated without a usable identity: the SHA-256 of its client
// certificate, or "x509:none" when there is no verified certificate.
func unidentifiedLabel(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		return "x509-sha256:" + hex.EncodeToString(sum[:])
	}
	return "x509:none"
}
