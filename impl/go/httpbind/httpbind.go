// Package httpbind is the HTTP binding of spec section 10: one POST endpoint
// carrying a call or a revoke, and a well-known document (Appendix B).
package httpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"writproto/exec"
	"writproto/jcs"
	"writproto/wire"
	"writproto/writ"
)

// ContentType is the media type for protocol objects.
const ContentType = "application/writ+json"

// WellKnown is the Appendix B document.
type WellKnown struct {
	V        int      `json:"v"`
	DID      string   `json:"did"`
	Endpoint string   `json:"endpoint"`
	Act      []string `json:"act"`
}

// maxRequestBytes is the larger of the call and revoke limits of spec 1.6.
const maxRequestBytes = max(writ.MaxCallBytes, writ.MaxRevokeBytes)

// Handler serves an executor over a transport that authenticates no peer,
// with no rate limit.
func Handler(e *exec.Executor, wk WellKnown) http.Handler {
	return NewHandler(e, wk, Options{})
}

// Options configure NewHandler.
type Options struct {
	// PeerOf reports the identity the transport authenticated for a request,
	// passed to the executor for peer binding and the audit record (spec
	// sections 7.6, 9.3, and 10).
	PeerOf func(*http.Request) (string, bool)
	// MTLS reads the peer and the keys it speaks for from the verified
	// client certificate (ClientCert), and only from there: PeerOf is not
	// consulted. A request without a verified certificate naming exactly one
	// peer fails closed, every call over it refused as peer_mismatch before
	// replay (exec.WithUnidentifiedPeer). The server's TLS configuration
	// must require and verify client certificates.
	MTLS bool
	// PerMinute, when above zero, bounds the requests accepted from each
	// peer, or from each remote host when there is no peer, and refuses the
	// rest with status 429 before they reach the executor or its audit
	// record (spec section 12).
	PerMinute int
}

// NewHandler serves an executor.
func NewHandler(e *exec.Executor, wk WellKnown, o Options) http.Handler {
	limit := newLimiter(o.PerMinute)
	peerOf := o.PeerOf
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/writ", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wk)
	})
	mux.HandleFunc("POST /writ", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		source := "host:" + remoteHost(r)
		if o.MTLS {
			if p, keys, ok := ClientCert(r); ok {
				ctx = exec.WithAttestedKeys(exec.WithPeer(ctx, p), keys)
				source = "peer:" + p
			} else {
				label := unidentifiedLabel(r)
				ctx = exec.WithUnidentifiedPeer(ctx, label)
				source = "peer:" + label
			}
		} else if peerOf != nil {
			if p, ok := peerOf(r); ok {
				ctx = exec.WithPeer(ctx, p)
				source = "peer:" + p
			}
		}
		if !limit.allow(source, time.Now()) {
			fail(w, http.StatusTooManyRequests, RateLimited)
			return
		}
		// An object rejected here never reaches the executor's own checks,
		// so the binding records it in the audit record itself (spec 9.3).
		unreadable := func(code writ.Reason) {
			e.AuditUnreadable(ctx, code)
			reject(w, code)
		}
		// A request body is one call or one revoke (spec section 10), and
		// both are limited to 65536 bytes, so no request may be larger.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
		if err != nil || len(body) > maxRequestBytes {
			unreadable(writ.TooLarge)
			return
		}
		if jcs.CheckDepth(body) != nil {
			unreadable(writ.TooLarge)
			return
		}
		obj, err := wire.Decode(body)
		if err != nil {
			unreadable(writ.Noncanonical)
			return
		}
		switch obj["typ"] {
		case "call":
			rep, rej := e.Execute(ctx, obj)
			if rej != nil {
				reject(w, rej.Code)
				return
			}
			respond(w, rep)
		case "revoke":
			rep, rej := e.RevokeContext(ctx, obj)
			if rej != nil && rej.Code == writ.Reason(exec.StoreUnavailable) {
				fail(w, http.StatusServiceUnavailable, rej.Code)
				return
			}
			if rej != nil {
				reject(w, rej.Code)
				return
			}
			respond(w, rep)
		default:
			unreadable(writ.WrongType)
		}
	})
	return mux
}

// RateLimited is the implementation code of a request refused by PerMinute.
const RateLimited = writ.Reason("httpbind/rate_limited")

func remoteHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// limiter is a token bucket per source: PerMinute tokens, refilled evenly.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int) *limiter {
	if perMinute <= 0 {
		return nil
	}
	return &limiter{rate: float64(perMinute) / 60, burst: float64(perMinute), buckets: map[string]*bucket{}}
}

func (l *limiter) allow(source string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[source]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[source] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func reject(w http.ResponseWriter, code writ.Reason) { fail(w, http.StatusBadRequest, code) }

func fail(w http.ResponseWriter, status int, code writ.Reason) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": string(code)})
}

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", ContentType)
	_ = json.NewEncoder(w).Encode(v)
}

// Client sends calls and revokes to executors.
type Client struct {
	HTTP *http.Client
}

// NewClient returns a client with a 30 second timeout.
func NewClient() *Client { return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}} }

// Discover fetches the well-known document at base (scheme and host).
func (c *Client) Discover(ctx context.Context, base string) (*WellKnown, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/.well-known/writ", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var wk WellKnown
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return nil, err
	}
	return &wk, nil
}

// RejectedError is an unsigned rejection from the executor (status 400).
type RejectedError struct{ Code writ.Reason }

func (e *RejectedError) Error() string { return "rejected: " + string(e.Code) }

func (c *Client) post(ctx context.Context, endpoint string, obj wire.Object) (wire.Object, error) {
	body, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4*writ.MaxTallyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusBadRequest {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		return nil, &RejectedError{Code: writ.Reason(e.Error)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return wire.Decode(data)
}

// Call sends a call and returns the raw tally object and result body.
func (c *Client) Call(ctx context.Context, endpoint string, k *writ.Call) (wire.Object, any, error) {
	rep, err := c.post(ctx, endpoint, k.Raw)
	if err != nil {
		return nil, nil, err
	}
	tally, ok := rep["tally"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("reply lacks a tally")
	}
	return tally, rep["res"], nil
}

// Revoke sends a revoke and returns the answer: the tallies of the forward
// calls it stopped, the executor's ack with its body, and any acks it relays
// (spec 10). The acks are returned as received; writ.VerifyAck checks one.
func (c *Client) Revoke(ctx context.Context, endpoint string, r *writ.Revoke) (*exec.RevokeReply, error) {
	rep, err := c.post(ctx, endpoint, r.Raw)
	if err != nil {
		return nil, err
	}
	out := &exec.RevokeReply{Tallies: []wire.Object{}, Res: rep["res"]}
	if arr, ok := rep["tallies"].([]any); ok {
		for _, t := range arr {
			if o, ok := t.(map[string]any); ok {
				out.Tallies = append(out.Tallies, o)
			}
		}
	}
	out.Ack, _ = rep["ack"].(map[string]any)
	if arr, ok := rep["fwd"].([]any); ok {
		for _, f := range arr {
			if m, ok := f.(map[string]any); ok {
				a, _ := m["ack"].(map[string]any)
				out.Fwd = append(out.Fwd, exec.AckPair{Ack: a, Res: m["res"]})
			}
		}
	}
	return out, nil
}
