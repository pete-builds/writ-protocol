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
	"net/http"
	"time"

	"writproto/exec"
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

// Handler serves an executor.
func Handler(e *exec.Executor, wk WellKnown) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/writ", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wk)
	})
	mux.HandleFunc("POST /writ", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, writ.MaxTallyBytes+1))
		if err != nil || len(body) > writ.MaxTallyBytes {
			reject(w, writ.TooLarge)
			return
		}
		obj, err := wire.Decode(body)
		if err != nil {
			reject(w, writ.Noncanonical)
			return
		}
		switch obj["typ"] {
		case "call":
			rep, rej := e.Execute(r.Context(), obj)
			if rej != nil {
				reject(w, rej.Code)
				return
			}
			respond(w, rep)
		case "revoke":
			tallies, rej := e.Revoke(obj)
			if rej != nil {
				reject(w, rej.Code)
				return
			}
			if tallies == nil {
				tallies = []wire.Object{}
			}
			respond(w, map[string]any{"tallies": tallies})
		default:
			reject(w, writ.WrongType)
		}
	})
	return mux
}

func reject(w http.ResponseWriter, code writ.Reason) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
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

// Revoke sends a revoke and returns the affected pending tallies.
func (c *Client) Revoke(ctx context.Context, endpoint string, r *writ.Revoke) ([]wire.Object, error) {
	rep, err := c.post(ctx, endpoint, r.Raw)
	if err != nil {
		return nil, err
	}
	var out []wire.Object
	if arr, ok := rep["tallies"].([]any); ok {
		for _, t := range arr {
			if o, ok := t.(map[string]any); ok {
				out = append(out, o)
			}
		}
	}
	return out, nil
}
