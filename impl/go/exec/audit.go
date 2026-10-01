package exec

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"writproto/wire"
	"writproto/writ"
)

// AuditEntry is one entry of the audit record (spec 9.3): what arrived, over
// which connection, and what the executor answered. From is set only once the
// object's signature has verified, so a forged object cannot name someone else.
type AuditEntry struct {
	At      int64   `json:"at"`
	Kind    string  `json:"kind"` // call, revoke, or unknown when the binding could not read the object
	ID      string  `json:"id,omitempty"`
	From    string  `json:"from,omitempty"`
	Peer    *string `json:"peer"` // null when the transport authenticated no peer
	Root    string  `json:"root,omitempty"`
	Leaf    string  `json:"leaf,omitempty"` // leaf writ identity; for a revoke, the revoked writ or "*"
	Op      string  `json:"op,omitempty"`
	Outcome string  `json:"outcome"` // a tally's st, "rejected" when unsigned, or "recorded" for a revoke
	Reason  string  `json:"reason,omitempty"`
	Tally   string  `json:"tally,omitempty"`
}

// Execute runs spec section 7 on a decoded call object and, when Audit is
// set, records the answer (spec 9.3). It returns either a reply (always
// carrying a signed tally) or an unsigned rejection for failures before the
// call's signature could be verified (steps 1 and 2).
func (e *Executor) Execute(ctx context.Context, obj wire.Object) (*Reply, *writ.Error) {
	rep, rej := e.execute(ctx, obj)
	if e.Audit != nil {
		e.Audit(e.callEntry(ctx, obj, rep, rej))
	}
	return rep, rej
}

// Revoke runs spec 9.1 on a revoke delivered by a transport that
// authenticated no peer.
func (e *Executor) Revoke(obj wire.Object) (*RevokeReply, *writ.Error) {
	return e.RevokeContext(context.Background(), obj)
}

// RevokeContext runs spec 9.1 on a decoded revoke object and, when Audit is
// set, records the answer with the peer ctx carries (WithPeer). The peer is
// not checked: any key may revoke its own writs (spec 7.6).
func (e *Executor) RevokeContext(ctx context.Context, obj wire.Object) (*RevokeReply, *writ.Error) {
	rep, rej := e.revoke(obj)
	if e.Audit != nil {
		a := AuditEntry{At: e.Now(), Kind: "revoke", Peer: peerPtr(ctx), Outcome: "recorded"}
		a.ID, _ = wire.Hash(obj)
		if rej != nil {
			a.Outcome, a.Reason = "rejected", string(rej.Code)
		}
		// A revoke rejected only because it could not be persisted was
		// verified first, so its signer is known.
		if rej == nil || rej.Code == writ.Reason(StoreUnavailable) {
			if r, err := writ.ParseRevoke(obj); err == nil {
				a.From, a.Leaf = r.Iss, r.Writ
				if len(r.Chain) > 0 {
					a.Root = r.Chain[0].Iss
				}
			}
		}
		e.Audit(a)
	}
	return rep, rej
}

// AuditUnreadable records an object a transport binding rejected before it
// could be read as a call or a revoke (spec 9.3).
func (e *Executor) AuditUnreadable(ctx context.Context, reason writ.Reason) {
	if e.Audit != nil {
		e.Audit(AuditEntry{At: e.Now(), Kind: "unknown", Peer: peerPtr(ctx), Outcome: "rejected", Reason: string(reason)})
	}
}

func (e *Executor) callEntry(ctx context.Context, obj wire.Object, rep *Reply, rej *writ.Error) AuditEntry {
	a := AuditEntry{At: e.Now(), Kind: "call", Peer: peerPtr(ctx)}
	a.ID, _ = wire.Hash(obj)
	if rej != nil || rep == nil {
		a.Outcome = "rejected"
		if rej != nil {
			a.Reason = string(rej.Code)
		}
		return a
	}
	if k, err := writ.ParseCall(obj); err == nil {
		a.ID, a.From, a.Root, a.Leaf, a.Op = k.ID, k.From, k.Chain[0].Iss, k.Leaf().ID, k.Op
	}
	a.Outcome, _ = rep.Tally["st"].(string)
	if errObj, ok := rep.Tally["err"].(map[string]any); ok {
		a.Reason, _ = errObj["code"].(string)
	}
	a.Tally, _ = wire.Hash(rep.Tally)
	return a
}

func peerPtr(ctx context.Context) *string {
	if p, ok := peerOf(ctx); ok {
		return &p
	}
	return nil
}

// AuditLog is an append-only audit record in a file, one JSON object per
// line, each synced before Record returns.
type AuditLog struct {
	mu sync.Mutex
	f  *os.File
}

// OpenAuditLog opens path for appending, creating it if needed.
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f}, nil
}

// Record appends one entry.
func (l *AuditLog) Record(a AuditEntry) error {
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
}

// Close closes the file.
func (l *AuditLog) Close() error { return l.f.Close() }
