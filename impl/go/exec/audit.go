package exec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
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
	// Prev is the hash of the entry before this one in the record, as its
	// bytes stand in the file, or null for the first (spec 9.3). AuditLog
	// sets it; anything a caller puts here is replaced.
	Prev *string `json:"prev"`
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
// line, each synced before Record returns. Each entry carries the hash of
// the line before it (spec 9.3), so editing, removing, or reordering an
// entry breaks every later link; VerifyAudit walks them. Several processes
// may append to one file, as writ-hook's do: Record holds an exclusive lock
// on the file from reading the last line to syncing its own, where the
// platform has one (audit_lock_unix.go).
type AuditLog struct {
	mu sync.Mutex
	f  *os.File
}

// OpenAuditLog opens path for appending, creating it if needed.
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f}, nil
}

// Record appends one entry, linked to the line before it.
func (l *AuditLog) Record(a AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := lockFile(l.f)
	if err != nil {
		return err
	}
	defer unlock()
	last, torn, err := lastLine(l.f)
	if err != nil {
		return err
	}
	a.Prev = nil
	if last != nil {
		h := lineHash(last)
		a.Prev = &h
	}
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	out := append(line, '\n')
	if torn {
		// A crash cut the last line short. It stays, as an entry whose
		// bytes the next one links to, and is ended here.
		out = append([]byte{'\n'}, out...)
	}
	if _, err := l.f.Write(out); err != nil {
		return err
	}
	return l.f.Sync()
}

// lineHash is the hash of one line of the record, without its newline.
func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return wire.B64.EncodeToString(sum[:])
}

// lastLine returns the file's last line without its newline, nil for an
// empty file, and whether a crash left that line without one.
func lastLine(f *os.File) ([]byte, bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, false, nil
	}
	for chunk := int64(4096); ; chunk *= 2 {
		if chunk > size {
			chunk = size
		}
		buf := make([]byte, chunk)
		if _, err := f.ReadAt(buf, size-chunk); err != nil && err != io.EOF {
			return nil, false, err
		}
		torn := buf[len(buf)-1] != '\n'
		body := buf
		if !torn {
			body = buf[:len(buf)-1]
		}
		if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
			return append([]byte(nil), body[i+1:]...), torn, nil
		}
		if chunk == size {
			return append([]byte(nil), body...), torn, nil
		}
	}
}

// AuditReport is what VerifyAudit found in a record.
type AuditReport struct {
	Entries   int   // lines, torn ones included
	Unchained int   // leading lines with no prev member, written before chaining
	Torn      []int // 1-based lines that are not JSON objects: writes a crash cut short
	Breaks    []int // 1-based lines whose prev does not name the line before
}

// VerifyAudit walks an audit record's links (spec 9.3). A line breaks the
// chain when its prev is not the hash of the line before it, when the first
// line's prev is not null (the start of the record is missing), or when a
// line after the first chained one has no prev. A torn line cannot be
// checked itself, but the line after it must link to its bytes. What the
// chain cannot show is the newest entries cut off, or the whole record
// replaced: nothing in the record holds its own head.
func VerifyAudit(r io.Reader) (*AuditReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	rep := &AuditReport{Entries: len(lines)}
	chained := false
	for i, line := range lines {
		var m map[string]json.RawMessage
		if json.Unmarshal(line, &m) != nil {
			rep.Torn = append(rep.Torn, i+1)
			continue
		}
		raw, has := m["prev"]
		if !has {
			if chained {
				rep.Breaks = append(rep.Breaks, i+1)
			} else {
				rep.Unchained++
			}
			continue
		}
		chained = true
		var prev *string
		if json.Unmarshal(raw, &prev) != nil {
			rep.Breaks = append(rep.Breaks, i+1)
			continue
		}
		switch {
		case i == 0 && prev != nil, i > 0 && (prev == nil || *prev != lineHash(lines[i-1])):
			rep.Breaks = append(rep.Breaks, i+1)
		}
	}
	return rep, nil
}

// Close closes the file.
func (l *AuditLog) Close() error { return l.f.Close() }
