package exec

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"writproto/wire"
	"writproto/writ"
)

// Record is a call-store entry (spec section 9).
type Record struct {
	LeafID string      `json:"leaf"`
	CID    string      `json:"id"`
	Acc    int64       `json:"acc"`
	Exp    int64       `json:"exp"`
	Call   wire.Object `json:"call"`            // the call, so a crashed record can be resolved on restart
	Tally  wire.Object `json:"tally,omitempty"` // final tally; nil while executing
	Final  bool        `json:"final"`
	// While the call is pending: every writ the operation issued and every
	// sub-tally it received, persisted before the writ is sent or the
	// sub-tally acted on (spec 7.5), so a record resolved after a crash still
	// carries the evidence of work done below it (spec 9).
	Wrt []wire.Object `json:"wrt,omitempty"`
	Sub []wire.Object `json:"sub,omitempty"`
}

type tallyRec struct {
	Tally wire.Object `json:"tally"`
	Chain []string    `json:"chain"` // writ identities root to leaf
	// Iss is the issuer of each writ in Chain, so an ack of a key-wide
	// revoke can list the tallies under that key (spec 9.4). Nil in a record
	// written before acks existed.
	Iss  []string `json:"iss,omitempty"`
	Res  any      `json:"res,omitempty"`
	Keep int64    `json:"keep"`
	// Undo state for a reversible tally (spec 8.1). Undoing is the call key
	// of a reversal in progress, persisted before the reversal runs, so a
	// crash mid-reversal is never mistaken for "nothing happened". Undone is
	// the call key of the reversal that succeeded, and UndoRes its body.
	Undoing string `json:"undoing,omitempty"`
	Undone  string `json:"undone,omitempty"`
	UndoRes any    `json:"undo_res,omitempty"`
}

// FileStore is the executor stores of spec section 9. The call, count, and
// tally stores (with each tally's reversal state) are one JSON file,
// rewritten on every mutation. It is deliberately simple: durability across
// restart is a conformance requirement, throughput is not. Every mutation
// that the protocol relies on reports a failed write, and the caller refuses
// rather than claim durability it does not have.
//
// The revoke store is an append-only log beside that file. Anyone can send a
// valid key-wide revoke, since it needs no accepted root, so a revoke must
// cost one appended line, not a rewrite of every store (security review
// finding 7). Per-writ entries are dropped after the writ's exp by
// purgeRevoked; key-wide entries are kept for good (spec section 9).
type FileStore struct {
	mu      sync.Mutex
	path    string
	Calls   map[string]*Record   `json:"calls"`   // key leaf|id
	Counts  map[string]int64     `json:"counts"`  // writ identity
	Tallies map[string]*tallyRec `json:"tallies"` // tally identity
	Revoked map[string]int64     `json:"-"`       // writ identity, or "*:" and a key, to exp
	unsaved map[string]bool      // revokes held in memory whose log write failed
}

// revokeEntry is one line of the revoke log.
type revokeEntry struct {
	Writ string `json:"writ"`
	Exp  int64  `json:"exp"`
}

func (s *FileStore) revokeLog() string { return s.path + ".revoked" }

// OpenFileStore loads or creates a store at path ("" for memory only).
func OpenFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path, Calls: map[string]*Record{}, Counts: map[string]int64{},
		Tallies: map[string]*tallyRec{}, Revoked: map[string]int64{}}
	if path == "" {
		return s, nil
	}
	if err := s.loadRevoked(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // protocol objects must round-trip integers exactly
	if err := dec.Decode(s); err != nil {
		return nil, err
	}
	return s, nil
}

// loadRevoked reads the revoke log. A line that does not parse is the tail of
// an append a crash interrupted, and is skipped.
func (s *FileStore) loadRevoked() error {
	b, err := os.ReadFile(s.revokeLog())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		var e revokeEntry
		if json.Unmarshal(line, &e) == nil && e.Writ != "" {
			s.Revoked[e.Writ] = e.Exp
		}
	}
	return nil
}

// flush writes the whole store to a temporary file, syncs it, and renames it
// over the store. The caller holds s.mu.
func (s *FileStore) flush() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	// Make the rename durable. Not every platform can sync a directory, and
	// the file itself is already synced, so a failure here is not fatal.
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func callKey(leaf, cid string) string { return leaf + "|" + cid }

// admit runs spec section 7 steps 9 and 10 as one atomic operation. When the
// call store already has an entry for the call, admit returns it and changes
// nothing. Otherwise, when every writ id with a count bound is below it, admit
// increments each, records rec as the pending entry, persists both, and
// returns nil, true, nil. When a count is exhausted it returns nil, false, nil
// and records nothing. When the store cannot be written, admit undoes its
// changes and returns the error: nothing may run that is not recorded.
func (s *FileStore) admit(rec *Record, ids []string, bounds map[string]int64) (*Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := callKey(rec.LeafID, rec.CID)
	if prior, ok := s.Calls[key]; ok {
		return prior, true, nil
	}
	for _, id := range ids {
		if b, ok := bounds[id]; ok && s.Counts[id] >= b {
			return nil, false, nil
		}
	}
	for _, id := range ids {
		if _, ok := bounds[id]; ok {
			s.Counts[id]++
		}
	}
	s.Calls[key] = rec
	if err := s.flush(); err != nil {
		for _, id := range ids {
			if _, ok := bounds[id]; ok {
				s.Counts[id]--
			}
		}
		delete(s.Calls, key)
		return nil, false, err
	}
	return nil, true, nil
}

// finish records a call's final tally in the tally store and the call store
// in one write, so no crash can leave one without the other. On a failed
// write the call stays pending and the error is returned.
func (s *FileStore) finish(tid string, t *tallyRec, rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := callKey(rec.LeafID, rec.CID)
	prior := s.Calls[key]
	s.Tallies[tid] = t
	s.Calls[key] = rec
	if err := s.flush(); err != nil {
		delete(s.Tallies, tid)
		s.Calls[key] = prior
		return err
	}
	return nil
}

// errNotPending is returned for evidence about a call with no pending record:
// it was never admitted, or it is already final.
var errNotPending = errors.New("exec: the call is not pending")

// addEvidence persists a writ the pending call at key issued (w), or a
// sub-tally it received (t), in one write (spec 7.5). A sub-tally must name a
// writ already recorded, and replaces an earlier tally for the same sub-call,
// as a final tally supersedes a pending one (spec 6). On a failed write the
// record is left as it was and the error returned.
func (s *FileStore) addEvidence(key string, w, t wire.Object) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Calls[key]
	if !ok || rec.Tally != nil {
		return errNotPending
	}
	next := *rec
	next.Wrt = append([]wire.Object{}, rec.Wrt...)
	next.Sub = append([]wire.Object{}, rec.Sub...)
	issued := func(id string) bool {
		for _, o := range next.Wrt {
			if h, _ := wire.Hash(o); h == id {
				return true
			}
		}
		return false
	}
	if w != nil {
		id, err := wire.Hash(w)
		if err != nil {
			return err
		}
		if !issued(id) {
			next.Wrt = append(next.Wrt, w)
		}
	}
	if t != nil {
		if named, _ := t["writ"].(string); !issued(named) {
			return errors.New("exec: the sub-tally names a writ this call did not issue")
		}
		call, _ := t["call"].(string)
		replaced := false
		for i, o := range next.Sub {
			if c, _ := o["call"].(string); c == call {
				next.Sub[i], replaced = t, true
				break
			}
		}
		if !replaced {
			next.Sub = append(next.Sub, t)
		}
	}
	s.Calls[key] = &next
	if err := s.flush(); err != nil {
		s.Calls[key] = rec
		return err
	}
	return nil
}

// pendingRecords returns copies of every record not yet final.
func (s *FileStore) pendingRecords() []*Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Record
	for _, rec := range s.Calls {
		if rec.Tally == nil && rec.Call != nil {
			c := *rec
			out = append(out, &c)
		}
	}
	return out
}

// revokeView returns, in one read, what an answer to a revoke of writID (or,
// when writID is "*", of every writ iss issued) is built from: every pending
// call record, and for the ack's held list every tally in the tally store
// under the revoked writ with the call it answers (spec 9.1, 9.4). One read
// under one lock means a call that finishes concurrently is seen either
// pending or held, never neither. A record from before acks existed carries
// no issuers and is listed under every key-wide revoke: an extra entry in
// held accounts only for a tally that exists, so it can hide nothing.
func (s *FileStore) revokeView(writID, iss string) ([]*Record, []writ.AckHeld) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending []*Record
	for _, rec := range s.Calls {
		if rec.Tally == nil && rec.Call != nil {
			c := *rec
			pending = append(pending, &c)
		}
	}
	var held []writ.AckHeld
	for tid, r := range s.Tallies {
		under := false
		if writID == "*" {
			under = r.Iss == nil
			for _, k := range r.Iss {
				under = under || k == iss
			}
		} else {
			for _, id := range r.Chain {
				under = under || id == writID
			}
		}
		if under {
			call, _ := r.Tally["call"].(string)
			held = append(held, writ.AckHeld{Call: call, Tally: tid})
		}
	}
	return pending, held
}

// record returns a copy of the record at key, pending or final, or nil.
func (s *FileStore) record(key string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Calls[key]
	if !ok {
		return nil
	}
	c := *rec
	return &c
}

// pendingRecord returns a copy of the pending record at key, or nil.
func (s *FileStore) pendingRecord(key string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Calls[key]
	if !ok || rec.Tally != nil {
		return nil
	}
	c := *rec
	c.Wrt = append([]wire.Object{}, rec.Wrt...)
	c.Sub = append([]wire.Object{}, rec.Sub...)
	return &c
}

func (s *FileStore) getTally(id string) (*tallyRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.Tallies[id]
	return r, ok
}

// talliesUnder returns every tally indexed under writID in the order spec
// section 8.2 fixes: ascending acc, ties by tally identity as byte strings.
func (s *FileStore) talliesUnder(writID string) []wire.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	type hit struct {
		id  string
		acc int64
		obj wire.Object
	}
	var hits []hit
	for tid, r := range s.Tallies {
		for _, id := range r.Chain {
			if id == writID {
				acc, _ := r.Tally["acc"].(json.Number).Int64()
				hits = append(hits, hit{tid, acc, r.Tally})
				break
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].acc != hits[j].acc {
			return hits[i].acc < hits[j].acc
		}
		return hits[i].id < hits[j].id
	})
	out := make([]wire.Object, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.obj)
	}
	return out
}

// undoState reports whether a reversal of rec has succeeded (and its body),
// or was claimed and never settled, which after a restart means its outcome
// is unknown.
func (s *FileStore) undoState(rec *tallyRec) (done bool, res any, claimed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rec.Undone != "", rec.UndoRes, rec.Undoing != ""
}

// claimUndo persists that the call by is about to reverse rec.
func (s *FileStore) claimUndo(rec *tallyRec, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Undoing = by
	if err := s.flush(); err != nil {
		rec.Undoing = ""
		return err
	}
	return nil
}

// settleUndo records the reversal's result: on success rec is undone for
// good; on failure the claim is released so a later undo may try again. A
// failed write leaves the claim on disk, which a restart reads as unknown.
func (s *FileStore) settleUndo(rec *tallyRec, by string, ok bool, res any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Undoing = ""
	if ok {
		rec.Undone, rec.UndoRes = by, res
	}
	_ = s.flush()
}

// revoke records a revoke by appending one line to the revoke log and syncing
// it. A revoke that cannot be written still holds in memory, which only
// narrows authority, and the error is returned; a later call for the same
// revoke tries the write again.
func (s *FileStore) revoke(writID string, exp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Revoked[writID]; ok && !s.unsaved[writID] {
		return nil
	}
	s.Revoked[writID] = exp
	if s.path == "" {
		return nil
	}
	err := s.appendRevoke(writID, exp)
	if err != nil {
		if s.unsaved == nil {
			s.unsaved = map[string]bool{}
		}
		s.unsaved[writID] = true
		return err
	}
	delete(s.unsaved, writID)
	return nil
}

func (s *FileStore) appendRevoke(writID string, exp int64) error {
	line, err := json.Marshal(revokeEntry{Writ: writID, Exp: exp})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.revokeLog(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// purgeRevoked drops per-writ revokes whose writ has expired, since no call
// under an expired writ is accepted anyway (spec 9, revoke store lifetime),
// and compacts the log once. Key-wide revokes never expire.
func (s *FileStore) purgeRevoked(now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := false
	for id, exp := range s.Revoked {
		if exp <= now {
			delete(s.Revoked, id)
			dropped = true
		}
	}
	if !dropped || s.path == "" {
		return nil
	}
	ids := make([]string, 0, len(s.Revoked))
	for id := range s.Revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var buf bytes.Buffer
	for _, id := range ids {
		line, _ := json.Marshal(revokeEntry{Writ: id, Exp: s.Revoked[id]})
		buf.Write(append(line, '\n'))
	}
	tmp := s.revokeLog() + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.revokeLog())
}

func (s *FileStore) isRevoked(writID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Revoked[writID]
	return ok
}
