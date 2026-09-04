package exec

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"

	"writproto/wire"
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
}

type tallyRec struct {
	Tally  wire.Object `json:"tally"`
	Chain  []string    `json:"chain"` // writ identities root to leaf
	Res    any         `json:"res,omitempty"`
	Keep   int64       `json:"keep"`
	Undone string      `json:"undone,omitempty"` // identity of the undo tally
}

// FileStore is the four executor stores of spec section 9 in one JSON file,
// rewritten on every mutation. It is deliberately simple: durability across
// restart is a conformance requirement, throughput is not.
type FileStore struct {
	mu      sync.Mutex
	path    string
	Calls   map[string]*Record   `json:"calls"`   // key leaf|id
	Counts  map[string]int64     `json:"counts"`  // writ identity
	Tallies map[string]*tallyRec `json:"tallies"` // tally identity
	Revoked map[string]int64     `json:"revoked"` // writ identity to exp
}

// OpenFileStore loads or creates a store at path ("" for memory only).
func OpenFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path, Calls: map[string]*Record{}, Counts: map[string]int64{},
		Tallies: map[string]*tallyRec{}, Revoked: map[string]int64{}}
	if path == "" {
		return s, nil
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

func (s *FileStore) flush() {
	if s.path == "" {
		return
	}
	b, _ := json.MarshalIndent(s, "", " ")
	tmp := s.path + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, s.path)
}

func callKey(leaf, cid string) string { return leaf + "|" + cid }

func (s *FileStore) getCall(leaf, cid string) (*Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.Calls[callKey(leaf, cid)]
	return r, ok
}

func (s *FileStore) putCall(r *Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls[callKey(r.LeafID, r.CID)] = r
	s.flush()
}

// consume increments the count entry for every writ id if all are below their
// bound; returns false and consumes nothing otherwise.
func (s *FileStore) consume(ids []string, bounds map[string]int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if b, ok := bounds[id]; ok && s.Counts[id] >= b {
			return false
		}
	}
	for _, id := range ids {
		if _, ok := bounds[id]; ok {
			s.Counts[id]++
		}
	}
	s.flush()
	return true
}

func (s *FileStore) putTally(id string, rec *tallyRec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Tallies[id] = rec
	s.flush()
}

func (s *FileStore) getTally(id string) (*tallyRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.Tallies[id]
	return r, ok
}

func (s *FileStore) talliesUnder(writID string) []wire.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []wire.Object
	for _, r := range s.Tallies {
		for _, id := range r.Chain {
			if id == writID {
				out = append(out, r.Tally)
				break
			}
		}
	}
	return out
}

func (s *FileStore) revoke(writID string, exp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Revoked[writID] = exp
	s.flush()
}

func (s *FileStore) isRevoked(writID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Revoked[writID]
	return ok
}
