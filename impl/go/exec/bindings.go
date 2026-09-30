package exec

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Bindings is a PeerBinds source read from a JSON file mapping each
// transport identity to the did:key identifiers it speaks for:
//
//	{"spiffe://example.org/booking": ["did:key:z6Mk..."]}
//
// It is how a directory meets the executor (spec 7.6): whatever owns the
// workloads (SPIRE, Entra, Okta, a script over any of them) exports this file,
// and the executor rereads it when it changes. A file that cannot be read or
// parsed binds nothing, so the check fails closed.
type Bindings struct {
	path string

	mu    sync.Mutex
	mtime time.Time
	size  int64
	m     map[string]map[string]bool
	err   error
}

// LoadBindings reads path and returns a Bindings that follows its changes.
func LoadBindings(path string) (*Bindings, error) {
	b := &Bindings{path: path}
	b.refresh()
	return b, b.err
}

// Binds reports whether peer speaks for did. Use it as Executor.PeerBinds.
func (b *Bindings) Binds(peer, did string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	return b.err == nil && b.m[peer][did]
}

func (b *Bindings) refresh() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
}

func (b *Bindings) refreshLocked() {
	fi, err := os.Stat(b.path)
	if err != nil {
		b.m, b.err = nil, err
		return
	}
	if b.m != nil && fi.ModTime().Equal(b.mtime) && fi.Size() == b.size {
		return
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		b.m, b.err = nil, err
		return
	}
	var file map[string][]string
	if err := json.Unmarshal(raw, &file); err != nil {
		b.m, b.err = nil, fmt.Errorf("%s: %v", b.path, err)
		return
	}
	m := make(map[string]map[string]bool, len(file))
	for peer, keys := range file {
		m[peer] = map[string]bool{}
		for _, k := range keys {
			m[peer][k] = true
		}
	}
	b.m, b.err, b.mtime, b.size = m, nil, fi.ModTime(), fi.Size()
}
