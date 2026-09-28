package exec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"writproto/keys"
	"writproto/writ"
)

// Security review finding 7: a valid key-wide revoke needs no accepted root,
// so anyone can send one. Each must cost one appended line, never a rewrite of
// the call, count, and tally stores, and every one must survive a restart.
// Per-writ revokes are dropped once their writ has expired; key-wide ones are
// kept for good.
func TestRevokesAppendWithoutRewritingTheStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	before, _ := os.ReadFile(path)
	strangers := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		k, _ := keys.FromSeed(bytes.Repeat([]byte{byte(i % 250), byte(i / 250)}, 16))
		strangers = append(strangers, "*:"+k.DID())
		s.revoke(strangers[i], 1<<62)
	}
	s.revoke("expiredwrit", now-1)
	s.revoke("livewrit", now+3600)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatalf("revokes rewrote the main store file (%d bytes before, %d after)", len(before), len(after))
	}
	// A crash mid-append leaves a torn last line; it must not stop a restart.
	f, _ := os.OpenFile(s.revokeLog(), os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte(`{"writ":"torn`))
	f.Close()

	s2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range append(strangers, "expiredwrit", "livewrit") {
		if !s2.isRevoked(id) {
			t.Fatalf("%s not revoked after restart", id)
		}
	}
	e := New(id(3), s2)
	e.Now = func() int64 { return now }
	e.Recover()
	if s2.isRevoked("expiredwrit") {
		t.Error("a revoke of an expired writ survived Recover")
	}
	if !s2.isRevoked("livewrit") || !s2.isRevoked(strangers[0]) {
		t.Error("Recover dropped a live or key-wide revoke")
	}
	s3, _ := OpenFileStore(path)
	if s3.isRevoked("expiredwrit") || !s3.isRevoked("livewrit") || len(s3.Revoked) != 501 {
		t.Errorf("compacted log: expired %v, live %v, %d entries (want 501)", s3.isRevoked("expiredwrit"), s3.isRevoked("livewrit"), len(s3.Revoked))
	}
}

// Spec 8.2 as revised 2026-09-28: sys/tallies names a writ from issued or one
// below it. An intermediate issuer asking about an ancestor writ would see
// work under sibling delegations it never issued, so it is tally_mismatch.
func TestTalliesScopedToTheCallersWrit(t *testing.T) {
	f := newStandingFixture(t)
	for _, c := range []struct {
		who  *keys.Identity
		name *writ.Writ
		want string
	}{
		{f.A, f.w1, ""},
		{f.A, f.w2, ""},
		{f.B, f.w2, ""},
		{f.B, f.w1, string(writ.TallyMismatch)},
	} {
		k, _ := writ.NewCall(c.who, []*writ.Writ{f.w1, f.w2}, "sys/tallies", map[string]any{"writ": c.name.ID})
		rep, rej := f.e.Execute(context.Background(), k.Raw)
		if got := f.code(t, k, rep, rej); got != c.want {
			t.Errorf("%s naming %s: got %q, want %q", label(f, c.who), label(f, c.name), got, c.want)
		}
	}
}

func label(f *standingFixture, v any) string {
	switch v {
	case f.A:
		return "A"
	case f.B:
		return "B"
	case f.w1:
		return "w1"
	case f.w2:
		return "w2"
	}
	return fmt.Sprint(v)
}
