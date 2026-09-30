package exec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"writproto/wire"
	"writproto/writ"
)

// Spec 9.3: one audit entry for every call and revoke, refusals and unsigned
// rejections included, naming the peer or its absence.
func TestAuditRecordsEveryAnswer(t *testing.T) {
	A, S := id(1), id(9)
	e := newC(t, "", A, func(ctx context.Context, k *writ.Call) Result { return Result{} })
	var got []AuditEntry
	e.Audit = func(a AuditEntry) { got = append(got, a) }
	e.PeerBinds = func(peer, did string) bool { return peer == "spiffe://a/agent" && did == A.DID() }

	w, _ := writ.Issue(A, e.ID.DID(), bnd("act", "prefix", "x"), now+3600, nil)
	k, _ := writ.NewCall(A, []*writ.Writ{w}, "x/y", map[string]any{})
	rep, _ := e.Execute(WithPeer(context.Background(), "spiffe://a/agent"), k.Raw)
	e.Execute(WithPeer(context.Background(), "spiffe://s/other"), k.Raw)
	ws, _ := writ.Issue(S, e.ID.DID(), bnd("act", "prefix", "x"), now+3600, nil)
	ks, _ := writ.NewCall(S, []*writ.Writ{ws}, "x/y", map[string]any{})
	e.Execute(context.Background(), ks.Raw)
	forged, _ := wire.Clone(k.Raw)
	forged["from"] = S.DID()
	e.Execute(context.Background(), forged)
	rv, _ := writ.NewRevoke(A, []*writ.Writ{w})
	e.Revoke(rv.Raw)
	e.RevokeContext(WithPeer(context.Background(), "spiffe://s/other"), wire.Object{"v": 1, "typ": "revoke"})
	e.AuditUnreadable(context.Background(), writ.TooLarge)

	type row struct{ kind, outcome, reason, from, peer string }
	peer := func(p *string) string {
		if p == nil {
			return "<none>"
		}
		return *p
	}
	want := []row{
		{"call", "ok", "", A.DID(), "spiffe://a/agent"},
		{"call", "failed", "peer_mismatch", A.DID(), "spiffe://s/other"},
		{"call", "failed", "root_not_accepted", S.DID(), "<none>"},
		{"call", "rejected", "bad_signature", "", "<none>"},
		{"revoke", "recorded", "", A.DID(), "<none>"},
		{"revoke", "rejected", "malformed", "", "spiffe://s/other"},
		{"unknown", "rejected", "too_large", "", "<none>"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d audit entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if (row{g.Kind, g.Outcome, g.Reason, g.From, peer(g.Peer)}) != w {
			t.Errorf("entry %d: got %+v, want %+v", i, row{g.Kind, g.Outcome, g.Reason, g.From, peer(g.Peer)}, w)
		}
	}
	tid, _ := wire.Hash(rep.Tally)
	if got[0].Tally != tid || got[0].ID != k.ID || got[0].Root != A.DID() || got[0].Leaf != w.ID || got[0].Op != "x/y" {
		t.Errorf("entry 0 does not name the call, its chain, and its tally: %+v", got[0])
	}
	if got[3].Tally != "" {
		t.Errorf("an unsigned rejection names no tally: %+v", got[3])
	}
}

// The file log appends one JSON line per entry and keeps earlier lines
// across a reopen; peer is written as null when there was none.
func TestAuditLogAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 2; i++ {
		l, err := OpenAuditLog(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Record(AuditEntry{At: int64(i), Kind: "call", Outcome: "ok"}); err != nil {
			t.Fatal(err)
		}
		l.Close()
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["peer"]; !ok || v != nil || m["at"] != float64(1) {
		t.Fatalf("second line %s: want at 1 and an explicit null peer", lines[1])
	}
}
