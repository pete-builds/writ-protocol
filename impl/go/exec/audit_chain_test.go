package exec

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

func writeEntries(t *testing.T, path string, n int) {
	t.Helper()
	l, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := range n {
		if err := l.Record(AuditEntry{At: now + int64(i), Kind: "call", Outcome: "ok", Op: fmt.Sprintf("op/%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, data []byte) *AuditReport {
	t.Helper()
	rep, err := VerifyAudit(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func lines(data []byte) [][]byte {
	return bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
}

func join(ls [][]byte) []byte { return append(bytes.Join(ls, []byte("\n")), '\n') }

// Spec 9.3: each entry links to the one before it, so any edit, removal, or
// reordering breaks a link, and the first entry says it is the first.
func TestAuditChainShowsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEntries(t, path, 5)
	data, _ := os.ReadFile(path)
	if rep := verify(t, data); rep.Entries != 5 || len(rep.Breaks) != 0 || rep.Unchained != 0 || len(rep.Torn) != 0 {
		t.Fatalf("an untouched record: %+v", rep)
	}
	ls := lines(data)
	edited := slices.Clone(ls)
	edited[2] = bytes.Replace(edited[2], []byte(`"outcome":"ok"`), []byte(`"outcome":"failed"`), 1)
	removed := append(slices.Clone(ls[:1]), ls[2:]...)
	swapped := slices.Clone(ls)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	cases := []struct {
		name string
		data []byte
		want []int
	}{
		{"an entry edited", join(edited), []int{4}},
		{"an entry removed", join(removed), []int{2}},
		{"two entries swapped", join(swapped), []int{2, 3, 4}},
		{"the first entry removed", join(ls[1:]), []int{1}},
	}
	for _, c := range cases {
		if rep := verify(t, c.data); !slices.Equal(rep.Breaks, c.want) {
			t.Errorf("%s: breaks at %v, want %v", c.name, rep.Breaks, c.want)
		}
	}
	// What the chain cannot show: the newest entries cut off.
	if rep := verify(t, join(ls[:3])); len(rep.Breaks) != 0 {
		t.Errorf("a record cut short reads as whole: %+v; the spec says so", rep)
	}
}

// A crash can leave a torn last line. It stays as an entry, and the next
// entry links to its bytes, so the chain is unbroken around it.
func TestAuditChainAcrossATornLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEntries(t, path, 2)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte(`{"at":1788400099,"kind":"ca`))
	f.Close()
	writeEntries(t, path, 2)
	data, _ := os.ReadFile(path)
	if rep := verify(t, data); rep.Entries != 5 || !slices.Equal(rep.Torn, []int{3}) || len(rep.Breaks) != 0 {
		t.Fatalf("across a torn line: %+v", rep)
	}
}

// A record written before chaining keeps its entries; chaining starts at
// the first new one, which links to the last old line.
func TestAuditChainContinuesAnOlderRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	old := "{\"at\":1,\"kind\":\"call\",\"peer\":null,\"outcome\":\"ok\"}\n{\"at\":2,\"kind\":\"call\",\"peer\":null,\"outcome\":\"ok\"}\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	writeEntries(t, path, 3)
	data, _ := os.ReadFile(path)
	if rep := verify(t, data); rep.Unchained != 2 || len(rep.Breaks) != 0 {
		t.Fatalf("an older record continued: %+v", rep)
	}
	// Once chaining starts, an entry without a link is a break.
	ls := lines(data)
	ls = append(ls[:3], append([][]byte{[]byte(`{"at":9,"kind":"call","peer":null,"outcome":"ok"}`)}, ls[3:]...)...)
	if rep := verify(t, join(ls)); !slices.Equal(rep.Breaks, []int{4, 5}) {
		t.Fatalf("an unlinked entry inserted: breaks %v, want [4 5]", rep.Breaks)
	}
}

// writ-hook runs one process per hook event, all appending to one record.
// Two writers with their own handles never fork the chain.
func TestAuditChainWithTwoWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeEntries(t, path, 200)
		}()
	}
	wg.Wait()
	data, _ := os.ReadFile(path)
	if rep := verify(t, data); rep.Entries != 400 || len(rep.Breaks) != 0 {
		t.Fatalf("two writers: %d entries, breaks at %v", rep.Entries, rep.Breaks)
	}
}
