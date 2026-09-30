// Package filebind is a second transport for Writ: files in a directory, as
// the roadmap asks, to show the protocol does not depend on HTTP. The objects
// are the same bytes the HTTP binding carries (spec section 10).
//
// A caller writes one call or revoke per file into DIR/in, by writing a
// temporary name and renaming, so the executor never sees half a file. The
// executor claims a file by renaming it into DIR/work, answers it, writes the
// answer under the same name into DIR/out (again by rename), and removes the
// claimed file. An answer is {"tally", "res"} for a call, {"tallies"} for a
// revoke, or {"error"} for a rejection before any signature verified.
//
// A crash between claiming and answering leaves the file in DIR/work, and the
// next Serve answers it first. The call store makes that safe: a call that
// already ran is answered from the store and does not run again (spec 7 step
// 9).
package filebind

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"writproto/exec"
	"writproto/wire"
	"writproto/writ"
)

// Dirs creates and returns DIR/in, DIR/work, and DIR/out.
func Dirs(dir string) (in, work, out string, err error) {
	in, work, out = filepath.Join(dir, "in"), filepath.Join(dir, "work"), filepath.Join(dir, "out")
	for _, d := range []string{in, work, out} {
		if err = os.MkdirAll(d, 0o700); err != nil {
			return
		}
	}
	return
}

// Serve answers files until ctx ends, looking for new ones every poll.
func Serve(ctx context.Context, e *exec.Executor, dir string, poll time.Duration) error {
	in, work, out, err := Dirs(dir)
	if err != nil {
		return err
	}
	// Files claimed before a crash are answered first.
	for _, name := range jsonFiles(work) {
		answer(ctx, e, filepath.Join(work, name), filepath.Join(out, name))
	}
	for {
		for _, name := range jsonFiles(in) {
			claimed := filepath.Join(work, name)
			if os.Rename(filepath.Join(in, name), claimed) != nil {
				continue // another executor over the same directory took it
			}
			answer(ctx, e, claimed, filepath.Join(out, name))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func jsonFiles(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, en := range entries {
		n := en.Name()
		if !en.IsDir() && strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func answer(ctx context.Context, e *exec.Executor, claimed, outPath string) {
	var reply any
	raw, err := os.ReadFile(claimed)
	if err != nil {
		return
	}
	obj, derr := wire.Decode(raw)
	switch {
	case derr != nil:
		reply = map[string]any{"error": string(writ.Noncanonical)}
	case obj["typ"] == "call":
		rep, rej := e.Execute(ctx, obj)
		if rej != nil {
			reply = map[string]any{"error": string(rej.Code)}
		} else {
			m := map[string]any{"tally": rep.Tally}
			if rep.Res != nil {
				m["res"] = rep.Res
			}
			reply = m
		}
	case obj["typ"] == "revoke":
		rep, rej := e.Revoke(obj)
		if rej != nil {
			reply = map[string]any{"error": string(rej.Code)}
		} else {
			reply = rep
		}
	default:
		reply = map[string]any{"error": string(writ.WrongType)}
	}
	if writeAtomic(outPath, reply) == nil {
		_ = os.Remove(claimed)
	}
}

func writeAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Send writes obj into DIR/in under name, which must end in .json.
func Send(dir, name string, obj wire.Object) error {
	if !strings.HasSuffix(name, ".json") || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return errors.New("filebind: name must be a plain file name ending in .json")
	}
	in, _, _, err := Dirs(dir)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(in, name), obj)
}

// Await waits for the answer to name and returns it, removing the file.
func Await(ctx context.Context, dir, name string, poll time.Duration) (map[string]any, error) {
	_, _, out, err := Dirs(dir)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(out, name)
	for {
		if b, err := os.ReadFile(p); err == nil {
			obj, err := wire.Decode(b)
			if err != nil {
				return nil, err
			}
			_ = os.Remove(p)
			return obj, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}
