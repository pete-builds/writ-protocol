// writ-bench is the concurrency proof. It runs the reference executor,
// writ-agent, as its own operating-system process with a durable file store,
// and drives it over real HTTP on loopback with many requests in flight at
// once. It checks the rules that concurrency is most likely to break:
//
//   - claims: N distinct calls under a writ with count 1 race for one use, and
//     exactly one is accepted (spec 7 steps 9 and 10, atomic);
//   - totals: N distinct calls of one amount race for a total that fits K of
//     them, and exactly K are accepted, so the sum never passes the total
//     (spec 7 step 10 and 7.3);
//   - replays: M copies of one signed call race, the operation runs once, and
//     every final answer is the same tally byte for byte; a copy that arrives
//     while the first is still running is answered with a pending tally,
//     which spec 7 step 9 requires, and these are counted (spec 7 step 9).
//
// Every answer is a tally whose signature and chain this program verifies.
// After each phase it asks the executor itself, with sys/tallies, which
// tallies it holds under the writ, so the count of operations performed is
// the executor's signed statement and not this program's tally of replies.
// Then it kills the executor, starts it again on the same store, and checks
// that the spent count and total stay spent.
//
// It exits non-zero on any departure from the rule. The numbers it prints are
// the ones README.md publishes; CI runs it smaller on every change.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"writproto/httpbind"
	"writproto/jcs"
	"writproto/keys"
	"writproto/writ"
)

var (
	A, _ = keys.FromSeed(bytes.Repeat([]byte{1}, 32)) // root issuer and caller
	C, _ = keys.FromSeed(bytes.Repeat([]byte{3}, 32)) // the executor
)

type agent struct {
	cmd      *exec.Cmd
	endpoint string
	log      *os.File
}

func main() {
	claims := flag.Int("claims", 10000, "distinct calls racing for one use")
	totals := flag.Int("totals", 10000, "distinct calls racing for a total")
	fits := flag.Int("fits", 100, "how many of the totals calls the total fits")
	replays := flag.Int("replays", 100000, "copies of one signed call")
	workers := flag.Int("workers", 256, "requests in flight at once")
	bin := flag.String("agent", "", "writ-agent binary (built from ./cmd/writ-agent when empty)")
	race := flag.Bool("race", false, "build writ-agent with the race detector and fail on any race it reports")
	flag.Parse()

	dir, err := os.MkdirTemp("", "writ-bench-")
	check(err)
	defer os.RemoveAll(dir)
	if *bin == "" {
		*bin = filepath.Join(dir, "writ-agent")
		args := []string{"build", "-o", *bin}
		if *race {
			args = append(args, "-race")
		}
		b := exec.Command("go", append(args, "./cmd/writ-agent")...)
		b.Stdout, b.Stderr = os.Stdout, os.Stderr
		check(b.Run())
	}
	store := filepath.Join(dir, "store.json")
	ag := start(*bin, store, dir)

	client := httpbind.NewClient()
	client.HTTP.Transport = &http.Transport{MaxIdleConnsPerHost: *workers, MaxConnsPerHost: *workers}
	exp := time.Now().Unix() + 3600
	ctx := context.Background()
	fail := 0
	report := func(ok bool, format string, a ...any) {
		mark := "PASS"
		if !ok {
			mark, fail = "FAIL", fail+1
		}
		fmt.Printf("%s  %s\n", mark, fmt.Sprintf(format, a...))
	}

	// Claims: one use, many contenders.
	wCount := issue(map[string]any{"act": b("prefix", "travel"), "amount": b("max", 100), "uses": b("count", 1)}, exp)
	calls := make([]*writ.Call, *claims)
	for i := range calls {
		calls[i] = charge(wCount, 1)
	}
	t0 := time.Now()
	codes := outcomes(ctx, client, ag.endpoint, wCount, calls, *workers)
	el := time.Since(t0)
	report(codes["ok"] == 1 && codes["count_exhausted"] == *claims-1 && len(codes) == 2,
		"claims: %d calls for one use, %d in flight: %v in %v (%.0f calls/s)", *claims, *workers, codes, el.Round(time.Millisecond), float64(*claims)/el.Seconds())
	held := tallies(ctx, client, ag.endpoint, wCount)
	report(held == 1, "claims: the executor's own sys/tallies lists %d tally under the writ", held)

	// Totals: the total fits exactly fits calls of 7.
	const amount = 7
	wTotal := issue(map[string]any{"act": b("prefix", "travel"), "amount": b("total", int64(*fits*amount))}, exp)
	calls = make([]*writ.Call, *totals)
	for i := range calls {
		calls[i] = charge(wTotal, amount)
	}
	t0 = time.Now()
	codes = outcomes(ctx, client, ag.endpoint, wTotal, calls, *workers)
	el = time.Since(t0)
	report(codes["ok"] == *fits && codes["total_exhausted"] == *totals-*fits && len(codes) == 2,
		"totals: %d calls of %d for a total of %d, %d in flight: %v in %v (%.0f calls/s)", *totals, amount, *fits*amount, *workers, codes, el.Round(time.Millisecond), float64(*totals)/el.Seconds())
	held = tallies(ctx, client, ag.endpoint, wTotal)
	report(held == *fits, "totals: the executor's own sys/tallies lists %d tallies under the writ, %d spent of %d", held, held*amount, *fits*amount)

	// Replays: one signed call, many copies.
	wReplay := issue(map[string]any{"act": b("prefix", "travel"), "amount": b("max", 100)}, exp)
	one := charge(wReplay, 5)
	same := make([]*writ.Call, *replays)
	for i := range same {
		same[i] = one
	}
	var first []byte
	var mu sync.Mutex
	differ := atomic.Int64{}
	t0 = time.Now()
	codes = sendAll(ctx, client, ag.endpoint, wReplay, same, *workers, func(code string, canon []byte) {
		if code != "ok" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if first == nil {
			first = canon
		} else if !bytes.Equal(first, canon) {
			differ.Add(1)
		}
	})
	el = time.Since(t0)
	report(codes["ok"]+codes["pending"] == *replays && codes["ok"] > 0 && differ.Load() == 0,
		"replays: %d copies of one call, %d in flight: %v, %d final answers differing from the first, in %v (%.0f calls/s)", *replays, *workers, codes, differ.Load(), el.Round(time.Millisecond), float64(*replays)/el.Seconds())
	held = tallies(ctx, client, ag.endpoint, wReplay)
	report(held == 1, "replays: the executor's own sys/tallies lists %d tally, so the charge ran once", held)

	// Restart on the same store: what was spent stays spent.
	ag.stop()
	ag = start(*bin, store, dir)
	code := answer(ctx, client, ag.endpoint, wCount, charge(wCount, 1))
	report(code == "count_exhausted", "restart: a new call under the spent count is %s", code)
	code = answer(ctx, client, ag.endpoint, wTotal, charge(wTotal, amount))
	report(code == "total_exhausted", "restart: a new call under the spent total is %s", code)
	code = answer(ctx, client, ag.endpoint, wReplay, one)
	report(code == "ok", "restart: the replayed call is still answered from the store: %s", code)
	ag.stop()

	if *race {
		logb, _ := os.ReadFile(ag.log.Name())
		races := bytes.Count(logb, []byte("WARNING: DATA RACE"))
		report(races == 0, "race detector: %d data races reported by writ-agent", races)
	}
	if fail > 0 {
		fmt.Printf("%d checks failed\n", fail)
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}

func b(t string, v any) map[string]any { return map[string]any{"t": t, "v": v} }

func issue(bnd map[string]any, exp int64) *writ.Writ {
	w, err := writ.Issue(A, C.DID(), bnd, exp, nil)
	check(err)
	return w
}

func charge(w *writ.Writ, amount int64) *writ.Call {
	k, err := writ.NewCall(A, []*writ.Writ{w}, "travel/charge", map[string]any{"amount": amount, "currency": "USD"})
	check(err)
	return k
}

// sendAll sends every call with workers in flight at once, verifies each tally,
// passes its canonical bytes to seen when given, and counts the outcomes:
// "ok", a refusal's reason, or an error.
func sendAll(ctx context.Context, c *httpbind.Client, endpoint string, w *writ.Writ, calls []*writ.Call, workers int, seen func(string, []byte)) map[string]int {
	var mu sync.Mutex
	codes := map[string]int{}
	next := atomic.Int64{}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(calls) {
					return
				}
				code, canon := send(ctx, c, endpoint, w, calls[i])
				if seen != nil && canon != nil {
					seen(code, canon)
				}
				mu.Lock()
				codes[code]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return codes
}

func outcomes(ctx context.Context, c *httpbind.Client, endpoint string, w *writ.Writ, calls []*writ.Call, workers int) map[string]int {
	return sendAll(ctx, c, endpoint, w, calls, workers, nil)
}

func answer(ctx context.Context, c *httpbind.Client, endpoint string, w *writ.Writ, k *writ.Call) string {
	code, _ := send(ctx, c, endpoint, w, k)
	return code
}

// send makes one call and returns its outcome and the tally's canonical bytes.
// An answer whose tally does not verify against the writ and the call is an
// error, never an outcome.
func send(ctx context.Context, c *httpbind.Client, endpoint string, w *writ.Writ, k *writ.Call) (string, []byte) {
	t, res, err := c.Call(ctx, endpoint, k)
	if err != nil {
		return "error: " + err.Error(), nil
	}
	v, tl, err := writ.VerifyTally(w, k, t, res)
	if v != writ.Valid {
		return fmt.Sprintf("error: tally %s: %v", v, err), nil
	}
	canon, err := jcs.Marshal(map[string]any(t))
	if err != nil {
		return "error: " + err.Error(), nil
	}
	if tl.St == "ok" {
		return "ok", canon
	}
	return tl.Err.Code, canon
}

// tallies asks the executor, as the writ's issuer, how many tallies it holds
// under the writ (spec 8.2). The answer is the executor's signed statement.
func tallies(ctx context.Context, c *httpbind.Client, endpoint string, w *writ.Writ) int {
	k, err := writ.NewCall(A, []*writ.Writ{w}, "sys/tallies", map[string]any{"writ": w.ID})
	check(err)
	t, res, err := c.Call(ctx, endpoint, k)
	if err != nil {
		return -1
	}
	if v, tl, _ := writ.VerifyTally(w, k, t, res); v != writ.Valid || tl.St != "ok" {
		return -1
	}
	m, _ := res.(map[string]any)
	list, _ := m["tallies"].([]any)
	return len(list)
}

// start runs writ-agent as the payment executor on a free loopback port and
// waits until it is ready.
func start(bin, store, dir string) *agent {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	logf, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	check(err)
	cmd := exec.Command(bin, "-role", "payment", "-seed", hex.EncodeToString(bytes.Repeat([]byte{3}, 32)),
		"-port", strconv.Itoa(port), "-store", store, "-accept", A.DID())
	cmd.Stdout = logf
	stderr, err := cmd.StderrPipe()
	check(err)
	check(cmd.Start())
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintln(logf, line)
			if strings.TrimSpace(line) == "ready" {
				select {
				case ready <- true:
				default:
				}
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		check(fmt.Errorf("writ-agent did not start; see %s", logf.Name()))
	}
	// "ready" is printed just before the listener opens; wait for the port.
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		if i > 300 {
			check(fmt.Errorf("writ-agent never listened on %d", port))
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &agent{cmd: cmd, endpoint: fmt.Sprintf("http://127.0.0.1:%d/writ", port), log: logf}
}

// stop kills the executor without warning, as a crash would, and waits for it.
func (a *agent) stop() {
	_ = a.cmd.Process.Kill()
	_ = a.cmd.Wait()
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "writ-bench:", err)
		os.Exit(2)
	}
}
