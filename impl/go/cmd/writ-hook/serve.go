package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"writproto/httpbind"
)

// The gate can run as its own process, ideally as its own OS user, holding
// the keys, the grants, the store, and the audit record where Claude Code's
// tools cannot read them. The hook commands then only carry each event to it
// over a Unix socket and relay the answer. Granting stays a local command run
// as the gate's user (sudo -u), so a model with a shell cannot grant itself.

// request is one line a client sends; response is the one line it gets back.
type request struct {
	Cmd   string          `json:"cmd"`             // pre, post, recover, receipts
	Input json.RawMessage `json:"input,omitempty"` // the hook input; for recover, the SessionStart input or none
}

type response struct {
	Output json.RawMessage `json:"output,omitempty"` // the hook's stdout, when any
	Text   string          `json:"text,omitempty"`   // recover and receipts reports
	OK     bool            `json:"ok"`               // receipts: every receipt verified
	Error  string          `json:"error,omitempty"`
}

const socketTimeout = 30 * time.Second

// serve answers requests on a Unix socket until the listener fails. mode is
// the socket file's permission: the Claude Code user must be able to connect.
func (e *env) serve(socket string, mode os.FileMode, ready func()) error {
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(socket, mode); err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go e.answer(c)
	}
}

func (e *env) answer(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(socketTimeout))
	var req request
	line, err := bufio.NewReader(io.LimitReader(c, 1<<20)).ReadBytes('\n')
	if err == nil {
		err = json.Unmarshal(line, &req)
	}
	resp := response{}
	if err != nil {
		resp.Error = "unreadable request: " + err.Error()
	} else {
		resp = e.dispatch(context.Background(), "", req)
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

// dispatch answers one request from peer, over a connection whose context
// ctx carries it; peer is "" for the socket. A request over mTLS must name its
// session to recover, since recover with no session resolves every machine's
// unfinished calls.
func (e *env) dispatch(ctx context.Context, peer string, req request) response {
	var out bytes.Buffer
	var err error
	resp := response{}
	switch req.Cmd {
	case "pre":
		err = e.hookFrom(ctx, peer, bytes.NewReader(req.Input), &out, e.pre)
		resp.Output = trimJSON(out.Bytes())
	case "post":
		err = e.hookFrom(ctx, peer, bytes.NewReader(req.Input), &out, e.post)
		resp.Output = trimJSON(out.Bytes())
	case "recover":
		var h *hookInput
		if h, err = parseSessionStart(req.Input); err == nil && h == nil && peer != "" {
			err = errors.New("over mTLS, recover needs the SessionStart input, which names the session")
		} else if err == nil {
			if h != nil {
				h.ctx, h.peer = ctx, peer
			}
			err = e.recover(&out, h)
		}
		resp.Text, resp.OK = out.String(), err == nil
	case "receipts":
		resp.OK, err = e.receipts(&out)
		resp.Text = out.String()
	default:
		err = fmt.Errorf("unknown command %q; grants are made locally, as the gate's user", req.Cmd)
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp
}

func trimJSON(b []byte) json.RawMessage {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	return b
}

// ask sends one request to the gate at socket and returns its response.
func ask(socket string, req request) (*response, error) {
	c, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(socketTimeout))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// asker sends one request to a gate: over the socket (viaSocket) or mTLS
// (askTLS).
type asker func(request) (*response, error)

func viaSocket(socket string) asker {
	return func(r request) (*response, error) { return ask(socket, r) }
}

// remote runs a hook command through the gate at where, reached by send. It
// fails closed for pre: a gate that cannot be reached, or that answers with an
// error, blocks the tool call.
func remote(where string, send asker, cmd string, in io.Reader, out io.Writer) (bool, error) {
	var input json.RawMessage
	if cmd == "pre" || cmd == "post" || cmd == "recover" {
		b, err := io.ReadAll(in)
		if err != nil {
			return false, err
		}
		input = b
	}
	resp, err := send(request{Cmd: cmd, Input: input})
	if err == nil && resp.Error != "" {
		err = errors.New(resp.Error)
	}
	if err != nil {
		if cmd == "pre" {
			v := deny("the gate at " + where + " could not check this call, so it is blocked: " + err.Error())
			return false, json.NewEncoder(out).Encode(v)
		}
		return false, err
	}
	if len(resp.Output) > 0 {
		if _, err := out.Write(append(resp.Output, '\n')); err != nil {
			return false, err
		}
	}
	if resp.Text != "" {
		fmt.Fprint(out, resp.Text)
	}
	return resp.OK, nil
}

// The gate can also listen on TCP with mutual TLS, so one gate on a server
// serves the hooks of many machines and their keys are on none of them. Every
// request carries the client certificate's peer, read by the rules every Writ
// executor follows (spec 7.6, docs/directories.md): the one URI that is not a
// did:key names the machine, a bindings file says which keys it speaks for,
// and a certificate naming no machine, or two, is refused before replay. The
// TLS layer itself refuses a client with no certificate or one from another CA.

// hookPath is the one endpoint the mTLS listener serves.
const hookPath = "/v1/hook"

// gateTLS is the listener's TLS configuration: TLS 1.3, and a client
// certificate required and verified against the CA in clientCA.
func gateTLS(certFile, keyFile, clientCA string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool, err := certPool(clientCA)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

func certPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s holds no PEM certificate", file)
	}
	return pool, nil
}

// serveTLS answers requests over mTLS on ln, which must be a TLS listener
// built from gateTLS, until it fails.
func (e *env) serveTLS(ln net.Listener) error {
	srv := &http.Server{Handler: e.tlsHandler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: socketTimeout, WriteTimeout: socketTimeout}
	return srv.Serve(ln)
}

func (e *env) tlsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+hookPath, func(w http.ResponseWriter, r *http.Request) {
		ctx, peer, _ := httpbind.MTLSContext(r.Context(), r)
		var req request
		resp := response{}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			resp.Error = "unreadable request: " + err.Error()
		} else {
			resp = e.dispatch(ctx, peer, req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

// tlsClient reads the client side's configuration: the gate's URL in
// WRIT_HOOK_GATE, this machine's certificate and key in WRIT_HOOK_CERT and
// WRIT_HOOK_KEY, and the CA that signed the gate's certificate in WRIT_HOOK_CA.
func tlsClient(gate string) asker {
	cert, err := tls.LoadX509KeyPair(os.Getenv("WRIT_HOOK_CERT"), os.Getenv("WRIT_HOOK_KEY"))
	var pool *x509.CertPool
	if err == nil {
		pool, err = certPool(os.Getenv("WRIT_HOOK_CA"))
	}
	if err != nil {
		return func(request) (*response, error) { return nil, fmt.Errorf("client certificate: %v", err) }
	}
	return askTLS(gate, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool})
}

// askTLS sends one request to the gate at base over mTLS.
func askTLS(base string, cfg *tls.Config) asker {
	c := &http.Client{Timeout: socketTimeout, Transport: &http.Transport{TLSClientConfig: cfg}}
	return func(req request) (*response, error) {
		b, _ := json.Marshal(req)
		r, err := c.Post(strings.TrimSuffix(base, "/")+hookPath, "application/json", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("the gate answered %s", r.Status)
		}
		var resp response
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&resp); err != nil {
			return nil, err
		}
		return &resp, nil
	}
}
