package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// The gate can run as its own process, ideally as its own OS user, holding
// the keys, the grants, the store, and the audit record where Claude Code's
// tools cannot read them. The hook commands then only carry each event to it
// over a Unix socket and relay the answer. Granting stays a local command run
// as the gate's user (sudo -u), so a model with a shell cannot grant itself.

// request is one line a client sends; response is the one line it gets back.
type request struct {
	Cmd   string          `json:"cmd"` // pre, post, recover, receipts
	Input json.RawMessage `json:"input,omitempty"`
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
		resp = e.dispatch(req)
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

func (e *env) dispatch(req request) response {
	var out bytes.Buffer
	var err error
	resp := response{}
	switch req.Cmd {
	case "pre":
		err = e.hook(bytes.NewReader(req.Input), &out, e.pre)
		resp.Output = trimJSON(out.Bytes())
	case "post":
		err = e.hook(bytes.NewReader(req.Input), &out, e.post)
		resp.Output = trimJSON(out.Bytes())
	case "recover":
		err = e.recover(&out)
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

// remote runs a hook command through the gate at socket. It fails closed for
// pre: an unreachable gate blocks the tool call.
func remote(socket, cmd string, in io.Reader, out io.Writer) (bool, error) {
	var input json.RawMessage
	if cmd == "pre" || cmd == "post" {
		b, err := io.ReadAll(in)
		if err != nil {
			return false, err
		}
		input = b
	}
	resp, err := ask(socket, request{Cmd: cmd, Input: input})
	if err == nil && resp.Error != "" {
		err = errors.New(resp.Error)
	}
	if err != nil {
		if cmd == "pre" {
			v := deny("the gate at " + socket + " could not check this call, so it is blocked: " + err.Error())
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
