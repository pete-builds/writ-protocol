"""Section 10, the HTTP binding: one POST endpoint carrying a call or a
revoke, and the well-known document (Appendix B), over the standard
library's http.server. A client for the same binding is ``post``.

The server answers from ``Executor.receive_call``, which performs the
operation before it returns, so the application must return an Outcome:
an operation held for ``complete()`` has no answer to send over HTTP and is
refused with status 500.
"""

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import canon
from .executor import STORE_WRITE_FAILED

CONTENT_TYPE = "application/writ+json"
MAX_REQUEST = 65536  # a call and a revoke share the limit of section 1.6


def serve(executor, well_known, host="127.0.0.1", port=0, peer_of=None):
    """Start a server in a background thread and return it; its bound port
    is ``server.server_address[1]``. ``peer_of(handler)`` returns the
    identity the transport authenticated; an ``executor.UnidentifiedPeer``
    when it authenticated a peer it cannot name, such as a verified client
    certificate with no identity; or None only when it authenticated no peer
    at all (section 7.6). Returning None for an authenticated connection
    skips peer binding, so a captured call could fetch its stored result."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quiet: the audit record is the log
            pass

        def _send(self, status, body, ctype="application/json"):
            data = canon.canonicalize(body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/.well-known/writ":
                self._send(200, well_known)
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != well_known.get("endpoint", "/writ"):
                self._send(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_REQUEST:
                self._send(400, {"error": "too_large"})
                return
            body = self.rfile.read(length)
            try:
                typ = json.loads(body).get("typ")
            except (ValueError, AttributeError):
                self._send(400, {"error": "noncanonical"})
                return
            peer = peer_of(self) if peer_of is not None else None
            if typ == "call":
                answer = executor.receive_call(body, peer=peer)
                if "error" in answer:
                    self._send(400, answer)
                elif answer.get("inflight"):
                    self._send(500, {"error": "writ-py/held_operation"})
                else:
                    self._send(200, answer, CONTENT_TYPE)
            elif typ == "revoke":
                answer = executor.receive_revoke(body, peer=peer)
                if answer.get("error") == STORE_WRITE_FAILED:
                    self._send(503, answer)
                elif "error" in answer:
                    self._send(400, answer)
                else:
                    self._send(200, answer, CONTENT_TYPE)
            else:
                self._send(400, {"error": "wrong_type"})

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def post(url, obj, timeout=30):
    """POST one call or revoke; returns (status, parsed body)."""
    req = urllib.request.Request(url, data=canon.canonicalize(obj), method="POST",
                                 headers={"Content-Type": CONTENT_TYPE})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, canon.loads_lenient(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, canon.loads_lenient(e.read())
