"""Section 10 over a real socket: the Python server answers calls and
revokes, serves the well-known document, and rejects what it cannot read."""

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from writ import httpbind, issue, verify as V  # noqa: E402
from writ.executor import Executor, Outcome, UnidentifiedPeer  # noqa: E402
from writ.keys import Key  # noqa: E402

A = Key.from_seed("a1" * 32)
E = Key.from_seed("e3" * 32)
T0 = 1_788_400_000


class HTTPBindingTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="writ-http-")
        self.entries = []
        self.ex = Executor(E, [A.did], self.dir, app=lambda op: Outcome("ok", res={"n": 1}),
                           audit=self.entries.append)
        self.ex.set_time(T0 + 10)
        self.wk = {"v": 1, "did": E.did, "endpoint": "/writ", "act": ["tools"]}
        self.server = httpbind.serve(self.ex, self.wk, peer_of=lambda h: h.headers.get("X-Peer"))
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.w = issue.issue_root(A, E.did, {"act": {"t": "prefix", "v": "tools"}}, T0 + 3600)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_call_revoke_and_well_known(self):
        with urllib.request.urlopen(self.url + "/.well-known/writ") as r:
            self.assertEqual(json.loads(r.read()), self.wk)
        call = issue.make_call(A, [self.w], "tools/x", {})
        status, body = httpbind.post(self.url + "/writ", call)
        self.assertEqual(status, 200)
        self.assertEqual(body["tally"]["st"], "ok")
        self.assertTrue(V.verify_tally(self.w, call, body["tally"], res=body["res"]).ok)
        rv = issue.make_revoke(A, self.w, chain=[self.w])
        status, body = httpbind.post(self.url + "/writ", rv)
        self.assertEqual((status, body["tallies"]), (200, []))
        V.verify_ack(V.verify_revoke(rv), body["ack"], body["res"])  # section 9.4, over the wire
        status, body = httpbind.post(self.url + "/writ", issue.make_call(A, [self.w], "tools/y", {}))
        self.assertEqual((status, body["tally"]["err"]), (200, {"code": "revoked"}))

    def test_what_it_cannot_read(self):
        status, body = httpbind.post(self.url + "/writ", {"v": 1, "typ": "note"})
        self.assertEqual((status, body), (400, {"error": "wrong_type"}))
        forged = issue.make_call(A, [self.w], "tools/x", {})
        forged["from"] = E.did
        status, body = httpbind.post(self.url + "/writ", forged)
        self.assertEqual((status, body), (400, {"error": "bad_signature"}))
        req = urllib.request.Request(self.url + "/writ", data=b"{not json", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)

    def test_peer_reaches_the_executor(self):
        req = urllib.request.Request(self.url + "/writ", method="POST",
                                     data=json.dumps(issue.make_call(A, [self.w], "tools/x", {})).encode(),
                                     headers={"X-Peer": "spiffe://a/agent"})
        with urllib.request.urlopen(req) as r:
            body = json.loads(r.read())
        # No binding is held for that peer, so the call is refused (section 7.6).
        self.assertEqual(body["tally"]["err"], {"code": "peer_mismatch"})
        self.assertEqual(self.entries[-1]["peer"], "spiffe://a/agent")


class UnidentifiedPeerTest(unittest.TestCase):
    """A peer the transport authenticated but cannot name, such as a verified
    client certificate with no identity, binds nothing (section 7.6): a
    captured call replayed over it earns no stored result, and nothing
    runs, even where the peers map holds its label."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="writ-http-")
        self.runs = []
        self.entries = []
        self.ex = Executor(E, [A.did], self.dir,
                           app=lambda op: self.runs.append(op) or Outcome("ok", res={"account": "4111-1111"}),
                           peers={"spiffe://a/agent": [A.did], "x509:none": [A.did]},
                           audit=self.entries.append)
        self.ex.set_time(T0 + 10)
        wk = {"v": 1, "did": E.did, "endpoint": "/writ", "act": ["tools"]}

        def peer_of(h):
            if h.headers.get("X-Cert") == "none":
                return UnidentifiedPeer("x509:none")
            return h.headers.get("X-Peer")

        self.server = httpbind.serve(self.ex, wk, peer_of=peer_of)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/writ"
        self.w = issue.issue_root(A, E.did, {"act": {"t": "prefix", "v": "tools"}}, T0 + 3600)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def send(self, call, headers):
        req = urllib.request.Request(self.url, method="POST", data=json.dumps(call).encode(), headers=headers)
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def test_unidentified_peer_binds_nothing(self):
        call = issue.make_call(A, [self.w], "tools/x", {})
        body = self.send(call, {"X-Peer": "spiffe://a/agent"})
        self.assertEqual((body["tally"]["st"], body["res"], len(self.runs)), ("ok", {"account": "4111-1111"}, 1))
        body = self.send(call, {"X-Cert": "none"})
        self.assertEqual(body["tally"]["err"], {"code": "peer_mismatch"})
        self.assertNotIn("res", body)
        body = self.send(issue.make_call(A, [self.w], "tools/x", {}), {"X-Cert": "none"})
        self.assertEqual(body["tally"]["err"], {"code": "peer_mismatch"})
        self.assertEqual(len(self.runs), 1)
        self.assertEqual([e["peer"] for e in self.entries], ["spiffe://a/agent", "x509:none", "x509:none"])


if __name__ == "__main__":
    unittest.main()
