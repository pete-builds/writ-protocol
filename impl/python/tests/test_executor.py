"""Executor and durable store tests. Run from impl/python:

    python3 -B -m unittest discover -s tests

Every executor here is built over a fresh temporary directory, so each
test starts, like a section 14.1 scenario, with empty stores.
"""

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from writ import canon, cli, issue, objects as O, stores as S, verify as V  # noqa: E402
from writ.executor import HELD, STORE_WRITE_FAILED, Executor, Outcome  # noqa: E402
from writ.keys import Key  # noqa: E402

A = Key.from_seed("a1" * 32)      # root issuer, accepted
BK = Key.from_seed("b2" * 32)     # intermediate holder
EK = Key.from_seed("e3" * 32)     # the executor
CK = Key.from_seed("c4" * 32)     # a sub-executor
STRANGER = Key.from_seed("f5" * 32)

T0 = 1_788_400_000
EXP_ROOT = T0 + 3600
EXP_LEAF = T0 + 1800
REV = T0 + 86400

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIOS = os.path.join(HERE, "..", "..", "..", "conformance", "scenarios")


def nnc(n):
    return issue.b64u_encode(f"test-nonce-{n:05d}".encode())


def chain(root_bnd=None, leaf_bnd=None, leaf_holder=None, n=0):
    """A two-writ chain A -> B -> executor, with fixed nonces."""
    w1 = issue.issue_root(A, BK.did, root_bnd or {
        "act": {"t": "prefix", "v": "travel"},
        "amount": {"t": "max", "v": 60000},
        "uses": {"t": "count", "v": 3},
    }, EXP_ROOT, nnc=nnc(2 * n))
    w2 = issue.narrow(w1, BK, leaf_holder or EK.did, exp=EXP_LEAF, bnd=leaf_bnd or {
        "act": {"t": "prefix", "v": "travel/charge"},
        "amount": {"t": "max", "v": 58900},
    }, nnc=nnc(2 * n + 1))
    return [w1, w2]


def cid(n):
    return issue.b64u_encode(f"test-call-id-{n:05d}".encode())


def fwd(ch, n, amount=58900, op="travel/charge"):
    return issue.make_call(BK, ch, op, {"amount": amount}, call_id=cid(n))


class ScriptedApp:
    """An application that returns queued outcomes and records every call."""

    def __init__(self):
        self.outcomes = []
        self.calls = []

    def push(self, outcome):
        self.outcomes.append(outcome)

    def __call__(self, op):
        self.calls.append((op.kind, op.call_id))
        if not self.outcomes:
            raise AssertionError(f"unexpected application call for {op.op}")
        out = self.outcomes.pop(0)
        return out(op) if callable(out) else out


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="writ-test-")
        self.app = ScriptedApp()
        self.ex = Executor(EK, [A.did], self.dir, app=self.app)
        self.ex.set_time(T0 + 10)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def at(self, t):
        self.ex.set_time(t)
        return self.ex

    def assertRefused(self, answer, code, acc=None):
        self.assertIn("tally", answer, answer)
        t = answer["tally"]
        self.assertEqual(t["st"], "failed")
        self.assertEqual(t["err"], {"code": code})
        self.assertEqual((t["used"], t["rev"], t["out"], t["sub"], t["wrt"]), ({}, None, None, [], []))
        if acc is not None:
            self.assertEqual(t["acc"], acc)
        self.assertNotIn("res", answer)
        return t

    def charge(self, ch=None, n=1, t=T0 + 10, rev=REV):
        ch = ch or chain()
        self.app.push(Outcome("ok", res={"charge": f"ch_{n}"}, used={"amount": 58900}, rev=rev))
        ans = self.at(t).receive_call(fwd(ch, n))
        self.assertEqual(ans["tally"]["st"], "ok", ans)
        return ch, ans


# ------------------------------------------------------------------ stores

class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="writ-store-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_file_store_survives_reopen(self):
        st = S.FileStore(os.path.join(self.dir, "x"))
        st.put("k", {"a": [1, "two"]})
        st.put("k2", 7)
        again = S.FileStore(os.path.join(self.dir, "x"))
        self.assertEqual(again.get("k"), {"a": [1, "two"]})
        self.assertEqual(sorted(again.items()), [("k", {"a": [1, "two"]}), ("k2", 7)])
        again.delete("k")
        self.assertIsNone(S.FileStore(os.path.join(self.dir, "x")).get("k"))
        self.assertEqual(len(again), 1)

    def test_keys_differing_only_in_case_do_not_collide(self):
        # base64url identities differ by case; macOS file systems do not.
        st = S.FileStore(os.path.join(self.dir, "x"))
        st.put("AbC", 1)
        st.put("abc", 2)
        self.assertEqual((st.get("AbC"), st.get("abc")), (1, 2))

    def test_writes_leave_no_temporary_files(self):
        st = S.FileStore(os.path.join(self.dir, "x"))
        for i in range(5):
            st.put("k", i)
        self.assertEqual([n for n in os.listdir(st.path) if n.startswith(".")], [])

    def test_tally_store_order_and_index(self):
        path = os.path.join(self.dir, "t")
        st = S.TallyStore(path)
        st.add("tB", {"acc": 5, "n": 1}, ["W", "L"])
        st.add("ta", {"acc": 5, "n": 2}, ["W"])
        st.add("t-", {"acc": 4, "n": 3}, ["L"])
        st.add("t0", {"acc": 5, "n": 4}, ["W"])
        # acc first, then the ASCII bytes of the identity: "0" < "B" < "a".
        self.assertEqual([t["n"] for t in st.under("W")], [4, 1, 2])
        self.assertEqual([t["n"] for t in S.TallyStore(path).under("L")], [3, 1])
        self.assertTrue(S.TallyStore(path).holds("ta"))
        self.assertEqual(st.under("nothing"), [])

    def test_revoke_store(self):
        st = S.RevokeStore(os.path.join(self.dir, "r"))
        st.add({"writ": "W1", "iss": "K1"}, exp=100)
        st.add({"writ": "*", "iss": "K2"})
        self.assertTrue(st.revokes_writ("W1", "anyone"))
        self.assertTrue(st.revokes_writ("any writ", "K2"))
        self.assertFalse(st.revokes_writ("W2", "K1"))
        self.assertEqual(st.prune(100), 1)           # the writ revoke has run out
        self.assertTrue(st.revokes_writ("later", "K2"))  # key-wide is kept for good

    def test_call_and_count_prune_keep_what_is_still_needed(self):
        stores = S.Stores(self.dir)
        base = {"leaf": "L", "call": "c", "op": "x", "acc": 1, "chain": ["L"], "iss": ["k"], "exp": 50}
        stores.calls.record(dict(base, id="done", state=S.FINAL, standing=False, tally={}))
        stores.calls.record(dict(base, id="pend", state=S.PENDING, standing=False))
        stores.calls.record(dict(base, id="undo", state=S.FINAL, standing=True, tally={}))
        stores.counts.set_used("L", 1, 50)
        self.assertEqual(stores.prune(49), 0)
        self.assertEqual(stores.prune(50), 2)
        self.assertIsNone(stores.calls.lookup("L", "done"))
        self.assertIsNotNone(stores.calls.lookup("L", "pend"))   # must be resolved first
        self.assertIsNotNone(stores.calls.lookup("L", "undo"))   # standing: kept with its tally
        self.assertEqual(stores.counts.used("L"), 0)

    def test_reversal_began_becomes_unknown(self):
        st = S.ReversalStore(os.path.join(self.dir, "v"))
        st.begin("T1", "c1")
        st.done("T2", "c2", {"refund": 1})
        self.assertEqual(st.mark_unknown(), 1)
        self.assertEqual(st.state("T1")["state"], S.UNKNOWN)
        self.assertEqual(st.state("T2"), {"state": S.DONE, "call": "c2", "res": {"refund": 1}})


# --------------------------------------------------------- forward calls

class ForwardTest(Base):
    def test_ok_and_byte_identical_replay(self):
        ch, first = self.charge()
        t = first["tally"]
        self.assertEqual(first["res"], {"charge": "ch_1"})
        self.assertEqual(t["out"], O.hash_body({"charge": "ch_1"}))
        self.assertEqual((t["acc"], t["used"], t["rev"]), (T0 + 10, {"amount": 58900}, {"until": REV}))
        verdict = V.verify_tally(ch[-1], fwd(ch, 1), t, res=first["res"])
        self.assertTrue(verdict.ok, verdict)
        again = self.at(T0 + 20).receive_call(fwd(ch, 1))
        self.assertEqual(canon.canonicalize(again), canon.canonicalize(first))
        self.assertEqual(len(self.app.calls), 1)

    def test_input_is_not_mutated(self):
        ch = chain()
        call = fwd(ch, 1)
        before = copy.deepcopy(call)
        chain_list = call["chain"]
        self.app.push(Outcome("ok"))
        self.ex.receive_call(call)
        self.assertEqual(call, before)
        self.assertIs(call["chain"], chain_list)

    def test_unsigned_rejections_at_steps_1_and_2(self):
        ch = chain()
        call = fwd(ch, 1)
        self.assertEqual(self.ex.receive_call({**call, "v": 2}), {"error": "unsupported_version"})
        self.assertEqual(self.ex.receive_call(b'{"v":1,"v":1}'), {"error": "noncanonical"})
        self.assertEqual(self.ex.receive_call({**call, "args": {"amount": 1}}), {"error": "bad_signature"})
        broken = {k: v for k, v in ch[0].items() if k != "nnc"}
        self.assertEqual(self.ex.receive_call({**call, "chain": [broken, ch[1]]}), {"error": "malformed"})
        self.assertEqual(self.app.calls, [])

    def test_checks_in_order(self):
        ch = chain()
        self.assertRefused(self.ex.receive_call(issue.make_call(EK, ch, "travel/charge", {"amount": 1})), "no_standing")
        self.assertRefused(self.ex.receive_call(fwd(ch, 2, op="travel/chargeback")), "forbidden_op")
        self.assertRefused(self.ex.receive_call(issue.make_call(BK, ch, "travel/charge", {})), "missing_arg")
        self.assertRefused(self.ex.receive_call(fwd(ch, 3, amount=58901)), "out_of_bounds")
        self.assertRefused(self.at(EXP_LEAF).receive_call(fwd(ch, 4)), "expired", acc=EXP_LEAF)
        # Expiry (step 4) precedes root acceptance (step 5).
        stranger = issue.issue_root(STRANGER, EK.did, {"act": {"t": "prefix", "v": "x"}}, T0 + 5, nnc=nnc(99))
        call = issue.make_call(STRANGER, [stranger], "x", {}, call_id=cid(5))
        self.assertRefused(self.at(T0 + 10).receive_call(call), "expired")
        self.assertRefused(self.at(T0).receive_call(call), "root_not_accepted")
        other = chain(leaf_holder=CK.did, n=1)
        self.assertRefused(self.at(T0 + 10).receive_call(fwd(other, 6)), "wrong_executor")
        self.assertEqual(self.app.calls, [])

    def test_refusals_are_not_recorded(self):
        ch = chain(leaf_bnd={"act": {"t": "prefix", "v": "travel/charge"},
                             "amount": {"t": "max", "v": 58900}, "uses": {"t": "count", "v": 1}})
        self.charge(ch)
        first = self.assertRefused(self.at(T0 + 20).receive_call(fwd(ch, 2)), "count_exhausted", acc=T0 + 20)
        second = self.assertRefused(self.at(T0 + 25).receive_call(fwd(ch, 2)), "count_exhausted", acc=T0 + 25)
        self.assertNotEqual(first["sig"], second["sig"])
        self.assertIsNone(self.ex.stores.calls.lookup(O.identity(ch[1]), cid(2)))
        self.assertEqual(len(self.ex.stores.tallies), 1)

    def test_count_consumed_on_every_writ_and_refusal_consumes_nothing(self):
        # Root allows 2 uses; leaf a allows 1, leaf b allows 3.
        root = {"act": {"t": "prefix", "v": "travel"}, "uses": {"t": "count", "v": 2}}
        w1 = issue.issue_root(A, BK.did, root, EXP_ROOT, nnc=nnc(10))
        wa = issue.narrow(w1, BK, EK.did, bnd={"act": {"t": "prefix", "v": "travel/a"},
                                               "uses": {"t": "count", "v": 1}}, nnc=nnc(11))
        wb = issue.narrow(w1, BK, EK.did, bnd={"act": {"t": "prefix", "v": "travel/b"},
                                               "uses": {"t": "count", "v": 2}}, nnc=nnc(12))
        a = lambda n: issue.make_call(BK, [w1, wa], "travel/a", {}, call_id=cid(n))  # noqa: E731
        b = lambda n: issue.make_call(BK, [w1, wb], "travel/b", {}, call_id=cid(n))  # noqa: E731
        self.app.push(Outcome("ok"))
        self.assertEqual(self.ex.receive_call(a(1))["tally"]["st"], "ok")
        self.assertRefused(self.ex.receive_call(a(2)), "count_exhausted")
        self.app.push(Outcome("ok"))
        self.assertEqual(self.ex.receive_call(b(3))["tally"]["st"], "ok")   # root not charged by a(2)
        self.assertRefused(self.ex.receive_call(b(4)), "count_exhausted")    # root used up
        self.assertEqual(self.ex.stores.counts.used(O.identity(w1)), 2)
        self.assertEqual(self.ex.stores.counts.used(O.identity(wb)), 1)

    def test_several_count_bounds_the_smallest_holds(self):
        w = issue.issue_root(A, EK.did, {"act": {"t": "prefix", "v": "x"}, "uses": {"t": "count", "v": 1},
                                         "retries": {"t": "count", "v": 5}}, EXP_ROOT, nnc=nnc(20))
        self.app.push(Outcome("ok"))
        self.ex.receive_call(issue.make_call(A, [w], "x", {}, call_id=cid(1)))
        self.assertRefused(self.ex.receive_call(issue.make_call(A, [w], "x", {}, call_id=cid(2))), "count_exhausted")

    def test_replay_is_step_9_before_count_and_revoked_is_step_7_before_replay(self):
        ch = chain(leaf_bnd={"act": {"t": "prefix", "v": "travel/charge"},
                             "amount": {"t": "max", "v": 58900}, "uses": {"t": "count", "v": 1}})
        _, first = self.charge(ch)
        self.assertEqual(self.at(T0 + 30).receive_call(fwd(ch, 1)), first)   # count is used up
        rv = self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]]))
        self.assertEqual(rv, {"tallies": []})
        self.assertRefused(self.at(T0 + 40).receive_call(fwd(ch, 1)), "revoked")

    def test_application_failure_is_unknown_outcome(self):
        def boom(op):
            raise RuntimeError("the payment service fell over")
        self.app.push(boom)
        t = self.ex.receive_call(fwd(chain(), 1))["tally"]
        self.assertEqual((t["st"], t["err"]), ("failed", {"code": "unknown_outcome"}))
        self.assertEqual(self.at(T0 + 20).receive_call(fwd(chain(), 1))["tally"], t)

    def test_application_failure_codes_pass_through(self):
        self.app.push(Outcome("failed", "app/sold_out"))
        t = self.ex.receive_call(fwd(chain(), 1))["tally"]
        self.assertEqual((t["st"], t["err"], t["out"]), ("failed", {"code": "app/sold_out"}, None))


# --------------------------------------------------------------- held work

class HeldTest(Base):
    def test_held_operation_replay_is_pending_then_final(self):
        ch = chain()
        self.app.push(HELD)
        self.assertEqual(self.ex.receive_call(fwd(ch, 1)), {"inflight": True})
        call_id = O.identity(fwd(ch, 1))
        pend = self.at(T0 + 15).receive_call(fwd(ch, 1))["tally"]
        self.assertEqual((pend["st"], pend["err"], pend["acc"]), ("pending", {"code": "pending"}, T0 + 10))
        O.verify_object(pend, "tally", signer=EK.did)
        self.assertFalse(self.ex.signaled(call_id))
        done = self.ex.complete(call_id, Outcome("ok", res={"x": 1}))
        self.assertEqual((done["tally"]["st"], done["tally"]["acc"], done["res"]), ("ok", T0 + 10, {"x": 1}))
        self.assertEqual(self.at(T0 + 20).receive_call(fwd(ch, 1)), done)
        with self.assertRaises(KeyError):
            self.ex.complete(call_id, Outcome("ok"))


# ---------------------------------------------------------- standing calls

class StandingTest(Base):
    def undo(self, ch, target, n, key=A):
        return issue.make_call(key, ch, "sys/undo", {"tally": target}, call_id=cid(n))

    def test_undo_once_and_idempotent(self):
        ch, first = self.charge()
        target = first["tally"]
        self.assertRefused(self.ex.receive_call(self.undo(ch, target, 2, key=STRANGER)), "no_standing")
        self.app.push(Outcome("ok", res={"refund": "rf_1"}, rev=REV))
        u = self.at(T0 + 30).receive_call(self.undo(ch, target, 3))
        self.assertEqual((u["tally"]["st"], u["tally"]["rev"], u["res"]), ("ok", None, {"refund": "rf_1"}))
        self.assertEqual(self.at(T0 + 31).receive_call(self.undo(ch, target, 3)), u)
        again = self.at(T0 + 40).receive_call(self.undo(ch, target, 4, key=BK))
        self.assertEqual((again["tally"]["st"], again["tally"]["acc"], again["res"]), ("ok", T0 + 40, {"refund": "rf_1"}))
        self.assertEqual([k for k, _ in self.app.calls], ["forward", "undo"])

    def test_failed_reversal_can_be_retried(self):
        ch, first = self.charge()
        self.app.push(Outcome("failed", "app/declined"))
        f = self.ex.receive_call(self.undo(ch, first["tally"], 2))["tally"]
        self.assertEqual(f["err"], {"code": "app/declined"})
        self.app.push(Outcome("ok", res={"refund": 1}))
        self.assertEqual(self.ex.receive_call(self.undo(ch, first["tally"], 3))["tally"]["st"], "ok")

    def test_undo_targets(self):
        ch, first = self.charge()
        target = first["tally"]
        self.app.push(Outcome("ok"))
        norev = self.ex.receive_call(fwd(ch, 2))["tally"]
        self.assertRefused(self.ex.receive_call(self.undo(ch, norev, 3)), "not_reversible")
        self.assertRefused(self.ex.receive_call(self.undo(ch, "text", 4)), "malformed")
        forged = issue.make_tally(STRANGER, fwd(ch, 1), ch[1], out={"charge": "ch_1"}, rev={"until": REV}, acc=T0)
        self.assertRefused(self.ex.receive_call(self.undo(ch, forged, 5)), "not_reversible")
        other = chain(n=1)
        self.assertRefused(self.ex.receive_call(self.undo(other, target, 6)), "tally_mismatch")
        self.assertRefused(self.at(REV).receive_call(self.undo(ch, target, 7)), "not_reversible")
        # Signed by this executor and valid, but not in its tally store.
        unheld = issue.make_tally(EK, fwd(ch, 9), ch[1], out={"c": 1}, rev={"until": REV}, acc=T0)
        self.assertRefused(self.at(T0 + 50).receive_call(self.undo(ch, unheld, 8)), "not_reversible")
        self.assertEqual(len(self.app.calls), 2)

    def test_standing_survives_expiry_and_revocation(self):
        ch, first = self.charge()
        self.assertRefused(self.at(EXP_LEAF).receive_call(fwd(ch, 2)), "expired")
        self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]]))
        self.app.push(Outcome("ok", res={"refund": 1}))
        u = self.at(EXP_ROOT + 60).receive_call(self.undo(ch, first["tally"], 3))
        self.assertEqual(u["tally"]["st"], "ok")
        rec = issue.make_call(A, ch, "sys/tallies", {"writ": O.identity(ch[0])}, call_id=cid(4))
        got = self.at(EXP_ROOT + 70).receive_call(rec)
        self.assertEqual(got["res"], {"tallies": [first["tally"], u["tally"]]})

    def test_sys_tallies_order_contents_and_replay(self):
        ch = chain()
        for n, t in ((1, T0 + 10), (2, T0 + 10), (3, T0 + 5)):
            self.app.push(Outcome("ok", res={"n": n}))
            self.at(t).receive_call(fwd(ch, n))
        self.assertRefused(self.ex.receive_call(fwd(ch, 9, op="cars/x")), "forbidden_op")
        q = lambda n, w: issue.make_call(A, ch, "sys/tallies", {"writ": w}, call_id=cid(n))  # noqa: E731
        first = self.at(T0 + 30).receive_call(q(10, O.identity(ch[0])))
        listed = first["res"]["tallies"]
        self.assertEqual([t["acc"] for t in listed], [T0 + 5, T0 + 10, T0 + 10])
        ids = [O.identity(t) for t in listed[1:]]
        self.assertEqual(ids, sorted(ids, key=lambda i: i.encode("ascii")))
        self.assertEqual(first["tally"]["out"], O.hash_body(first["res"]))
        second = self.at(T0 + 40).receive_call(q(11, O.identity(ch[1])))
        self.assertEqual(len(second["res"]["tallies"]), 4)          # the first recovery included
        self.assertEqual(self.at(T0 + 50).receive_call(q(10, O.identity(ch[0]))), first)
        self.assertRefused(self.ex.receive_call(q(12, "d_w7FnA4bQwfLdDgNIYoAhNPTJFuXVsGqORJH5Ruqbg")), "tally_mismatch")
        self.assertRefused(self.ex.receive_call(issue.make_call(A, ch, "sys/tallies", {}, call_id=cid(13))), "tally_mismatch")
        self.assertRefused(self.ex.receive_call(issue.make_call(A, ch, "sys/other", {}, call_id=cid(14))), "forbidden_op")
        self.assertEqual(len(self.app.calls), 3)

    def test_second_undo_waits_for_the_running_reversal(self):
        ch, first = self.charge()
        self.app.push(HELD)
        self.assertEqual(self.ex.receive_call(self.undo(ch, first["tally"], 2)), {"inflight": True})
        self.assertEqual(self.ex.receive_call(self.undo(ch, first["tally"], 3)), {"inflight": True})
        done = self.ex.complete(O.identity(self.undo(ch, first["tally"], 2)), Outcome("ok", res={"refund": 1}))
        self.assertEqual(done["tally"]["st"], "ok")
        queued = self.at(T0 + 99).receive_call(self.undo(ch, first["tally"], 3))
        self.assertEqual((queued["tally"]["st"], queued["tally"]["acc"], queued["res"]), ("ok", T0 + 10, {"refund": 1}))
        self.assertEqual([k for k, _ in self.app.calls], ["forward", "undo"])   # reversed once

    def test_queued_undo_runs_after_a_failed_reversal(self):
        ch, first = self.charge()
        self.app.push(HELD)
        self.ex.receive_call(self.undo(ch, first["tally"], 2))
        self.ex.receive_call(self.undo(ch, first["tally"], 3))
        self.app.push(Outcome("ok", res={"refund": 2}))
        self.ex.complete(O.identity(self.undo(ch, first["tally"], 2)), Outcome("failed", "app/declined"))
        queued = self.ex.receive_call(self.undo(ch, first["tally"], 3))
        self.assertEqual(queued["res"], {"refund": 2})
        self.assertEqual([k for k, _ in self.app.calls], ["forward", "undo", "undo"])


# ---------------------------------------------------------------- revokes

class RevokeTest(Base):
    def test_invalid_revokes_change_nothing(self):
        ch = chain()
        r = issue.make_revoke(A, ch[1], chain=ch)
        self.assertEqual(self.ex.receive_revoke({**r, "iss": BK.did}), {"error": "bad_signature"})
        self.assertEqual(self.ex.receive_revoke(issue.make_revoke(STRANGER, ch[0], chain=[ch[0]])),
                         {"error": "no_standing"})
        self.app.push(Outcome("ok"))
        self.assertEqual(self.ex.receive_call(fwd(ch, 1))["tally"]["st"], "ok")
        self.assertEqual(self.ex.receive_revoke(r), {"tallies": []})
        self.assertRefused(self.ex.receive_call(fwd(ch, 2)), "revoked")

    def test_answer_order_signal_and_scope(self):
        ch = chain()
        other_root = chain(n=1)
        calls = [fwd(ch, n) for n in range(1, 4)] + [fwd(other_root, 4)]
        for c in calls:
            self.app.push(HELD)
            self.assertEqual(self.ex.receive_call(c), {"inflight": True})
        ans = self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]]))
        got = [t["call"] for t in ans["tallies"]]
        want = sorted((O.identity(c) for c in calls[:3]), key=lambda i: i.encode("ascii"))
        self.assertEqual(got, want)
        self.assertTrue(all(t["st"] == "pending" for t in ans["tallies"]))
        self.assertTrue(all(self.ex.signaled(O.identity(c)) for c in calls[:3]))
        self.assertFalse(self.ex.signaled(O.identity(calls[3])))
        fin = self.ex.complete(O.identity(calls[0]), Outcome("canceled", "revoked"))
        self.assertEqual((fin["tally"]["st"], fin["tally"]["err"]), ("canceled", {"code": "revoked"}))

    def test_key_wide_revoke_covers_later_writs_and_keeps_standing(self):
        ch, first = self.charge()
        self.assertEqual(self.ex.receive_revoke(issue.make_revoke(A, "*")), {"tallies": []})
        self.assertRefused(self.ex.receive_call(fwd(ch, 2)), "revoked")
        later = chain(n=5)
        self.assertRefused(self.ex.receive_call(fwd(later, 3)), "revoked")
        self.app.push(Outcome("ok", res={"refund": 1}))
        undo = issue.make_call(A, ch, "sys/undo", {"tally": first["tally"]}, call_id=cid(4))
        self.assertEqual(self.ex.receive_call(undo)["tally"]["st"], "ok")

    def test_revoke_leaves_a_running_undo_alone(self):
        ch, first = self.charge()
        self.app.push(HELD)
        undo = issue.make_call(A, ch, "sys/undo", {"tally": first["tally"]}, call_id=cid(2))
        self.ex.receive_call(undo)
        self.assertEqual(self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]])), {"tallies": []})
        self.assertFalse(self.ex.signaled(O.identity(undo)))

    def test_revoke_survives_restart(self):
        ch = chain()
        self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]]))
        again = Executor(EK, [A.did], self.dir, app=self.app)
        again.set_time(T0 + 10)
        self.assertRefused(again.receive_call(fwd(ch, 1)), "revoked")


# ---------------------------------------------------------------- restart

class RestartTest(Base):
    def test_crash_while_running(self):
        ch = chain(leaf_bnd={"act": {"t": "prefix", "v": "travel"}, "amount": {"t": "max", "v": 58900},
                             "uses": {"t": "count", "v": 1}})
        self.app.push(HELD)
        self.ex.receive_call(fwd(ch, 1))
        self.assertEqual(self.ex.restart(), 1)
        t = self.at(T0 + 20).receive_call(fwd(ch, 1))["tally"]
        self.assertEqual((t["st"], t["err"], t["acc"]), ("failed", {"code": "unknown_outcome"}, T0 + 10))
        self.assertRefused(self.ex.receive_call(fwd(ch, 2)), "count_exhausted")
        self.assertEqual(self.ex.restart(), 0)
        self.assertEqual(self.ex.receive_call(fwd(ch, 1))["tally"], t)

    def test_a_new_process_resolves_at_open(self):
        ch = chain()
        self.app.push(HELD)
        self.ex.receive_call(fwd(ch, 1))
        again = Executor(EK, [A.did], self.dir, app=self.app)
        self.assertEqual(again.resolved_at_open, 1)

    def test_crash_while_reversing(self):
        ch, first = self.charge()
        undo = lambda n: issue.make_call(A, ch, "sys/undo", {"tally": first["tally"]}, call_id=cid(n))  # noqa: E731
        self.app.push(HELD)
        self.ex.receive_call(undo(2))
        self.assertEqual(self.ex.restart(), 1)
        self.assertEqual(self.ex.receive_call(undo(2))["tally"]["err"], {"code": "unknown_outcome"})
        t = self.at(T0 + 40).receive_call(undo(3))["tally"]
        self.assertEqual((t["err"], t["acc"]), ({"code": "unknown_outcome"}, T0 + 40))
        self.assertEqual([k for k, _ in self.app.calls], ["forward", "undo"])

    def test_resolver_decides_an_interrupted_reversal(self):
        # Section 8.1: a reversal that failed consumes nothing, even when
        # that is learned only after a restart; one that succeeded counts.
        for resolved, retry_runs in ((Outcome("failed", "app/declined"), True),
                                     (Outcome("ok", res={"refund": 9}), False)):
            with self.subTest(resolved=resolved.st):
                self.tearDown()
                self.setUp()
                ch, first = self.charge()
                undo = lambda n: issue.make_call(A, ch, "sys/undo", {"tally": first["tally"]}, call_id=cid(n))  # noqa: E731,B023
                self.app.push(HELD)
                self.ex.receive_call(undo(2))
                self.ex.resolver = lambda rec, out=resolved: out
                self.assertEqual(self.ex.restart(), 1)
                if retry_runs:
                    self.app.push(Outcome("ok", res={"refund": 1}))
                again = self.ex.receive_call(undo(3))
                self.assertEqual(again["tally"]["st"], "ok")
                self.assertEqual(len(self.app.calls), 3 if retry_runs else 2)
                if not retry_runs:
                    self.assertEqual(again["res"], {"refund": 9})

    def test_resolver_can_supply_the_outcome(self):
        ch = chain()
        self.app.push(HELD)
        self.ex.receive_call(fwd(ch, 1))
        self.ex.resolver = lambda rec: Outcome("ok", res={"found": rec["op"]})
        self.assertEqual(self.ex.restart(), 1)
        ans = self.ex.receive_call(fwd(ch, 1))
        self.assertEqual((ans["tally"]["st"], ans["res"]), ("ok", {"found": "travel/charge"}))


# ------------------------------------------------------ store write failures

class StoreFailureTest(Base):
    def test_call_store_write_failure_refuses_and_records_nothing(self):
        ch = chain(leaf_bnd={"act": {"t": "prefix", "v": "travel"}, "amount": {"t": "max", "v": 58900},
                             "uses": {"t": "count", "v": 1}})
        real = self.ex.stores.calls.record

        def broken(rec):
            raise OSError("disk full")
        self.ex.stores.calls.record = broken
        self.assertRefused(self.ex.receive_call(fwd(ch, 1)), STORE_WRITE_FAILED)
        self.assertEqual(self.app.calls, [])
        self.assertEqual(self.ex.stores.counts.used(O.identity(ch[1])), 0)   # rolled back
        self.ex.stores.calls.record = real
        self.app.push(Outcome("ok"))
        self.assertEqual(self.ex.receive_call(fwd(ch, 1))["tally"]["st"], "ok")

    def test_unpersisted_final_tally_is_answered_pending(self):
        ch = chain()
        real = self.ex.stores.calls.record

        def fail_final(rec):
            if rec["state"] == S.FINAL:
                raise OSError("disk full")
            real(rec)
        self.ex.stores.calls.record = fail_final
        self.app.push(Outcome("ok", res={"x": 1}))
        t = self.ex.receive_call(fwd(ch, 1))["tally"]
        self.assertEqual(t["st"], "pending")
        self.assertEqual(self.ex.restart(), 1)


# ------------------------------------------------------- delegating onward

class DelegationTest(Base):
    def setUp(self):
        super().setUp()
        self.cdir = tempfile.mkdtemp(prefix="writ-test-c-")
        self.capp = ScriptedApp()
        self.cex = Executor(CK, [A.did], self.cdir, app=self.capp)
        self.cex.set_time(T0 + 12)

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.cdir, ignore_errors=True)

    def root_chain(self):
        # The executor holds the root, so it can issue children of it.
        return [issue.issue_root(A, EK.did, {"act": {"t": "prefix", "v": "travel"},
                                             "amount": {"t": "max", "v": 60000}}, EXP_ROOT, nnc=nnc(40))]

    def test_tally_tree_verifies(self):
        ch = self.root_chain()
        self.capp.push(Outcome("ok", res={"charge": "c"}, used={"amount": 58900}))

        def book(op):
            child = op.issue(CK.did, bnd={"act": {"t": "prefix", "v": "travel/charge"},
                                          "amount": {"t": "max", "v": 58900}}, nnc=nnc(41))
            sub = op.make_call(child, "travel/charge", {"amount": 58900}, call_id=cid(50))
            ans = self.cex.receive_call(sub)
            self.assertTrue(op.receive_tally(sub, ans["tally"], ans.get("res")).ok)
            return Outcome("ok", res={"pnr": "K"}, used={"amount": 58900})
        self.app.push(book)
        call = issue.make_call(A, ch, "travel/book", {"amount": 60000}, call_id=cid(1))
        ans = self.ex.receive_call(call)
        t = ans["tally"]
        self.assertEqual((len(t["sub"]), len(t["wrt"])), (1, 1))
        verdict = V.verify_tally(ch[-1], call, t, res=ans["res"])
        self.assertTrue(verdict.ok, verdict)
        self.assertEqual([s.status for s in verdict.subs], [V.VALID])

    def test_widening_child_is_refused_and_not_recorded(self):
        ch = self.root_chain()
        seen = {}

        def book(op):
            with self.assertRaises(Exception) as cm:
                op.issue(CK.did, bnd={"amount": {"t": "max", "v": 70000}})
            seen["reason"] = getattr(cm.exception, "reason", None)
            return Outcome("ok")
        self.app.push(book)
        t = self.ex.receive_call(issue.make_call(A, ch, "travel/book", {"amount": 1}, call_id=cid(1)))["tally"]
        self.assertEqual((seen["reason"], t["wrt"]), ("not_narrowed", []))

    def test_child_that_breaks_depth_is_refused(self):
        root = issue.issue_root(A, EK.did, {"act": {"t": "prefix", "v": "travel"},
                                            "depth": {"t": "max", "v": 0}}, EXP_ROOT, nnc=nnc(45))
        seen = {}

        def book(op):
            try:
                op.issue(CK.did, nnc=nnc(46))
            except Exception as e:  # noqa: BLE001
                seen["reason"] = getattr(e, "reason", repr(e))
            return Outcome("ok")
        self.app.push(book)
        t = self.ex.receive_call(issue.make_call(A, [root], "travel/book", {}, call_id=cid(1)))["tally"]
        self.assertEqual((seen.get("reason"), t["wrt"]), ("not_narrowed", []))

    def test_unverifiable_sub_tally_is_left_out_and_pending_is_superseded(self):
        ch = self.root_chain()

        def book(op):
            child = op.issue(CK.did, nnc=nnc(42))
            lost = op.make_call(child, "travel/charge", {"amount": 2}, call_id=cid(53))
            forged = issue.make_tally(STRANGER, lost, child, acc=T0)
            self.assertEqual(op.receive_tally(lost, forged).status, V.UNVERIFIABLE)
            sub = op.make_call(child, "travel/charge", {"amount": 1}, call_id=cid(51))
            pending = issue.make_tally(CK, sub, child, st="pending", acc=T0 + 11)
            op.receive_tally(sub, pending)
            final = issue.make_tally(CK, sub, child, st="failed", err={"code": "app/x"}, acc=T0 + 11)
            op.receive_tally(sub, final)
            return Outcome("failed", "undeliverable")
        self.app.push(book)
        call = issue.make_call(A, ch, "travel/book", {"amount": 1}, call_id=cid(1))
        t = self.ex.receive_call(call)["tally"]
        self.assertEqual([s["st"] for s in t["sub"]], ["failed"])
        self.assertTrue(V.verify_tally(ch[-1], call, t).ok)

    def test_restart_keeps_wrt_and_sub_and_forwards_revokes(self):
        ch = self.root_chain()
        forwarded = []
        self.ex.forward_revoke = lambda r, holder: forwarded.append(holder)
        self.capp.push(Outcome("ok"))

        def book(op):
            child = op.issue(CK.did, nnc=nnc(43))
            sub = op.make_call(child, "travel/charge", {"amount": 1}, call_id=cid(52))
            ans = self.cex.receive_call(sub)
            op.receive_tally(sub, ans["tally"])
            op.issue(CK.did, nnc=nnc(44))     # a second sub-call that never answers
            return HELD
        self.app.push(book)
        call = issue.make_call(A, ch, "travel/book", {"amount": 1}, call_id=cid(1))
        self.ex.receive_call(call)
        self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=ch))
        self.assertEqual(forwarded, [CK.did])
        self.assertEqual(self.ex.restart(), 1)
        t = self.ex.receive_call(call)
        self.assertRefused(t, "revoked")          # revoked is step 7, before replay
        rec = self.ex.stores.calls.lookup(O.identity(ch[-1]), cid(1))
        self.assertEqual((len(rec["tally"]["sub"]), len(rec["tally"]["wrt"])), (1, 2))
        self.assertTrue(V.verify_tally(ch[-1], call, rec["tally"]).ok)


# --------------------------------------------------------- scenario runner

class ScenarioRunnerTest(unittest.TestCase):
    def run_one(self, sc):
        d = tempfile.mkdtemp(prefix="writ-sc-")
        try:
            cli.run_scenario(sc, d)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def load(self, name):
        with open(os.path.join(SCENARIOS, name), "rb") as f:
            return canon.loads_lenient(f.read())

    def test_corpus_scenarios_pass(self):
        names = sorted(n for n in os.listdir(SCENARIOS) if n.endswith(".json"))
        self.assertEqual(len(names), 20)
        for name in names:
            with self.subTest(name=name):
                self.run_one(self.load(name))

    def test_runner_catches_a_wrong_answer_and_a_wrong_signal(self):
        sc = self.load("001_count_replay_and_root_acceptance.json")
        sc["steps"][1]["expect"]["tally"]["acc"] += 1
        with self.assertRaises(cli.ScenarioFailure):
            self.run_one(sc)
        sc = self.load("013_revoke_stops_in-flight_work_under_its_writ_only.json")
        sc["steps"][4]["signaled"] = True
        with self.assertRaises(cli.ScenarioFailure):
            self.run_one(sc)

    def test_runner_catches_an_unexpected_application_call(self):
        sc = self.load("001_count_replay_and_root_acceptance.json")
        del sc["steps"][0]["app"]
        with self.assertRaises(cli.ScenarioFailure):
            self.run_one(sc)

    def test_cli_reports_a_crash_and_continues(self):
        d = tempfile.mkdtemp(prefix="writ-sc-dir-")
        try:
            sc = self.load("004_several_count_bounds_on_one_writ_the_smallest_holds.json")
            with open(os.path.join(d, "a.json"), "w") as f:
                json.dump({"name": "broken", "executor": sc["executor"], "steps": [{"do": "call"}]}, f)
            with open(os.path.join(d, "b.json"), "w") as f:
                json.dump(sc, f)
            import contextlib
            import io
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(["scenarios", d])
            lines = out.getvalue().splitlines()
            self.assertEqual(code, 1)
            self.assertTrue(lines[0].startswith("FAIL broken: CRASH KeyError"), lines[0])
            self.assertTrue(lines[1].startswith("PASS "), lines[1])
            self.assertEqual(lines[-1], "1 passed, 1 failed, 2 total")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
