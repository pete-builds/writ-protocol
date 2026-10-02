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

from writ import canon, cli, executor as E, issue, objects as O, stores as S, verify as V  # noqa: E402
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

    def assertAcked(self, answer, revoke, tallies=()):
        """Section 9.4: a recorded revoke is answered with its tallies and
        this executor's own ack of it, which verifies for that revoke."""
        self.assertEqual(answer["tallies"], list(tallies), answer)
        a = V.verify_ack(V.verify_revoke(revoke), answer["ack"], answer["res"])
        self.assertEqual(a["iss"], self.ex.did)
        self.assertNotIn("fwd", answer)
        return a

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
        stores.totals.set_used("L", "amount", 400, 50)
        self.assertEqual(stores.prune(49), 0)
        self.assertEqual(stores.prune(50), 3)
        self.assertEqual(stores.totals.used("L", "amount"), 0)
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
        r = issue.make_revoke(A, ch[0], chain=[ch[0]])
        self.assertAcked(self.ex.receive_revoke(r), r)
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


# ------------------------------------------------------------ total bounds

class TotalTest(Base):
    """Section 7 step 10 and section 7.3: a total bounds the running sum of
    one argument at this executor, against every writ in the chain."""

    def writs(self, root=None, leaves=((600, None),)):
        """A root A -> BK carrying ``root`` bounds (amount total 1000 by
        default), and one leaf BK -> executor per (total, extra bounds)."""
        w1 = issue.issue_root(A, BK.did, root or {"act": {"t": "prefix", "v": "pay"},
                                                  "amount": {"t": "total", "v": 1000}}, EXP_ROOT, nnc=nnc(70))
        out = [w1]
        for n, (total, extra) in enumerate(leaves):
            out.append(issue.narrow(w1, BK, EK.did, bnd={"amount": {"t": "total", "v": total}, **(extra or {})},
                                    nnc=nnc(71 + n)))
        return out

    def pay(self, w1, leaf, n, amount, ok=True):
        if ok:
            self.app.push(Outcome("ok", used={"amount": amount}))
        return self.ex.receive_call(issue.make_call(BK, [w1, leaf], "pay", {"amount": amount}, call_id=cid(n)))

    def used(self, writ):
        return self.ex.stores.totals.used(O.identity(writ), "amount")

    def test_running_sum(self):
        w1, leaf = self.writs()
        self.assertEqual(self.pay(w1, leaf, 1, 400)["tally"]["used"], {"amount": 400})
        self.assertEqual(self.pay(w1, leaf, 2, 200)["tally"]["st"], "ok")      # exactly 600
        self.assertEqual(self.pay(w1, leaf, 3, 0)["tally"]["st"], "ok")        # zero still fits
        self.assertRefused(self.pay(w1, leaf, 4, 1, ok=False), "total_exhausted")
        self.assertEqual((self.used(leaf), self.used(w1)), (600, 600))
        self.assertEqual(len(self.app.calls), 3)
        # A retry is answered at step 9, before total, and adds nothing.
        self.assertEqual(self.pay(w1, leaf, 1, 400, ok=False)["tally"]["st"], "ok")
        self.assertEqual(self.used(leaf), 600)

    def test_refusal_consumes_nothing(self):
        w1, leaf = self.writs(leaves=((600, {"uses": {"t": "count", "v": 3}}),))
        self.pay(w1, leaf, 1, 400)
        self.assertRefused(self.pay(w1, leaf, 2, 300, ok=False), "total_exhausted")
        self.assertEqual((self.used(leaf), self.used(w1)), (400, 400))
        self.assertEqual(self.ex.stores.counts.used(O.identity(leaf)), 1)    # no use spent either
        self.assertIsNone(self.ex.stores.calls.lookup(O.identity(leaf), cid(2)))
        self.assertEqual(self.pay(w1, leaf, 3, 200)["tally"]["st"], "ok")     # the 200 left is still there
        self.assertEqual(self.pay(w1, leaf, 4, 0)["tally"]["st"], "ok")       # uses 3 of 3
        self.assertRefused(self.pay(w1, leaf, 5, 0, ok=False), "count_exhausted")
        self.assertEqual((self.used(leaf), self.used(w1)), (600, 600))     # count refusal adds nothing

    def test_draws_against_every_writ_in_the_chain(self):
        # Two children of 600 under a root total of 1000: each is a share
        # that still draws on the root (section 7.3).
        w1, wa, wb = self.writs(leaves=((600, None), (600, None)))
        self.assertEqual(self.pay(w1, wa, 1, 600)["tally"]["st"], "ok")
        self.assertEqual(self.pay(w1, wb, 2, 400)["tally"]["st"], "ok")
        self.assertRefused(self.pay(w1, wb, 3, 1, ok=False), "total_exhausted")   # wb has 200, root none
        self.assertEqual((self.used(w1), self.used(wa), self.used(wb)), (1000, 600, 400))

    def test_count_is_reported_before_total(self):
        # The root's total and the leaf's count are both used up. Every
        # count in the chain is checked before any total, so the leaf's
        # count is reported although the root comes first in the chain.
        root = {"act": {"t": "prefix", "v": "pay"}, "amount": {"t": "total", "v": 100}}
        w1, leaf = self.writs(root=root, leaves=((100, {"uses": {"t": "count", "v": 1}}),))
        self.pay(w1, leaf, 1, 100)
        self.assertRefused(self.pay(w1, leaf, 2, 50, ok=False), "count_exhausted")

    def test_total_survives_restart(self):
        w1, leaf = self.writs()
        self.pay(w1, leaf, 1, 400)
        self.assertEqual(self.ex.restart(), 0)
        self.assertRefused(self.pay(w1, leaf, 2, 300, ok=False), "total_exhausted")
        again = Executor(EK, [A.did], self.dir, app=self.app)
        again.set_time(T0 + 10)
        self.ex = again
        self.assertRefused(self.pay(w1, leaf, 3, 201, ok=False), "total_exhausted")
        self.assertEqual(self.pay(w1, leaf, 4, 200)["tally"]["st"], "ok")
        self.assertEqual(self.used(w1), 600)

    def test_store_write_failure_gives_the_total_back(self):
        w1, leaf = self.writs()
        self.pay(w1, leaf, 1, 400)
        real = self.ex.stores.calls.record

        def broken(rec):
            raise OSError("disk full")
        self.ex.stores.calls.record = broken
        self.assertRefused(self.pay(w1, leaf, 2, 100, ok=False), STORE_WRITE_FAILED)
        self.assertEqual((self.used(leaf), self.used(w1)), (400, 400))
        self.ex.stores.calls.record = real
        self.assertEqual(self.pay(w1, leaf, 3, 200)["tally"]["st"], "ok")

    def test_used_covers_sub_tallies_under_a_total(self):
        # Section 6: used is inclusive of the subtree for total bounds as
        # for max, including in a record resolved after a restart.
        w1, leaf = self.writs()
        self.app.push(HELD)
        self.ex.receive_call(issue.make_call(BK, [w1, leaf], "pay", {"amount": 500}, call_id=cid(1)))
        names = self.ex.stores.calls.lookup(O.identity(leaf), cid(1))["max"]
        self.assertEqual(names, ["amount"])
        subs = [{"used": {"amount": 300}}, {"used": {"amount": 200}}]
        self.assertEqual(E._cover_subs({"amount": 100}, names, subs), {"amount": 500})


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
        self.assertAcked(self.ex.receive_revoke(r), r)
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
        self.assertAcked(self.ex.receive_revoke(issue.make_revoke(A, "*")), issue.make_revoke(A, "*"))
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
        r = issue.make_revoke(A, ch[0], chain=[ch[0]])
        self.assertAcked(self.ex.receive_revoke(r), r)
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

    def test_unsaved_key_wide_revoke_is_an_error_and_still_honored(self):
        ch = chain()
        real = self.ex.stores.revokes.add

        def broken(revoke, exp=None):
            raise OSError("disk full")
        self.ex.stores.revokes.add = broken
        self.assertEqual(self.ex.receive_revoke(issue.make_revoke(A, "*")), {"error": STORE_WRITE_FAILED})
        self.assertRefused(self.ex.receive_call(fwd(ch, 1)), "revoked")
        self.ex.stores.revokes.add = real
        self.assertAcked(self.ex.receive_revoke(issue.make_revoke(A, "*")), issue.make_revoke(A, "*"))
        self.assertEqual(self.ex.restart(), 0)
        self.assertRefused(self.ex.receive_call(fwd(ch, 2)), "revoked")

    def test_unsaved_writ_revoke_is_an_error_and_still_honored(self):
        # Section 9: a revoke of one writ MUST survive restart too; answering
        # an unsaved one as recorded let a restart re-admit the writ.
        ch = chain()
        real = self.ex.stores.revokes.add

        def broken(revoke, exp=None):
            raise OSError("disk full")
        self.ex.stores.revokes.add = broken
        rv = issue.make_revoke(A, ch[0], chain=[ch[0]])
        self.assertEqual(self.ex.receive_revoke(rv), {"error": STORE_WRITE_FAILED})
        self.assertRefused(self.ex.receive_call(fwd(ch, 1)), "revoked")
        self.ex.stores.revokes.add = real
        self.assertAcked(self.ex.receive_revoke(rv), rv)
        self.assertEqual(self.ex.restart(), 0)
        self.assertRefused(self.ex.receive_call(fwd(ch, 2)), "revoked")


# ------------------------------------------------------------------- acks

class AckTest(Base):
    """Section 9.4: an ack accounts for every tally its signer signs for work
    under the revoked writ, and nothing it signs for work accepted later,
    however that tally's acc is dated."""

    def check(self, r, answer, ch, tally):
        try:
            V.check_ack(r, answer["ack"], answer["res"], ch, tally)
        except Exception as e:  # noqa: BLE001, the reason is what is asserted
            return getattr(e, "reason", repr(e))
        return None

    def forgetful(self, ch, n, t):
        """An executor with this one's key and none of its stores: one that
        lost the revoke, or ignored it, and does new work under it."""
        d = tempfile.mkdtemp(prefix="writ-forgetful-")
        self.addCleanup(shutil.rmtree, d, True)
        app = ScriptedApp()
        app.push(Outcome("ok", res={"late": n}))
        g = Executor(EK, [A.did], d, app=app)
        g.set_time(t)
        return g.receive_call(fwd(ch, n))["tally"]

    def test_honest_work_is_accounted_for_and_late_work_is_not(self):
        ch, first = self.charge()
        self.app.push(HELD)
        self.assertEqual(self.at(T0 + 11).receive_call(fwd(ch, 2)), {"inflight": True})
        pending = self.at(T0 + 12).receive_call(fwd(ch, 2))["tally"]
        r = issue.make_revoke(A, ch[0], chain=[ch[0]])
        answer = self.at(T0 + 20).receive_revoke(r)
        self.assertEqual([len(answer["res"]["held"]), len(answer["res"]["open"])], [1, 1])
        refused = self.assertRefused(self.at(T0 + 30).receive_call(fwd(ch, 3)), "revoked")
        final = self.ex.complete(O.identity(fwd(ch, 2)), Outcome("canceled", "revoked"))["tally"]
        for name, t in (("finished before", first["tally"]), ("pending at", pending),
                        ("final after running across", final), ("refused after", refused)):
            self.assertIsNone(self.check(r, answer, ch, t), name)
        late = self.forgetful(ch, 4, T0 + 40)
        self.assertTrue(V.verify_tally(ch[1], fwd(ch, 4), late).ok)  # 6.2 alone cannot tell
        self.assertEqual(self.check(r, answer, ch, late), "revoked")
        back = issue.make_tally(EK, fwd(ch, 5), ch[1], acc=T0 + 1)
        self.assertTrue(V.verify_tally(ch[1], fwd(ch, 5), back).ok)
        self.assertEqual(self.check(r, answer, ch, back), "revoked", "a backdated acc must not help")

    def test_key_wide_ack_holds_work_under_the_keys_writs(self):
        ch, first = self.charge()
        r = issue.make_revoke(BK, "*")
        answer = self.at(T0 + 20).receive_revoke(r)
        self.assertEqual(answer["res"]["held"], [{"call": first["tally"]["call"], "tally": O.identity(first["tally"])}])
        self.assertIsNone(self.check(r, answer, ch, first["tally"]))
        self.assertEqual(self.check(r, answer, ch, self.forgetful(ch, 4, T0 + 40)), "revoked")

    def test_forwarded_acks_are_relayed_only_when_they_verify(self):
        ch = chain(leaf_bnd={"act": {"t": "prefix", "v": "travel"}, "amount": {"t": "max", "v": 58900}})
        sub_dir = tempfile.mkdtemp(prefix="writ-sub-")
        self.addCleanup(shutil.rmtree, sub_dir, True)
        below = Executor(CK, [A.did], sub_dir)
        below.set_time(T0 + 20)
        tampered = {"forwarded": 0}

        def forward(data, holder):
            answer = below.receive_revoke(data)
            if tampered["forwarded"]:
                answer = dict(answer, res={"held": [], "open": ["x"]})
            tampered["forwarded"] += 1
            return answer

        self.ex.forward_revoke = forward
        # The executor delegates to CK under ch[1], so it forwards to CK.
        def delegate(op):
            op.issue(CK.did, bnd={"act": {"t": "prefix", "v": "travel/charge"},
                                  "amount": {"t": "max", "v": 100}}, nnc=nnc(99))
            return Outcome("ok")
        self.app.push(delegate)
        self.assertEqual(self.ex.receive_call(fwd(ch, 1))["tally"]["st"], "ok")
        r = issue.make_revoke(A, ch[0], chain=[ch[0]])
        answer = self.at(T0 + 20).receive_revoke(r)
        self.assertEqual(len(answer.get("fwd", [])), 1, answer.keys())
        relayed = V.verify_ack(V.verify_revoke(r), answer["fwd"][0]["ack"], answer["fwd"][0]["res"])
        self.assertEqual(relayed["iss"], CK.did)
        # Forwarded again, the answer below is tampered with and not kept;
        # the ack kept the first time is still relayed.
        again = self.at(T0 + 21).receive_revoke(r)
        self.assertEqual(len(again["fwd"]), 1)
        V.verify_ack(V.verify_revoke(r), again["fwd"][0]["ack"], again["fwd"][0]["res"])
        self.assertIsNotNone(self.ex.keep_acks(V.verify_revoke(r), {"ack": answer["ack"], "res": {"held": [], "open": []}}))


# ------------------------------------------------------------ peer binding

class PeerBindingTest(Base):
    PEER = "spiffe://b.example/booking"

    def setUp(self):
        super().setUp()
        self.ex = Executor(EK, [A.did], self.dir, app=self.app,
                           peers={self.PEER: [BK.did], "spiffe://gw.example/relay": [A.did, BK.did]})
        self.ex.set_time(T0 + 10)

    def test_a_captured_call_is_useless_from_another_peer(self):
        ch = chain()
        self.app.push(Outcome("ok", res={"charge": "ch_1"}))
        k = fwd(ch, 1)
        self.assertEqual(self.ex.receive_call(k, peer=self.PEER)["tally"]["st"], "ok")
        self.assertRefused(self.ex.receive_call(k, peer="spiffe://s.example/other"), "peer_mismatch")
        self.assertRefused(self.ex.receive_call(k, peer=""), "peer_mismatch")
        again = self.ex.receive_call(k, peer="spiffe://gw.example/relay")
        self.assertEqual(again["res"], {"charge": "ch_1"})
        self.assertEqual(len(self.app.calls), 1)

    def test_no_peer_skips_the_check(self):
        self.app.push(Outcome("ok"))
        self.assertEqual(self.ex.receive_call(fwd(chain(), 1))["tally"]["st"], "ok")


# ------------------------------------------------------------ audit record

class AuditTest(Base):
    def setUp(self):
        super().setUp()
        self.entries = []
        self.ex = Executor(EK, [A.did], self.dir, app=self.app, audit=self.entries.append,
                           peers={"spiffe://b/agent": [BK.did]})
        self.ex.set_time(T0 + 10)

    def rows(self):
        return [(e["kind"], e["outcome"], e.get("reason"), e.get("from"), e["peer"]) for e in self.entries]

    def test_every_answer_is_recorded_once(self):
        ch = chain()
        self.app.push(Outcome("ok", res={"charge": "c"}))
        k = fwd(ch, 1)
        ok = self.ex.receive_call(k, peer="spiffe://b/agent")
        self.ex.receive_call(k, peer="spiffe://s/other")
        stranger_root = issue.issue_root(STRANGER, EK.did, {"act": {"t": "prefix", "v": "travel"}}, EXP_ROOT, nnc=nnc(90))
        self.ex.receive_call(issue.make_call(STRANGER, [stranger_root], "travel/x", {}, call_id=cid(9)))
        forged = copy.deepcopy(fwd(ch, 2))
        forged["from"] = STRANGER.did
        self.ex.receive_call(forged)
        self.ex.receive_revoke(issue.make_revoke(A, ch[0], chain=[ch[0]]))
        self.ex.receive_revoke({"v": 1, "typ": "revoke"}, peer="spiffe://s/other")
        self.assertEqual(self.rows(), [
            ("call", "ok", None, BK.did, "spiffe://b/agent"),
            ("call", "failed", "peer_mismatch", BK.did, "spiffe://s/other"),
            ("call", "failed", "root_not_accepted", STRANGER.did, None),
            ("call", "rejected", "bad_signature", None, None),
            ("revoke", "recorded", None, A.did, None),
            ("revoke", "rejected", "malformed", None, "spiffe://s/other"),
        ])
        first = self.entries[0]
        self.assertEqual((first["id"], first["root"], first["leaf"], first["op"], first["tally"]),
                         (O.identity(k), A.did, O.identity(ch[-1]), "travel/charge", O.identity(ok["tally"])))
        self.assertNotIn("tally", self.entries[3])

    def test_a_held_call_is_recorded_when_it_finishes(self):
        self.app.push(HELD)
        k = fwd(chain(), 1)
        self.assertEqual(self.ex.receive_call(k, peer="spiffe://b/agent"), {"inflight": True})
        self.assertEqual(self.entries, [])
        self.ex.complete(O.identity(k), Outcome("ok", res={"charge": "c"}))
        self.assertEqual(self.rows(), [("call", "ok", None, BK.did, "spiffe://b/agent")])

    def test_audit_log_appends_json_lines(self):
        from writ.audit import AuditLog
        path = os.path.join(self.dir, "audit.jsonl")
        for i in range(2):
            log = AuditLog(path)
            log.record({"at": i, "kind": "call", "peer": None, "outcome": "ok"})
            log.close()
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1]), {"at": 1, "kind": "call", "peer": None, "outcome": "ok"})


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

    def charge_below(self, op, n):
        child = op.issue(CK.did, bnd={"act": {"t": "prefix", "v": "travel/charge"},
                                      "amount": {"t": "max", "v": 58900}}, nnc=nnc(60 + n))
        sub = op.make_call(child, "travel/charge", {"amount": 58900}, call_id=cid(60 + n))
        ans = self.cex.receive_call(sub)
        self.assertTrue(op.receive_tally(sub, ans["tally"], ans.get("res")).ok)

    def test_used_covers_sub_tallies(self):
        # Section 6: used is inclusive of the subtree. An outcome that
        # reports less than the sub-tallies consumed is raised to cover them,
        # so the executor never signs a tally every verifier rejects.
        ch = self.root_chain()
        self.capp.push(Outcome("ok", res={"charge": "c"}, used={"amount": 58900}))

        def book(op):
            self.charge_below(op, 1)
            return Outcome("ok", res={"pnr": "K"}, used={"amount": 0})
        self.app.push(book)
        call = issue.make_call(A, ch, "travel/book", {"amount": 60000}, call_id=cid(1))
        ans = self.ex.receive_call(call)
        self.assertEqual(ans["tally"]["used"], {"amount": 58900})
        self.assertTrue(V.verify_tally(ch[-1], call, ans["tally"], res=ans["res"]).ok)

    def test_restart_after_a_charge_below_resolves_covering_it(self):
        # Sections 7.5 and 9: a record resolved after a crash carries the
        # sub-tally persisted before the crash, with used covering it.
        ch = self.root_chain()
        self.capp.push(Outcome("ok", res={"charge": "c"}, used={"amount": 58900}))

        def book(op):
            self.charge_below(op, 2)
            return HELD
        self.app.push(book)
        call = issue.make_call(A, ch, "travel/book", {"amount": 60000}, call_id=cid(1))
        self.ex.receive_call(call)
        self.assertEqual(self.ex.restart(), 1)
        t = self.ex.receive_call(call)["tally"]
        self.assertEqual((t["err"], t["used"], len(t["sub"]), len(t["wrt"])),
                         ({"code": "unknown_outcome"}, {"amount": 58900}, 1, 1))
        self.assertTrue(V.verify_tally(ch[-1], call, t).ok)


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
        self.assertEqual(len(names), 25)
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
