"""Writ v0.1 Python implementation tests. Run from impl/python:

    python3 -m unittest discover -s tests
"""

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from writ import bounds as B  # noqa: E402
from writ import canon, chain as C, issue, keys, objects as O, verify as V  # noqa: E402
from writ.errors import WritError  # noqa: E402

A = keys.Key.from_seed("00" * 32)
BK = keys.Key.from_seed("11" * 32)
CK = keys.Key.from_seed("22" * 32)
DK = keys.Key.from_seed("33" * 32)
STRANGER = keys.Key.from_seed("44" * 32)

NOW = 1_700_000_000
EXP1 = 1_800_000_000
EXP2 = 1_799_000_000

ROOT_BND = {
    "act": {"t": "prefix", "v": "travel"},
    "amount": {"t": "max", "v": 60000},
    "currency": {"t": "set", "v": ["USD"]},
    "uses": {"t": "count", "v": 1},
    "fare": {"t": "set", "v": ["refundable"]},
    "date": {"t": "window", "v": [20261015, 20261019]},
}


def sign_raw(body, key):
    """Test-only: sign an arbitrary object. The library never exposes this."""
    body = {k: v for k, v in body.items() if k != "sig"}
    return {**body, "sig": key.sign(O.signing_input(body))}


def resign(obj, key, **changes):
    """Copy obj with changes applied and re-sign it with key."""
    body = {k: v for k, v in obj.items() if k != "sig"}
    body.update(changes)
    return sign_raw(body, key)


def bnd_with(base, **changes):
    out = dict(base)
    for k, v in changes.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


class Fixture:
    def __init__(self):
        self.w1 = issue.issue_root(A, BK.did, ROOT_BND, EXP1, nnc="Qm3bq8w1s5XK7jZRt0aB2w")
        self.w2 = issue.narrow(self.w1, BK, CK.did, exp=EXP2, bnd={
            "act": {"t": "prefix", "v": "travel/charge"},
            "amount": {"t": "max", "v": 58900},
        }, nnc="Rn4cr9x2t6YL8kASu1bC3g")
        self.callA = issue.make_call(A, [self.w1], "travel/book", {
            "amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261016,
        }, call_id="a1f1c0a3Ln2k9QpXs4vYzw")
        self.callB = issue.make_call(BK, [self.w1, self.w2], "travel/charge", {
            "amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015, "pnr": "K7Q2ZD",
        }, call_id="b7f1c0a3Ln2k9QpXs4vYzw")
        self.resC = {"charge": "ch_8813"}
        self.tC = issue.make_tally(CK, self.callB, self.w2, out=self.resC, used={"amount": 58900},
                                   rev={"until": EXP2 - 100}, acc=NOW + 10)
        self.resB = {"pnr": "K7Q2ZD", "charge": "ch_8813"}
        self.tB = issue.make_tally(BK, self.callA, self.w1, out=self.resB, used={"amount": 58900},
                                   sub=[self.tC], wrt=[self.w2], acc=NOW + 20)


FX = Fixture()


class Base(unittest.TestCase):
    def assertReason(self, reason, fn, *args, **kwargs):
        with self.assertRaises(WritError) as cm:
            fn(*args, **kwargs)
        self.assertEqual(cm.exception.reason, reason, str(cm.exception))

    def assertTallyReason(self, reason, status, *args, **kwargs):
        verdict = V.verify_tally(*args, **kwargs)
        self.assertEqual(verdict.status, status, repr(verdict))
        self.assertEqual(verdict.reason, reason, repr(verdict))


# ------------------------------------------------------------------ keys

class KeysTest(Base):
    def test_zero_seed_is_the_known_did(self):
        self.assertEqual(A.did, "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")

    def test_did_roundtrip(self):
        self.assertEqual(keys.decode_did(BK.did), BK.public_bytes)

    def test_reject_other_methods_and_key_types(self):
        for bad in ["did:web:example.com", "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                    "did:key:6Mk", "did:key:z6Mk0OIl", 42, ""]:
            self.assertReason("bad_key", keys.decode_did, bad)

    def test_sign_and_verify(self):
        sig = A.sign(b"hello")
        self.assertEqual(len(sig), 86)
        keys.verify(A.did, b"hello", sig)
        self.assertReason("bad_signature", keys.verify, BK.did, b"hello", sig)
        self.assertReason("bad_signature", keys.verify, A.did, b"hello!", sig)


# ----------------------------------------------------------------- canon

class CanonTest(Base):
    def test_sorting_escaping_and_integers(self):
        raw = '{"b": 1, "a": [true, null, -0, 9007199254740991], "\\u00e9": "x", "z\\n": "\\u001f\\u007f\\"\\\\/"}'
        got = canon.canonical_text(raw)
        self.assertEqual(got, '{"a":[true,null,0,9007199254740991],"b":1,"z\\n":"\\u001f\x7f\\"\\\\/","\u00e9":"x"}')

    def test_utf16_order(self):
        # U+1F600 encodes as surrogates D83D DE00, which sort before U+FF01 in UTF-16.
        got = canon.canonical_text('{"\\uff01": 1, "\\ud83d\\ude00": 2, "\\u0041": 3}')
        self.assertEqual(got, '{"A":3,"\U0001F600":2,"\uff01":1}')

    def test_duplicate_member_any_depth(self):
        self.assertReason("noncanonical", canon.parse, '{"a": 1, "a": 2}')
        self.assertReason("noncanonical", canon.parse, '{"a": {"b": [{"c": 1, "c": 1}]}}')

    def test_lone_surrogate(self):
        self.assertReason("noncanonical", canon.parse, '{"a": "\\ud800"}')
        self.assertReason("noncanonical", canon.parse, '{"\\udc00": 1}')
        self.assertEqual(canon.parse('{"a": "\\ud83d\\ude00"}'), {"a": "\U0001F600"})

    def test_non_integer_numbers(self):
        for raw in ["1.0", "1e3", "1E3", "-1.5", "9007199254740992", "-9007199254740992", "NaN", "Infinity"]:
            self.assertReason("noncanonical", canon.parse, raw)
        self.assertEqual(canon.parse("9007199254740991"), 9007199254740991)

    def test_invalid_utf8(self):
        self.assertReason("noncanonical", canon.parse, b'{"a": "\xff"}')
        self.assertReason("noncanonical", canon.parse, b'{"a": "\xed\xa0\x80"}')

    def test_not_json(self):
        for raw in ["", "{", '{"a":1} x', "'a'", '{"a":1,}']:
            self.assertReason("noncanonical", canon.parse, raw)

    def test_parsed_value_checks(self):
        self.assertReason("noncanonical", canon.canonicalize, {"a": 1.5})
        self.assertReason("noncanonical", canon.canonicalize, {"a": 1 << 53})
        self.assertReason("noncanonical", canon.canonicalize, {"a": "\udfff"})
        d = canon.loads_lenient('{"a": 1, "a": 2}')
        self.assertReason("noncanonical", canon.canonicalize, d)


# ---------------------------------------------------------------- bounds

class BoundsTest(Base):
    def test_prefix_rule(self):
        m = B.prefix_matches
        self.assertTrue(m("travel", "travel"))
        self.assertTrue(m("travel", "travel/charge"))
        self.assertTrue(m("travel/", "travel/charge"))
        self.assertFalse(m("travel/", "travel"))
        self.assertTrue(m("travel/charge", "travel/charge/retry"))
        self.assertFalse(m("travel/charge", "travel/chargeback"))
        self.assertFalse(m("travel", "travelling"))

    def test_prefix_segment_rule_as_reason(self):
        self.assertReason("not_narrowed", B.check_narrows,
                          {"t": "prefix", "v": "travel/chargeback"}, {"t": "prefix", "v": "travel/charge"})
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "prefix", "v": "travel/charge"}, "travel/chargeback")
        B.check_satisfies({"t": "prefix", "v": "travel/charge"}, "travel/charge/retry")

    def test_narrows_all_types(self):
        self.assertTrue(B.narrows({"t": "max", "v": 5}, {"t": "max", "v": 5}))
        self.assertFalse(B.narrows({"t": "max", "v": 6}, {"t": "max", "v": 5}))
        self.assertTrue(B.narrows({"t": "count", "v": 0}, {"t": "count", "v": 1}))
        self.assertTrue(B.narrows({"t": "set", "v": ["a"]}, {"t": "set", "v": ["a", "b"]}))
        self.assertFalse(B.narrows({"t": "set", "v": ["c"]}, {"t": "set", "v": ["a", "b"]}))
        self.assertTrue(B.narrows({"t": "set", "v": []}, {"t": "set", "v": ["a"]}))
        self.assertTrue(B.narrows({"t": "window", "v": [2, 3]}, {"t": "window", "v": [1, 4]}))
        self.assertFalse(B.narrows({"t": "window", "v": [0, 3]}, {"t": "window", "v": [1, 4]}))
        self.assertFalse(B.narrows({"t": "max", "v": 1}, {"t": "count", "v": 1}))

    def test_set_type_confusion(self):
        self.assertReason("not_narrowed", B.check_narrows, {"t": "set", "v": [1]}, {"t": "set", "v": ["1"]})
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "set", "v": ["1"]}, 1)
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "set", "v": [1]}, "1")
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "set", "v": [1]}, True)
        B.check_satisfies({"t": "set", "v": [1, "1"]}, 1)
        B.validate({"t": "set", "v": [1, "1"]})

    def test_satisfies_type_confusion(self):
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "max", "v": 5}, "3")
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "max", "v": 5}, -1)
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "max", "v": 5}, True)
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "window", "v": [1, 5]}, "3")
        self.assertReason("out_of_bounds", B.check_satisfies, {"t": "prefix", "v": "a"}, 1)
        B.check_satisfies({"t": "max", "v": 5}, 5)
        B.check_satisfies({"t": "max", "v": 5}, 0)
        B.check_satisfies({"t": "count", "v": 0}, "anything")

    def test_validation_reasons(self):
        self.assertReason("unknown_bound", B.validate, {"t": "regex", "v": "a.*"})
        self.assertReason("noncanonical", B.validate, {"t": "max", "v": -1})
        self.assertReason("noncanonical", B.validate, {"t": "window", "v": [5, 1]})
        self.assertReason("noncanonical", B.validate, {"t": "set", "v": ["a", "a"]})
        self.assertReason("malformed", B.validate, {"t": "max", "v": "5"})
        self.assertReason("malformed", B.validate, {"t": "max", "v": 5, "x": 1})
        self.assertReason("malformed", B.validate, {"t": "max"})
        self.assertReason("malformed", B.validate, {"t": "set", "v": [True]})


# ------------------------------------------------------------------ writ

class WritTest(Base):
    def test_root_and_child_verify(self):
        V.verify_writ(FX.w1)
        V.verify_writ(canon.canonicalize(FX.w2))
        V.verify_chain([FX.w1, FX.w2], now=NOW)
        self.assertEqual(len(O.identity(FX.w1)), 43)

    def test_example_from_spec_is_parseable(self):
        self.assertIn('"prv":null', canon.canonicalize(FX.w1).decode())

    def test_widened_max(self):
        self.assertReason("not_narrowed", issue.narrow, FX.w1, BK, CK.did, bnd={"amount": {"t": "max", "v": 65000}})
        bad = resign(FX.w2, BK, bnd=bnd_with(FX.w2["bnd"], amount={"t": "max", "v": 65000}))
        self.assertReason("not_narrowed", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_dropped_bound(self):
        bad = resign(FX.w2, BK, bnd=bnd_with(FX.w2["bnd"], fare=None))
        self.assertReason("not_narrowed", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_retyped_bound(self):
        bad = resign(FX.w2, BK, bnd=bnd_with(FX.w2["bnd"], amount={"t": "count", "v": 1}))
        self.assertReason("not_narrowed", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_unknown_bound_type(self):
        bad = resign(FX.w2, BK, bnd=bnd_with(FX.w2["bnd"], fare={"t": "glob", "v": "*"}))
        self.assertReason("unknown_bound", V.verify_writ, bad)
        self.assertReason("unknown_bound", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_prv_mismatch(self):
        bad = resign(FX.w2, BK, prv=O.identity(FX.w2))
        self.assertReason("chain_broken", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_iss_hld_mismatch(self):
        bad = resign(FX.w2, STRANGER, iss=STRANGER.did)
        self.assertReason("chain_broken", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_exp_longer_than_parent(self):
        self.assertReason("not_narrowed", issue.narrow, FX.w1, BK, CK.did, exp=EXP1 + 1)
        bad = resign(FX.w2, BK, exp=EXP1 + 1)
        self.assertReason("not_narrowed", V.verify_chain, [FX.w1, bad], now=NOW)

    def test_hld_set_violation(self):
        root = issue.issue_root(A, BK.did, bnd_with(ROOT_BND, hld={"t": "set", "v": [DK.did]}), EXP1)
        self.assertReason("not_narrowed", issue.narrow, root, BK, CK.did)
        ok = issue.narrow(root, BK, DK.did)
        V.verify_chain([root, ok], now=NOW)
        bad = resign(ok, BK, hld=CK.did)
        self.assertReason("not_narrowed", V.verify_chain, [root, bad], now=NOW)

    def test_depth_violation(self):
        root = issue.issue_root(A, BK.did, bnd_with(ROOT_BND, depth={"t": "max", "v": 1}), EXP1)
        w2 = issue.narrow(root, BK, CK.did)
        V.verify_chain([root, w2], now=NOW)
        w3 = issue.narrow(w2, CK, DK.did)
        self.assertReason("not_narrowed", V.verify_chain, [root, w2, w3], now=NOW)

    def test_chain_too_long(self):
        chain = [FX.w1]
        holders = [BK, CK, DK, STRANGER, A, BK, CK, DK, A]
        for i in range(8):
            chain.append(issue.narrow(chain[-1], holders[i], holders[i + 1].did))
        self.assertEqual(len(chain), 9)
        self.assertReason("too_large", V.verify_chain, chain, now=NOW)
        V.verify_chain(chain[:8], now=NOW)

    def test_non_null_root_prv(self):
        bad = resign(FX.w1, A, prv=O.identity(FX.w2))
        self.assertReason("chain_broken", V.verify_chain, [bad], now=NOW)

    def test_expired_chain(self):
        self.assertReason("expired", V.verify_chain, [FX.w1, FX.w2], now=EXP2)
        V.verify_chain([FX.w1, FX.w2], now=EXP2 - 1)

    def test_duplicate_key_in_raw_json(self):
        raw = canon.canonicalize(FX.w1).decode()
        raw = raw.replace('"v":1}', '"v":1,"v":1}', 1)
        self.assertIn('"v":1,"v":1}', raw)
        self.assertReason("noncanonical", V.verify_writ, raw)

    def test_lone_surrogate(self):
        raw = canon.canonicalize(FX.w1).decode().replace('"typ":"writ"', '"typ":"writ","x":"\\ud800"')
        self.assertReason("noncanonical", V.verify_writ, raw)

    def test_float(self):
        raw = canon.canonicalize(FX.w1).decode().replace(f'"exp":{EXP1}', f'"exp":{EXP1}.0')
        self.assertReason("noncanonical", V.verify_writ, raw)
        self.assertReason("noncanonical", V.verify_writ, {**FX.w1, "exp": float(EXP1)})

    def test_padded_base64url_signature(self):
        self.assertReason("noncanonical", V.verify_writ, {**FX.w1, "sig": FX.w1["sig"] + "=="})
        self.assertReason("noncanonical", V.verify_writ, {**FX.w1, "sig": FX.w1["sig"][:-1] + "+"})
        self.assertReason("noncanonical", V.verify_writ, {**FX.w1, "nnc": FX.w1["nnc"] + "=="})

    def test_wrong_signer(self):
        self.assertReason("bad_signature", V.verify_writ, sign_raw(FX.w1, STRANGER))

    def test_tampered_after_signing(self):
        self.assertReason("bad_signature", V.verify_writ, {**FX.w1, "exp": EXP1 + 1})

    def test_wrong_typ(self):
        self.assertReason("wrong_type", V.verify_writ, resign(FX.w1, A, typ="call"))
        self.assertReason("wrong_type", O.verify_object, FX.w1, "call")

    def test_wrong_v(self):
        self.assertReason("unsupported_version", V.verify_writ, resign(FX.w1, A, v=2))
        self.assertReason("unsupported_version", V.verify_writ, resign(FX.w1, A, v=True))

    def test_crit_unknown(self):
        self.assertReason("unsupported_critical", V.verify_writ, resign(FX.w1, A, crit=["nbf"], nbf=1))
        ok = resign(FX.w1, A, crit=["exp"])
        V.verify_writ(ok)
        self.assertReason("malformed", V.verify_writ, resign(FX.w1, A, crit=["exp"], exp=None))

    def test_unknown_members_are_ignored(self):
        V.verify_writ(resign(FX.w1, A, extra={"anything": [1, 2]}))

    def test_malformed_and_bad_key(self):
        self.assertReason("malformed", V.verify_writ, resign(FX.w1, A, exp="soon"))
        self.assertReason("malformed", V.verify_writ, resign(FX.w1, A, bnd={}))
        self.assertReason("malformed", V.verify_writ, resign(FX.w1, A, nnc="c2hvcnQ"))
        self.assertReason("bad_key", V.verify_writ, resign(FX.w1, A, hld="did:web:example.com"))
        b = resign(FX.w1, A, bnd=bnd_with(ROOT_BND, hld={"t": "set", "v": ["did:web:x"]}))
        self.assertReason("bad_key", V.verify_writ, b)

    def test_too_large(self):
        big = resign(FX.w1, A, pad="x" * 4096)
        self.assertReason("too_large", V.verify_writ, big)

    def test_signature_is_type_bound(self):
        # A signature made over "writ/1" input must not verify when the bytes are presented as a call.
        body = {k: v for k, v in FX.w1.items() if k != "sig"}
        sig_as_call = A.sign(b"call/1\x00" + canon.canonicalize(body))
        self.assertReason("bad_signature", V.verify_writ, {**body, "sig": sig_as_call})

    def test_narrow_refuses_stranger_and_never_signs_literal(self):
        self.assertReason("chain_broken", issue.narrow, FX.w1, STRANGER, CK.did)
        self.assertFalse(hasattr(issue, "sign_object"))


# ------------------------------------------------------------------ call

class CallTest(Base):
    def test_forward_call_verifies(self):
        c = V.verify_call(FX.callB, now=NOW, executor=CK.did, accepted_roots=[A.did])
        self.assertEqual(c["op"], "travel/charge")

    def test_forward_op_under_sys(self):
        # An op under sys/ that is not a defined standing operation is forbidden, even for the leaf iss.
        bad = resign(FX.callB, BK, op="sys/forward")
        self.assertReason("forbidden_op", V.verify_call, bad, now=NOW)
        # An act prefix of "sys" never matches: sys/ ops go by standing, so a stranger has none.
        root = issue.issue_root(A, BK.did, {"act": {"t": "prefix", "v": "sys"}}, EXP1)
        c = issue.make_call(A, [root], "sys/tallies", {"writ": O.identity(root)})
        V.verify_call(c, now=NOW)
        c2 = resign(c, STRANGER, **{"from": STRANGER.did})
        self.assertReason("no_standing", V.verify_call, c2, now=NOW)

    def test_standing_undo_and_tallies(self):
        undo = issue.make_call(A, [FX.w1, FX.w2], "sys/undo", {"tally": FX.tC})
        V.verify_call(undo, now=NOW + 50, executor=CK.did)
        self.assertReason("not_reversible", V.verify_call, undo, now=EXP2 - 100)
        no_rev = resign(FX.tC, CK, rev=None)
        self.assertReason("not_reversible", V.verify_call, resign(undo, A, args={"tally": no_rev}), now=NOW)
        failed = resign(FX.tC, CK, st="failed", err={"code": "x"})
        self.assertReason("not_reversible", V.verify_call, resign(undo, A, args={"tally": failed}), now=NOW)
        forged = sign_raw(FX.tC, STRANGER)
        self.assertReason("not_reversible", V.verify_call, resign(undo, A, args={"tally": forged}), now=NOW)
        other = resign(FX.tC, CK, writ=O.identity(FX.w1))
        self.assertReason("tally_mismatch", V.verify_call, resign(undo, A, args={"tally": other}), now=NOW)
        t = issue.make_call(BK, [FX.w1, FX.w2], "sys/tallies", {"writ": O.identity(FX.w1)})
        V.verify_call(t, now=NOW)
        self.assertReason("tally_mismatch", V.verify_call, resign(t, BK, args={"writ": O.identity(FX.callA)}), now=NOW)

    def test_forbidden_op(self):
        bad = resign(FX.callB, BK, op="travel/chargeback")
        self.assertReason("forbidden_op", V.verify_call, bad, now=NOW)
        ok = resign(FX.callB, BK, op="travel/charge/retry")
        V.verify_call(ok, now=NOW)

    def test_missing_arg(self):
        args = dict(FX.callB["args"])
        del args["amount"]
        self.assertReason("missing_arg", V.verify_call, resign(FX.callB, BK, args=args), now=NOW)

    def test_out_of_bounds_arg(self):
        for change in [{"amount": 61000}, {"amount": "58900"}, {"currency": "EUR"}, {"date": 20261020}, {"fare": 1}]:
            args = {**FX.callB["args"], **change}
            self.assertReason("out_of_bounds", V.verify_call, resign(FX.callB, BK, args=args), now=NOW)

    def test_no_standing_forward(self):
        bad = resign(FX.callB, CK, **{"from": CK.did})
        self.assertReason("no_standing", V.verify_call, bad, now=NOW)

    def test_root_not_accepted_and_wrong_executor(self):
        self.assertReason("root_not_accepted", V.verify_call, FX.callB, now=NOW, accepted_roots=[STRANGER.did])
        self.assertReason("wrong_executor", V.verify_call, FX.callB, now=NOW, executor=BK.did)

    def test_revoked(self):
        self.assertReason("revoked", V.verify_call, FX.callB, now=NOW, revoked={O.identity(FX.w1)})

    def test_standing_survives_expiry_and_revocation(self):
        # Section 7 step 6: a forward call is expired at exp, and stays so
        # however the chain is presented; a standing call is not.
        undo = issue.make_call(A, [FX.w1, FX.w2], "sys/undo", {"tally": FX.tC})
        tallies = issue.make_call(BK, [FX.w1, FX.w2], "sys/tallies", {"writ": O.identity(FX.w1)})
        after_leaf = EXP2
        after_root = EXP1 + 60
        self.assertReason("expired", V.verify_call, FX.callB, now=after_leaf)
        self.assertReason("expired", V.verify_call, FX.callB, now=after_root)
        # Reversible until EXP2 - 100, so after the leaf's exp an undo is bound
        # by rev.until, not by exp: standing passes, then 8.1 says not_reversible.
        self.assertReason("not_reversible", V.verify_call, undo, now=after_leaf)
        V.verify_call(undo, now=after_leaf, standing_ops=False)
        V.verify_call(tallies, now=after_root, executor=CK.did, accepted_roots=[A.did])
        # Revocation: forward refused, standing unaffected.
        revoked = {O.identity(FX.w1)}
        self.assertReason("revoked", V.verify_call, FX.callB, now=NOW, revoked=revoked)
        V.verify_call(undo, now=NOW + 50, revoked=revoked)
        V.verify_call(tallies, now=after_root, revoked=revoked)
        # What a standing call never skips: standing, root, executor, chain.
        stranger = resign(tallies, STRANGER, **{"from": STRANGER.did})
        self.assertReason("no_standing", V.verify_call, stranger, now=after_root)
        self.assertReason("root_not_accepted", V.verify_call, tallies, now=after_root, accepted_roots=[STRANGER.did])
        self.assertReason("wrong_executor", V.verify_call, tallies, now=after_root, executor=BK.did)
        self.assertReason("chain_broken", V.verify_call, resign(tallies, BK, chain=[FX.w2, FX.w1]), now=after_root)
        self.assertReason("bad_signature", V.verify_call, {**tallies, "args": {"writ": "x"}}, now=after_root)

    def test_call_limits_and_chain(self):
        self.assertReason("malformed", V.verify_call, resign(FX.callB, BK, chain=[]), now=NOW)
        self.assertReason("too_large", V.verify_call, resign(FX.callB, BK, chain=[FX.w1] * 9), now=NOW)
        self.assertReason("chain_broken", V.verify_call, resign(FX.callB, BK, chain=[FX.w2]), now=NOW)
        self.assertReason("expired", V.verify_call, FX.callB, now=EXP2)

    def test_revoke_object(self):
        r = issue.make_revoke(A, FX.w2, chain=[FX.w1, FX.w2])
        V.verify_revoke(r)
        r2 = issue.make_revoke(BK, FX.w2, chain=[FX.w1, FX.w2])
        V.verify_revoke(r2)
        star = issue.make_revoke(A, "*")
        V.verify_revoke(star)
        self.assertReason("malformed", V.verify_revoke, resign(star, A, chain=[FX.w1]))
        self.assertReason("malformed", V.verify_revoke, resign(r, A, chain=[]))
        self.assertReason("no_standing", V.verify_revoke, resign(r, CK, iss=CK.did))
        self.assertReason("chain_broken", V.verify_revoke, resign(r, A, chain=[FX.w1]))
        self.assertReason("chain_broken", V.verify_revoke, resign(r, A, chain=[FX.w2]))
        self.assertReason("bad_signature", V.verify_revoke, {**r, "iss": BK.did})


# ----------------------------------------------------------------- tally

class TallyTest(Base):
    def test_tree_valid(self):
        v = V.verify_tally(FX.w1, FX.callA, FX.tB, res=FX.resB, now=NOW + 100)
        self.assertTrue(v.ok, repr(v))
        self.assertEqual(len(v.subs), 1)
        self.assertTrue(v.subs[0].ok)
        v2 = V.verify_tally(FX.w2, FX.callB, FX.tC, res=FX.resC)
        self.assertTrue(v2.ok)
        self.assertTrue(V.verify_tally(FX.w1, FX.callA, FX.tB).ok)

    def test_standing_tally_acc_after_exp(self):
        # 6.2 step 5 binds a forward tally's acc to the writ's exp; an undo
        # tally answers a standing call and is judged by rev.until instead.
        undo = issue.make_call(A, [FX.w1, FX.w2], "sys/undo", {"tally": FX.tC})
        t_undo = issue.make_tally(CK, undo, FX.w2, out={"refund": "rf_1"}, acc=EXP1 + 60)
        self.assertTrue(V.verify_tally(FX.w2, undo, t_undo, res={"refund": "rf_1"}).ok)
        late = resign(FX.tC, CK, acc=EXP2)
        self.assertTallyReason("expired", "signed_unauthorized", FX.w2, FX.callB, late)

    def test_tally_names_wrong_call(self):
        bad = resign(FX.tB, BK, call=O.identity(FX.callB))
        self.assertTallyReason("tally_mismatch", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_tally_names_wrong_writ(self):
        bad = resign(FX.tB, BK, writ=O.identity(FX.w2))
        self.assertTallyReason("tally_mismatch", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_tally_wrong_op(self):
        bad = resign(FX.tB, BK, op="travel/charge")
        self.assertTallyReason("tally_mismatch", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_tally_out_mismatch(self):
        self.assertTallyReason("tally_mismatch", "signed_unauthorized", FX.w1, FX.callA, FX.tB, res={"pnr": "other"})
        bad = resign(FX.tB, BK, out=None)
        self.assertTallyReason("tally_mismatch", "signed_unauthorized", FX.w1, FX.callA, bad, res=FX.resB)

    def test_used_over_max(self):
        bad = resign(FX.tB, BK, used={"amount": 60001})
        self.assertTallyReason("out_of_bounds", "signed_unauthorized", FX.w1, FX.callA, bad)
        sub_bad = resign(FX.tC, CK, used={"amount": 58901})
        bad = resign(FX.tB, BK, sub=[sub_bad])
        self.assertTallyReason("out_of_bounds", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_sub_sum_over_max(self):
        w2b = issue.narrow(FX.w1, BK, DK.did, bnd={"amount": {"t": "max", "v": 58900}})
        callB2 = issue.make_call(BK, [FX.w1, w2b], "travel/charge", FX.callB["args"])
        tD = issue.make_tally(DK, callB2, w2b, out={"charge": "ch_2"}, used={"amount": 58900}, acc=NOW + 10)
        bad = resign(FX.tB, BK, sub=[FX.tC, tD], wrt=[FX.w2, w2b])
        self.assertTallyReason("out_of_bounds", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_sub_tally_with_writ_absent_from_wrt(self):
        bad = resign(FX.tB, BK, wrt=[])
        self.assertTallyReason("sub_unmatched", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_acc_at_or_after_exp(self):
        bad = resign(FX.tB, BK, acc=EXP1)
        self.assertTallyReason("expired", "signed_unauthorized", FX.w1, FX.callA, bad)
        sub_bad = resign(FX.tC, CK, acc=EXP2)
        bad = resign(FX.tB, BK, sub=[sub_bad])
        self.assertTallyReason("expired", "signed_unauthorized", FX.w1, FX.callA, bad)
        ok = resign(FX.tB, BK, acc=EXP1 - 1)
        self.assertTrue(V.verify_tally(FX.w1, FX.callA, ok).ok)

    def test_unverifiable(self):
        self.assertTallyReason("bad_signature", "unverifiable", FX.w1, FX.callA, sign_raw(FX.tB, CK))
        self.assertTallyReason("malformed", "unverifiable", FX.w1, FX.callA, resign(FX.tB, BK, sub=None))
        sub_bad = sign_raw(FX.tC, STRANGER)
        v = V.verify_tally(FX.w1, FX.callA, resign(FX.tB, BK, sub=[sub_bad]))
        self.assertEqual(v.status, "signed_unauthorized")
        self.assertEqual(v.reason, "bad_signature")
        self.assertEqual(v.subs[0].status, "unverifiable")

    def test_wrt_must_be_valid_children(self):
        wide = resign(FX.w2, BK, bnd=bnd_with(FX.w2["bnd"], amount={"t": "max", "v": 65000}))
        bad = resign(FX.tB, BK, wrt=[wide], sub=[])
        self.assertTallyReason("not_narrowed", "signed_unauthorized", FX.w1, FX.callA, bad)
        foreign = issue.issue_root(STRANGER, CK.did, ROOT_BND, EXP1)
        bad = resign(FX.tB, BK, wrt=[foreign], sub=[])
        self.assertTallyReason("chain_broken", "signed_unauthorized", FX.w1, FX.callA, bad)

    def test_pending_shape_and_err_shape(self):
        p = issue.make_tally(BK, FX.callA, FX.w1, st="pending", acc=NOW)
        self.assertTrue(V.verify_tally(FX.w1, FX.callA, p).ok)
        self.assertReason("malformed", O.verify_object, resign(p, BK, used={"amount": 1}), "tally", signer=BK.did)
        self.assertReason("malformed", O.verify_object, resign(FX.tB, BK, st="failed"), "tally", signer=BK.did)
        f = issue.make_tally(BK, FX.callA, FX.w1, st="failed", err={"code": "undeliverable"}, acc=NOW)
        self.assertTrue(V.verify_tally(FX.w1, FX.callA, f).ok)

    def test_writ_and_call_disagree(self):
        self.assertReason("tally_mismatch", V.verify_tally, FX.w2, FX.callA, FX.tB)

    def test_depth_applies_to_wrt(self):
        root = issue.issue_root(A, BK.did, bnd_with(ROOT_BND, depth={"t": "max", "v": 0}), EXP1)
        call = issue.make_call(A, [root], "travel/book", FX.callA["args"])
        child = resign(FX.w2, BK, prv=O.identity(root), bnd=bnd_with(FX.w2["bnd"], depth={"t": "max", "v": 0}))
        t = issue.make_tally(BK, call, root, out={"x": 1}, wrt=[child], acc=NOW)
        self.assertTallyReason("not_narrowed", "signed_unauthorized", root, call, t)


# ------------------------------------------------------------------- cli

class CliTest(Base):
    def test_conformance_runner(self):
        import tempfile
        from writ import cli
        vectors = [
            {"name": "good writ", "op": "verify_writ", "input": {"writ": FX.w1}, "expect": "accept"},
            {"name": "bad sig", "op": "verify_writ", "input": {"writ": {**FX.w1, "exp": 1}},
             "expect": "reject", "reason": "bad_signature"},
            {"name": "chain", "op": "verify_chain", "input": {"chain": [FX.w1, FX.w2]}, "expect": "accept", "now": NOW},
            {"name": "chain expired", "op": "verify_chain", "input": {"chain": [FX.w1, FX.w2]},
             "expect": "reject", "reason": "expired", "now": EXP1},
            {"name": "tally", "op": "verify_tally",
             "input": {"writ": FX.w1, "call": FX.callA, "tally": FX.tB, "res": FX.resB}, "expect": "accept"},
            {"name": "narrows", "op": "narrows", "input": {"child": {"t": "max", "v": 1}, "parent": {"t": "max", "v": 2}},
             "expect": "accept"},
            {"name": "satisfies", "op": "satisfies", "input": {"bound": {"t": "set", "v": ["1"]}, "arg": 1},
             "expect": "reject", "reason": "out_of_bounds"},
            {"name": "canon", "op": "canonicalize", "input": {"raw": '{"b":1, "a":2}', "canonical": '{"a":2,"b":1}'},
             "expect": "accept"},
            {"name": "canon dup", "op": "canonicalize", "input": {"raw": '{"a":1,"a":2}', "canonical": ""},
             "expect": "reject", "reason": "noncanonical"},
        ]
        with tempfile.TemporaryDirectory() as d:
            for i, vec in enumerate(vectors):
                with open(os.path.join(d, f"{i:03d}.json"), "w") as f:
                    json.dump(vec, f)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["conformance", d]), 0)
            with open(os.path.join(d, "999.json"), "w") as f:
                json.dump({"name": "wrong reason", "op": "verify_writ", "input": {"writ": {**FX.w1, "v": 2}},
                           "expect": "reject", "reason": "malformed"}, f)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["conformance", d]), 1)

    def test_keygen_and_verify_files(self):
        import tempfile
        from writ import cli
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            out = os.path.join(d, "k.json")
            self.assertEqual(cli.main(["keygen", "--seed", "00" * 32, "--out", out]), 0)
            with open(out) as f:
                self.assertEqual(json.load(f)["did"], A.did)
            for name, obj in [("w.json", FX.w1), ("c.json", FX.callA), ("t.json", FX.tB), ("r.json", FX.resB),
                              ("chain.json", [FX.w1, FX.w2])]:
                with open(os.path.join(d, name), "wb") as f:
                    f.write(canon.canonicalize(obj))
            self.assertEqual(cli.main(["verify-writ", os.path.join(d, "w.json")]), 0)
            self.assertEqual(cli.main(["verify-chain", os.path.join(d, "chain.json"), "--now", str(NOW)]), 0)
            self.assertEqual(cli.main(["verify-tally", "--writ", os.path.join(d, "w.json"), "--call",
                                       os.path.join(d, "c.json"), "--tally", os.path.join(d, "t.json"),
                                       "--res", os.path.join(d, "r.json")]), 0)
            self.assertEqual(cli.main(["verify-tally", "--writ", os.path.join(d, "w.json"), "--call",
                                       os.path.join(d, "c.json"), "--tally", os.path.join(d, "t.json"),
                                       "--res", os.path.join(d, "w.json")]), 1)


if __name__ == "__main__":
    unittest.main()
