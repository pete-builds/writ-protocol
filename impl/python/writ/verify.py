"""Verification entry points.

- verify_writ: section 6.1 for one writ.
- verify_chain: section 2.1 (6.1 per writ, section 4 per pair, depth), then
  expiry against the verifier's clock.
- verify_call: section 7 steps 1 to 8, the stateless part of executing a
  call, for an executor or an auditor that holds no stores. Expiry (step
  4) and revocation (step 7) apply to forward calls only; a standing call
  (sys/) is authorized by the chain as historical proof.
- verify_tally: section 6.2, the tally tree, returning a Verdict of
  valid, signed_unauthorized, or unverifiable plus the reason code.
"""

import time

from . import bounds as B
from . import chain as C
from . import objects as O
from .errors import WritError

VALID = "valid"
SIGNED_UNAUTHORIZED = "signed_unauthorized"
UNVERIFIABLE = "unverifiable"


class Verdict:
    """Result of verifying one tally, with the verdicts of its sub-tallies."""

    def __init__(self, status, reason=None, message="", tally_id=None):
        self.status = status
        self.reason = reason
        self.message = message
        self.tally_id = tally_id
        self.subs = []

    @property
    def ok(self):
        return self.status == VALID

    def __repr__(self):
        r = f"Verdict({self.status}"
        if self.reason:
            r += f", {self.reason}: {self.message}"
        return r + ")"


NO_CLOCK = object()


def _now(now):
    """None means the real clock; NO_CLOCK means skip expiry checks."""
    return int(time.time()) if now is None else now


def _expired(writs, now):
    if now is NO_CLOCK:
        return
    t = _now(now)
    for w in writs:
        if t >= w["exp"]:
            raise WritError("expired", f"writ expired at {w['exp']}, now {t}")


def verify_writ(data):
    """Section 6.1 for a writ. Returns the parsed writ or raises WritError."""
    return O.verify_object(data, "writ")


def verify_chain(chain, now=None):
    """Section 2.1 plus expiry. Returns the parsed chain or raises.

    Order: chain length (too_large), every writ passes 6.1 in order, root
    prv is null, each adjacent pair attenuates (section 4), depth over the
    whole chain, then now < exp for every writ (expired). ``now`` None
    means the real clock; verify.NO_CLOCK skips the expiry step.
    """
    if not isinstance(chain, list):
        raise WritError("malformed", "chain is not an array")
    if len(chain) > O.MAX_CHAIN:
        raise WritError("too_large", f"chain has {len(chain)} writs, limit {O.MAX_CHAIN}")
    if not chain:
        raise WritError("malformed", "chain is empty")
    writs = [O.verify_object(w, "writ") for w in chain]
    C.check_chain(writs)
    _expired(writs, now)
    return writs


def check_forward_args(leaf, args):
    """Section 7.2: every applicable leaf bound has an argument that satisfies it.

    Presence is checked for every bound before satisfaction is checked for
    any, so missing_arg always precedes out_of_bounds.
    """
    bnd = leaf["bnd"]
    names = [n for n in sorted(bnd, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
             if n not in B.RESERVED_NAMES and bnd[n]["t"] != "count"]
    for name in names:
        if name not in args:
            raise WritError("missing_arg", f"args lacks {name}")
    for name in names:
        b = bnd[name]
        if not B.satisfies(b, args[name]):
            raise WritError("out_of_bounds", f"args[{name}] = {args[name]!r} violates the {b['t']} bound")


STANDING_OPS = ("sys/undo", "sys/tallies")


def check_standing_args(op, args, writs, ids, now):
    """Section 8: the stateless checks on a standing call's args.

    An op under sys/ that is not a defined standing operation is
    forbidden_op. sys/undo: the target tally verifies under the leaf hld
    (not_reversible), names the leaf writ (tally_mismatch), is reversible
    now (not_reversible), and is ok (not_reversible). sys/tallies: the
    named writ is in the chain (tally_mismatch).
    """
    if op not in STANDING_OPS:
        raise WritError("forbidden_op", f"{op!r} is not a standing operation")
    leaf = writs[-1]
    if op == "sys/undo":
        target = args.get("tally")
        try:
            target = O.verify_object(target, "tally", signer=leaf["hld"])
        except WritError as e:
            raise WritError("not_reversible", f"target tally does not verify under the leaf hld: {e.message}") from None
        if target["writ"] != ids[-1]:
            raise WritError("tally_mismatch", "target tally names a writ other than the leaf")
        if target["rev"] is None or now >= target["rev"]["until"]:
            raise WritError("not_reversible", "target tally has no rev or its until has passed")
        if target["st"] != "ok":
            raise WritError("not_reversible", "target tally is not ok")
    elif op == "sys/tallies":
        if args.get("writ") not in ids:
            raise WritError("tally_mismatch", "args.writ is not the identity of a writ in the chain")


def verify_call(data, now=None, executor=None, accepted_roots=None, revoked=None, standing_ops=True):
    """Section 7 steps 1 to 8 without the call and count stores.

    ``executor`` is the receiving key's did (step 6), ``accepted_roots`` an
    iterable of root issuer dids (step 5), ``revoked`` a set of revoked writ
    identities (step 7, forward calls only, as is expiry at step 4). Each of
    the three is skipped when None. With
    ``standing_ops`` false a standing call gets only the no_standing check,
    which is the conformance scope of the verify_call op. Returns the
    parsed call.
    """
    call = O.check_structure(data, "call")                      # step 1
    writs = [O.verify_object(w, "writ") for w in call["chain"]]  # step 2
    O.check_signature(call, call["from"])
    ids = C.check_chain(writs)                                   # step 3
    op = call["op"]
    standing = op.startswith("sys/")
    # Steps 4 and 7 apply to forward calls only. Forward authority ends at
    # exp and on revocation. A standing call uses the signed chain as
    # historical proof of standing; its time bound is operation-specific
    # (rev.until, tally retention). Neither expiry nor revocation restores
    # forward authority, because every forward call passes both steps.
    if not standing:
        _expired(writs, now)                                     # step 4
    t = _now(None if now is NO_CLOCK else now)
    if accepted_roots is not None and writs[0]["iss"] not in set(accepted_roots):
        raise WritError("root_not_accepted", f"root issuer {writs[0]['iss']} is not accepted")   # step 5
    leaf = writs[-1]
    if executor is not None and leaf["hld"] != executor:        # step 6
        raise WritError("wrong_executor", "the receiving party is not the leaf hld")
    if revoked and not standing:                                 # step 7
        for i in ids:
            if i in revoked:
                raise WritError("revoked", f"writ {i} is revoked")
    if standing:                                                 # step 8
        if call["from"] not in {w["iss"] for w in writs}:
            raise WritError("no_standing", "from is not the iss of any writ in the chain")
        if standing_ops:
            check_standing_args(op, call["args"], writs, ids, t)
    else:
        if call["from"] != leaf["iss"]:
            raise WritError("no_standing", "from is not the leaf iss")
        if not B.prefix_matches(leaf["bnd"]["act"]["v"], op):
            raise WritError("forbidden_op", f"op {op!r} is not matched by act {leaf['bnd']['act']['v']!r}")
        check_forward_args(leaf, call["args"])
    call["chain"] = writs
    return call


def verify_revoke(data, now=None):
    """Section 9.1: a revoke passes 6.1, its chain is valid, its leaf is the
    revoked writ, and the revoker is an issuer on the chain.

    Reasons beyond 6.1: chain failures as reported by section 4;
    chain_broken when the leaf identity is not ``writ``; no_standing when
    ``iss`` is not the iss of a writ in the chain. Expiry is not checked,
    since revoking an expired writ is harmless. Returns the parsed revoke.
    """
    r = O.verify_object(data, "revoke")
    if r["writ"] == "*":
        return r
    writs = [O.verify_object(w, "writ") for w in r["chain"]]
    ids = C.check_chain(writs)
    if ids[-1] != r["writ"]:
        raise WritError("chain_broken", "the chain's leaf is not the revoked writ")
    if r["iss"] not in {w["iss"] for w in writs}:
        raise WritError("no_standing", "iss is not the issuer of any writ in the chain")
    r["chain"] = writs
    return r


def _max_bounds(writ):
    bnd = writ["bnd"]
    return [(n, bnd[n]["v"]) for n in sorted(bnd, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
            if bnd[n]["t"] == "max"]


def _check_used(writ, used, who):
    """Section 6.2 step 7: each max bound's used value is within the writ."""
    for name, limit in _max_bounds(writ):
        u = used.get(name, 0)
        if u > limit:
            raise WritError("out_of_bounds", f"{who} used[{name}] = {u} exceeds bound {limit}")


def _tree(writ, writ_id, chain, tally, call=None, call_id=None, res=None):
    """Section 6.2 steps 1 to 10 for one tally under writ W, recursing into sub."""
    try:
        T = O.verify_object(tally, "tally", signer=writ["hld"])           # step 1
    except WritError as e:
        return Verdict(UNVERIFIABLE, e.reason, e.message)
    verdict = Verdict(VALID, tally_id=O.identity(T))
    try:
        if call is not None:
            if T["call"] != call_id:                                          # step 2
                raise WritError("tally_mismatch", "tally names a different call")
            if T["writ"] != writ_id:                                          # step 3
                raise WritError("tally_mismatch", "tally names a different writ")
            if T["op"] != call["op"]:                                         # step 4
                raise WritError("tally_mismatch", "tally op differs from the call op")
        # Step 5 applies to forward tallies only: a standing operation (sys/)
        # may be accepted after the writ's exp (section 7 step 6, section 8).
        if not T["op"].startswith("sys/") and T["acc"] >= writ["exp"]:        # step 5
            raise WritError("expired", f"acc {T['acc']} is at or after exp {writ['exp']}")
        if res is not None and T["out"] != O.hash_body(res):                  # step 6
            raise WritError("tally_mismatch", "out does not commit to the result body")
        _check_used(writ, T["used"], "tally")                                 # step 7
        wrt = []                                                              # step 8
        for X in T["wrt"]:
            X = O.verify_object(X, "writ")
            C.check_pair(writ, X, writ_id)
            C.check_depth(chain + [X])
            wrt.append((O.identity(X), X))
        wrt_ids = {i: x for i, x in wrt}
        for S in T["sub"]:                                                    # step 9
            named = S.get("writ") if isinstance(S, dict) else None
            if named not in wrt_ids:
                raise WritError("sub_unmatched", "sub-tally names a writ absent from wrt")
            X = wrt_ids[named]
            sub = _tree(X, named, chain + [X], S)
            verdict.subs.append(sub)
            if not sub.ok:
                raise WritError(sub.reason, f"sub-tally: {sub.message}")
        for name, limit in _max_bounds(writ):                                 # step 10
            total = 0
            for S in T["sub"]:
                total += S["used"].get(name, 0)
            if total > limit:
                raise WritError("out_of_bounds", f"sub-tallies used {total} of {name}, bound {limit}")
    except WritError as e:
        verdict.status = SIGNED_UNAUTHORIZED
        verdict.reason = e.reason
        verdict.message = e.message
    return verdict


def verify_tally(writ, call, tally, res=None, now=None):
    """Section 6.2: verify tally T received for call K under leaf writ W.

    W and K are the verifier's own objects; they are checked under section
    6.1 first (raising WritError), and K's chain leaf must be W. Returns a
    Verdict for T with nested verdicts for every sub-tally.
    """
    W = O.verify_object(writ, "writ")
    K = O.verify_object(call, "call")
    chain = [O.verify_object(w, "writ") for w in K["chain"]]
    W_id = O.identity(W)
    if O.identity(chain[-1]) != W_id:
        raise WritError("tally_mismatch", "the call's leaf writ is not the writ supplied")
    return _tree(W, W_id, chain, tally, call=K, call_id=O.identity(K), res=res)
