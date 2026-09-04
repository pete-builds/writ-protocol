"""Builders that construct and sign protocol objects.

Every builder assembles the object itself from parts it was given and signs
that. narrow() is the only way to make a child writ: it starts from a parent
writ the caller holds, applies overrides, checks attenuation, and signs. No
function here accepts a literal writ object to sign (section 7.5, 12).
"""

import os
import time

from . import bounds as B
from . import chain as C
from . import objects as O
from .canon import canonicalize
from .errors import WritError
from .keys import b64u_encode

hash_body = O.hash_body


def nonce():
    """16 random bytes, base64url, 22 characters."""
    return b64u_encode(os.urandom(16))


def _sign(body, key):
    """Sign a freshly assembled object. Private on purpose."""
    body = {k: v for k, v in body.items() if k != "sig"}
    return {**body, "sig": key.sign(O.signing_input(body))}


def issue_root(key, holder, bnd, exp, nnc=None):
    """Issue a root writ from key to holder with bounds bnd until exp."""
    writ = _sign({
        "v": 1, "typ": "writ", "iss": key.did, "hld": holder, "bnd": bnd,
        "prv": None, "exp": exp, "nnc": nnc or nonce(),
    }, key)
    return O.verify_object(writ, "writ")


def narrow(parent, key, holder, exp=None, bnd=None, nnc=None):
    """Issue a child of ``parent`` held by ``key``, to ``holder``.

    ``bnd`` maps bound names to replacement bounds; every parent bound not
    replaced is carried over unchanged, and names absent from the parent are
    added. ``exp`` defaults to the parent's. The child is verified as a
    valid child under section 4 before it is returned; a widening override
    raises not_narrowed and nothing is signed.
    """
    parent = O.verify_object(parent, "writ")
    if key.did != parent["hld"]:
        raise WritError("chain_broken", "only the parent's hld may issue a child")
    child_bnd = dict(parent["bnd"])
    for name, bound in (bnd or {}).items():
        B.validate(bound, name)
        if name in child_bnd and not B.narrows(bound, child_bnd[name]):
            raise WritError("not_narrowed", f"override for {name} does not narrow the parent")
        child_bnd[name] = bound
    child_exp = parent["exp"] if exp is None else exp
    if child_exp > parent["exp"]:
        raise WritError("not_narrowed", "child exp is after parent exp")
    body = {
        "v": 1, "typ": "writ", "iss": key.did, "hld": holder, "bnd": child_bnd,
        "prv": O.identity(parent), "exp": child_exp, "nnc": nnc or nonce(),
    }
    O.check_bnd(child_bnd)
    C.check_pair(parent, body)
    return O.verify_object(_sign(body, key), "writ")


def make_call(key, chain, op, args, call_id=None):
    """Sign a call from key under chain (root first)."""
    chain = [O.verify_object(w, "writ") for w in chain]
    call = _sign({
        "v": 1, "typ": "call", "id": call_id or nonce(), "chain": chain,
        "from": key.did, "op": op, "args": args,
    }, key)
    return O.verify_object(call, "call")


def make_tally(key, call, writ, st="ok", out=None, used=None, rev=None,
               sub=None, wrt=None, acc=None, err=None):
    """Sign the executor's tally for ``call`` under leaf ``writ``.

    ``out`` may be a hash string or a result body (any JSON value), in which
    case its canonical hash is committed. ``err`` defaults to null for ok
    and to {"code": "unknown_outcome"} otherwise.
    """
    call = O.check_structure(call, "call")
    writ = O.check_structure(writ, "writ")
    if out is not None and not isinstance(out, str):
        out = O.hash_body(out)
    if err is None and st != "ok":
        err = {"code": "unknown_outcome"}
    tally = _sign({
        "v": 1, "typ": "tally", "call": O.identity(call), "writ": O.identity(writ),
        "op": call["op"], "acc": int(time.time()) if acc is None else acc,
        "st": st, "err": err, "out": out, "used": used or {}, "rev": rev,
        "sub": sub or [], "wrt": wrt or [],
    }, key)
    return O.verify_object(tally, "tally", signer=key.did)


def make_revoke(key, target, chain=None):
    """Sign a revoke of writ ``target`` (a writ object) or of every writ ("*")."""
    if target == "*":
        body = {"v": 1, "typ": "revoke", "writ": "*", "iss": key.did, "chain": []}
    else:
        chain = [O.verify_object(w, "writ") for w in (chain or [])]
        body = {"v": 1, "typ": "revoke", "writ": O.identity(target), "iss": key.did, "chain": chain}
    return O.verify_object(_sign(body, key), "revoke")


def to_bytes(obj):
    """Canonical bytes of an object, for sending or storing."""
    return canonicalize(obj)
