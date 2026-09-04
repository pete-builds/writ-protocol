"""Attenuation (section 4) and chain shape (section 2.1, section 7 step 3).

check_pair(parent, child) runs the five numbered checks of section 4 in
order and raises the first failure. check_depth(chain) applies the depth
rule over a whole chain. check_chain(chain) ties both together for a list
of writs that already passed section 6.1.
"""

from . import bounds as B
from .canon import is_int
from .errors import WritError
from .objects import identity


def check_pair(parent, child, parent_id=None):
    """Section 4 checks 1 to 5, in order, for one adjacent pair."""
    if parent_id is None:
        parent_id = identity(parent)
    if child["iss"] != parent["hld"]:
        raise WritError("chain_broken", "child iss is not the parent hld")
    if child["prv"] != parent_id:
        raise WritError("chain_broken", "child prv is not the identity of the parent")
    if child["exp"] > parent["exp"]:
        raise WritError("not_narrowed", "child exp is after parent exp")
    pb, cb = parent["bnd"], child["bnd"]
    for name in sorted(pb, key=lambda k: k.encode("utf-16-be", "surrogatepass")):
        if name not in cb:
            raise WritError("not_narrowed", f"child drops bound {name}")
        if cb[name]["t"] != pb[name]["t"]:
            raise WritError("not_narrowed", f"child retypes bound {name}")
        if not B.narrows(cb[name], pb[name]):
            raise WritError("not_narrowed", f"child widens bound {name}")
    if "hld" in pb:
        allowed = pb["hld"]["v"]
        if child["hld"] not in allowed:
            raise WritError("not_narrowed", "child hld is not in the parent hld set")


def check_depth(chain):
    """Section 4 depth rule: writ at index i of n with depth d needs n-1-i <= d."""
    n = len(chain)
    for i, w in enumerate(chain):
        d = w["bnd"].get("depth")
        if d is not None and is_int(d["v"]) and (n - 1 - i) > d["v"]:
            raise WritError("not_narrowed", f"chain has {n - 1 - i} writs below index {i}, depth allows {d['v']}")


def check_chain(chain):
    """Root prv null, every adjacent pair attenuates, depth holds.

    Returns the list of writ identities. Writs must already have passed
    section 6.1.
    """
    if not chain:
        raise WritError("malformed", "chain is empty")
    if chain[0]["prv"] is not None:
        raise WritError("chain_broken", "root writ has a non-null prv")
    ids = [identity(chain[0])]
    for i in range(1, len(chain)):
        check_pair(chain[i - 1], chain[i], ids[-1])
        ids.append(identity(chain[i]))
    check_depth(chain)
    return ids
