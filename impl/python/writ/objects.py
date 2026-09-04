"""Signed objects: structural validation and signatures (sections 1.4 to 1.7, 2, 5, 6, 9.1).

verify_object() runs section 6.1 in its normative order and returns the
parsed object. signing_input() and identity() implement sections 1.4 and
1.5. Limits come from section 1.6, crit from section 1.7.
"""

from . import bounds as B
from .canon import canonicalize, is_int, parse, validate_value
from .errors import WritError
from .keys import is_b64u, is_did, sha256_b64u, verify as verify_sig

# Section 1.6
LIMITS = {"writ": 4096, "call": 65536, "tally": 262144, "revoke": 65536}
MAX_CHAIN = 8
MIN_NONCE_BYTES = 16
HASH_BYTES = 32
SIG_BYTES = 64

TYPES = ("writ", "call", "tally", "revoke")

# Every member this implementation understands, per type. A name in crit
# outside this set is reason unsupported_critical.
KNOWN_MEMBERS = {
    "writ": frozenset(["v", "typ", "iss", "hld", "bnd", "prv", "exp", "nnc", "crit", "sig"]),
    "call": frozenset(["v", "typ", "id", "chain", "from", "op", "args", "crit", "sig"]),
    "tally": frozenset(["v", "typ", "call", "writ", "op", "acc", "st", "err", "out",
                        "used", "rev", "sub", "wrt", "crit", "sig"]),
    "revoke": frozenset(["v", "typ", "writ", "iss", "chain", "crit", "sig"]),
}

TALLY_STATES = ("ok", "failed", "canceled", "pending")

SIGNER_MEMBER = {"writ": "iss", "call": "from", "revoke": "iss"}


# ------------------------------------------------------ identity and input

def signing_input(obj):
    """Section 1.4: <typ> "/" <v> 0x00 <canonical form without sig>."""
    body = {k: v for k, v in obj.items() if k != "sig"}
    prefix = f"{obj['typ']}/{obj['v']}".encode("utf-8")
    return prefix + b"\x00" + canonicalize(body)


def identity(obj):
    """Section 1.5: hash of the canonical form of the whole object, sig included."""
    return sha256_b64u(canonicalize(obj))


def hash_body(body):
    """Hash of the canonical form of a result body (tally.out)."""
    return sha256_b64u(canonicalize(body))


# ------------------------------------------------------------ 6.1 helpers

def _mal(msg):
    return WritError("malformed", msg)


def _is_hash(v):
    return isinstance(v, str) and is_b64u(v, nbytes=HASH_BYTES)


def _require_b64u(obj, name, allow_null=False, allow_star=False):
    """Section 1.1 rule 5 for one member, if it is present and a string."""
    if name not in obj:
        return
    v = obj[name]
    if v is None and allow_null:
        return
    if v == "*" and allow_star:
        return
    if isinstance(v, str) and not is_b64u(v):
        raise WritError("noncanonical", f"{name} is not unpadded base64url")


def _check_binary_members(obj, typ):
    """Rule 5 on the binary members that belong to this object type."""
    _require_b64u(obj, "sig")
    if typ == "writ":
        _require_b64u(obj, "prv", allow_null=True)
        _require_b64u(obj, "nnc")
    elif typ == "call":
        _require_b64u(obj, "id")
    elif typ == "tally":
        _require_b64u(obj, "call")
        _require_b64u(obj, "writ")
        _require_b64u(obj, "out", allow_null=True)
        err = obj.get("err")
        if isinstance(err, dict):
            _require_b64u(err, "ref")
    elif typ == "revoke":
        _require_b64u(obj, "writ", allow_star=True)


def _check_chain_length(obj):
    chain = obj.get("chain")
    if isinstance(chain, list) and len(chain) > MAX_CHAIN:
        raise WritError("too_large", f"chain has {len(chain)} writs, limit {MAX_CHAIN}")


def load(data, typ):
    """Steps 1 and 2 of section 6.1. Returns (object, canonical bytes).

    ``data`` is received bytes or text, or an already parsed value. For raw
    input the received length is checked against the limit before parsing,
    then the canonical length after. Chain length is checked here too, so
    that both limits precede any signature work.
    """
    if typ not in TYPES:
        raise ValueError(f"unknown object type {typ}")
    limit = LIMITS[typ]
    if isinstance(data, (bytes, str)):
        raw_len = len(data) if isinstance(data, bytes) else len(data.encode("utf-8", "surrogatepass"))
        if raw_len > limit:
            raise WritError("too_large", f"{typ} is {raw_len} bytes, limit {limit}")
        obj = parse(data)
    else:
        obj = data
        validate_value(obj)
    canon = canonicalize(obj)
    if len(canon) > limit:
        raise WritError("too_large", f"{typ} canonical form is {len(canon)} bytes, limit {limit}")
    if not isinstance(obj, dict):
        raise _mal(f"{typ} is not a JSON object")
    _check_binary_members(obj, typ)
    _check_chain_length(obj)
    return obj, canon


def _check_version_and_type(obj, typ):
    """Step 3."""
    v = obj.get("v")
    if not (is_int(v) and v == 1):
        raise WritError("unsupported_version", f"v is {v!r}, expected 1")
    if obj.get("typ") != typ:
        raise WritError("wrong_type", f"typ is {obj.get('typ')!r}, expected {typ!r}")


def _check_crit(obj, typ):
    """Step 4, section 1.7."""
    if "crit" not in obj:
        return
    crit = obj["crit"]
    if not isinstance(crit, list) or not all(isinstance(n, str) for n in crit):
        raise _mal("crit is not an array of strings")
    for name in crit:
        if name not in KNOWN_MEMBERS[typ]:
            raise WritError("unsupported_critical", f"crit names {name!r}, which this verifier does not understand")
        if name not in obj:
            raise _mal(f"crit names {name!r}, which is not present")


def _require(obj, name, pred, what):
    if name not in obj:
        raise _mal(f"required member {name} is missing")
    if not pred(obj[name]):
        raise _mal(f"member {name} is not {what}")
    return obj[name]


def _require_key(obj, name):
    v = _require(obj, name, lambda x: isinstance(x, str), "a string")
    if not is_did(v):
        raise WritError("bad_key", f"{name} is not an Ed25519 did:key: {v!r}")
    return v


def _require_sig(obj):
    v = _require(obj, "sig", lambda x: isinstance(x, str), "a string")
    if not is_b64u(v, nbytes=SIG_BYTES):
        raise _mal("sig is not 86 characters of base64url")
    return v


def _require_hash(obj, name, allow_null=False):
    if name not in obj:
        raise _mal(f"required member {name} is missing")
    v = obj[name]
    if v is None and allow_null:
        return v
    if not _is_hash(v):
        raise _mal(f"member {name} is not a 43 character hash")
    return v


def check_bnd(bnd):
    """Structural rules for a writ's bnd (sections 3 and 3.2)."""
    if not isinstance(bnd, dict):
        raise _mal("bnd is not an object")
    if "act" not in bnd:
        raise _mal("bnd lacks act")
    for name in sorted(bnd, key=lambda k: k.encode("utf-16-be", "surrogatepass")):
        B.validate(bnd[name], name)
    if bnd["act"]["t"] != "prefix":
        raise _mal("act is not a prefix bound")
    if "hld" in bnd:
        if bnd["hld"]["t"] != "set":
            raise _mal("hld bound is not a set")
        for e in bnd["hld"]["v"]:
            if not isinstance(e, str):
                raise _mal("hld set element is not a string")
            if not is_did(e):
                raise WritError("bad_key", f"hld set element is not an Ed25519 did:key: {e!r}")
    if "depth" in bnd and bnd["depth"]["t"] != "max":
        raise _mal("depth bound is not a max")


def _check_writ_members(obj):
    _require_key(obj, "iss")
    _require_key(obj, "hld")
    check_bnd(_require(obj, "bnd", lambda x: isinstance(x, dict), "an object"))
    _require_hash(obj, "prv", allow_null=True)
    _require(obj, "exp", is_int, "an integer")
    nnc = _require(obj, "nnc", lambda x: isinstance(x, str), "a string")
    if not is_b64u(nnc, min_bytes=MIN_NONCE_BYTES):
        raise _mal("nnc is shorter than 16 bytes")
    _require_sig(obj)


def _check_writ_array(obj, name):
    arr = _require(obj, name, lambda x: isinstance(x, list), "an array")
    for i, w in enumerate(arr):
        if not isinstance(w, dict):
            raise _mal(f"{name}[{i}] is not an object")
    return arr


def _check_call_members(obj):
    ident = _require(obj, "id", lambda x: isinstance(x, str), "a string")
    if not is_b64u(ident, min_bytes=MIN_NONCE_BYTES):
        raise _mal("id is shorter than 16 bytes")
    chain = _check_writ_array(obj, "chain")
    if not chain:
        raise _mal("chain is empty")
    _require_key(obj, "from")
    _require(obj, "op", lambda x: isinstance(x, str), "a string")
    _require(obj, "args", lambda x: isinstance(x, dict), "an object")
    _require_sig(obj)


def _check_tally_members(obj):
    _require_hash(obj, "call")
    _require_hash(obj, "writ")
    _require(obj, "op", lambda x: isinstance(x, str), "a string")
    _require(obj, "acc", is_int, "an integer")
    st = _require(obj, "st", lambda x: isinstance(x, str) and x in TALLY_STATES, "one of ok, failed, canceled, pending")
    if "err" not in obj:
        raise _mal("required member err is missing")
    err = obj["err"]
    if st == "ok":
        if err is not None:
            raise _mal("err must be null when st is ok")
    else:
        if not isinstance(err, dict) or not isinstance(err.get("code"), str):
            raise _mal("err must be an object with a string code when st is not ok")
        if "ref" in err and not _is_hash(err["ref"]):
            raise _mal("err.ref is not a hash")
    _require_hash(obj, "out", allow_null=True)
    used = _require(obj, "used", lambda x: isinstance(x, dict), "an object")
    for k, v in used.items():
        if not is_int(v) or v < 0:
            raise _mal(f"used[{k}] is not a non-negative integer")
    if "rev" not in obj:
        raise _mal("required member rev is missing")
    rev = obj["rev"]
    if rev is not None:
        if not isinstance(rev, dict) or not is_int(rev.get("until")):
            raise _mal("rev must be null or an object with an integer until")
    sub = _require(obj, "sub", lambda x: isinstance(x, list), "an array")
    for i, s in enumerate(sub):
        if not isinstance(s, dict):
            raise _mal(f"sub[{i}] is not an object")
    _check_writ_array(obj, "wrt")
    if st == "pending" and (used != {} or rev is not None or obj["out"] is not None):
        raise _mal("a pending tally must have used {}, rev null and out null")
    _require_sig(obj)


def _check_revoke_members(obj):
    if "writ" not in obj:
        raise _mal("required member writ is missing")
    w = obj["writ"]
    if w != "*" and not _is_hash(w):
        raise _mal("writ is neither a hash nor \"*\"")
    _require_key(obj, "iss")
    chain = _check_writ_array(obj, "chain")
    if w == "*" and chain:
        raise _mal("chain must be empty when writ is \"*\"")
    if w != "*" and not chain:
        raise _mal("chain must not be empty when writ is a hash")
    _require_sig(obj)


_MEMBER_CHECKS = {
    "writ": _check_writ_members,
    "call": _check_call_members,
    "tally": _check_tally_members,
    "revoke": _check_revoke_members,
}


def check_structure(data, typ):
    """Section 6.1 steps 1 to 5. Returns the parsed object."""
    obj, _ = load(data, typ)
    _check_version_and_type(obj, typ)
    _check_crit(obj, typ)
    _MEMBER_CHECKS[typ](obj)
    return obj


def check_signature(obj, signer):
    """Section 6.1 step 6 for an object that passed steps 1 to 5."""
    verify_sig(signer, signing_input(obj), obj["sig"])


def verify_object(data, typ, signer=None):
    """Section 6.1 in full. Returns the parsed object.

    ``signer`` is the did:key that must have signed. For a writ, call, or
    revoke it defaults to the object's own iss or from member. A tally's
    signer is the hld of the writ it names, which the caller must supply.
    """
    obj = check_structure(data, typ)
    if signer is None:
        member = SIGNER_MEMBER.get(typ)
        if member is None:
            raise ValueError("a tally's signer must be supplied (hld of the writ it names)")
        signer = obj[member]
    check_signature(obj, signer)
    return obj
