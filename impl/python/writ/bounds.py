"""The five bound types (section 3), narrowing and satisfaction.

A bound is ``{"t": <type>, "v": <value>}`` and nothing else. validate()
checks shape and value, narrows() implements the "child narrows parent"
column, satisfies() implements the "argument satisfies" column, and
prefix_matches() is section 3.1.
"""

from .canon import is_int
from .errors import WritError

TYPES = ("max", "count", "prefix", "set", "window")

# Bounds that section 7.2 does not compare against args.
RESERVED_NAMES = ("act", "hld", "depth")


def _set_key(element):
    """Distinguish the integer 1 from the string "1" (section 3)."""
    return (type(element).__name__, element)


def validate(bound, name="bound"):
    """Check a bound's shape and value.

    Reasons: ``malformed`` for a wrong shape or a value of the wrong JSON
    type, ``unknown_bound`` for a type outside section 3, ``noncanonical``
    for a value of the right type but outside the rules of section 3.
    """
    if not isinstance(bound, dict):
        raise WritError("malformed", f"bound {name} is not an object")
    if set(bound.keys()) != {"t", "v"}:
        raise WritError("malformed", f"bound {name} must have exactly members t and v")
    t = bound["t"]
    v = bound["v"]
    if not isinstance(t, str):
        raise WritError("malformed", f"bound {name} type is not a string")
    if t not in TYPES:
        raise WritError("unknown_bound", f"bound {name} has unknown type {t!r}")
    if t in ("max", "count"):
        if not is_int(v):
            raise WritError("malformed", f"bound {name} ({t}) value is not an integer")
        if v < 0:
            raise WritError("noncanonical", f"bound {name} ({t}) value is below zero")
    elif t == "prefix":
        if not isinstance(v, str):
            raise WritError("malformed", f"bound {name} (prefix) value is not a string")
    elif t == "set":
        if not isinstance(v, list):
            raise WritError("malformed", f"bound {name} (set) value is not an array")
        seen = set()
        for e in v:
            if not (isinstance(e, str) or is_int(e)):
                raise WritError("malformed", f"bound {name} (set) element is not a string or integer")
            k = _set_key(e)
            if k in seen:
                raise WritError("noncanonical", f"bound {name} (set) has duplicate element {e!r}")
            seen.add(k)
    elif t == "window":
        if not (isinstance(v, list) and len(v) == 2 and is_int(v[0]) and is_int(v[1])):
            raise WritError("malformed", f"bound {name} (window) value is not [lo, hi] integers")
        if v[0] > v[1]:
            raise WritError("noncanonical", f"bound {name} (window) has lo above hi")
    return t, v


def prefix_matches(prefix, s):
    """Section 3.1: P matches S when S == P, or P ends with '/' and S starts
    with P, or S starts with P + '/'."""
    if s == prefix:
        return True
    if prefix.endswith("/") and s.startswith(prefix):
        return True
    return s.startswith(prefix + "/")


def narrows(child, parent):
    """True when child narrows parent under the rule for their common type.

    Both bounds are assumed validated. A type mismatch is not narrowing.
    """
    if child["t"] != parent["t"]:
        return False
    t = child["t"]
    c, p = child["v"], parent["v"]
    if t in ("max", "count"):
        return c <= p
    if t == "prefix":
        return prefix_matches(p, c)
    if t == "set":
        parent_keys = {_set_key(e) for e in p}
        return all(_set_key(e) in parent_keys for e in c)
    if t == "window":
        return p[0] <= c[0] and c[1] <= p[1]
    return False


def satisfies(bound, arg):
    """True when arg satisfies bound. The bound is assumed validated.

    A ``count`` bound is not applied by argument (section 3, section 7.3),
    so it is satisfied by anything. Type confusion never satisfies: a string
    never satisfies max or window, a non-string never satisfies prefix, and
    the integer 1 does not satisfy a set holding only the string "1".
    """
    t = bound["t"]
    v = bound["v"]
    if t == "max":
        return is_int(arg) and 0 <= arg <= v
    if t == "count":
        return True
    if t == "prefix":
        return isinstance(arg, str) and prefix_matches(v, arg)
    if t == "set":
        if not (isinstance(arg, str) or is_int(arg)):
            return False
        return _set_key(arg) in {_set_key(e) for e in v}
    if t == "window":
        return is_int(arg) and v[0] <= arg <= v[1]
    return False


def check_narrows(child, parent):
    """Vector-style check: validate both, then require narrowing.

    Raises the validation reason, or ``not_narrowed``.
    """
    validate(parent, "parent")
    validate(child, "child")
    if child["t"] != parent["t"]:
        raise WritError("not_narrowed", "child retypes the bound")
    if not narrows(child, parent):
        raise WritError("not_narrowed", "child does not narrow parent")


def check_satisfies(bound, arg):
    """Vector-style check: validate, then require satisfaction.

    Raises the validation reason, or ``out_of_bounds``.
    """
    validate(bound)
    if not satisfies(bound, arg):
        raise WritError("out_of_bounds", f"argument {arg!r} does not satisfy {bound['t']} bound")
