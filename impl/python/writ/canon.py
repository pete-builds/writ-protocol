"""Canonical JSON per RFC 8785 with the spec's integer restriction (section 1.1, 1.2).

Two entry points matter to the rest of the package:

- parse(data): strict parse of received bytes or text. Rejects duplicate
  members at any depth, unpaired surrogate escapes, numbers that are not
  integers, integers outside the safe range, invalid UTF-8, and anything
  that is not JSON. Every rejection is reason ``noncanonical``.
- canonicalize(value): serialize an already parsed value to canonical bytes.
  Member names sort by UTF-16 code units, no whitespace, strings escaped
  only as RFC 8785 section 3.2.2.2 requires, integers in shortest form.

validate_value(value) applies the section 1.1 value rules to a value that was
parsed by something else (for example a conformance vector loaded with the
lenient loader) so that the same rejections fire on it.
"""

import json

from .errors import WritError

MAX_SAFE_INT = (1 << 53) - 1
MIN_SAFE_INT = -MAX_SAFE_INT


def _nc(msg):
    return WritError("noncanonical", msg)


def is_int(value):
    """True for a JSON integer. bool is excluded even though Python makes it an int."""
    return type(value) is int


class MarkedDict(dict):
    """Dict produced by the lenient loader; ``duplicate`` is set when the
    source text repeated a member name in this object."""

    duplicate = False


# ---------------------------------------------------------------- parsing

def _strict_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _nc(f"duplicate member {k!r}")
        out[k] = v
    return out


def _lenient_pairs(pairs):
    out = MarkedDict()
    for k, v in pairs:
        if k in out:
            out.duplicate = True
        out[k] = v
    return out


def _reject_float(text):
    raise _nc(f"number is not an integer: {text}")


def _parse_int(text):
    n = int(text)
    if n < MIN_SAFE_INT or n > MAX_SAFE_INT:
        raise _nc(f"integer outside the safe range: {text}")
    return n


def _reject_constant(text):
    raise _nc(f"non-JSON constant: {text}")


def _lenient_int(text):
    return int(text)


def _to_text(data):
    """Decode received bytes as strict UTF-8. A str is round-tripped through
    UTF-8 so that a lone surrogate character in it is caught as invalid UTF-8."""
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise _nc(f"invalid UTF-8: {e}") from None
    if isinstance(data, str):
        try:
            data.encode("utf-8")
        except UnicodeEncodeError as e:
            raise _nc(f"invalid UTF-8: {e}") from None
        return data
    raise TypeError("parse expects bytes or str")


def parse(data):
    """Strictly parse received JSON bytes or text into Python values.

    Raises WritError('noncanonical') for any section 1.1 rule 2 to 4
    violation or for text that is not JSON at all.
    """
    text = _to_text(data)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except WritError:
        raise
    except (ValueError, RecursionError) as e:
        raise _nc(f"not valid JSON: {e}") from None
    _check_strings(value)
    return value


def loads_lenient(data):
    """Parse JSON keeping problems visible instead of rejecting them.

    Used only for conformance vector files, whose embedded objects may be
    deliberately broken. Duplicate members set MarkedDict.duplicate, floats
    stay floats, and out-of-range integers stay as they are, so that
    validate_value() reports them later with the spec's reason code.
    """
    text = _to_text(data)
    return json.loads(
        text,
        object_pairs_hook=_lenient_pairs,
        parse_int=_lenient_int,
    )


def _check_strings(value):
    """Reject strings containing surrogate code points (from \\u escapes)."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            _check_str(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                _check_str(k)
                stack.append(x)
        elif isinstance(v, list):
            stack.extend(v)


def _check_str(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise _nc("string contains an unpaired surrogate")


def validate_value(value, _path="$"):
    """Apply section 1.1 rules 2 to 4 to an already parsed value.

    Raises WritError('noncanonical'). Accepts exactly what parse() accepts.
    """
    if isinstance(value, bool) or value is None:
        return
    if type(value) is int:
        if value < MIN_SAFE_INT or value > MAX_SAFE_INT:
            raise _nc(f"integer outside the safe range at {_path}")
        return
    if isinstance(value, float):
        raise _nc(f"number is not an integer at {_path}")
    if isinstance(value, str):
        _check_str(value)
        return
    if isinstance(value, dict):
        if getattr(value, "duplicate", False):
            raise _nc(f"duplicate member at {_path}")
        for k, v in value.items():
            if not isinstance(k, str):
                raise _nc(f"member name is not a string at {_path}")
            _check_str(k)
            validate_value(v, f"{_path}.{k}")
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            validate_value(v, f"{_path}[{i}]")
        return
    raise _nc(f"unsupported value type {type(value).__name__} at {_path}")


# ---------------------------------------------------------- serialization

_SHORT_ESCAPES = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def _escape(s):
    out = ['"']
    for ch in s:
        e = _SHORT_ESCAPES.get(ch)
        if e is not None:
            out.append(e)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(name):
    return name.encode("utf-16-be", "surrogatepass")


def _serialize(value, out):
    if value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif value is None:
        out.append("null")
    elif type(value) is int:
        out.append(str(value))
    elif isinstance(value, str):
        out.append(_escape(value))
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for k in sorted(value, key=_utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_escape(k))
            out.append(":")
            _serialize(value[k], out)
        out.append("}")
    elif isinstance(value, list):
        out.append("[")
        for i, v in enumerate(value):
            if i:
                out.append(",")
            _serialize(v, out)
        out.append("]")
    else:
        raise _nc(f"cannot serialize {type(value).__name__}")


def canonicalize(value):
    """Return the RFC 8785 canonical bytes of a parsed value.

    The value is validated first, so a float, an out-of-range integer, a
    surrogate, or a duplicate-marked dict raises WritError('noncanonical').
    """
    validate_value(value)
    out = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")


def canonical_text(data):
    """Parse raw JSON text strictly and return its canonical form as text."""
    return canonicalize(parse(data)).decode("utf-8")
