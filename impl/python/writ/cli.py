"""Command line entry: python3 -m writ.cli <command> ...

  keygen --seed <hex32> [--out <file>]
  verify-writ <file> [--now N]
  verify-chain <file-with-array> [--now N]
  verify-tally --writ <file> --call <file> --tally <file> [--res <file>] [--now N]
  conformance <dir>

Exit status 0 on accept, 1 on reject or any failing vector, 2 on usage error.
"""

import argparse
import json
import os
import sys

from . import bounds as B
from . import canon
from . import verify as V
from .errors import WritError
from .keys import Key


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _print_result(status, reason=None, message=""):
    if reason:
        print(f"{status} {reason}: {message}")
    else:
        print(status)


def cmd_keygen(args):
    seed = args.seed
    if len(seed) != 64:
        print("seed must be 32 bytes as 64 hex characters", file=sys.stderr)
        return 2
    key = Key.from_seed(seed)
    out = args.out or f"{key.did}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"did": key.did, "seed": key.seed.hex()}, f)
        f.write("\n")
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(key.did)
    print(f"saved {out}")
    return 0


def cmd_verify_writ(args):
    try:
        w = V.verify_writ(_read(args.file))
    except WritError as e:
        _print_result("reject", e.reason, e.message)
        return 1
    _print_result("accept")
    print(f"iss {w['iss']}\nhld {w['hld']}\nexp {w['exp']}")
    return 0


def cmd_verify_chain(args):
    try:
        chain = canon.parse(_read(args.file))
        writs = V.verify_chain(chain, now=args.now)
    except WritError as e:
        _print_result("reject", e.reason, e.message)
        return 1
    _print_result("accept")
    print(f"{len(writs)} writs, leaf hld {writs[-1]['hld']}")
    return 0


def cmd_verify_tally(args):
    try:
        writ = canon.parse(_read(args.writ))
        call = canon.parse(_read(args.call))
        tally = canon.parse(_read(args.tally))
        res = canon.parse(_read(args.res)) if args.res else None
        verdict = V.verify_tally(writ, call, tally, res=res, now=args.now)
    except WritError as e:
        _print_result("reject", e.reason, e.message)
        return 1
    _print_result(verdict.status, verdict.reason, verdict.message)
    _print_subs(verdict, 1)
    return 0 if verdict.ok else 1


def _print_subs(verdict, depth):
    for s in verdict.subs:
        pad = "  " * depth
        if s.reason:
            print(f"{pad}sub {s.status} {s.reason}: {s.message}")
        else:
            print(f"{pad}sub {s.status}")
        _print_subs(s, depth + 1)


# ------------------------------------------------------------ conformance

def run_vector(vec):
    """Run one vector. Returns (accepted: bool, reason or None, message)."""
    op = vec["op"]
    inp = vec.get("input", {})
    # A vector without now is judged with no clock at all: expiry is skipped.
    now = vec["now"] if "now" in vec else V.NO_CLOCK
    try:
        if op == "verify_writ":
            V.verify_writ(inp["writ"])
        elif op == "verify_chain":
            V.verify_chain(inp["chain"], now=now)
        elif op == "verify_call":
            V.verify_call(inp["call"], now=now, standing_ops=False)
        elif op == "verify_tally":
            verdict = V.verify_tally(inp["writ"], inp["call"], inp["tally"], res=inp.get("res"), now=now)
            if not verdict.ok:
                return False, verdict.reason, f"{verdict.status}: {verdict.message}"
        elif op == "narrows":
            B.check_narrows(inp["child"], inp["parent"])
        elif op == "satisfies":
            B.check_satisfies(inp["bound"], inp["arg"])
        elif op == "canonicalize":
            got = canon.canonical_text(inp["raw"])
            if got != inp["canonical"]:
                return False, None, f"canonical form differs: got {got!r}"
        else:
            return False, None, f"unknown op {op!r}"
    except WritError as e:
        return False, e.reason, e.message
    except (KeyError, TypeError) as e:
        return False, None, f"vector input malformed: {e!r}"
    return True, None, ""


def judge(vec, accepted, reason, message):
    """Compare an outcome against the vector's expectation. Returns (passed, note)."""
    expect = vec.get("expect")
    if expect == "accept":
        return accepted, "" if accepted else f"rejected {reason}: {message}"
    if expect == "reject":
        if accepted:
            return False, "accepted, expected rejection"
        want = vec.get("reason")
        if want is not None and want != reason:
            return False, f"reason {reason} (expected {want}): {message}"
        return True, ""
    return False, f"vector has no valid expect: {expect!r}"


def cmd_conformance(args):
    files = sorted(f for f in os.listdir(args.dir) if f.endswith(".json"))
    if not files:
        print(f"no .json vectors in {args.dir}", file=sys.stderr)
        return 2
    passed = failed = 0
    for name in files:
        path = os.path.join(args.dir, name)
        try:
            vec = canon.loads_lenient(_read(path))
        except (ValueError, WritError) as e:
            print(f"FAIL {name}: cannot load vector: {e}")
            failed += 1
            continue
        label = vec.get("name", name)
        accepted, reason, message = run_vector(vec)
        ok, note = judge(vec, accepted, reason, message)
        if ok:
            passed += 1
            print(f"PASS {label}")
        else:
            failed += 1
            print(f"FAIL {label}: {note}")
    print(f"{passed} passed, {failed} failed, {passed + failed} total")
    return 1 if failed else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m writ.cli", description="Writ v0.1 verifier")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="derive a key from a 32 byte hex seed")
    k.add_argument("--seed", required=True)
    k.add_argument("--out")
    k.set_defaults(fn=cmd_keygen)

    w = sub.add_parser("verify-writ", help="section 6.1 for one writ")
    w.add_argument("file")
    w.add_argument("--now", type=int)
    w.set_defaults(fn=cmd_verify_writ)

    c = sub.add_parser("verify-chain", help="section 2.1 for a JSON array of writs")
    c.add_argument("file")
    c.add_argument("--now", type=int)
    c.set_defaults(fn=cmd_verify_chain)

    t = sub.add_parser("verify-tally", help="section 6.2 for a tally tree")
    t.add_argument("--writ", required=True)
    t.add_argument("--call", required=True)
    t.add_argument("--tally", required=True)
    t.add_argument("--res")
    t.add_argument("--now", type=int)
    t.set_defaults(fn=cmd_verify_tally)

    v = sub.add_parser("conformance", help="run every vector in a directory")
    v.add_argument("dir")
    v.set_defaults(fn=cmd_conformance)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
