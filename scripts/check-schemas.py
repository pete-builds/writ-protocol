#!/usr/bin/env python3
"""Check every conformance vector and scenario against its JSON schema.

conformance/schema/vector.schema.json describes a vector (spec section 14)
and scenario.schema.json an executor scenario (section 14.1), the way
Wycheproof ships JSON schemas beside its test vectors. This script validates
conformance/vectors, impl/python/vectors, and conformance/scenarios, and
fails if the schema's list of rejection reasons differs from the reason-code
table in spec section 11, so the two cannot drift apart.

Needs jsonschema (pip install "jsonschema>=4.18,<5"). Exits non-zero on any
failure. With --control it also checks that the schemas can fail: each of a
set of broken copies of real files must be rejected.
"""

import copy
import json
import pathlib
import re
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "conformance" / "schema"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validators():
    vector = load(SCHEMAS / "vector.schema.json")
    scenario = load(SCHEMAS / "scenario.schema.json")
    registry = Registry().with_resources(
        [(s["$id"], Resource.from_contents(s)) for s in (vector, scenario)]
    )
    for s in (vector, scenario):
        Draft202012Validator.check_schema(s)
    return (
        Draft202012Validator(vector, registry=registry),
        Draft202012Validator(scenario, registry=registry),
        vector,
    )


def spec_reasons():
    text = (ROOT / "docs" / "spec" / "writ-v0.1.md").read_text(encoding="utf-8")
    section = text.split("## 11. Reason codes", 1)[1].split("\n## 12.", 1)[0]
    return {m for m in re.findall(r"^\| `([a-z_]+)` \|", section, re.M)} - {"pending"}


def errors(validator, doc):
    return sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))


def check_all(vec, scen):
    failures = 0
    counted = {}
    for label, pattern, validator in (
        ("vector", "conformance/vectors/*.json", vec),
        ("vector", "impl/python/vectors/*.json", vec),
        ("scenario", "conformance/scenarios/*.json", scen),
    ):
        files = sorted(ROOT.glob(pattern))
        if not files:
            print(f"FAIL no files match {pattern}")
            failures += 1
        for path in files:
            for e in errors(validator, load(path)):
                failures += 1
                where = "/".join(str(p) for p in e.absolute_path) or "(top)"
                print(f"FAIL {path.relative_to(ROOT)} at {where}: {e.message[:200]}")
        counted[pattern] = len(files)
    return failures, counted


def controls(vec, scen):
    """Broken copies of real files, each of which the schema must reject."""
    v = load(ROOT / "conformance/vectors/001_canonicalize_sorted_keys_and_whitespace.json")
    r = next(load(p) for p in sorted(ROOT.glob("conformance/vectors/*.json")) if load(p)["expect"] == "reject")
    t = next(load(p) for p in sorted(ROOT.glob("conformance/vectors/*.json")) if load(p)["op"] == "verify_tally")
    s = load(sorted(ROOT.glob("conformance/scenarios/*.json"))[0])
    a = next(load(p) for p in sorted(ROOT.glob("conformance/vectors/*.json")) if load(p)["op"] == "check_ack")
    rs = next(load(p) for p in sorted(ROOT.glob("conformance/scenarios/*.json"))
              if any(x["do"] == "revoke" and "tallies" in x["expect"] for x in load(p)["steps"]))
    ri = next(i for i, x in enumerate(rs["steps"]) if x["do"] == "revoke" and "tallies" in x["expect"])

    def edit(doc, fn):
        d = copy.deepcopy(doc)
        fn(d)
        return d

    first_call = next(i for i, x in enumerate(s["steps"]) if x["do"] == "call")
    cases = [
        (vec, "accept with a reason", edit(v, lambda d: d.update(reason="malformed"))),
        (vec, "reject with no reason", edit(r, lambda d: d.pop("reason"))),
        (vec, "a reason outside section 11", edit(r, lambda d: d.update(reason="nope"))),
        (vec, "pending as a rejection", edit(r, lambda d: d.update(reason="pending"))),
        (vec, "an unknown op", edit(v, lambda d: d.update(op="verify_everything"))),
        (vec, "canonicalize accept without canonical", edit(v, lambda d: d["input"].pop("canonical"))),
        (vec, "verify_tally without its call", edit(t, lambda d: d["input"].pop("call"))),
        (vec, "an extra top-level member", edit(v, lambda d: d.update(extra=1))),
        (vec, "now as a string", edit(v, lambda d: d.update(now="1"))),
        (scen, "a short seed", edit(s, lambda d: d["executor"].update(seed="ab"))),
        (scen, "an unknown step", edit(s, lambda d: d["steps"][0].update(do="explode"))),
        (scen, "a call step without now", edit(s, lambda d: d["steps"][first_call].pop("now"))),
        (scen, "a reply with two shapes", edit(s, lambda d: d["steps"][first_call]["expect"].update(inflight=True, error="revoked"))),
        (scen, "app failed with no code", edit(s, lambda d: d["steps"][first_call].update(app={"st": "failed"}))),
        (scen, "app ok with a code", edit(s, lambda d: d["steps"][first_call].update(app={"st": "ok", "code": "x"}))),
        (scen, "held app with a status", edit(s, lambda d: d["steps"][first_call].update(app={"st": "ok", "hold": True}))),
        (scen, "no steps", edit(s, lambda d: d.update(steps=[]))),
        (vec, "check_ack without its tally", edit(a, lambda d: d["input"].pop("tally"))),
        (scen, "a revoke answer with no ack", edit(rs, lambda d: d["steps"][ri]["expect"].pop("ack"))),
        (scen, "an ack body missing open", edit(rs, lambda d: d["steps"][ri]["expect"]["res"].pop("open"))),
        (scen, "a single executor relaying acks", edit(rs, lambda d: d["steps"][ri]["expect"].update(fwd=[]))),
    ]
    survived = 0
    for validator, name, doc in cases:
        if not errors(validator, doc):
            survived += 1
            print(f"CONTROL SURVIVED {name}: the schema accepted a broken file")
    print(f"controls: {len(cases) - survived}/{len(cases)} broken files rejected")
    return survived


def main():
    vec, scen, vector_schema = validators()
    failures = 0
    schema_reasons = set(vector_schema["$defs"]["reason"]["enum"])
    if schema_reasons != spec_reasons():
        failures += 1
        print(f"FAIL the schema's reasons differ from spec section 11: "
              f"only in the schema {sorted(schema_reasons - spec_reasons())}, "
              f"only in the spec {sorted(spec_reasons() - schema_reasons)}")
    more, counted = check_all(vec, scen)
    failures += more
    if "--control" in sys.argv[1:]:
        failures += controls(vec, scen)
    summary = ", ".join(f"{n} {p}" for p, n in counted.items())
    print(f"{'FAIL' if failures else 'PASS'}: {summary}; {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
