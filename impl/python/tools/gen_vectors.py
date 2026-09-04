"""Generate interoperability vectors from fixed seeds into ../vectors/.

Seeds: A = 0x01 * 32, B = 0x02 * 32, C = 0x03 * 32. Every nonce, id, exp,
acc and now is fixed, and Ed25519 is deterministic, so the output is
reproducible byte for byte. Run from impl/python:

    python3 tools/gen_vectors.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from writ import canon, issue, keys, objects as O  # noqa: E402

OUT = os.path.join(HERE, "..", "vectors")

A = keys.Key.from_seed("01" * 32)
B = keys.Key.from_seed("02" * 32)
C = keys.Key.from_seed("03" * 32)

NOW = 1788400010
EXP1, EXP2, EXP3 = 1788403600, 1788401800, 1788401000

ROOT_BND = {
    "act": {"t": "prefix", "v": "travel"},
    "amount": {"t": "max", "v": 60000},
    "currency": {"t": "set", "v": ["USD"]},
    "uses": {"t": "count", "v": 1},
    "fare": {"t": "set", "v": ["refundable"]},
    "date": {"t": "window", "v": [20261015, 20261019]},
}


def sign_raw(body, key):
    body = {k: v for k, v in body.items() if k != "sig"}
    return {**body, "sig": key.sign(O.signing_input(body))}


def resign(obj, key, **changes):
    body = {k: v for k, v in obj.items() if k != "sig"}
    body.update(changes)
    return sign_raw(body, key)


def build():
    w1 = issue.issue_root(A, B.did, ROOT_BND, EXP1, nnc="Qm3bq8w1s5XK7jZRt0aB2w")
    w2 = issue.narrow(w1, B, C.did, exp=EXP2, nnc="Rn4cr9x2t6YL8kASu1bC3g", bnd={
        "act": {"t": "prefix", "v": "travel/charge"},
        "amount": {"t": "max", "v": 58900},
    })
    w3 = issue.narrow(w2, C, A.did, exp=EXP3, nnc="So5ds0y3u7ZM9lBTv2cD4A", bnd={
        "amount": {"t": "max", "v": 10000},
    })
    args_a = {"amount": 60000, "currency": "USD", "fare": "refundable", "date": 20261016}
    args_b = {"amount": 58900, "currency": "USD", "fare": "refundable", "date": 20261015, "pnr": "K7Q2ZD"}
    call_a = issue.make_call(A, [w1], "travel/book", args_a, call_id="a1f1c0a3Ln2k9QpXs4vYzw")
    call_b = issue.make_call(B, [w1, w2], "travel/charge", args_b, call_id="b7f1c0a3Ln2k9QpXs4vYzw")
    res_c = {"charge": "ch_8813"}
    t_c = issue.make_tally(C, call_b, w2, out=res_c, used={"amount": 58900},
                           rev={"until": 1788486400}, acc=NOW + 5)
    res_b = {"pnr": "K7Q2ZD", "charge": "ch_8813"}
    t_b = issue.make_tally(B, call_a, w1, out=res_b, used={"amount": 58900},
                           sub=[t_c], wrt=[w2], acc=NOW + 10)

    vec = []

    def add(name, op, inp, expect, reason=None, now=None):
        v = {"name": name, "op": op, "input": inp, "expect": expect}
        if reason:
            v["reason"] = reason
        if now is not None:
            v["now"] = now
        vec.append(v)

    add("verify_writ root", "verify_writ", {"writ": w1}, "accept")
    add("verify_writ child", "verify_writ", {"writ": w2}, "accept")
    add("verify_chain three links", "verify_chain", {"chain": [w1, w2, w3]}, "accept", now=NOW)
    wide = resign(w2, B, bnd={**w2["bnd"], "amount": {"t": "max", "v": 65000}})
    add("verify_chain child widens max", "verify_chain", {"chain": [w1, wide]}, "reject", "not_narrowed", now=NOW)
    broken = resign(w2, B, prv=O.identity(w2))
    add("verify_chain prv mismatch", "verify_chain", {"chain": [w1, broken]}, "reject", "chain_broken", now=NOW)
    add("verify_chain expired", "verify_chain", {"chain": [w1, w2]}, "reject", "expired", now=EXP2)
    add("verify_call forward", "verify_call", {"call": call_b}, "accept", now=NOW)
    add("verify_call standing sys/tallies from root issuer", "verify_call",
        {"call": issue.make_call(A, [w1, w2], "sys/tallies", {"writ": O.identity(w1)}, call_id="c3f1c0a3Ln2k9QpXs4vYzw")},
        "accept", now=NOW)
    add("verify_call no_standing from is holder", "verify_call",
        {"call": resign(call_b, C, **{"from": C.did})}, "reject", "no_standing", now=NOW)
    add("verify_call forbidden_op chargeback", "verify_call",
        {"call": resign(call_b, B, op="travel/chargeback")}, "reject", "forbidden_op", now=NOW)
    add("verify_call missing_arg amount", "verify_call",
        {"call": resign(call_b, B, args={k: v for k, v in args_b.items() if k != "amount"})}, "reject", "missing_arg", now=NOW)
    add("verify_call out_of_bounds amount", "verify_call",
        {"call": resign(call_b, B, args={**args_b, "amount": 61000})}, "reject", "out_of_bounds", now=NOW)
    add("verify_call missing_arg precedes out_of_bounds", "verify_call",
        {"call": resign(call_b, B, args={"amount": 61000, "currency": "USD", "fare": "refundable"})},
        "reject", "missing_arg", now=NOW)
    add("verify_tally leaf with res", "verify_tally",
        {"writ": w2, "call": call_b, "tally": t_c, "res": res_c}, "accept", now=NOW)
    add("verify_tally with sub and wrt", "verify_tally",
        {"writ": w1, "call": call_a, "tally": t_b, "res": res_b}, "accept", now=NOW)
    add("verify_tally out mismatch", "verify_tally",
        {"writ": w2, "call": call_b, "tally": t_c, "res": {"charge": "ch_0000"}}, "reject", "tally_mismatch", now=NOW)
    add("verify_tally sub_unmatched", "verify_tally",
        {"writ": w1, "call": call_a, "tally": resign(t_b, B, wrt=[]), "res": res_b}, "reject", "sub_unmatched", now=NOW)
    add("verify_tally used over max", "verify_tally",
        {"writ": w2, "call": call_b, "tally": resign(t_c, C, used={"amount": 58901}), "res": res_c},
        "reject", "out_of_bounds", now=NOW)
    add("narrows prefix segment rule", "narrows",
        {"child": {"t": "prefix", "v": "travel/chargeback"}, "parent": {"t": "prefix", "v": "travel/charge"}},
        "reject", "not_narrowed")
    add("satisfies set 1 vs \"1\"", "satisfies", {"bound": {"t": "set", "v": ["1"]}, "arg": 1}, "reject", "out_of_bounds")
    add("canonicalize utf16 order and escapes", "canonicalize",
        {"raw": "{\"\\uff01\": 1, \"\\ud83d\\ude00\": 2, \"b\\n\": \"\\u001f\\u007f/\", \"a\": [true, null, -0]}",
         "canonical": "{\"a\":[true,null,0],\"b\\n\":\"\\u001f\u007f/\",\"\U0001F600\":2,\"\uff01\":1}"}, "accept")
    add("canonicalize rejects float", "canonicalize", {"raw": "{\"a\": 1.0}", "canonical": ""}, "reject", "noncanonical")
    undo = issue.make_call(A, [w1, w2], "sys/undo", {"tally": t_c}, call_id="d4f1c0a3Ln2k9QpXs4vYzw")
    add("verify_call forward expired at leaf exp", "verify_call", {"call": call_b}, "reject", "expired", now=EXP2)
    add("verify_call standing undo after leaf exp", "verify_call", {"call": undo}, "accept", now=EXP2)
    add("verify_call standing tallies after root exp", "verify_call",
        {"call": issue.make_call(B, [w1, w2], "sys/tallies", {"writ": O.identity(w1)}, call_id="e5f1c0a3Ln2k9QpXs4vYzw")},
        "accept", now=EXP1 + 60)
    t_undo = issue.make_tally(C, undo, w2, out={"refund": "rf_8813"}, acc=EXP1 + 60)
    add("verify_tally undo tally acc after exp", "verify_tally",
        {"writ": w2, "call": undo, "tally": t_undo, "res": {"refund": "rf_8813"}}, "accept", now=EXP1 + 60)
    return vec


def main():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        if f.endswith(".json"):
            os.remove(os.path.join(OUT, f))
    vec = build()
    for i, v in enumerate(vec):
        slug = "".join(ch if ch.isalnum() else "_" for ch in v["name"]).strip("_").lower()
        path = os.path.join(OUT, f"{i:03d}_{slug}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False, indent=1)
            f.write("\n")
        canon.parse(open(path, "rb").read())
    print(f"wrote {len(vec)} vectors to {os.path.abspath(OUT)}")


if __name__ == "__main__":
    main()
