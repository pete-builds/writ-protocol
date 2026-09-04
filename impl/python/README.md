# Writ v0.1, Python implementation

An independent implementation of the Writ protocol verifier, written from
`docs/spec/writ-v0.1.md` alone, without reading the Go implementation.
Python 3.14 and the `cryptography` package are the only requirements.

## Layout

| Module | Spec sections |
|---|---|
| `writ/canon.py` | 1.1, 1.2: strict parse, RFC 8785 canonical form with the integer restriction |
| `writ/keys.py` | 1.3, 1.4: did:key for Ed25519, base58btc, base64url, sign and verify |
| `writ/bounds.py` | 3, 3.1: the five bound types, `narrows()`, `satisfies()` |
| `writ/objects.py` | 1.4 to 1.7, 2, 5, 6, 9.1: signing input, identity, limits, crit, section 6.1 |
| `writ/chain.py` | 4: attenuation in the normative order, `hld`, `depth` |
| `writ/verify.py` | 6.1, 2.1, 6.2, 7 steps 1 to 8, 8, 9.1: `verify_writ`, `verify_chain`, `verify_call`, `verify_tally`, `verify_revoke` |
| `writ/issue.py` | builders: `issue_root`, `narrow`, `make_call`, `make_tally`, `make_revoke` |
| `writ/cli.py` | `python3 -m writ.cli` |

`narrow()` is the only way to produce a child writ. It starts from a parent
writ the caller holds, applies overrides, checks section 4, and signs what
it built. Nothing in the package signs a writ object handed to it as data.

## Tests

From this directory:

    python3 -m unittest discover -s tests

## Conformance runner

    python3 -m writ.cli conformance <dir>

Runs every `*.json` vector in the directory, prints `PASS` or `FAIL` per
vector and a summary, and exits non-zero on any failure. Vector files are
loaded with a lenient reader so that deliberately broken embedded objects
(duplicate members, floats, out of range integers, lone surrogate escapes)
reach the verifier and are rejected with the spec's reason code. Supported
ops: `verify_writ`, `verify_chain`, `verify_call`, `verify_tally`, `narrows`,
`satisfies`, `canonicalize`. `verify_call` covers section 6.1 on the call,
section 4 on its chain, expiry, and the section 5 classification with 7.2
for forward calls; executor state (7 steps 5 to 7) and section 8 argument
checks are outside it. A `now` member fixes the clock; a vector without
one is judged with no clock, so expiry is not checked. The CLI commands use
real time unless given `--now`.

Other commands:

    python3 -m writ.cli keygen --seed <hex32> [--out file]
    python3 -m writ.cli verify-writ <file>
    python3 -m writ.cli verify-chain <file-with-array> [--now N]
    python3 -m writ.cli verify-tally --writ <file> --call <file> --tally <file> [--res <file>]

Exit status: 0 accept or valid, 1 reject or any other verdict, 2 usage.

## Interoperability vectors

`vectors/` holds vectors produced by this implementation from fixed seeds
(0x01, 0x02, 0x03 repeated, for A, B, C). Regenerate with

    python3 tools/gen_vectors.py

and run them with `python3 -m writ.cli conformance vectors`.

## Spec ambiguities found

Each entry names the section, quotes or paraphrases the sentence, and
states the choice this implementation made. Where two implementations could
reasonably differ, the conformance corpus will show it.

1. **1.6 and 6.1 step 1, "Byte length within section 1.6" before "Parse".** The limits are in canonical bytes, which are unknown until after parsing. Choice: for raw input, reject when the received bytes exceed the limit (`too_large`) before parsing, then check the canonical length after parsing; for an already parsed object only the canonical length is checked. A received form padded with whitespace past the limit is rejected although its canonical form would fit. An object that both contains a float and is oversized reports `noncanonical`, because its canonical form cannot be computed.

2. **1.1 rule 5 vs 6.1 step 5, base64url values of the wrong length.** A 40 character `prv`, or a 10 character `nnc`, is neither padded nor outside the alphabet. Choice: alphabet and padding violations are `noncanonical` (step 2); length violations (hash not 32 bytes, sig not 64, `nnc` or `id` under 16) are `malformed` (step 5). A string whose length mod 4 is 1 cannot decode at all and is `noncanonical`.

3. **1.1 rule 5, non-zero trailing bits.** A 22 character `nnc` whose last character sets its low four bits decodes to 16 bytes, but re-encoding those bytes gives a different string, so one byte value would have two object identities. Choice: reject as `noncanonical` unless the value re-encodes to itself. The spec's example nonce passes. The text should say whether this strictness is required.

4. **1.1 rule 2, "-0".** Written without fraction or exponent, but RFC 8785 serializes it as `0`. Choice: accept in received bytes and canonicalize to `0`, treating it like non-canonical whitespace under the MAY of 1.2.

5. **1.3 vs 6.1 step 5 vs 11, an identifier that is a string but not an Ed25519 did:key.** Step 5 says a member of the wrong type is `malformed`; 1.3 says any other identifier is `bad_key`. Choice: a non-string is `malformed`; a string that is not an Ed25519 did:key is `bad_key`, raised at step 5 before the signature. The same applies to elements of the `hld` set bound.

6. **6.1 step 3, `v` missing or of the wrong JSON type.** Choice: anything other than the integer 1 (including `true`, `"1"`, or absence) is `unsupported_version`; anything other than the expected `typ` string (including absence) is `wrong_type`.

7. **1.7, "Members named in crit MUST be present"** has no reason code, nor does a `crit` that is not an array of strings. Choice: both `malformed`, at step 4. "Understand" is read as: the name is one of the members this version defines for that object type (`crit` and `sig` included).

8. **6.1 step 2, rule 5 depends on the object type.** Which members are binary depends on `typ`, which is checked only at step 3. Choice: rule 5 is applied to the binary members of the expected type (`sig`; `prv` and `nnc` for a writ; `id` for a call; `call`, `writ`, `out`, `err.ref` for a tally; `writ` for a revoke unless it is `"*"`) before `v` and `typ` are checked.

9. **3 vs 6.1 step 5, bound value errors.** Section 3 gives `noncanonical` for negative `max`, `lo` above `hi`, and duplicate set elements; step 5 gives `malformed` for a wrong type. Choice: `v` of the wrong JSON type (a string for `max`, a three element window, a boolean in a set) is `malformed`; the right type with a bad value is `noncanonical`; unknown `t` is `unknown_bound`. Bounds inside `bnd` are checked in canonical name order, after `act` presence and before the reserved name typing below, so the first reported failure depends on this order, which the spec should fix.

10. **3.2, `act` not a prefix, `hld` not a set, `depth` not a max.** No reason given. Choice: `malformed`. An `hld` set element that is not a string is `malformed`; a string that is not a did:key is `bad_key`.

11. **3, set "array of strings or integers".** Mixed arrays are not addressed. Choice: allowed, and `1` and `"1"` may coexist because they are distinct elements.

12. **3.1, the empty prefix.** `""` matches `""` and any string beginning with `/`. Not forbidden. Choice: allowed as written; the spec may want to forbid it.

13. **3, `count` "not by argument".** For a `satisfies` vector on a `count` bound there is no rule. Choice: any argument satisfies a `count` bound; section 7.2 skips them entirely.

14. **4, the `depth` paragraph sits outside the numbered list.** Its place in the normative order is unstated. Choice: after all five checks for every adjacent pair, then depth for every writ in index order. In 6.2 step 8 depth is checked over the call's chain extended by each `wrt` writ.

15. **7 step 3, root `prv` null vs adjacent pairs.** Both are in one step; order unstated. Choice: root `prv` first, then pairs. It matters when the root has a non-null `prv` and a pair also widens: this implementation reports `chain_broken`.

16. **2.1, whether chain verification includes expiry.** Section 6.1 has no clock and 7 step 4 does. Choice: `verify_chain` checks `now < exp` for every writ as its final step, after depth; `verify_writ` (6.1) does not check expiry. In the conformance runner the expiry step runs only when the vector carries `now` (see 35).

17. **5, "A chain MUST NOT be empty for any call"** has no reason code. Choice: `malformed`, at step 5. A chain longer than 8 is `too_large`, checked immediately after parsing and before `v` and `typ`, because 1.6 requires it before any signature. A revoke with a hash `writ` and an empty chain is also `malformed`.

18. **6.1 for a tally on its own.** The signer is "hld of the writ named", but the tally holds only that writ's hash, so 6.1 cannot complete without the writ object. Choice: tally verification always requires the writ; the CLI has no standalone `verify-tally-object`.

19. **6, "A pending tally has used {}, rev null, and out null"** is stated as a fact, not a MUST with a reason. Choice: enforced at step 5 as `malformed`. Likewise `err` must be null exactly when `st` is `ok` and otherwise an object with a string `code` (optional `ref` hash), and `used` values must be non-negative integers; the spec gives no reason for any of these.

20. **6.2 steps 7 and 10, `used` names that are not `max` bounds of W.** Choice: ignored, following the ignore rule of 1.7. The spec should say whether to reject.

21. **6.2 step 9, "Step 8 and this step recurse".** Step 10 (sum of sub-tallies) and step 5 (`acc` before `exp`) are not named as recursing, yet step 9 restates step 5 and step 7 for S. Choice: each sub-tally S is verified exactly as T was, with X in place of W and no call: steps 5, 7, 8, 9 and 10. Each S is fully checked, subtree included, before the next S; step 10 for T runs after all of `T.sub`.

22. **6.2 step 9, S that is not an object or has no `writ` member.** Choice: `sub_unmatched` fires whenever S does not name a writ in `wrt`, including when S is not an object; section 6.1 for S runs afterwards.

23. **6.2 result categories.** "unverifiable (signature fails or the writ is absent)" does not cover a tally that fails 6.1 before the signature step (`malformed`, `too_large`, `noncanonical`). Choice: every 6.1 failure is `unverifiable`; every failure in steps 2 to 10, including one inside a sub-tally, makes T `signed_unauthorized` with that reason, while the sub-tally's own verdict is recorded separately.

24. **6.2 preconditions on W and K.** The spec assumes the verifier's own objects are consistent. Choice: W and K are each verified under 6.1 (raising the 6.1 reason), and the identity of K's leaf must equal W's identity; a mismatch is reported as `tally_mismatch`.

25. **6.2 step 6, R present and `T.out` null.** Choice: `tally_mismatch`. R absent with a non-null `out` is accepted, since a body may be withheld (section 12).

26. **8 and 11, "a forward op under sys/".** Section 5 classifies every `op` beginning with `sys/` as standing, so no forward op can be under `sys/`. Choice: after the standing `no_standing` check, an `op` under `sys/` that is not `sys/undo` or `sys/tallies` is `forbidden_op`.

27. **8.1, "the tally's signature verifies under its own key".** "Its own" is read as the executor's key, which is the leaf `hld`. `verify_call` performs the 8.1 and 8.2 argument checks that need no store, in the order the sentence lists them.

28. **9.1, revoke validity** names three conditions beyond 6.1 without reason codes. Choice in `verify_revoke`: chain failures as reported by section 4; leaf identity not equal to `writ` is `chain_broken`; `iss` not on the chain is `no_standing`. Expiry is not checked for a revoke.

29. **12, "verifiers SHOULD reject a root whose exp is more than 24 hours ahead"** has no reason code. Not implemented; a deployment can add it in front of `verify_chain`.

30. **6.2 step 9 does not compare `S.op` against `X.act`.** Only the top-level call's `op` is checked (step 4, and 7 step 8). Choice: not checked, as written. If intended, it belongs in step 9 with `forbidden_op`.

31. **2, `nnc` "at least 16 random bytes".** A verifier can check only length. Choice: decoded length under 16 bytes is `malformed`.

32. **14 lists an "execute call" vector op** that the runner does not support, because executing needs the executor's identity, accepted roots, and stores. `verify_call(call, now, executor, accepted_roots, revoked)` covers section 7 steps 1 to 8 for a future vector shape that supplies those inputs.

33. **7.2, missing_arg vs out_of_bounds across bounds.** The two numbered steps are per bound, so with bounds checked in name order an out of bounds `amount` would be reported before a missing `date`. Choice, matching the coordinator's stated precedence: presence of every argument is checked first, then satisfaction, so `missing_arg` always precedes `out_of_bounds`.

34. **verify_call scope for standing calls.** Section 7 step 8 says "section 8 applies" to a standing call, but section 8's checks need the executor's own key and clock. Choice: the conformance op checks only `no_standing` for a `sys/` op; the library's `verify_call` performs the stateless section 8 checks unless `standing_ops=False`.

35. **Vectors without `now`.** The Go corpus has `verify_chain` accept vectors with no `now` whose `exp` is already in the past, so the corpus convention is: no `now`, no clock, expiry not checked. The runner follows that (`verify.NO_CLOCK`); the CLI commands use real time. The corpus format should state this explicitly.
