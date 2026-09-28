# Writ v0.1, Python implementation

A second implementation of the Writ protocol, in a different language from the Go reference, written from `docs/spec/writ-v0.1.md` without consulting the Go code. It has two halves:

- **The verifier** checks writs, chains, calls, tallies, and revokes. It was written by the same author as the Go implementation, so it checks that one text reads the same way twice.
- **The executor** (`executor.py`, `stores.py`, and the scenario runner) receives calls and does the work. It was written for the "stranger test": from the spec text as revised on 2026-09-28, the conformance corpus, and this verifier, without reading `impl/go/`, `demo/`, or `docs/design/`. Every place where that needed a guess is in [DIVERGENCES.md](DIVERGENCES.md), with the spec sentences quoted and a verdict for each.

Requirements: Python 3.12 or later (tested on 3.13 and 3.14) and the `cryptography` package. Nothing else.

## Quick start

From this directory:

    python3 -B -m unittest discover -s tests                           # unit tests
    python3 -B -m writ.cli conformance ../../conformance/vectors       # the shared vectors
    python3 -B -m writ.cli scenarios ../../conformance/scenarios       # the executor scenarios

Pass `-B`, so a stale `.pyc` can never stand in for the source. `tests/test_writ.py` covers the verifier. `tests/test_executor.py` covers the stores, the executor, and the scenario runner, and runs every corpus scenario.

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
| `writ/stores.py` | 9: durable call, count, tally, and revoke stores, plus the 8.1 reversal state |
| `writ/executor.py` | 7, 7.1 to 7.5, 8, 9, 9.1, 9.2: the `Executor` |
| `writ/cli.py` | `python3 -m writ.cli`, including the section 14 and 14.1 runners |

`narrow()` is the only way to produce a child writ. It starts from a parent writ the caller holds, applies overrides, checks section 4, and signs what it built. Nothing in the package signs a writ object handed to it as data.

## Using the executor

    from writ.executor import Executor, Outcome, HELD

    ex = Executor(key, accept=[root_did], store_dir="state/", app=my_app)
    ex.set_time(1788400010)          # or pass clock=callable
    answer = ex.receive_call(call)   # {"tally": ..., "res": ...}, {"error": ...}, or {"inflight": True}
    answer = ex.receive_revoke(rev)  # {"tallies": [...]} or {"error": ...}
    ex.complete(call_id, Outcome("ok", res={...}))   # a held operation returns
    ex.restart()                     # crash and reopen: resolves pending records

Answers take the shapes of spec sections 10 and 14.1. Your application, `my_app(op)`, performs a forward operation (`op.kind == "forward"`) or a reversal (`"undo"`), and returns an `Outcome(st, code, res, used, rev)`, or `HELD` to finish later through `complete()`. `op.stop_requested()` turns true when a revoke tells the operation to stop. An application that raises has an unknown outcome (`unknown_outcome`). `sys/tallies` never calls the application.

How it behaves:

- **Admission is atomic.** Steps 9 and 10 (replay and count) and the pending record of step 11 are admitted under one lock, shared with revocation. No two calls can pass replay with one id or spend one last use, and no revoke can slip between a call's step 7 and its admission.
- **Refusals are signed and forgotten.** A refusal at steps 3 to 10 is signed at the executor's clock and stored nowhere. A failure at steps 1 and 2 is the unsigned `{"error": ...}`.
- **Standing operations check their own arguments when they run.** The checks of `sys/undo` and `sys/tallies` (sections 8.1 and 8.2) run when the operation is performed, after replay. A failure there is a stored outcome, so a retry of the same call gets it back.
- **`sys/undo` reverses at most once** per target tally. It records that a reversal began before starting it, lets a failed reversal be retried, answers later undos with the successful reversal's body, and after a crash mid-reversal answers `unknown_outcome` for good. A second undo of a tally whose reversal is running waits for it.
- **`sys/tallies` is scoped.** It names a writ the caller issued, or one below it.
- **A revoke stops work in flight.** It answers with pending tallies for forward calls in flight under the revoked writ, in call identity order, and tells those operations to stop. Standing calls are neither stopped nor listed.
- **Operations can delegate onward** (section 7.5). `op.issue()` narrows the held leaf into a child, `op.make_call()` signs a sub-call, and `op.receive_tally()` verifies a sub-tally under 6.2 and persists it before returning. Final and resolved tallies carry every issued writ in `wrt` and every sub-tally in `sub`. A valid revoke is passed to an optional `forward_revoke(revoke, holder)` for every holder of a writ issued under the revoked writ.
- **Store failures never pass silently.** If the call or count store cannot be written at admission, the call is refused with `writ-py/store_write_failed` and nothing is recorded. If a final tally cannot be persisted, the answer is the pending tally the record resolves to after a restart.

The stores live under one directory: `calls/`, `counts/`, `tallies/`, `revokes/`, and `reversals/`, with one fsynced, atomically renamed JSON file per record, named by the SHA-256 of its key. `Stores.prune(now)` applies the section 9 lifetimes; nothing prunes automatically.

What it does not do:
- the HTTP binding (section 10);
- any policy for root acceptance beyond a fixed list (section 7.1);
- compensation in which a reversal issues its own `sys/undo` calls to sub-executors;
- a `canceled` answer for calls not yet accepted, which never exist here, because admission and revocation are serialized.

## The conformance runner

    python3 -m writ.cli conformance <dir>

Runs every `*.json` vector in the directory, prints `PASS` or `FAIL` for each and a summary, and exits non-zero on any failure. An unexpected exception is reported as that vector's failure (`CRASH`), and the run carries on.

- **Loading.** Vector files are loaded with a lenient reader, so deliberately broken embedded objects (duplicate members, floats, out-of-range integers, lone surrogate escapes) reach the verifier and are rejected with the spec's reason code.
- **Ops supported:** `verify_writ`, `verify_chain`, `verify_call`, `verify_tally`, `verify_revoke`, `narrows`, `satisfies`, `canonicalize`.
- **`verify_call` covers** section 6.1 on the call, section 4 on its chain, expiry for forward calls only (a standing `sys/` call is authorized by the chain as historical proof, spec section 7 step 4), and the section 5 classification, with 7.2 for forward calls. Executor state (section 7 steps 5 to 7) and section 8's argument checks are outside it.
- **Clock.** A `now` member fixes the clock; a vector without one is judged with no clock, so expiry is not checked. The CLI commands use real time unless given `--now`.

## The scenario runner

    python3 -B -m writ.cli scenarios <dir>

Runs each scenario (spec section 14.1) against a fresh executor with empty stores in a temporary directory. It compares every step's answer with `expect` by canonical form, checks `signaled` before a `finish`, and fails a step with no `app` if the executor calls the application. It prints `PASS` or `FAIL` for each scenario and a summary, reports an unexpected exception as `FAIL <name>: CRASH <type>: <msg>` and continues, and exits non-zero on any failure.

## Other commands

    python3 -m writ.cli keygen --seed <hex32> [--out file]
    python3 -m writ.cli verify-writ <file>
    python3 -m writ.cli verify-chain <file-with-array> [--now N]
    python3 -m writ.cli verify-tally --writ <file> --call <file> --tally <file> [--res <file>]

Exit status: 0 for accept or valid, 1 for reject or any other verdict, 2 for usage errors.

## Interoperability vectors

`vectors/` holds vectors this implementation produced from fixed seeds (0x01, 0x02, 0x03 repeated, for A, B, and C). Regenerate them with

    python3 tools/gen_vectors.py

and run them with `python3 -m writ.cli conformance vectors`.

## Spec ambiguities found while writing the verifier

These 35 were found while writing the verifier, before the September 2026 revisions answered most of them; the executor's findings are in [DIVERGENCES.md](DIVERGENCES.md). Each entry names the section, quotes or paraphrases the sentence, and states the choice this implementation made at the time. Where two implementations could reasonably differ, the conformance corpus shows it.

**Later changes.** The spec revisions of 2026-09-28 settled several of these differently, and this implementation now follows the spec: a chain longer than 8 is `too_large` as a step 5 rule at the `chain` member, after `id` and after `v` and `typ` (item 17); a pending tally's whole shape is checked, including `err.code` `pending` and empty `sub` and `wrt` (item 19); a sub-tally that is not an object makes its tally `malformed` at section 6.1 rather than `sub_unmatched` (item 22); and the conformance op checks `forbidden_op` as well as `no_standing` for a `sys/` op, while section 8's argument checks now run inside the operation, after replay (item 34). The items are kept below as they were written.

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

## Revision of 2026-09-04: standing calls after expiry

Items 16 and 34 above were written when the spec checked expiry for every call. The spec now applies expiry (section 7 step 4) and revocation (step 7) to forward calls only; a standing call (`sys/undo`, `sys/tallies`) is accepted under an expired or revoked chain and is bounded by `rev.until` and by tally retention instead. This implementation follows that: `verify_call` skips both checks for a `sys/` op, and section 6.2 step 5 (`acc` before `exp`) is skipped for a tally whose `op` is under `sys/`. The tests `test_standing_survives_expiry_and_revocation` and `test_standing_tally_acc_after_exp`, and vectors 022 to 025, pin it.
