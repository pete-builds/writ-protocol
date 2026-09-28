# Divergence log: the Python executor, written from the spec

This log records every place where building the Python executor from
`docs/spec/writ-v0.1.md` (revised 2026-09-28) needed a decision the text did
not make, or where the conformance corpus expected something that was not
derived from the text first. The executor was written without reading
`impl/go/`, `demo/`, or `docs/design/`. Where the corpus settled a question,
the entry says so; the corpus was never edited.

Verdicts:

- PYTHON_BUG: the spec was clear and this implementation got it wrong.
- SPEC_AMBIGUOUS: the text allows more than one reading.
- SPEC_SILENT: the text says nothing about it.
- CORPUS_CONTRADICTS_SPEC: the expected output disagrees with the spec text.

## Entries

### 1. `verify_revoke` checked the revoke's signature before its chain

- Implementing: the `verify_revoke` conformance op (section 14) and section 9.1.
- Spec: section 9.1, "A verifier checks a revoke in this order, which is the order of section 7 steps 1 to 3 for a call: 1. Section 6.1 steps 1 to 5 on the revoke. [...] 2. Every writ in `chain` passes section 6.1, in array order. 3. The revoke's signature verifies under `iss` (`bad_signature`)."
- Decision: none needed. The pre-existing `verify_revoke` ran all of section 6.1 on the revoke, signature included, before verifying the chain's writs.
- Corpus: vector `bad writ in chain before revoke signature` expects `malformed`; the old code reported `bad_signature`. Once the op was wired into the runner that was the only failure of 209. Fixed by splitting section 6.1 at step 5, as `verify_call` already did; `test_revoke_check_order` pins both orderings and fails on the old code.
- Verdict: PYTHON_BUG

### 2. Where the sys/undo reversal state lives

- Implementing: the durable stores (section 9) and `sys/undo` (section 8.1).
- Spec: section 8.1, "the executor MUST durably record that a reversal of the tally has begun before it performs one", "once one has [succeeded], a later `sys/undo` for the same tally, under any call `id`, performs nothing and is answered `ok` with the successful reversal's result body", and "A record of a reversal that began and never reported, found after a restart, means its outcome is unknown". Section 9's table lists exactly four stores (call, count, tally, revoke) with a key, lifetime, durability, and loss consequence for each.
- Decision: none of the four stores is keyed by the target tally, and none is said to hold a result body except the call store's entry for the undo call itself (section 7 step 9), which a later undo under a different `id` cannot find. So the reversal state (began, done with its body, or unknown) needs a fifth durable store keyed by the target tally's identity, whose lifetime, durability requirement, and loss consequence the spec does not give. This implementation adds `ReversalStore`, keeps records for good, and treats it as MUST survive restart, since losing a `done` record would let a second reversal run.
- Corpus: scenarios 005, 007 and 017 need exactly this state (the body of the successful reversal replayed under new ids; a failed reversal consuming nothing; a began record becoming `unknown_outcome` after restart). They say nothing about where it lives.
- Verdict: SPEC_SILENT

### 3. The key and lifetime of a key-wide revoke in the revoke store

- Implementing: the revoke store (section 9) for `writ` `"*"` (section 9.1).
- Spec: section 9 table, revoke store: "Key: writ identity", "Lifetime: until that writ's `exp`". Section 9.1: "For `"*"`, `iss` is the key every one of whose writs is revoked." Section 7 step 7: "no writ in the chain is revoked in E's store, by identity or by a key-wide revoke of its issuer".
- Decision: a key-wide revoke names no writ, so it has neither the table's key nor its lifetime. This implementation keys it by the revoking key and keeps it for good, because it covers writs the key issues after the revoke arrives, whose `exp` cannot be known in advance.
- Corpus: scenario 011 step 3 ("a writ A issued after the revoke's arrival is covered too") confirms that a key-wide revoke must outlive every writ that existed when it arrived, which rules out any lifetime derived from those writs. The storage key and retention are still unstated.
- Verdict: SPEC_SILENT

### 4. "Tally identity compared as byte strings": which bytes

- Implementing: the order of `sys/tallies` results (section 8.2) and of a revoke's answer (section 9.1).
- Spec: section 8.2, "in ascending order of `acc`, ties in ascending order of tally identity compared as byte strings"; section 9.1, "in ascending order of call identity compared as byte strings". Section 1: "**Hash** means the base64url encoding, without padding, of the SHA-256 of a byte string"; section 1.5, "The identity of a signed object is the hash of the canonical form".
- Decision: an identity is defined as the base64url text, so "as byte strings" most plausibly means the ASCII bytes of that text. It can also be read as the 32 decoded SHA-256 bytes, and the two orders differ, because base64url's alphabet (`A-Z a-z 0-9 - _`) is not in ASCII order (`- 0-9 A-Z _ a-z`). This implementation compares the ASCII bytes of the text.
- Corpus: scenario 014 expects call identities beginning `4FUw`, `yxBo`, `zdyA`, in that order. That is ASCII order of the text; the decoded bytes (`4` is 56, `y` is 50, `z` is 51) would put `4FUw` last. The corpus settles it for the text reading; the spec sentence should say "the ASCII bytes of the identity string".
- Verdict: SPEC_AMBIGUOUS

### 5. The `acc` of a tally for a call the executor never accepted

- Implementing: refusals at section 7 steps 3 to 10.
- Spec: section 6 table, "`acc` | integer | yes | the time the executor accepted the call; for a forward call, bounds and expiry are judged at this time". Section 7, "every later failure MUST be answered with a signed tally with `st` `failed` and the reason in `err.code`". Section 7 step 11, "E records `acc` = now", which a refused call never reaches. Section 9.1, "`canceled` for calls not yet accepted".
- Decision: a refused call was never accepted, yet its signed tally needs an integer `acc`, and nothing says which time to use (receipt, zero, or something else). This implementation uses the executor's clock when it received the call. The other members of a refusal follow from the table: `used` `{}` ("absent names mean zero"), `out` null ("null when there is none"), `rev` null, `sub` and `wrt` empty. The same gap covers a `canceled` tally for a call "not yet accepted" in a revoke's answer; this executor never holds such a call, because admission and revocation take one lock, so it never had to choose there.
- Corpus: every refusal in the scenarios carries the step's `now` as `acc` (003 step 2 says so outright: "a refusal is not stored: the retry is checked again and signed at the new time"). This matches.
- Verdict: SPEC_SILENT

### 6. Unsigned or signed rejection at section 7 steps 1 and 2

- Implementing: the executor's answer when the call fails section 6.1 steps 1 to 5, a chain writ fails section 6.1, or the call's signature fails.
- Spec: section 7, "A failure at step 1 or 2 MAY be answered with an unsigned error; every later failure MUST be answered with a signed tally". Section 14.1, "`{"error": <reason>}` for an unsigned rejection at section 7 steps 1 and 2", and "two conforming executors given the same scenario sign the same bytes".
- Decision: after a step 2 failure the call has parsed, so it has an identity and a leaf, and an executor may take the other branch of the MAY and sign a `failed` tally. That executor conforms to section 7 and fails scenario 009 step 1, which expects `{"error": "bad_signature"}`. This implementation answers unsigned at both steps. For conformance the MAY is a MUST, and the text should say so.
- Corpus: 009 step 1 expects the unsigned form.
- Verdict: SPEC_AMBIGUOUS

### 7. A second sys/undo for a tally whose reversal is running

- Implementing: section 8.1 serialization of reversals.
- Spec: section 8.1, "Reversals of one tally MUST NOT run concurrently, and the executor MUST durably record that a reversal of the tally has begun before it performs one."
- Decision: the text forbids concurrency but does not say what a second undo of the same target, under a different call `id`, receives while the first is running: to wait, a pending tally, or a refusal (and if a refusal, with what code, and whether it is recorded, since it is not one of steps 3 to 10). This implementation admits it (recorded pending at steps 9 and 11), queues it behind the running reversal, and answers `{"inflight": true}`. When the running reversal returns, success answers the queued call `ok` with that reversal's body and reverses nothing; failure lets the queued call run its own reversal. After a restart a queued call resolves like any pending record, to `unknown_outcome`.
- Corpus: not exercised; scenario 015 runs one reversal alone.
- Verdict: SPEC_SILENT

### 8. A held scenario operation's `app.st` is the empty string

- Implementing: the section 14.1 runner.
- Spec: section 14.1, "Its members are `st` (`ok`, `failed`, or `canceled`), `code` (the `err.code`, present exactly when `st` is not `ok`), and optionally [...] `hold`".
- Decision: the runner reads `hold` first and ignores `st` for a held operation, whose outcome comes from the later `finish` step.
- Corpus: scenarios 013 to 017 script held operations as `{"st": "", "hold": true}`: `st` is none of the three values, and `code` is absent although `st` is not `ok`. A runner that validated `app` as the text describes would reject these steps. This is format only; no executor behavior depends on it.
- Verdict: CORPUS_CONTRADICTS_SPEC

### 9. The library's sys/undo check misreported a target that is not an object

- Implementing: section 7 step 8 argument checks for sys/undo, shared by `verify_call` and the executor.
- Spec: section 8.1, "in this order: `args.tally` is an object (`malformed`); it passes section 6.1 with this executor's own key as signer, any failure there being `not_reversible`".
- Decision: none needed. The pre-existing `check_standing_args` skipped the object check and handed a string to section 6.1, whose loader treats a string as received JSON text, so `{"tally": "not an object"}` came out `not_reversible`, and a missing `tally` also escaped `malformed`.
- Corpus: scenario 006 step 7 expects `malformed`. The executor now calls the fixed library function; `test_undo_target_not_an_object_is_malformed` fails on the old code.
- Verdict: PYTHON_BUG

### 10. Which received sub-tallies go into `sub`

- Implementing: delegating onward (section 7.5) and the tally's `sub` member (section 6).
- Spec: section 6 table, "`sub` | array of tally | yes | every tally this executor received from calls it made under child writs, signed members only". Section 7.5, "It MUST persist each sub-tally it receives before acting on the sub-tally's contents, MUST include every sub-tally in `sub` and every issued writ in `wrt`, whatever its own `st`". Section 6, "A later tally with the same `call` from the same executor supersedes it." Section 6.2 step 9 recurses into every element of `sub`, and section 6.2's result makes T `signed_unauthorized` when a check fails "anywhere in the tree".
- Decision: "every tally received" does not say what to do with (a) an object that fails section 6.1 under the child's holder, which proves nothing about who made it and would make the executor's own tally fail verification, (b) a tally that passes section 6.1 but fails a later section 6.2 check, a signed admission by the sub-executor that also marks the executor's own tally `signed_unauthorized`, or (c) a pending sub-tally later superseded by a final one: listed both, or replaced. This implementation leaves (a) out, includes (b) as evidence against the sub-executor, and replaces (c) in place, so `sub` holds one tally per sub-call, the latest.
- Corpus: not exercised. Section 14.1 says "Scripted outcomes carry no `sub` or `wrt`; tally trees are tested by `verify_tally` vectors", which test verification of a given tree, not which tree an executor builds.
- Verdict: SPEC_SILENT

### 11. Section 7 step 3 against section 4's chain order, and depth

- Implementing: section 7 step 3 in the executor.
- Spec: section 7 step 3, "For each adjacent pair in the chain, section 4 holds. Root: `chain[0].prv` is null (`chain_broken`)." Section 4, "Chain verification, as an operation, is: [...] the root's `prv` is null (`chain_broken`); every adjacent pair passes steps 1 to 5 above, root first; `depth` holds." Section 5, "Checks on a call after section 6.1 apply in this order: chain verification (section 4); [...]".
- Decision: step 3 read on its own checks the pairs before the root's `prv`, and does not mention `depth`, which is a rule over the whole chain rather than a pair. Section 4's operation checks the root first and ends with `depth`. The two readings report different first failures for a chain whose root has a non-null `prv` and whose child widens a bound (`not_narrowed` against `chain_broken`), and differ on whether an executor enforces `depth` at all. This executor runs section 4's operation at step 3, because sections 5 and 14 name it for a call.
- Corpus: nothing pins it for the executor. The three corpus chains with a non-null root `prv` (`wrong order`, `call chain broken`, `revoke chain out of order`) fail with `chain_broken` under either reading, and no scenario carries a `depth` bound. Step 3 should say "the chain passes section 4's chain verification".
- Verdict: SPEC_AMBIGUOUS

### 12. Whether section 8.1's checks run before or after replay

- Implementing: a retry of a `sys/undo` call (section 7 steps 8 and 9, section 8.1).
- Spec: section 7 step 8, "Standing call: [...] that operation's argument checks apply." Section 8.1, "The executor checks, after section 7 steps 1 to 8 (with steps 4 and 7 skipped, as for every standing call), in this order: [...]" and, in the same paragraph, "A retry of the same signed call is answered from the call store (section 7 step 9)."
- Decision: step 8 puts the undo checks before replay at step 9. Section 8.1 places them "after section 7 steps 1 to 8", which can mean the end of step 8 or somewhere after it, and then says without condition that a retry is answered from the call store. They disagree on a retry of a successful undo that arrives at or after the target's `rev.until`, or after the target has left the tally store: checked first, it is refused `not_reversible` and the caller cannot get its tally back except through `sys/tallies`; replayed first, it gets the stored `ok`. This executor checks at step 8, as the forward path does for revocation (scenario 013 step 6: "a replay after the revoke is refused at step 7, before replay at step 9; recovery is sys/tallies").
- Corpus: no scenario retries an undo after `rev.until`; 005 step 4 retries one second later, when both orders give the same answer.
- Verdict: SPEC_AMBIGUOUS

### 13. Which writ a `sys/tallies` caller may ask about

- Implementing: the `sys/tallies` argument check (section 8.2).
- Spec: section 8.2, "`args` is `{"writ": <hash>}`; a `writ` member that is absent, not a string, or not the identity of a writ in `chain` is `tally_mismatch`. `from` is any `iss` on the chain." Section 12, "`sys/tallies` lets a delegator ask any executor it learns of what ran under its writ"; section 7.3, "`sys/tallies` lets it ask any executor it learns of".
- Decision: section 8.2 lets any issuer on the chain name any writ in the chain, including a writ above its own position. An issuer lower on the chain can then list every tally the executor holds under an ancestor writ, which includes work done under sibling delegations it never issued or saw. Section 12's "its writ" suggests the intent is the writ the caller issued, or one below it. This executor follows section 8.2 as written and accepts any writ in the chain.
- Corpus: every `sys/tallies` scenario step names exactly the writ its `from` issued (008, 010, 013, 016, and 018 steps 5 to 7), so the corpus agrees with both readings. The difference is confidentiality, not interoperability, but two executors will answer the same call differently if one restricts it.
- Verdict: SPEC_AMBIGUOUS

### 14. A resolved reversal stayed unknown after a restart

- Implementing: resolving a pending `sys/undo` record after a restart (sections 8.1 and 9).
- Spec: section 9, "A pending call record found after a restart MUST be resolved to a final tally: `ok` or `failed` when the outcome can be determined, otherwise `failed` with `unknown_outcome`." Section 8.1, "Only a reversal that succeeded counts: [...] a reversal that failed consumes nothing and a later `sys/undo` may try again", and "A record of a reversal that began and never reported, found after a restart, means its outcome is unknown".
- Decision: none needed. The first executor marked every begun reversal unknown at restart and never revisited it, so when the application's resolver determined the outcome, a failed reversal still blocked every later undo with `unknown_outcome`, and a successful one was not recorded as the reversal later undos should answer with. Found in review, not by the corpus (the scenarios have no resolver: an operation lost in a crash is always unknown). Fixed so that the resolved outcome of the call that began the reversal updates its state; `test_resolver_decides_an_interrupted_reversal` fails on the old code both ways.
- Verdict: PYTHON_BUG

## Counts

| Verdict | Count |
|---|---|
| PYTHON_BUG | 3 |
| SPEC_AMBIGUOUS | 5 |
| SPEC_SILENT | 5 |
| CORPUS_CONTRADICTS_SPEC | 1 |

SPEC_AMBIGUOUS plus SPEC_SILENT: 10. Each of those entries names at least
one spec sentence that should change, which is the unit `docs/adoption.md`
counts for this phase. The one CORPUS_CONTRADICTS_SPEC entry is a scenario
format detail; no scenario expected executor behavior the spec text rules
out. The three PYTHON_BUG entries are this implementation's own errors
against clear text: two in the pre-existing verifier (one caught by a
corpus vector, one found while sharing its checks with the executor, which
scenario 006 step 7 would have caught), and one in the new executor, caught
in review.
