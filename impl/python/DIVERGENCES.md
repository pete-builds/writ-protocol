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

## Counts

| Verdict | Count |
|---|---|
| PYTHON_BUG | 1 |
| SPEC_AMBIGUOUS | 1 |
| SPEC_SILENT | 2 |
| CORPUS_CONTRADICTS_SPEC | 0 |
