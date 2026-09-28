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

## Counts

| Verdict | Count |
|---|---|
| PYTHON_BUG | 1 |
| SPEC_AMBIGUOUS | 0 |
| SPEC_SILENT | 0 |
| CORPUS_CONTRADICTS_SPEC | 0 |
