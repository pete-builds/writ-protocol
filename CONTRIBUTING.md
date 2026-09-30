# Contributing to Writ

Writ is a draft protocol with one author so far. The most useful thing you can do is prove the spec can be read the same way by someone else, or show where it cannot. Three ways, from quickest to most valuable:

1. **Run it and tell us what confused you.** `sh demo/run.sh` (Go 1.25 or newer), or a release from the Releases page. Anything unclear in the output or the README is worth an issue.
2. **Try to break it.** Read `docs/spec/writ-v0.1.md`, starting with section 12, and `docs/design/05-threat-model.md`. A way to widen authority, forge or hide a receipt, replay a call, or make two careful readers disagree is the best issue you can file. Security findings go through `SECURITY.md`, not a public issue.
3. **Build your own from the spec.** Without reading `impl/`, write a verifier, or an executor, in any language, and run it against `conformance/`. Then open a *stranger test* issue with what you built and every vector or scenario where your answer differed. That report is the project's next milestone, and a divergence is a finding about the spec, not a failure of yours.

## The corpus

- `conformance/vectors/`: one JSON object per file with `name`, `op`, `input`, `expect` (`accept` or `reject`), and on a reject the `reason` a verifier must give. Spec section 14 defines the operations.
- `conformance/scenarios/`: multi-step executor behavior, compared byte for byte (section 14.1).

Both are generated, never edited by hand: `go run ./cmd/writ-vectors` and `go run ./cmd/writ-scenarios` from `impl/go`, `python3 tools/gen_vectors.py` from `impl/python`. CI fails if a regeneration changes a byte, so new vectors go at the end.

## Changing the code or the spec

- Run what CI runs before opening a pull request: `gofmt -l .`, `go vet ./...`, and `go test ./...` in `impl/go`; `python -m unittest discover -s tests` in `impl/python`; the conformance runners in both; and `sh demo/run.sh`.
- A fix comes with the test that would have caught it, and a test is only trusted once you have seen it fail with the fix removed.
- A change to what a verifier or executor must do is a spec change first: section text, a vector or scenario, and both implementations, in one pull request. `docs/design/10-decision-record.md` records why each rule is the way it is; read it before changing one.
- The reference implementation has no dependencies outside the Go and Python standard libraries (Python needs `cryptography` for Ed25519). Keep it that way.

Contributions are under the Apache 2.0 license, as the repository is.
