# Adversarial test map

Each seed from the threat model (docs/design/05-threat-model.md section 7) mapped to the vector or test that demonstrates it. Vectors live in `conformance/vectors/` and are named `NNN_<op>_<name>.json`; Go tests are in `impl/go`. "Executor" cases need state and live in `impl/go/exec/exec_test.go` rather than in the stateless corpus.

| Seed | Threat | Demonstrated by | Reason code |
|---|---|---|---|
| 1 | child widens a bound | vector `child widens max`, `narrows max larger` | `not_narrowed` |
| 2 | child omits an inherited bound | vector `child drops bound` | `not_narrowed` |
| 3 | unknown bound type | vectors `unknown bound type`, `narrows unknown type` | `unknown_bound` |
| 4 | canonicalization divergence, duplicate key | vectors `sorted keys and whitespace`, `utf16 key order`, `duplicate key`, `duplicate key nested`, `lone high surrogate` | `noncanonical` |
| 5 | second link signed by a non-holder | vector `issuer not parent holder` | `chain_broken` |
| 6 | invocation signed by someone other than the standing party | vectors `from is holder`, `from is stranger`, `from is root not leaf issuer` | `no_standing` |
| 7 | count exhausted by a fresh id | `TestExecuteCountReplayAndRoot` (second call, and self-delegation reset attempt) | `count_exhausted` |
| 8 | receipt for a different call | vector `tally for other call` | `tally_mismatch` |
| 9 | receipt output mismatch | vector `tally body mismatch` | `tally_mismatch` |
| 10 | omitted sub-delegation | `sub` and `wrt` are mandatory even when empty (vector `tally missing sub`); contradiction surfaces via `sys/tallies` (`TestExecuteCountReplayAndRoot`, demo step 8) | `malformed` |
| 11 | stranger root | `TestExecuteCountReplayAndRoot`, demo step 6 | `root_not_accepted` |
| 12 | expired by verifier clock | vectors `root expired`, `child expired only`, `tally acc at exp` | `expired` |
| 13 | revoke bypassing the intermediate; non-ancestor revoke ignored | `TestRevokeCancelsInflightAndRestartRecovers`; `TestRevoke` (holder cannot revoke from below) | `revoked`, `no_standing` |
| 14 | cancel racing completion | `TestRevokeCancelsInflightAndRestartRecovers`, demo step 7 (final tally `canceled`; a completed call answers with its completed tally) | |
| 15 | forward grant used for reversal | vector `act prefix sys does not grant standing`; reversal is a standing op, never matched by `act` | `no_standing` |
| 16 | repeated reversal | `TestExecuteCountReplayAndRoot` (second undo does not refund), demo step 5 | |
| 17 | duplicate delivery | `TestExecuteCountReplayAndRoot` (replay returns byte-identical tally, one execution) | |
| 18 | chain deeper than the maximum, checked before signatures | vector `nine links` | `too_large` |
| 19 | algorithm confusion | there is no algorithm member; vectors `did web holder`, `secp256k1 did key` reject any non-Ed25519 key | `bad_key` |
| 20 | cross-type and cross-protocol reuse | vectors `typ call` (a writ presented as a call), `tally typ writ`; signing input carries the type prefix (spec 1.4) | `wrong_type` |

Additional adversarial cases beyond the seeds:

| Case | Demonstrated by | Reason code |
|---|---|---|
| segment escape in prefix (`travel/charge` vs `travel/chargeback`) | vectors `prefix chargeback`, `op segment escape`, `child escapes act segment` | `not_narrowed`, `forbidden_op` |
| enforcement by name coincidence (bound key absent from args) | vector `missing amount`, demo step 6 | `missing_arg` |
| set element type confusion (`1` vs `"1"`) | vectors `set int vs string`, `set int as string` | `not_narrowed`, `out_of_bounds` |
| delegation to an unwanted key | vector `hld set violated` | `not_narrowed` |
| chain deeper than the issuer allowed | vector `depth exceeded` | `not_narrowed` |
| fan-out whose sum exceeds the parent | vector `sum of sub exceeds parent max` (audit-time detection, as the spec states) | `out_of_bounds` |
| sub-tally signed by a throwaway key that is not the named holder | vector `sub tally wrong signer` | `bad_signature` |
| padded base64url | vector `padded signature` | `malformed` |
| oversized object before signature check | vector `writ over 4096 bytes` | `too_large` |
| crash between accept and tally | `TestRevokeCancelsInflightAndRestartRecovers` (restart resolves to `unknown_outcome`) | `unknown_outcome` |
| language model output presented as a writ to sign | `Issue` narrows from a held parent and refuses widening (`TestIssueRefusesWidening`); there is no API that signs a caller-supplied writ object | |
