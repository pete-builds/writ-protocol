# Adversarial test map

This maps each attack seed from the threat model (docs/design/05-threat-model.md section 7) to the vector, scenario, or test that shows Writ stopping it, and the reason code a verifier or executor answers with.

Where to find each kind of evidence:

- **Vectors** live in `conformance/vectors/`, named `NNN_<op>_<name>.json`. They cover everything that can be checked without memory.
- **Scenarios** live in `conformance/scenarios/`. They cover executor behavior that needs memory (count, replay, undo, revoke, restart), and both the Go and Python executors run them.
- **Go tests** live in `impl/go`, mostly in `impl/go/exec/`. They cover concurrency, store failures, and the security review's regressions, which a scenario cannot express.

| Seed | Threat | Demonstrated by | Reason code |
|---|---|---|---|
| 1 | a child widens a bound | vectors `child widens max`, `narrows max larger` | `not_narrowed` |
| 2 | a child leaves out an inherited bound | vector `child drops bound` | `not_narrowed` |
| 3 | an unknown bound type | vectors `unknown bound type`, `narrows unknown type` | `unknown_bound` |
| 4 | two parsers read one object differently (canonicalization, duplicate keys) | vectors `sorted keys and whitespace`, `utf16 key order`, `duplicate key`, `duplicate key nested`, `lone high surrogate` | `noncanonical` |
| 5 | a second link signed by someone other than the holder | vector `issuer not parent holder` | `chain_broken` |
| 6 | a call signed by someone other than the party with standing | vectors `from is holder`, `from is stranger`, `from is root not leaf issuer` | `no_standing` |
| 7 | a used-up count retried under a fresh id | `TestExecuteCountReplayAndRoot` (the second call, and an attempt to reset by delegating to itself); scenario 001 | `count_exhausted` |
| 8 | a receipt for a different call | vector `tally for other call` | `tally_mismatch` |
| 9 | a receipt whose output does not match | vector `tally body mismatch` | `tally_mismatch` |
| 10 | a sub-delegation left out | `sub` and `wrt` are mandatory even when empty (vector `tally missing sub`); the contradiction surfaces through `sys/tallies` (`TestExecuteCountReplayAndRoot`, demo step 8) | `malformed` |
| 11 | a root issued by a stranger | `TestExecuteCountReplayAndRoot`, demo step 6; scenario 001 | `root_not_accepted` |
| 12 | expired by the verifier's clock | vectors `root expired`, `child expired only`, `tally acc at exp`, `forward call at leaf exp`, `forward call after root exp`, `forward tally acc at leaf exp`; `TestForwardCallRejectedAfterExpiry` | `expired` |
| 13 | a revoke that bypasses the intermediate; a revoke by someone below the writ, ignored; a key-wide revoke | `TestRevokeCancelsInflightAndRestartRecovers`; `TestRevoke` (a holder cannot revoke from below); `TestKeyWideRevokeStopsForwardCalls`; scenario 011 | `revoked`, `no_standing` |
| 14 | a cancel racing completion | `TestRevokeCancelsInflightAndRestartRecovers`, demo step 7 (final tally `canceled`; a completed call answers with its completed tally); `TestUndoAfterRevokeSucceeds` (the revoker can still `sys/undo` the completed effect) | |
| 15 | a forward grant used for reversal | vector `act prefix sys does not grant standing`; reversal is a standing operation, never matched by `act` | `no_standing` |
| 16 | reversing the same effect twice | `TestExecuteCountReplayAndRoot` (a second undo does not refund), `TestUndoAfterExpiryBeforeRevUntil` (a byte-identical replay and a fresh call id, both safe to repeat), `TestConcurrentUndosReverseOnce`, demo step 5; scenarios 005 and 007 | |
| 17 | the same call delivered twice | `TestExecuteCountReplayAndRoot` (a replay returns the byte-identical tally, and runs once); `TestConcurrentDuplicateExecutesOnce` (identical calls arriving together run once) | |
| 18 | a chain longer than the maximum, checked before any signature | vector `nine links` | `too_large` |
| 19 | algorithm confusion | there is no algorithm member; vectors `did web holder` and `secp256k1 did key` reject any key that is not Ed25519 | `bad_key` |
| 20 | reuse across object types and across protocols | vectors `typ call` (a writ presented as a call), `tally typ writ`; the signing input carries the type prefix (spec 1.4) | `wrong_type` |

## Further adversarial cases, beyond the seeds

| Case | Demonstrated by | Reason code |
|---|---|---|
| escaping a prefix at a segment boundary (`travel/charge` against `travel/chargeback`) | vectors `prefix chargeback`, `op segment escape`, `child escapes act segment` | `not_narrowed`, `forbidden_op` |
| enforcement by a coincidence of names (a bound's key absent from `args`) | vector `missing amount`, demo step 6 | `missing_arg` |
| type confusion in a set (`1` against `"1"`) | vectors `set int vs string`, `set int as string` | `not_narrowed`, `out_of_bounds` |
| delegation to an unwanted key | vector `hld set violated` | `not_narrowed` |
| a chain deeper than its issuer allowed | vector `depth exceeded`; for a writ listed in a tally's `wrt`, vector `depth applies to wrt` | `not_narrowed` |
| fan-out whose sum exceeds the parent | vector `sum of sub exceeds parent max` (detected at audit time, as the spec states) | `out_of_bounds` |
| a sub-tally signed by a throwaway key that is not the named holder | vector `sub tally wrong signer` | `bad_signature` |
| padded base64url | vector `padded signature` | `noncanonical` |
| an oversized object, before the signature check | vector `writ over 4096 bytes` | `too_large` |
| nesting deep enough to exhaust a parser | vectors `nesting over the limit`, `writ nesting over the limit`, `writ nesting before number rules`; `TestNestingLimit`, and the Python test that parses 100,000 levels | `too_large` |
| a request padded past its limit with whitespace | `TestRequestLimits` (HTTP binding) | `too_large` |
| two faults on one object, to tell implementations apart | the vectors from 168 onward, most of which carry two faults each, and the differential fuzzer (`cmd/writ-fuzz`) | the first failure, in the pinned order |
| a crash between acceptance and the tally | `TestRevokeCancelsInflightAndRestartRecovers` (the restart resolves to `unknown_outcome`); scenarios 016 and 017 | `unknown_outcome` |
| a standing call under an expired chain (`sys/undo` before `rev.until`, `sys/tallies`) | vectors `standing undo after leaf exp`, `standing tallies after root exp`, `undo tally acc after exp`; `TestUndoAfterExpiryBeforeRevUntil`, `TestTallyRecoveryAfterExpiry`; scenario 008 (accepted: expiry ends forward authority, not standing) | |
| an undo past `rev.until` | `TestUndoAfterRevUntilFails`; scenario 006 | `not_reversible` |
| an expired or revoked chain used to regain forward authority | `TestForwardCallRejectedAfterExpiry`, `TestUndoAfterRevokeSucceeds` (forward calls refused before and after the undo) | `expired`, `revoked` |
| a standing call that is tampered with, chain-broken, rooted elsewhere, misaddressed, unauthorized, or undefined, after expiry | `TestStandingCallsStillFailClosed`; vector `standing call by holder after exp`; scenario 009 | `bad_signature`, `chain_broken`, `root_not_accepted`, `wrong_executor`, `no_standing`, `forbidden_op`, `tally_mismatch`, `not_reversible` |
| an intermediate issuer listing work under sibling delegations it never issued | `TestTalliesScopedToTheCallersWrit`; scenario 020 | `tally_mismatch` |
| a captured call replayed over a different connection to fetch the stored result, or delivered by a peer bound to another key or to none | scenario 021; `TestPeerAndUnsavedRevoke` (HTTP binding); Python `PeerBindingTest` | `peer_mismatch` |
| a key-wide revoke lost at a restart, silently re-admitting a withdrawn key | scenario 022; `TestKeyWideRevokeWriteFailure` (a revoke that cannot be written is answered as an error, still honored, and written on retry); Python `test_unsaved_key_wide_revoke_is_an_error_and_still_honored` | `revoked` |
| strangers flooding an executor with valid key-wide revokes | `TestRevokesAppendWithoutRewritingTheStore` (each revoke costs one appended line, and the spec asks executors to bound revoke intake per peer) | |
| a write to the store that fails | `TestStoreWriteFailureRunsNothing` (nothing runs unrecorded) | an implementation code |
| fan-out across executors under sibling writs | cannot be prevented at request time (spec 7.3); `sum of sub exceeds parent max` and `sys/tallies` are how it is detected at audit time | `out_of_bounds` |
| a language model's output presented as a writ to sign | `Issue` narrows from a parent it holds and refuses to widen (`TestIssueRefusesWidening`); no API signs a writ object supplied by the caller | |
