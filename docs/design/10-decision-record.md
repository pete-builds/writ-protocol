# Decision record: selecting and trimming Writ

Date: 2026-09-04. Inputs: 04-architectures.md, 05-threat-model.md, 06-kill-round-skeptic.md, 07-distsys-review.md, 08-builder-review.md, 09-security-review.md, and docs/adoption.md.

## Selection

Six candidates were generated on six structural axes. Verdicts after the kill round:

| Candidate | Axis | Verdict | Killed by |
|---|---|---|---|
| Writ | holder-narrowable grant plus signed receipt | SELECTED | survives all reviews with conditions |
| Voucher | receipt only, OAuth RAR for authority | KILLED, echo idea kept | needs an authorization server at every hop; attenuation is audit-time, not request-time |
| Tether | TCP-like session | KILLED | authority lives in a session, not an object; re-implements A2A streaming |
| Docket | transparency-log anchored | KILLED, optional anchor kept | needs a log operator online; one vendor's log sees every chain |
| Behalf | HTTP headers only | KILLED as protocol, kept as an extension binding | the protocol cannot depend on a transport; header limits cap chains |
| Pouch | store-and-forward envelope | KILLED, bounce semantics kept | Writ plus routing machinery the core does not need |

## Decisions that resolve conflicts between reviewers

1. **Roles.** A writ is a task grant from `iss` to `hld`. The party that executes a call is the leaf `hld`. A forward call is signed by the leaf `iss`, the party assigning the work. This is the architect's example made explicit. The Security Architect's holder-binding requirement is met because a writ confers nothing without the holder's key: only the holder can sign a tally or issue a child.

2. **Reversal.** The Skeptic wanted reversal to be a writ; the Security Architect wanted standing by chain membership; the systems engineer wanted no dependence on an executor's stored copy. Adopted: a reversal is a call with `op` `sys/undo`, carrying the original chain verbatim and the tally being reversed inside `args`. Standing: `from` is any `iss` on that chain. The executor verifies its own signature on the tally and needs no lookup. No call ever carries an empty chain, and no forward `act` prefix can match a `sys/` op. The Skeptic's condition 3 is met in spirit: authority is derived from the chain the tally names.

3. **Result bodies.** The Skeptic and the Security Architect both wanted hashes. Adopted: the tally carries `out`, the hash of the result body; the body travels beside the tally in the reply and is never inside a signed object. Sub-tallies embed only signed members.

4. **Fields cut** (Skeptic conditions 5, 9, 10): `nbf`, call `ts`, tally `ts`, `exe`, `in`, `res`, `err.msg`. Fields kept against the Skeptic's cut list: `from` (needed for standing calls), tally `writ` and `op` (the verifier of a sub-tally never holds the call it answers, so the receipt must be self-describing). Field added on the systems engineer's and Security Architect's advice: `acc`, the acceptance time, which is the time at which bounds and expiry are judged.

5. **Count** is consumed at acceptance, per executor, against every writ hash in the chain (Skeptic condition 1, systems engineer rule 3). `max` is per call at request time; aggregate limits across siblings are the issuer's responsibility and are audited from `used` (Skeptic condition 2, systems engineer rule 4). The spec says so in plain language and does not claim `count` survives store loss.

6. **Prefix** compares on `/` separated segments (Skeptic condition 4).

7. **Presence rule.** Every leaf bound key other than the reserved `act`, `hld`, `depth`, and any `count` key MUST appear in `args` (Skeptic condition 7, threat T-series on enforcement by name coincidence).

8. **Delegation bounds** from the Security Architect: reserved keys `hld` (type `set`) and `depth` (type `max`). Zero new comparisons.

9. **Root acceptance** from the Security Architect (T10): the executor holds an acceptance decision for the root `iss` from outside the chain. The protocol defines the check, not the policy.

10. **Domain separation.** Signatures are over the type label, a NUL byte, and the canonical bytes (Security Architect, T31).

11. **Sizes and depth**: chain at most 8, writ 4 KB, call 64 KB, tally 256 KB, checked before any signature (Security Architect T20, T21; the Skeptic proposed 4 links, the larger fixed constant avoids a configurable knob).

12. **Revocation** stays in the core as a fourth object, `revoke`, because the demo and the systems engineer's cancel-race rules need it and it is five members. Honoring is mandatory on receipt; delivery is best effort; safety never depends on it.

13. **Recovery** from orphaned effects: `sys/tallies`, a standing call that returns every tally an executor holds under a writ hash (systems engineer rule 8, Security Architect T09). Executors index tallies by every hash in the chain they ran under.

14. **Pending.** `st: pending` exists for the case where an executor cannot yet say what happened (systems engineer attack a). A pending tally is superseded by a final one for the same call.

15. **Versioning.** Unknown members are ignored; a `crit` array names members a verifier must understand or reject (Security Architect T29, historian test 9).

16. **Name.** Writ, with `tally` for the receipt and `revoke` for cancellation (the Skeptic asked for `recall` to become `revoke`). Packages and domains use `writ-protocol` to avoid the one collision found (infinri/Writ, a coding harness).

17. **Host body.** Bare Ed25519 over JCS is a new envelope, so v0.1 is published independently. A JWS profile is the planned bridge to the IETF; the Skeptic's condition 14 is answered as "new body, on purpose, with the bridge named."

18. **Extensions, not core:** the header form of the HTTP binding, the SCITT anchor, `ttl` and `budget`, the root-writ hash cache, the bounds echo, Agent Card binding (`crd`), WebAuthn approval (`apv`), did:web holders.

## Re-scoring the trimmed design against the historian's ten tests

| Test | Result | Evidence |
|---|---|---|
| 1 minimal core, one week | pass | four objects, 33 mandatory members total, five comparisons; the builder's cut estimate is 16 developer days including CLI, demo, and vectors |
| 2 offline verify | pass | did:key embeds the key; no fetch in any verification step |
| 3 narrow waist | pass | objects are transport-independent; HTTP binding is one POST |
| 4 strict core, one parse | pass | canonical round-trip, duplicate and surrogate rejection, fixed verification order, fixed error vocabulary |
| 5 value at N=2 | pass | issuer signs a bound, executor's runtime enforces it, issuer holds a signed tally |
| 6 state explicit or absent | pass | four named stores with lifetimes (spec section 9) |
| 7 readable wire | pass | JSON, no base64 payloads |
| 8 no central authority | pass | no registry, no authorization server, no log |
| 9 no flag day | pass | `v` signed, `crit`, unknown members ignored |
| 10 failure is a message | pass | every rejection has a code; silence is named `unacknowledged`; `undeliverable` and `unknown_outcome` are tallies |
