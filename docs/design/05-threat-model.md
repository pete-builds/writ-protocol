# 05. Threat model for the delegation chain and receipt object

Status: design constraint, 2026-09-03. Role: Security Architect. This document proposes no design; it states what any candidate must survive. Section 6 is the pass/fail gate, section 4 seeds the spec's Security Considerations, section 7 seeds the conformance suite.

Vocabulary, neutral to any candidate. A **grant** is one link of a delegation chain: a signed statement by an issuer that a named holder key may act within typed **bounds**, under a named parent link, until an expiry. The **root** grant is self-issued by the principal that started the task. An **invocation** is a signed request by a holder to exercise a grant. A **receipt** is a signed statement by an executor that it performed an operation under exactly one grant link, on inputs and outputs of stated hashes, with a **reversal handle** when reversible. A **verifier** is any party checking these objects with public keys and no network call.

Assumptions. Agents may be compromised, malicious, prompt-injected, overprivileged, impersonated, buggy, or offline. No shared authorization server, PKI hierarchy, blockchain, trusted hardware, or central registry. Ed25519 over canonical JSON is available. Transport is TLS-protected HTTP by default and may be anything.

## 1. Assets and security goals

### Assets

1. **Authority.** The operations the human behind A intended to permit, as encoded in the root grant's bounds. Everything downstream is a subset of this or the system has failed.
2. **Attribution.** The true mapping from each performed operation to the key that performed it and the grant link it ran under.
3. **Evidence.** Receipts, used to settle what happened without trusting any hop's narrative.
4. **Reversal handles.** The ability to undo a reversible operation; an unauthorized reversal is itself an attack, so these are authority too.
5. **Task payload.** Inputs and outputs, often personal or commercial data, passing through parties that need only some of it.
6. **Private keys.** Of A, B, and C. Loss of one hands that principal's whole standing authority to the attacker.
7. **Availability.** Verifiers and executors must not be exhaustible by cheap malformed input.

### Security goals

- **G1 No amplification.** Authority never grows along a chain. Every link permits a subset of its parent, decided by mechanical comparison, not by policy or the issuer's opinion.
- **G2 Unforgeable, non-reattributable receipts.** No party can produce a receipt attributed to a key it does not hold, or present another's receipt as its own or as covering a different grant, input, or task.
- **G3 No replay beyond intent.** A grant for task T cannot be exercised for task T2, more times than it permits, after expiry, by another holder, or at another party.
- **G4 True executor set.** A can determine every key that acted under its root grant, or prove by signature that a hop lied about the set.
- **G5 Fail closed on time and revocation.** A grant whose validity cannot be established is invalid. Expired, unknown key, unknown version, unknown critical field, unknown bound type, or uncomparable bound all mean rejected. Revocation is honored when it arrives; when it cannot, expiry bounds the damage.
- **G6 The LLM is never the enforcement point.** Every check here runs in deterministic runtime code on the receiving side of a message. A candidate whose safety argument contains "the model will refuse" fails.
- **G7 Offline verifiability.** Every check above needs only the objects plus cached participant keys; no issuer need be live.
- **G8 Minimal disclosure.** A hop or verifier learns no more of the payload than it must. Receipts commit to data rather than carry it.
- **G9 Bounded cost.** Verification is linear in chain length and object size, both capped; cheap rejections precede expensive ones.
- **G10 Reversal is distinct authority.** Forward and reverse are separate operation classes. A grant to do is never a grant to undo, and vice versa.

## 2. Principals and trust boundaries

**H, the human who authorized A.** Trusts A's runtime to encode intent into bounds and hold A's key; trusts nothing downstream. H's approval, if captured (a WebAuthn assertion, a signed statement), is what turns a key into authority; the protocol must allow binding it into the root grant and must not require it.

**A, the root delegator.** An LLM, a runtime, and a key custodian. A's runtime trusts its own clock, its custodian, and the keys it fetched for B under authenticated discovery. It does not trust B's reports about C, B's claims about time, B's summary of results, or any unsigned byte. It does not trust its own LLM to decide what a grant contains; the runtime signs only bounds that passed a check the LLM cannot bypass.

**B, the middle hop.** Trusts the root key it resolved for A, its own clock and custodian, and the keys it resolved for C. Trusts A's invocation only as far as A's signature and grant prove, C's receipt only as far as C's signature, and never the text of C's results, which may be crafted to steer B's LLM. B's runtime decides whether a proposed child is a subset of what B holds; B's LLM may propose, never issue.

**C, the leaf executor.** Trusts its own clock, custodian, and key cache. Trusts nothing about B's standing; it accepts an invocation only because a chain from a root it is willing to act for, through B's holder key, arrives intact and within bounds, verifiable with A and B offline.

**The LLM inside each agent.** Trusted by nobody, its own runtime included, for any authority decision. It reads tool output, documents, and results, all attacker-writable; its outputs are proposals subject to the same checks as network input.

**The runtime of each agent.** The enforcement point, trusted by its own principal only. Bugs here are in scope: the protocol must make correct enforcement simple and incorrect enforcement loud, rejected by the peer, hence one canonicalization, one algorithm, one verification order.

**The key custodian of each agent.** Trusted by its own runtime. Compromise is bounded, not prevented.

**Transports and the network.** Untrusted for integrity, authenticity, authority, and ordering. TLS supplies confidentiality and is required for no goal except G8.

**Key discovery.** How a name resolves to a key (Agent Card, did:web, did:key). Trusted only as far as resolution is authenticated to the name's domain, and only for the document's stated lifetime.

**The resource R.** The system C acts on (a payments processor, a ticket store). Outside the protocol unless protocol-aware. If R checks chains, bounds are enforced at the last possible point; if not, C's honesty is a residual risk (section 5).

**Verifiers after the fact.** Auditors who see only the objects and trust only the participants' keys.

## 3. Attacker classes

- **NET, external network attacker.** Reads, modifies, delays, reorders, duplicates, and drops any message. Cannot break Ed25519 or TLS. Runs its own agents and publishes its own discovery documents.
- **MAL-C, malicious leaf.** Holds a valid grant and its own key. Signs anything with its key, executes anything R allows, lies in receipts, presents receipts late, and returns crafted result text intended to steer B's LLM.
- **MAL-B, malicious middle.** Everything MAL-C can do, plus the man-in-the-middle position: mints child grants, sees every C receipt before A does, can drop, delay, or substitute receipts, claim C's work, omit C from its report, withhold cancel from C, and call C under its standing vendor credentials outside the chain.
- **KEY-A, compromised root key.** Mints root grants indistinguishable from A's. Cannot alter discovery documents unless the discovery key is also compromised.
- **INJ-B, prompt-injected middle.** B's runtime and key are honest; B's LLM follows attacker text and proposes any child grant, invocation, delegate, cancel, or reversal the runtime will sign.
- **COL-BC, colluding middle and leaf.** MAL-B plus MAL-C sharing keys and state. Fabricates a consistent story between them; cannot forge A's signature.
- **THIEF, stolen grant.** Has read a grant but not the holder's key.
- **REPLAY, replaying attacker.** NET or any hop re-presenting a captured grant, invocation, receipt, cancel, or reversal, at any party, in any task.
- **CLOCK, a peer that lies about time.** False timestamps in receipts, asserted current time in messages, or simply a wrong clock.
- **PHANTOM, a peer that claims work it did not do.** Signs a well-formed receipt for an operation never performed, or performed on different inputs.
- **OMIT, a peer that omits sub-delegations.** Delegated and reports no children, or fewer.
- **DRIFT, a hop that delegates to a party A would not accept**, within nominal bounds.

## 4. Threat catalogue

Steps: S1 discovery of B; S2 A mints root grant and invokes B; S3 B mints child grant and invokes C; S4 C executes at R; S5 C returns result and receipt to B; S6 B returns results and receipts to A; S7 A verifies; S8 A cancels or compensates.

| Id | Threat | Attacker | Step | Impact | Required mitigation | Test |
|---|---|---|---|---|---|---|
| T01 | Crafted child grant widens a bound (max_amount 600 to 900, count 1 to 5, read to write) | MAL-B, INJ-B | S3 | Amplification | Verifier MUST reject any child whose bounds are not a subset of the parent's under the registered per-type comparison, which MUST be total and mechanical with no policy override. | C's max_amount exceeds B's: C and any third party MUST reject identically. |
| T02 | Bound type confusion: child uses a type the parent lacks, or drops a parent bound | MAL-B | S3 | Child evades a restriction | Authority MUST be the conjunction of every bound on every link root to leaf, so a dropped bound still applies. A child MAY add a bound type, MUST NOT remove one. Unknown types and incomparable units MUST be rejected. | Child omits parent's resource_pattern and invokes outside it: reject. Unregistered type: reject. 600 USD vs 500 EUR: reject. |
| T03 | Canonicalization mismatch: NFC vs NFD, duplicate keys, key order, float forms, escaping | NET, MAL-B | any | Verifiers disagree on what was signed | One canonicalization MUST be specified; signatures MUST cover canonical bytes; verifier MUST re-canonicalize and reject anything that does not round-trip byte-identically. Duplicate keys, lone surrogates, and out-of-range numbers MUST be rejected. | Two serializations of one grant: identical verdict. Duplicated max_amount key: MUST reject. |
| T04 | Key substitution: attacker embeds its own key as issuer and self-signs a link | NET, MAL-B | S3, S7 | Chain verifies under an unauthorized key | Verifier MUST NOT trust a key because it appears in the object it signs. Issuer key MUST equal the parent's holder key; the root key MUST come from task context or authenticated discovery, never the object. | Second link signed by a key other than the first link's holder: MUST reject, issuer mismatch. |
| T05 | Audience confusion and grant theft: a grant issued to B is exercised at C by a party without B's key, including after capture on a plaintext transport | THIEF, NET | S3 | Possession of bytes equals authority | Every grant MUST name its holder key; every invocation MUST be signed by that key; any other signer MUST be rejected. No goal except G8 MAY depend on transport. | Invocation signed by a non-holder key: MUST reject, holder mismatch. Exchange captured in plaintext: every reuse MUST be rejected. |
| T06 | Grant replayed across tasks or beyond its count | MAL-B, REPLAY | S3 | Unbounded reuse within expiry | Grant MUST bind to a task id and carry an absolute expiry. Count bounds MUST count distinct invocation ids. Executors MUST keep a replay record keyed by grant hash and invocation id for the grant's validity. | Second invocation under count 1: MUST reject, count exhausted. Invocation naming another task id: MUST reject. |
| T07 | Receipt replayed for a new task | MAL-B, REPLAY | S6 | A believes new work was done | Receipt MUST name grant hash, invocation id, and input hash. Verifier MUST reject a receipt whose invocation id it did not issue for this task. | Task 1 receipt presented in task 2: MUST reject, invocation unknown. |
| T08 | Receipt for a different input | MAL-B, MAL-C | S4, S5 | Wrong action attributed to A's intent | Invocation and receipt MUST both carry the hash of canonical inputs; verifier MUST compare against what it sent. | Receipt input hash differs from A's record: MUST reject, input mismatch. |
| T09 | Receipt omits C: B claims the work itself | OMIT, MAL-B, COL-BC | S6 | A never learns C existed | Every receipt MUST enumerate child grants issued under its link, an explicit empty set included, so omission is a signed false statement. Executor MUST be the signer and holder of the named link. Receipts SHOULD be deliverable to the root by any path. | B declares no children; a C receipt naming B's link appears: B's receipt MUST be flagged as contradicted by its own signature. |
| T10 | Chain truncation: B's grant presented as root | MAL-B | S3, S7 | C acts for a root nobody authorized | Every link MUST carry its parent hash; the root MUST be self-issued and recognizable. Verifier MUST walk to a root key it chose to act for in this task and reject any chain ending elsewhere. | Chain beginning at a link issued and held by B: MUST reject, untrusted root. |
| T11 | Chain splice: a link from chain X grafted under chain Y | MAL-B, NET | S3 | Authority from one task exercised in another | Parent hash MUST cover the entire canonical parent, and issuer-equals-parent-holder MUST hold at every link. | Link whose parent hash matches a link from a different root: MUST reject, parent mismatch. |
| T12 | Clock skew or lying about time | CLOCK | S3, S4 | Expired grant accepted | Expiry MUST be absolute time in signed bytes. Verifier MUST use only its own clock and MUST NOT accept any message field as the current time. Candidates MUST state tolerated skew; it SHOULD be minutes. | Grant expired by verifier clock, invocation asserting an earlier time: MUST reject, expired. |
| T13 | Receipt timestamp outside grant window | CLOCK, PHANTOM | S5 | Post-hoc receipts under a dead grant | Receipt time is a claim. Verifier MUST reject a receipt whose claimed execution time is outside the grant window and SHOULD reject one arriving beyond a stated grace. | Receipt claiming execution after expiry: MUST reject, time outside window. |
| T14 | Revocation never reaches C | MAL-B, NET, offline C | S8 | Work continues after A withdrew authority | Revocation MUST be a signed object valid from any ancestor, verifiable offline, honored by any delivery path. A hop MUST forward it to its children. Delivery is best effort, so candidates MUST NOT rely on it for safety. | A's revocation delivered directly to C: next invocation rejected, revoked. Revocation from a non-ancestor: ignored. |
| T15 | Cancel races completion, or C is unreachable at cancel | any, honest race | S8 | A cannot tell whether the effect happened | Cancel MUST be idempotent with a fixed set of signed outcomes: stopped before effect, completed with reversal handle, completed irreversible, unacknowledged after a stated timeout. Silence MUST NOT mean stopped. | Cancel after commit: completed with reversal handle, identical on repeat. Cancel to unreachable C: A's state MUST be unacknowledged. |
| T16 | Forward grant used to reverse | MAL-B, INJ-B | S8 | Unauthorized refunds or deletions | Reversal MUST be a distinct operation class. A forward grant MUST NOT authorize reversal unless it names it explicitly. Reversal MUST reference the receipt hash it reverses. | Reversal under a forward-only grant: MUST reject, operation class not granted. |
| T17 | Reverse grant used to redo | MAL-B | S8 | Second charge under refund authority | A reversal grant or handle MUST NOT authorize any forward operation and MUST be exercisable only against the named receipt. | Forward invocation under a reversal-only grant: MUST reject. |
| T18 | Reversal replayed: refund twice | REPLAY, MAL-B | S8 | Double compensation | Executor MUST treat a second reversal of the same receipt hash as idempotent, returning the existing reversal receipt. | Two reversals of one receipt: second returns the first's receipt; R shows one reversal. |
| T19 | Duplicate delivery causes double execution, or id collision swallows a legitimate call | NET, honest retry, buggy B | S3, S4 | Two charges, or a lost operation | Invocation id MUST be unique per holder with at least 128 bits of entropy. Executor MUST dedupe on (grant hash, invocation id) for the grant's validity and return the original receipt on a duplicate. | Invocation delivered twice: one operation at R, identical receipts. Same id under two grants: both execute. |
| T20 | DoS by deep chain | NET, MAL-B | S3, S7 | Verifier exhausted | Candidates MUST state a maximum depth; verifiers MUST reject deeper chains before any signature check. Cost MUST be linear in depth. | Chain of depth max+1: MUST reject, depth exceeded, with zero signatures verified. |
| T21 | DoS by huge grant or bound set | NET | any | Parser or memory exhaustion | Candidates MUST state maximum object size and bound count, enforced before parsing completes. | Object one byte over limit: MUST reject before parse. |
| T22 | Replay-record exhaustion by flooding unique ids | NET, MAL-B | S3 | Executor drops replay state | Replay records MUST be bounded by grant expiry. Executors SHOULD rate limit per root key. | Flood under one short grant: store empty after expiry, replayed id still rejected before. |
| T23 | Task payload in receipts: passenger and card data reach every hop and auditor | MAL-B, NET, auditors | S5, S6 | Confidentiality loss beyond need | Receipts MUST commit to inputs and outputs by hash and MUST NOT require plaintext. Low-entropy values SHOULD use salted commitments. | Plaintext where a hash belongs: flagged. Auditor with a dictionary of ticket ids cannot recover the ticket from a salted commitment. |
| T24 | Metadata leakage in discovery or sibling links | NET, any observer | S1, S3 | Relationships and task shapes exposed | Discovery documents MUST carry only identity and keys. A hop MUST need only its ancestor links, never siblings. | C's chain verified with only A and B links: succeeds. Discovery document containing grant material: flagged. |
| T25 | Prompt injection in returned results attempts to mint grants | MAL-C via INJ-B | S5, S3 | B's LLM proposes an amplified grant | No in-band result field MAY alter authority. Issuance MUST pass the same subset check as inbound verification, independent of LLM output; the receiver MUST reject amplification regardless of B's internal state. | Injected B emits a child exceeding its own grant: receiver MUST reject, subset violation. |
| T26 | Injected B delegates within bounds to an attacker agent | INJ-B, DRIFT | S3 | Authority narrowed but handed to the wrong party | Bounds MUST be able to constrain delegation: at minimum no-further-delegation and a permitted-delegate set. Receipts MUST reveal the executor key. | No-delegation bound on B's link plus a child link: reject, delegation forbidden. |
| T27 | Long-lived grant stolen months later | THIEF, MAL-B | S3 | Standing authority outlives intent | Expiry MUST be mandatory; absent expiry MUST be rejected. Verifiers SHOULD enforce a configurable maximum lifetime. | No expiry: reject. One-year expiry at a verifier capped at 24 hours: reject, lifetime exceeded. |
| T28 | Compromised root key, or a rotated key still trusted from cache | KEY-A | S2 | Attacker mints roots | Custody is outside the protocol. Rotation MUST be supported via discovery; documents MUST carry a lifetime; cached keys MUST NOT be used past it. High-impact roots SHOULD be able to embed a human approval assertion. | Root signed by a key removed from A's document after cache lifetime: MUST reject, unknown key. |
| T29 | Version downgrade: v2 object rewritten as v1 without a critical field | NET, MAL-B | any | Protections removed | Version MUST be in signed bytes. Unknown versions and unrecognized critical fields MUST be rejected. A child SHOULD NOT carry a lower version than its parent. | Version altered after signing: signature fails. v1 verifier, v3 object with a critical field: reject, unsupported critical field. |
| T30 | Algorithm agility: alg none, alg swapped, alg chosen by attacker | NET, MAL-B | any | Signature bypass | Algorithm MUST be fixed by version, not by a field. Any algorithm identifier MUST be signed and match the version's single value. No unsigned variant may exist. | alg none or HS256: reject, algorithm not permitted. |
| T31 | Cross-protocol reuse: grant as OAuth JWT assertion, JWT as grant, receipt as grant | MAL-B, NET | S3 | Signature valid in one protocol honored in another | Signed bytes MUST include a protocol and object-type tag, checked first. The object MUST NOT parse as a valid JWT, or MUST carry a typ OAuth verifiers reject. Receipts MUST NOT verify as grants and vice versa. | Grant fed to a JWT library: fails. Receipt where a grant is expected: MUST reject, type mismatch. |
| T32 | Receipt reattribution: B strips C's signature and re-signs as executor | MAL-B | S6 | C's work claimed by B | Executor MUST be the signer and equal the holder key of the named link. | Receipt naming C's link, signed by B: reject, executor mismatch. |
| T33 | Phantom receipt for work never done | PHANTOM, MAL-C | S5 | False completion | Not preventable (section 5). Receipt MUST carry output hash and, where reversible, a handle resolvable at R, so the claim is checkable and the lie non-repudiable. | Handle R cannot resolve: verifier marks unverified, not completed. |
| T34 | Result without receipt | MAL-B, buggy B | S6 | Unsigned data treated as completion | A result without a valid receipt MUST be unverified, never success. Task state MUST distinguish completed-verified from completed-unverified. | Result with no receipt: A's state MUST be unverified. |
| T35 | Colluding B and C fabricate a consistent story within bounds | COL-BC | S3 to S6 | Within-bound misuse hidden | Not preventable; both are within authority. Every statement MUST be signed so the story is non-repudiable; bounds MUST be enforceable at a protocol-aware R. | Any deviation from bounds is still rejected at C and at a protocol-aware R. |
| T36 | Discovery poisoning: B resolves C's key from an attacker document | NET | S3 | Grant issued to the attacker's key | Key resolution MUST be authenticated to the name (TLS to the named domain, or a self-certifying identifier). Holder key MUST be explicit in the grant so a wrong resolution is visible. | Discovery over plain HTTP or a certificate for another name: MUST be rejected as a key source. |
| T37 | Bound comparison ambiguity: glob vs regex, inclusive vs exclusive, mixed units | MAL-B | S3 | Verifiers disagree on subset | Every registered bound type MUST define syntax, comparison, and unit. Incomparable values MUST fail. Candidates MUST ship test vectors. | Parent tickets/1*, child tickets/150: accepted. Child tickets/[1-9]*: rejected if the type is glob. |
| T38 | Grant expires mid-execution | CLOCK, honest | S4 | Ambiguous validity of the effect | Candidates MUST state whether validity is judged at acceptance or at commit; receipts MUST record both times. | Expiry between accept and commit: outcome matches the stated rule and is recorded. |
| T39 | B withholds cancel from C | MAL-B | S8 | C keeps working | Cancel MUST be a signed object from any ancestor, valid by any path. C MUST accept cancel delivered directly by A. | A cancels C directly: C honors it and returns a signed cancel state. |
| T40 | Out-of-band invocation under B's standing vendor credential, no chain | MAL-B | S3 | Chain bypassed | A protocol-aware executor MUST refuse chain-governed operations lacking a chain. A receipt MUST be unproducible without a grant hash, so bypassed work is never presentable as verified. | Invocation with no grant: C rejects. Receipt lacking a grant hash: verifier rejects. |
| T41 | Human approval reused: an approval for task T bound into a root for T2 | KEY-A, compromised A runtime | S2 | Human intent misrepresented | An embedded approval MUST be bound to the root's task id and bound hash; a root whose approval names another MUST be rejected. | Approval challenge naming a different task id: reject, approval mismatch. |

## 5. Non-goals and residual risks

**A malicious executor lying about the physical world within its bounds.** If C may charge $600 once and charges $600 for the wrong flight, no protocol check catches it. Compensation: bounds cap the damage, the receipt is a statement C cannot disown, the reversal handle lets A undo it when R permits, and reputation and contract handle the rest.

**Collusion between the executor and the resource.** If C and R are one vendor and R is not protocol-aware, R does whatever C asks. The protocol reaches only as far as the last verifying party; it MUST make it possible for R to verify and MUST NOT require it.

**Semantics of bounds.** The protocol compares typed values; it does not know what "refundable" means. Divergent interpretation is a registry problem, compensated by test vectors and rejection of unknown types.

**Key custody.** Loss of a private key is loss of that principal. The protocol bounds the damage through expiry, count, bounds, rotation, and optional human-approval binding; it does not prevent the loss.

**Within-bounds prompt injection.** An injected B that delegates to a permitted party, within bounds, for the attacker, is lawful as far as the protocol can see. Compensation: delegation bounds (T26), narrow bounds, short expiry, and the executor set in receipts.

**Omission with no counter-evidence.** If B did the work itself, or used C and C never surfaces, A cannot tell the two apart. What the protocol delivers: B's receipt is a signed statement about its children, so if C's receipt ever appears, B is caught by its own signature.

**Availability of honest parties.** Offline C, dropped messages, and slow networks produce unacknowledged states, not unsafe ones.

**Correctness of the human's bounds.** If H authorized $6,000 by mistake, every hop is within authority.

**Liveness of revocation.** Best effort. Safety rests on expiry. A candidate promising timely revocation without an online authority is overclaiming.

## 6. Security requirements checklist

Pass or fail per line. A candidate failing any MUST is dead; SHOULD failures are weighed.

1. MUST perform every authority check in deterministic runtime code on the receiving side; none may rest on model behavior. (G6, T25)
2. MUST be verifiable from the objects plus cached participant keys, with no call to any issuer. (G7)
3. MUST define authority as the conjunction of every bound on every link from root to leaf. (T02)
4. MUST reject a child whose bounds are not a subset of its parent's under a mechanical, total, registered comparison; no policy override. (T01)
5. MUST reject unknown bound types and incomparable values. (T02, T37)
6. MUST define syntax, comparison, and unit for every registered bound type, with test vectors. (T37)
7. MUST specify one canonicalization, sign canonical bytes, re-canonicalize on verify, and reject objects that do not round-trip byte-identically. (T03)
8. MUST reject duplicate keys, lone surrogates, and out-of-range numbers. (T03)
9. MUST fix the signature algorithm by version, never by a field in the object, and MUST have no unsigned variant. (T30)
10. MUST include a protocol and object-type tag in signed bytes, checked first, so grant, receipt, revocation, and cancel cannot verify as one another or as a JWT. (T31)
11. MUST sign the version and reject unknown versions and unrecognized critical fields. (T29)
12. MUST name the holder key in every grant and require invocations signed by that key. (T05)
13. MUST require each link's issuer key to equal its parent link's holder key. (T04, T11)
14. MUST carry the parent's full canonical hash in each child link. (T10, T11)
15. MUST resolve the root key from task context or authenticated discovery, never the object, and reject chains ending at any other root. (T04, T10)
16. MUST require authenticated key resolution and MUST NOT use a cached key past its document's lifetime. (T28, T36)
17. MUST bind every grant to a task id and reject invocations naming another. (T06)
18. MUST require an absolute expiry in every grant and reject grants without one. (T27)
19. SHOULD let verifiers enforce a configurable maximum grant lifetime. (T27)
20. MUST judge time by the verifier's own clock, state the tolerated skew, and never accept a message field as the current time. (T12)
21. MUST state whether validity is judged at acceptance or commit, and record both times in the receipt. (T38)
22. MUST carry an invocation id unique per holder with 128 bits of entropy, dedupe on (grant hash, invocation id) for the grant's validity, and return the original receipt on a duplicate. (T19)
23. MUST define count-style bounds as counting distinct invocation ids. (T06, T19)
24. MUST bound replay state by grant expiry. (T22)
25. MUST name grant hash, invocation id, input hash, and output hash in every receipt. (T07, T08)
26. MUST require the receipt signer to equal the holder key of the named link. (T32)
27. MUST enumerate in every receipt the child grants issued under its link, an explicit empty set included. (T09)
28. SHOULD make receipts deliverable to the root by any path. (T09)
29. MUST treat a result without a valid receipt as unverified, never completed. (T34)
30. MUST commit to inputs and outputs by hash and never require plaintext; SHOULD support salted commitments for low-entropy values. (T23)
31. MUST reject a receipt whose claimed execution time falls outside the grant window. (T13)
32. MUST define reversal as a distinct operation class; forward grants MUST NOT authorize reversal and reversal grants MUST NOT authorize forward operations. (T16, T17)
33. MUST require a reversal to name the receipt it reverses and make repeated reversal idempotent. (T17, T18)
34. MUST define cancel as idempotent with fixed signed outcome states, including unacknowledged after timeout; silence MUST NOT mean stopped. (T15)
35. MUST define revocation and cancel as signed objects valid from any ancestor, verifiable offline, honored by any delivery path. (T14, T39)
36. MUST require a hop to forward revocation and cancel to its children. (T14)
37. MUST NOT depend on revocation delivery for safety; expiry is the hard bound. (T14)
38. MUST provide delegation bounds: no-further-delegation and a permitted-delegate set at minimum. (T26)
39. MUST define maximum chain depth and object size, enforced before parsing or signature checks, with verification linear in depth. (T20, T21)
40. MUST verify a link from its ancestors alone, never siblings; discovery documents MUST carry no task state. (T24)
41. MUST NOT depend on transport for integrity, authenticity, or authority; SHOULD require confidential transport for payload. (T05, T23)
42. MUST refuse, at a protocol-aware executor, any chain-governed operation lacking a chain, and MUST make a receipt unproducible without a grant hash. (T40)
43. MUST support embedding a human approval assertion in a root grant, bound to its task id and bound hash, rejecting mismatches. (T41)
44. MUST define one verification order (type tag, size and depth, canonical round-trip, version, signature, chain walk, subset per link, expiry, task binding, holder match, replay) so two implementations reject the same object for the same reason. (T03, T29, T30)
45. MUST specify a fixed vocabulary of rejection reasons so tests can assert the reason, not only the outcome. (all)

## 7. Adversarial test seeds

1. T01: Given a chain where C's link permits max_amount 900 and B's permits 600, when C verifies the invocation, the verifier MUST reject with reason subset violation.
2. T02: Given a parent bound resource_pattern tickets/1* and a child that omits it, when an invocation targets tickets/250, the verifier MUST reject with reason inherited bound violated.
3. T02: Given a child link carrying a bound of type x-vendor-limit not in the registry, when any verifier evaluates it, the verifier MUST reject with reason unknown bound type.
4. T03: Given two serializations of one grant differing only in key order and escaping, when both are verified, the verdicts MUST be identical; and given a duplicated key, the verifier MUST reject with reason non-canonical.
5. T04: Given a chain whose second link is signed by a key not equal to the first link's holder, when verified, the verifier MUST reject with reason issuer mismatch.
6. T05: Given a valid grant naming B's holder key, when an invocation under it is signed by any other key, the executor MUST reject with reason holder mismatch.
7. T06: Given a grant with count 1, when a second invocation with a fresh invocation id arrives, the executor MUST reject with reason count exhausted.
8. T07: Given a receipt whose invocation id belongs to a prior task, when A verifies it against the current task, A MUST reject with reason invocation unknown.
9. T08: Given a receipt whose input hash differs from the hash of the inputs A sent, when A verifies, A MUST reject with reason input mismatch.
10. T09: Given a receipt from B declaring no children and a receipt from C naming B's link as parent, when both reach A, A MUST mark B's receipt contradicted under B's own signature.
11. T10: Given a chain whose earliest link is issued and held by B's key, when C verifies against a task rooted at A, C MUST reject with reason untrusted root.
12. T12: Given a grant expired by the verifier's clock and an invocation asserting an earlier current time, when verified, the verifier MUST reject with reason expired.
13. T14: Given a revocation signed by A delivered directly to C, bypassing B, when the next invocation under that link arrives, C MUST reject with reason revoked; and given a revocation signed by a non-ancestor, C MUST ignore it.
14. T15: Given a cancel arriving after C has committed at R, when C responds, the response MUST be the signed state completed with reversal handle, identical on repeat.
15. T16: Given a grant permitting only the forward operation class, when a reversal invocation arrives under it, the executor MUST reject with reason operation class not granted.
16. T18: Given a reversal already executed for receipt hash X, when a second reversal naming X arrives, the executor MUST return the original reversal receipt and R MUST show exactly one reversal.
17. T19: Given one invocation delivered twice by a retrying transport, when both copies are processed, the executor MUST produce exactly one operation at R and return byte-identical receipts.
18. T20: Given a chain one link deeper than the stated maximum, when verified, the verifier MUST reject with reason depth exceeded before any signature check.
19. T30: Given an object whose algorithm identifier is set to none or to any value other than the version's fixed algorithm, when verified, the verifier MUST reject with reason algorithm not permitted.
20. T31: Given a grant presented to an OAuth resource server as a bearer assertion, when parsed, the JWT library MUST reject it; and given a receipt where a grant is expected, the verifier MUST reject with reason type mismatch.
