# 09. Security review of the six architectures


> **Historical document (2026-09-03).** Security review of the six candidates. `recall` is `revoke` in v0.1; `exe`, `in`, and `ts` were cut from the tally; the Behalf binding of section 3 is not the v0.1 HTTP binding. Section 4's draft Security Considerations were the input to spec section 12, which governs where they differ, including the standing-after-expiry rule that v0.1 adopted after this review.

Status: review, 2026-09-03. Role: Security Architect. Inputs: `05-threat-model.md` (45 requirements, 41 threats) and `04-architectures.md`. Grading is against the checklist in `05-threat-model.md` section 6, by number. KILLED means a MUST fails because of the architecture's shape, not because a sentence is missing.

## 1. Pass/fail matrix

Columns: W Writ, V Voucher, T Tether, D Docket, B Behalf, P Pouch. Notes are two to five words.

| # | Requirement (short) | W | V | T | D | B | P |
|---|---|---|---|---|---|---|---|
| 1 | Runtime, not LLM, enforces | PASS C runtime | PARTIAL AS3 policy decides | PASS | PASS C plus log | PASS | PASS |
| 2 | Offline verifiable, no issuer call | PASS | FAIL AS online both hops | PARTIAL session-bound evidence | PARTIAL register online | PASS | PASS |
| 3 | Authority is conjunction root to leaf | PASS child carries all keys | FAIL audit time only | PARTIAL checks lineage[last] only | PASS | PASS | PASS |
| 4 | Mechanical subset, no policy | PASS five comparisons | FAIL AS policy | PASS | PASS | PASS | PASS |
| 5 | Unknown types rejected | PASS stated | PARTIAL unknown RAR fields | PASS | PASS | PASS via registry | PASS |
| 6 | Syntax, unit, vectors per type | PARTIAL unit not bound, no vectors | PARTIAL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| 7 | One canonicalization, round-trip | PASS JCS, NFC producer | PASS | PASS | PASS CBOR deterministic if profiled | PARTIAL SF re-serialization | PASS |
| 8 | Reject dup keys, surrogates, ranges | PARTIAL parser rules unstated | PARTIAL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| 9 | Algorithm fixed by version | PASS bare Ed25519 | PASS | PASS | PARTIAL COSE alg header | PARTIAL 9421 alg param | PASS |
| 10 | Type tag, no cross-verify or JWT | PASS typ, not JWS | PASS | PASS | PARTIAL COSE content type | PARTIAL req label untagged | PASS |
| 11 | Version signed, critical fields | PARTIAL v signed, no crit rule | PARTIAL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| 12 | Holder-bound grants | PASS hld plus from | PARTIAL DPoP only | PARTIAL session peer is holder | PASS sub | PASS | PASS |
| 13 | Issuer equals parent holder | PASS | FAIL no chain | PARTIAL session-opener rule | PASS | PASS | PASS |
| 14 | Parent hash in child | PASS prv over signed parent | FAIL | PARTIAL verbatim copy, no hash | PASS at reference | FAIL g2 omits grant-1 | PASS |
| 15 | Root from context, reject other roots | PARTIAL root acceptance unstated | FAIL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| 16 | Authenticated key resolution, TTL | PASS did:key self-certifying | PARTIAL card JWK, no TTL | PASS | PASS | PASS | PASS |
| 17 | Task binding | PASS nnc is the task | PARTIAL jti | PASS tid | PASS index | PASS nnc | PASS |
| 18 | Mandatory absolute expiry | PASS | PASS token exp | PASS deadline | PASS | PASS | PASS |
| 19 | Max lifetime (SHOULD) | PARTIAL unstated | PARTIAL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| 20 | Own clock, skew stated | PASS 120 s | PARTIAL AS clocks | PASS | PASS log time | PASS | PASS |
| 21 | Accept vs commit rule | PARTIAL one ts | PARTIAL | PARTIAL | PASS log order | PARTIAL | PARTIAL |
| 22 | Invocation id, dedupe on (grant, id) | PARTIAL keyed id plus from | FAIL none | PARTIAL tid | PASS log dedupe | PARTIAL (iss, nnc) | PARTIAL |
| 23 | Count counts distinct ids | PASS per writ hash | FAIL | PARTIAL | PASS | PASS | PASS |
| 24 | Replay state bounded by expiry | PASS | FAIL | PARTIAL | PASS | PASS | PASS |
| 25 | Receipt names grant, id, in, out | PASS out optional | PARTIAL no call hash | PARTIAL tid only | PASS | PARTIAL grant index only | PASS |
| 26 | Signer equals link holder | PASS step 8 | PARTIAL no link | PARTIAL | PASS | PASS | PASS |
| 27 | Receipt enumerates children | PASS sub plus wrt | PASS sub | PASS sub | PASS sub_entries | PARTIAL absence unsigned | PASS |
| 28 | Receipt to root by any path (SHOULD) | PARTIAL unstated | FAIL | FAIL | PASS log | PARTIAL | PARTIAL |
| 29 | No receipt means unverified | PARTIAL unstated | PARTIAL | PARTIAL | PASS unregistered is nothing | PARTIAL | PARTIAL |
| 30 | Hash commitments, no plaintext | PARTIAL res in clear | PARTIAL | FAIL res only | FAIL res in public log | PASS Content-Digest | PARTIAL |
| 31 | Receipt time inside window | PASS | PARTIAL | PASS | PASS | PASS | PASS |
| 32 | Reversal distinct class | FAIL prefix covers refund | FAIL new AS grant | FAIL | PARTIAL void then delegate | FAIL | FAIL |
| 33 | Reversal names receipt, idempotent | PARTIAL names tally, once unstated | FAIL | PARTIAL | PASS | PASS | PARTIAL |
| 34 | Cancel idempotent, fixed states | PASS recall outcomes | FAIL | PASS | PASS | PARTIAL DELETE, no timeout state | PASS |
| 35 | Revocation from any ancestor, any path | PASS recall | FAIL | PARTIAL in-session only | PASS void | PARTIAL no signed recall to C | PASS |
| 36 | Hop forwards revocation | PARTIAL unstated | FAIL | PARTIAL | PASS log | FAIL | PASS |
| 37 | Expiry, not revocation, is safety | PASS | PARTIAL | PASS | PARTIAL freshness window | PASS | PASS |
| 38 | Delegation bounds | FAIL no such type | FAIL | FAIL | FAIL | FAIL | FAIL |
| 39 | Depth and size caps before parse | FAIL none | PARTIAL | FAIL | PARTIAL | PARTIAL max_chain, 8 KB | PARTIAL |
| 40 | Ancestors only, no task state in discovery | PASS | PASS | PASS | FAIL log exposes chain | PASS | PASS |
| 41 | No transport dependence | PASS | PARTIAL DPoP, TLS | PARTIAL session MAC | PASS | FAIL headers are protocol | PASS |
| 42 | Refuse chain-less ops | PARTIAL refund has empty chain | FAIL | PARTIAL | PASS | PARTIAL | PARTIAL |
| 43 | Human approval binding | FAIL no field | FAIL | FAIL | FAIL | FAIL | FAIL |
| 44 | One verification order | PASS | PASS | PARTIAL | PASS | PARTIAL | PASS |
| 45 | Fixed rejection vocabulary | PARTIAL examples only | FAIL | PARTIAL | PARTIAL | PARTIAL | PARTIAL |

Rows #38, #43, #6, and #8 fail everywhere by omission and are one field or one rule each; they do not discriminate.

### Verdicts

**Writ: SURVIVES.** No structural MUST failure. Three real holes: #32 (the forward `act` prefix `travel/` matches `travel/refund`, so B can refund under writ_1 with no tally, and the empty-chain refund call bypasses the chain), #39 (no depth or size cap), and #30 (result bodies in the clear inside signed receipts). Each is a rule or a field; section 2 gives the text.

**Voucher: KILLED.** Fails #2, #4, #12, #13, #14 by shape: authority is minted by an authorization server the delegator cannot see, no holder can narrow it, and nothing links C's token to A's bound. C cannot refuse an over-limit charge on A's word. A good receipt format; its `det` echo is worth stealing.

**Tether: KILLED.** Fails #12 and #41 by shape: the holder is "the peer who opened this session" rather than a key named in the authority object, and integrity rests on a session MAC. Fails #35 because cancel lives inside a session that may be gone. The portable frames are Writ objects.

**Docket: KILLED.** Fails #40 and #30 by shape: a chain through three vendors is one vendor's public log holding result bodies. Fails #2 for registration and #37 because void freshness needs the log online. Its index ordering for the cancel race is worth an optional anchor.

**Behalf: KILLED as a standalone protocol, RETAINED as Writ's HTTP binding.** Fails #41 by shape (the protocol is the transport) and #14 by construction (`g2` covers only `behalf-grant-2`, so a grant-2 from task X pairs with any grant-1 naming the same holder). As a binding the first is accepted on purpose and the second is one covered component.

**Pouch: SURVIVES, behind Writ.** Same holes as Writ plus a larger mandatory core. Its stamp and bounce semantics answer #34 and #29 and belong in a Writ appendix.

## 2. Writ in detail

Closed as written: T01, T02, T04, T05, T06, T07, T08, T11, T12, T13, T15, T22, T24, T30, T32, T36, T39. Residual by design: T33, T35. Everything else is below with its fix.

**T03, canonical bytes.** JCS and producer-side NFC are specified; parser rules are not. Fix: reject any object whose JCS re-serialization differs from the received bytes, any duplicate member, any lone surrogate, any number outside 0 to 2^53 minus 1, reason `noncanonical`.

**T09, omitted sub-delegation (tension e).** The chain-return rule binds the honest; today A detects omission only if C's tally reaches it by another path, and Writ names none. Fix, two rules. `sub` and `wrt` stay mandatory even when empty, so B's `sub: []` is a signed statement. C MUST retain every tally indexed by chain-root hash and MUST return it to a signed `call` with `op: "sys/tallies"` from the root key, which every hop can identify from `chain[0].iss`. A asks C directly, with no B in the path, what ran under `<h1>`; a tally whose writ is absent from B's `wrt` convicts B by B's own signature. A lookup, not a push, so C needs no path to A and A pays only when it audits.

**T10, chain truncation and root acceptance.** Writ verifies every root as self-issued and stops, so any key can mint a root to itself and call C. Fix: C MUST hold an acceptance decision for the root `iss` from outside the chain (transport identity at hop one, or an accepted-root set fed by Agent Cards or contract). The protocol defines the check, `root_not_accepted`, not the set.

**T14 and T39, recall forwarding.** Closed except forwarding. Add: a hop receiving a recall for a writ it narrowed MUST forward it to every `hld` in its `wrt` and MUST answer with a signed `canceled` tally or the existing completed one.

**T16, T17, T18, T40, reversal (tension a).** Three defects. The forward prefix `travel/` covers `travel/refund`, so writ_1 authorizes refunds directly. The refund call's `chain: []` is a chain-less path. And "chain root iss" is the wrong sole party: B holds `rev` on its own tally too, and A's key is the highest-value key in the system, so routing every refund through it is the opposite of least privilege. The rule:

Who may reverse: any `iss` on the chain the tally names, which for tally_C is B (the leaf issuer) and A (the root).

What they present: a `call` with `op` equal to `tally.rev.op`, `chain` equal to the original chain verbatim (so C re-verifies it and needs no lookup for authority), `args.tally` the tally hash, and `from` equal to one of that chain's `iss` values. No new writ. The tally is what is reversed; the chain proves standing.

What C checks: `from` signs the call; the tally hash is in C's store with `rev` not null and `until` not passed; the presented chain hashes to the leaf writ the tally names; `from` is an `iss` in that chain; `op` equals `rev.op` exactly, never matched against `act` prefixes. The reversal is consumed once per tally hash; a repeat returns the first reversal tally, which has `rev: null`.

Two supporting rules. `rev.op` values live in a reserved namespace (`sys/reverse/...`) that no `act` prefix can match, so forward and reverse can never satisfy each other. `chain: []` is invalid for every `op`; the reversal carries the original chain, which closes T40.

**T19, idempotency.** `call.id` has no entropy rule and the store is keyed on `(id, from)`. Fix: `id` MUST be at least 16 random bytes; dedupe on `(hash(leaf writ), id)`.

**T20, T21, size and depth.** Nothing caps the chain. Fix: 8 links, writ 4 KB, call 64 KB, tally 256 KB, checked on byte and array length before any signature; reason `too_large`.

**T23, result confidentiality (tension b).** My call: hash. `out` becomes mandatory and signed; `res` becomes an unsigned sibling any hop MAY strip before embedding or logging. C signs `out = hash(JCS(res) || nnc_tally)` with a per-tally nonce in the signed bytes, so a low-entropy body (a charge id) cannot be dictionaried; B keeps `res` for its own use; A verifies against `out` and receives `res` only where the application needs it. "Verbatim" in the chain-return rule means signed members verbatim, `res` detachable.

**T25, prompt injection (tension g).** The injected text asks B to issue a writ with an empty `act` prefix. That writ is wider than writ_1; C rejects it under the attenuation rule and A holds proof in `wrt`. Amplification is closed by the protocol at the receiver. What the protocol cannot see is a within-bounds writ to `did:key:zEvil`. That rule lives in B's runtime and the protocol states it as a conformance requirement on issuers: an issuer MUST derive a child writ by applying the attenuation function to a writ it holds and MUST NOT sign a writ object received as data from any source, its own model output included. Checkable in conformance (feed a literal writ, expect refusal), not on the wire. The wire backstop is the delegation bound below.

**T26, delegation drift.** Add two registry keys using existing types. `hld` as a `set`: the child `hld` MUST be in it, `[]` forbids delegation. `depth` as a `max`: links permitted below. Zero new comparison functions.

**T27, long life.** SHOULD: verifiers reject a root whose lifetime exceeds a configured maximum, 24 hours by default.

**T28, key rotation with did:key (tension d).** A did:key cannot rotate; a new key is a new principal. Short `exp` bounds a stolen key's forward damage but not a persistent vendor key. A `kid` adds nothing, since the identifier is the key. v0.1 needs two things. Optional `crd` on a root writ, the URL of the signed Agent Card listing this `iss`: a verifier holding the card MUST reject an `iss` it no longer lists, bounded by the card TTL; a verifier without it verifies the key alone and records that the vendor binding was unchecked. And `recall` with `writ: "*"`, meaning every writ this key issued: an attacker holding the key cannot un-recall, and a verifier that has seen one MUST reject that key thereafter. Short `exp` is enough for safety; the card binding is for liability; the key-wide recall is for the day the key leaks.

**T29, version.** `v` is signed. Add `crit`, an array of member names a verifier MUST understand or reject with `unsupported_critical`; other unknown members are ignored.

**T31, cross-protocol (tension f).** Against JWT confusion, `typ` plus JCS is sufficient: a writ has no base64 header and no JWT library parses it, and a JWT presented as a writ lacks `typ: "writ"`. Against another JCS-signing protocol that reuses the member names and does not check `typ`, it is not. Zero-cost fix: the signing input is `"writ/1" || 0x00 || JCS(object without sig)`, likewise `tally/1`, `call/1`, `recall/1`. A signature under one prefix verifies under no other, here or anywhere.

**T34, result without receipt.** State it: a result whose tally is absent, unverifiable, or names a foreign writ leaves the task `unverified`, never `ok`.

**T37, unit binding.** `amount.max` is unitless if the parent omits `currency.set`. SHOULD: a money `max` carries a companion unit `set`, and the test vectors include a parent without one so implementers see the hazard.

**T38, accept versus commit.** Add `acc`, the acceptance time, and judge bounds and `exp` at `acc`; `acc` inside and `ts` outside the window is valid, the reverse is not.

**T41, approval binding.** Add optional `apv` on a root writ: a WebAuthn assertion whose challenge is `hash(writ without sig and apv)`. Verifiers that require it reject roots without it.

**Tension c, the fabricated sub-tally.** B mints `did:key:zThrow`, issues a valid writ_2 to it, signs a tally as zThrow, embeds both. Every check passes because everything B claims is true: B delegated to zThrow and zThrow signed. A learns exactly the executor set, one key it has never seen. The lie is only in prose, "that was C", and the protocol has no prose. If A cares that the leaf is a particular vendor, A says so in writ_1 with the `hld` bound, which does mean naming the permitted set in advance, and that is correct: authority to delegate to anyone is authority A chose to grant. If A does not care, dynamic delegation works and A learns the key. The residual is a phantom charge (T33); `rev.ref` resolvable at R is the check, and if R is B's own system the residual stands. Minimum rule: an executor identity is a key, never a name; a vendor claim requires the Agent Card listing that key, and A's verifier MUST report "vendor unverified" rather than accept a name from `res`.

## 3. Behalf binding risks

**Header injection.** Applications that build `Behalf-Grant-N` by concatenation will interpolate untrusted values into `act` or `pax.set`; a CRLF or stray `,` splits the field. Rule: producers MUST serialize with an RFC 9651 library; verifiers MUST parse strictly and reject a field that fails to parse or re-serializes to different bytes, since a lenient parser would verify one reading and enforce another.

**Size limits.** Proxies cap a header near 8 KB and the block at 16 to 32 KB; a grant with six bounds is about 400 bytes, so practical depth is six to eight hops. A dropped whole field fails closed because `req` covers it. A gap (`-1` and `-3`, no `-2`) MUST be `chain_broken`: `N` contiguous from 1, `req` covering every grant present. The subtle case is a stripped leaf: C sees only `Behalf-Grant-1` with `hld` B and B's `req` signature, a valid one-hop call under B's wider authority. Not amplification, but it hides the sub-delegation. Rule: `req` MUST cover a `Behalf-Chain` field stating the count, so a stripped leaf breaks `req`.

**Proxy stripping and reordering.** Some CDNs strip unknown fields and most normalize case, whitespace, and list joining, after which `g1` fails, safely but indistinguishably from an attack. Rule: fail closed, and SHOULD fall back to the Writ chain in the body as `application/writ+json` when a preflight to `/.well-known/behalf` shows headers do not survive. The body form is the same objects.

**RFC 9421 coverage.** `g2` covers `("behalf-grant-2")` only, the #14 failure: no cryptographic link to grant 1. Rule: grant N MUST carry a `prv` member with the parent's hash, which makes the header a Writ in another encoding and lets header and body forms hash identically. `keyid` MUST equal the covered `iss` or `exe`; a verifier MUST NOT take the key from `keyid` alone. `req` MUST cover `@method`, `@authority`, `@path`, `content-digest`, every grant field, and `Behalf-Chain`; response labels MUST cover `@status`, `content-digest`, the return field, and the request grants with `;req`, the least-implemented corner of RFC 9421 and the one needing the most test vectors. `created` MUST fall inside the leaf window. `alg` MUST be absent or `ed25519`.

## 4. Security Considerations (draft for the specification)

This section uses RFC 2119 language. It assumes the Writ objects (`writ`, `call`, `tally`, `recall`) and the HTTP binding.

**Enforcement point.** Every check in this section MUST be performed by the receiving implementation before any effect, independent of any language model. An implementation MUST NOT sign a `writ` received as data, including from its own model output; a child `writ` MUST be produced by applying the attenuation function to a `writ` the implementation holds. Conformance tests present a literal `writ` and expect refusal.

**Verification order.** A verifier MUST apply checks in this order and stop at the first failure: object type and version, byte length and chain length against the limits in this section, canonical round-trip, signature under the key inside `iss` or `exe`, chain walk from root to leaf checking `prv` and `iss` equals parent `hld` at each link, attenuation at each link, validity windows against the verifier's own clock, root acceptance, holder match of `from` to leaf `hld`, and replay. Two implementations MUST reject the same object with the same reason from the fixed vocabulary in the reasons registry.

**Canonical bytes.** Signatures are Ed25519 over the byte string formed by the object type label, a NUL byte, and the RFC 8785 serialization of the object without `sig`. A verifier MUST reject any object whose re-serialization differs from the bytes received, any duplicate member name, any lone surrogate, any non-integer number, and any integer outside the range 0 to 2^53 minus 1. Producers MUST emit NFC strings; verifiers MUST compare bytes and MUST NOT normalize.

**Algorithm and type.** The algorithm is fixed by `v`; there is no algorithm member and no unsigned variant. A `writ` MUST NOT be accepted where a `tally`, `call`, or `recall` is expected, and none of these objects is a JWS or JWT. Implementations MUST NOT present a `writ` as an OAuth assertion or accept a JWT as a `writ`.

**Attenuation.** Authority under a chain is the conjunction of every bound on every link. A child MUST carry every bound key of its parent with the same type and a value no wider under that type's comparison, MAY add keys, and MUST NOT remove or retype one. A bound type absent from the registry MUST cause rejection. The `hld` bound restricts which keys may hold a child and an empty set forbids delegation; the `depth` bound limits links below. Verifiers MUST reject a chain longer than 8 links, a `writ` larger than 4 KB, a `call` larger than 64 KB, or a `tally` larger than 256 KB, before verifying any signature.

**Holder binding and replay.** A `writ` is useless without the private key of `hld`. A `call` MUST be signed by the leaf `hld` and MUST carry an `id` of at least 16 random bytes. Executors MUST keep a replay record keyed by leaf writ hash and `id` until the leaf `exp`, MUST return the stored `tally` on a duplicate, and MUST count `count` bounds by distinct `id`. `chain` MUST NOT be empty for any operation.

**Time.** Windows are absolute Unix seconds and are checked strictly against the verifier's clock with at most 120 seconds of future tolerance for `ts`. No field in any message is treated as the current time. Bounds and windows are judged at the accepted time `acc`, which the `tally` MUST record alongside `ts`. Verifiers SHOULD reject a root whose lifetime exceeds a configured maximum, 24 hours by default. Safety MUST NOT depend on the delivery of a `recall`.

**Root acceptance.** A self-issued root proves only that a key signed it. An executor MUST hold an acceptance decision for the root `iss` from outside the chain and MUST reject a chain whose root it does not accept. Where a `writ` carries `crd`, a verifier that has the referenced card MUST reject an `iss` the card no longer lists. A `recall` with `writ: "*"` signed by a key revokes every `writ` that key issued; a verifier that has seen one MUST reject that key thereafter.

**Receipts.** A `tally` MUST name the leaf writ hash, the call hash, the input hash, and the output hash, and MUST be signed by the key in `exe`, which MUST equal the leaf `hld`. `sub` and `wrt` MUST be present even when empty; a sub-tally naming a `writ` absent from `wrt` invalidates the parent. `res` is not covered by the signature and MAY be removed by any hop; verifiers compare against `out`. Executors MUST retain tallies indexed by chain root and MUST return them to a signed request from the root key. A result that arrives without a valid `tally` MUST leave the task `unverified`. A `tally` whose `acc` is outside the leaf window MUST be rejected.

**Reversal.** Reversal operations live in a reserved namespace that no `act` prefix can match. An executor MUST accept a reversal only from a key that is an `iss` on the chain the target `tally` names, presented as a `call` carrying that chain verbatim, `op` equal to `rev.op`, and the tally hash. A reversal MUST be consumed once per tally hash; a repeat MUST return the first reversal `tally`. A forward `writ` MUST NOT authorize a reversal and a reversal MUST NOT authorize a forward operation.

**Cancellation.** A `recall` MUST be honored when signed by any `iss` above the recalled `writ`, by whatever path it arrives. A hop that narrowed the recalled `writ` MUST forward the `recall` to every `hld` in its `wrt`. The answer to a `recall` is always a signed `tally` with `st` in `canceled` or `ok`; silence MUST NOT be read as stopped, and a caller that hears nothing by the leaf `exp` treats the task as `unacknowledged`.

**Confidentiality.** Signed objects commit to inputs and outputs by hash. Implementations MUST NOT require plaintext in a `tally` and SHOULD carry a per-tally nonce in the output commitment when the output has low entropy. Discovery documents MUST NOT contain task state. A verifier needs only the ancestors of the link it checks.

**HTTP binding.** Producers MUST serialize fields with a Structured Fields library; verifiers MUST parse strictly and fail closed on any field that does not round-trip. Grant numbers MUST be contiguous, the request signature MUST cover every grant field and the chain count, each grant MUST carry `prv`, `keyid` MUST equal the covered `iss` or `exe`, and the `alg` parameter MUST be absent or `ed25519`. Implementations MUST support the body form of the same objects for transports that do not preserve headers.

**Residual risks.** The protocol does not detect an executor that lies about the world within its bounds, an executor colluding with a resource that does not verify chains, or a sub-delegation that never surfaces when the sub-delegate stays silent. It makes each of these a signed statement that its author cannot disown, bounds the damage by `exp`, `count`, and typed bounds, and leaves attribution to the Agent Card and liability to contract.
