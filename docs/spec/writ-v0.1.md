# The Writ Protocol, version 0.1

Status: draft for independent implementation. First published 2026-09-04.

Revisions:

- **2026-09-04, the same day.** Fixed the standing-operation expiry and revocation rule (section 7 steps 4 and 7, section 8).
- **2026-09-23.** Added executor scenarios and `verify_revoke` vectors to the conformance corpus (section 14), and pinned the executor details those scenarios compare byte for byte: the pending tally's `err` (section 6), atomic replay and count (section 7 steps 9 and 10), what the tally store holds (section 9), the order of `sys/tallies` results and of a revoke's answer, which undo counts and how reversals of one tally are serialized (section 8), the order of revoke checks and that a revoke leaves standing calls running (section 9.1), a writ with several `count` bounds (section 7 step 10), store write failures (section 9), and a nesting limit (sections 1.1 and 1.6). No member, object, or reason code changed meaning; `pending` is named as the pending tally's `err.code`.
- **2026-09-28.** Pinned every first-failure order a differential fuzzer found open between two implementations: the checks inside one bound (section 3); which binary members section 6.1 step 2 covers; the order of `crit` checks; member order in section 6.1 step 5, including inside `bnd`, `chain`, and `err`; that a tally's `wrt` and `sub` entries are checked at section 6.2 steps 8 and 9, after the tally's own signature, with `depth` applied to `wrt` entries; the order of section 7 steps 1 and 2 for the `verify_call` vector; that every element of a chain is checked to be an object before any writ in it is verified (section 4); and the operand order of the `narrows` vector (section 14). Two rules changed: a pending tally's shape is now checked in full (section 6.1 step 5), and a tally whose `sub` names a writ absent from its `wrt` is `signed_unauthorized`, an admission by its signer, where the 2026-09-23 text also called it `unverifiable`.
- **2026-09-28, second revision.** A second executor, written from this text alone without reading the first, logged the ten places the text left it to guess (`impl/python/DIVERGENCES.md`). This revision answers each one: a refusal's `acc` (section 6); which sub-tallies go into `sub` (section 7.5); that failures at section 7 steps 1 and 2 are unsigned; that step 3 is section 4's chain verification, `depth` included; that a standing operation's own checks run when it is performed, after replay, so their failures are stored outcomes (sections 7, 8.1, 8.2); what a second `sys/undo` gets while a reversal is running (section 8.1); the reversal store and the key and lifetime of a key-wide revoke (section 9); which bytes "identity compared as byte strings" means (sections 8.2 and 9.1); and a held operation's `app` (section 14.1). Two rules changed by decision: `sys/tallies` names a writ `from` issued or one below it (section 8.2), and executors bound revoke intake (section 12).
- **2026-09-29.** A review dated that day found that section 6.2 step 10 summed only the immediate sub-tallies and left out the tally's own `used`, so a complete tree two levels deep could report twice the root's `max` and verify. `used` is now inclusive of the subtree: a tally's `used` covers what its sub-tallies report, and step 10 checks that it does (sections 6 and 6.2). Every accepted vector in the corpus already met the rule; what it newly rejects is a tally whose signer reported less than its own sub-tallies. Also pinned: an executor persists each writ it issues before sending it, and a resolved pending record carries that evidence (sections 7.5 and 9); recording a revoke is atomic with steps 7 to 11 of a forward call (section 7); and the section 2 example says what its numbers bound. Section 13 no longer implies that UCAN has no receipts, and names Tenuo.
- **2026-09-30.** Tied the protocol to workload identity and audit, after review by someone who would have to operate it. A call delivered over an authenticated transport is now checked against a binding of that peer to the call's `from`, before replay (section 7 step 8, section 7.6, new reason `peer_mismatch`), so a captured call is useless from any other connection. A key-wide revoke MUST survive restart, and one an executor cannot persist is answered with an error, not as recorded (sections 9 and 10). Added an audit record kept beside the protocol's stores (section 9.3), and security text on rotating a key and on which keys in a chain are tied to anything outside it (section 12). Executor scenarios gained `peers` and `peer` (section 14.1).
- **2026-09-30, later.** Added Appendix D, a non-normative JWS profile: the signed object as the payload of a compact JWS signed again by the same key. No rule, object, or reason code changed.
- **2026-09-30, review.** A review found a binding that treated a verified client certificate naming no peer as a transport that authenticated no peer, which skips the check of section 7.6, so a captured call replayed over such a connection returned its stored result. Section 7.6 now says that a peer the transport authenticated but cannot name is a peer the executor holds no binding for, and that a binding must not fall back to "no peer" or to another source of identity. What an executor checks is unchanged.
- **2026-09-30, revocation.** A question from a reader: if a writ is revoked after its holder delegated under it, what does a verifier do with the sub-delegate's tally? A revoke of one writ MUST now survive restart, as a key-wide revoke already did, and one an executor cannot persist is answered with an error, not as recorded (sections 9 and 10): an executor that lost a revoke at a restart accepted work under the revoked writ again and signed tallies for it that verified. Added a fifth signed object, the **ack**: an executor that records a revoke signs when it recorded it and exactly which work under the revoked writ it held at that moment, and returns it with its answer (sections 9.1, 9.4, and 10). A tally that reports forward work its signer's own ack does not account for is now `signed_unauthorized` with reason `revoked`, however its `acc` is dated; section 6.2 says that revocation is not otherwise an input to verifying a tally; an executor that forwards a revoke relays the acks it receives, so a delegator learns that its revoke reached executors it never contacted. New reason `ack_mismatch`, new vector operation `check_ack` (section 14), and a revoke step's `expect` now carries the ack and its body (section 14.1). A sender that does not know acks reads the answer's `tallies` exactly as before.
- **2026-10-01.** Two places a stranger test (issue #22) found unclear. Section 1.1 rule 7 now counts nesting from the outermost array or object, and says a scalar does not add a level, which is the reading vector 176 already encodes: 64 levels of containers with a scalar inside, accepted. Section 9.1 no longer says a revoke answers `canceled` for a call not yet accepted, and the `acc` row of section 6 no longer covers that case: since recording a revoke is atomic with steps 7 to 11 of a forward call (section 7), such a call is refused at step 7 and is never left for the revoke to answer, so the text named no `err.code` for a tally no executor could send. What an executor or verifier does is unchanged.
- **2026-10-01, total.** Added a sixth bound type, `total`: a limit on the sum of one argument across every call an executor accepts under a writ, the running total a payment needs and `max` with `count` could not give (section 3). It narrows, and is checked against one call's argument, as `max` is (sections 3 and 7.2); the running sum is consumed at section 7 step 10 beside `count`, against every writ in the chain that carries it, from a new durable total store (section 9), and a call that would take a total past its value is refused with the new reason `total_exhausted`. A tally's `used` reports `total` bounds as well as `max` bounds, and section 6.2 steps 7 and 10 check both. It is per executor, like `count`; section 7.3 says what it does not bound. A verifier that predates this revision rejects a writ carrying `total` as `unknown_bound`, which is the failure section 3 requires of a bound it cannot compare.
- **2026-10-01, later.** Added Appendix E, non-normative: approval of a call above an agent's limits as an ordinary delegation. No rule, object, or reason code changed.

Writ: pass narrowable authority between agents and bring back a signed account of what was done under it.

## Abstract

Writ defines five signed JSON objects and the rules for checking them. A **writ** is a grant of bounded authority from one key to another that the holder can narrow and pass on without contacting the original issuer. A **call** assigns work under a chain of writs. A **tally** is the executor's signed account of what it did under exactly which writ, including the tallies of everyone it delegated to. A **revoke** withdraws a writ. An **ack** is an executor's signed record of when it recorded a revoke and of exactly which work under the revoked writ it held at that moment. Verification needs only the objects and the public keys embedded in them.

Writ is not a transport, a discovery mechanism, a task lifecycle, or a tool schema. Those belong to existing protocols (HTTP, A2A Agent Cards, A2A and MCP tasks, MCP tools). Writ carries what they leave out: an authority object that survives a hop into a foreign trust domain, can be narrowed by its holder under a mechanical subset rule, and is named by the receipt that comes back.

How to read this specification (non-normative). Sections 1 to 4 define the encoding, the writ, its bounds, and how a chain is checked for narrowing. Sections 5 and 6 define the call and the tally, and how each is verified. Sections 7 to 9 say what an executor does with a call, which operations stay open to issuers after a writ expires, and what state the executor keeps and for how long. Section 10 is the HTTP binding, section 11 the reason codes, section 12 the security considerations, section 13 how Writ relates to other protocols, and section 14 what conformance means. Appendix A walks through one complete exchange. The orders of checks in sections 3, 4, 6.1, 6.2, 7, 9.1, 9.4, and 14 are normative: two implementations must reject a bad object for the same reason.

In terms of prior work: a writ is an OAuth Rich Authorization Request value set plus a comparison table, signed by the delegator instead of an authorization server; a tally is a UCAN-style receipt with consumption accounting and an embedded sub-tree. Hash-linked offline attenuation for agents is also the subject of several 2026 Internet-Drafts; section 13 and the prior-art survey place Writ against them.

## 1. Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be interpreted as in RFC 2119 and RFC 8174.

**Object** means a JSON object. **Member** means a name and value pair in an object. **Hash** means the base64url encoding, without padding, of the SHA-256 of a byte string: 43 characters. **Key** means a did:key identifier of an Ed25519 public key.

### 1.1 Encoding rules

1. Every protocol object is UTF-8 JSON (RFC 8259).
2. Numbers MUST be integers in the range negative (2^53 minus 1) to positive (2^53 minus 1), written without fraction or exponent. Any other number is a rejection with reason `noncanonical`. The literal `-0` is accepted and canonicalizes to `0`.
3. Strings MUST be valid UTF-8. A `\u` escape MUST NOT encode an unpaired surrogate. Producers SHOULD emit NFC-normalized strings. Verifiers compare bytes and MUST NOT normalize.
4. An object MUST NOT repeat a member name at any depth.
5. Binary values (signatures, hashes, nonces, identifiers) are base64url (RFC 4648 section 5) without padding. A verifier MUST reject, with reason `noncanonical`, a value that is empty, contains padding or characters outside the base64url alphabet, or is an encoding that does not re-encode to the same string (non-zero trailing bits, or a length congruent to 1 modulo 4), so that every byte string has exactly one encoding. A value that decodes to the wrong number of bytes for its member (32 for a hash, 64 for a signature, fewer than 16 for `nnc` or `id`) is a rejection with reason `malformed`.
6. Times are integer Unix seconds, UTC.
7. Arrays and objects MUST NOT nest more than 64 levels deep, the outermost array or object being level 1; a scalar does not add a level. Deeper input is a rejection with reason `too_large`, found before any other rule of this section is applied, so a verifier can refuse it without building it.

### 1.2 Canonical form

The canonical form of an object is its serialization under RFC 8785 (JSON Canonicalization Scheme) with the integer restriction of rule 2 above: member names sorted by UTF-16 code units, no whitespace, strings escaped per RFC 8785 section 3.2.2.2, integers in shortest decimal form.

A verifier MUST reject an object whose received bytes, after parsing, violate rules 2 to 4 of section 1.1, reason `noncanonical`. A verifier MAY accept non-canonical whitespace and member order in received bytes, because it re-canonicalizes before checking any signature or computing any hash.

### 1.3 Identity

A principal is identified by a did:key for an Ed25519 public key: the string `did:key:z` followed by the base58btc encoding of the bytes `0xed 0x01` and the 32-byte public key. Every such identifier begins with `did:key:z6Mk`. Version 1 supports exactly this one key type. A verifier MUST reject any other identifier with reason `bad_key`.

The identifier is the key. No resolution, registry, or fetch is needed to verify a signature. Binding a key to a vendor, a person, or a domain is outside this protocol (see section 12).

### 1.4 Signatures

Every object has a `sig` member. The signing input is the byte string:

    <typ> "/" <v> 0x00 <canonical form of the object with sig removed>

for example `writ/1` followed by a NUL byte followed by the canonical bytes. The signature is Ed25519 (RFC 8032) over that input, encoded base64url without padding (86 characters). The NUL-separated prefix prevents a signature made for one object type or protocol from verifying as another.

### 1.5 Object identity

The identity of a signed object is the hash of the canonical form of the whole object, `sig` included. Every reference from one object to another (`prv`, `call`, `writ`, `revoke`) is such a hash.

### 1.6 Limits

| Limit | Value |
|---|---|
| chain length | at most 8 writs |
| writ, canonical bytes | at most 4096 |
| call, canonical bytes | at most 65536 |
| tally, canonical bytes | at most 262144 |
| revoke, canonical bytes | at most 65536 |
| ack, canonical bytes | at most 4096 |
| `id` and `nnc` | at least 16 random bytes (22 characters) |
| nesting depth of arrays and objects | at most 64 levels (section 1.1 rule 7) |

A verifier MUST check byte length, nesting depth, and chain length before verifying any signature, reason `too_large`. The deepest legitimate object, a tally tree under an eight-writ chain, nests fewer than 30 levels.

### 1.7 Unknown members and `crit`

A verifier MUST ignore members it does not recognize, except that every object MAY carry `crit`, an array of member names; a verifier that does not understand every name in `crit` MUST reject the object with reason `unsupported_critical`. Members named in `crit` MUST be present.

## 2. The writ

A writ is a grant from `iss` to `hld` of authority to perform operations matching `act` within `bnd`, until `exp`.

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | protocol version, `1` |
| `typ` | string | yes | `"writ"` |
| `iss` | key | yes | the issuer, who signs |
| `hld` | key | yes | the holder: the only principal that may execute under this writ or issue a child of it |
| `bnd` | object | yes | bounds, section 3; MUST contain `act` |
| `prv` | hash or null | yes | identity of the parent writ; null for a root |
| `exp` | integer | yes | expiry, exclusive: the writ is invalid at and after this time |
| `nnc` | string | yes | at least 16 random bytes, base64url; makes every writ unique |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by `iss` |

Example, A grants B the authority to book travel for at most 60000 minor units per call, one call at each executor, refundable fares only, within a date window. Neither number is a total across executors: section 7.3 says what they bound and what a delegator does when it needs a total.

```json
{"v":1,"typ":"writ",
 "iss":"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
 "hld":"did:key:z6MkfrJQSdQ9ZhAhzYuA2n6nLAKmg5LQ2YNZE1U8wCkXm4Ez",
 "bnd":{"act":{"t":"prefix","v":"travel"},
        "amount":{"t":"max","v":60000},
        "currency":{"t":"set","v":["USD"]},
        "uses":{"t":"count","v":1},
        "fare":{"t":"set","v":["refundable"]},
        "date":{"t":"window","v":[20261015,20261019]}},
 "prv":null,"exp":1788403600,"nnc":"Qm3bq8w1s5XK7jZRt0aB2w","sig":"..."}
```

### 2.1 Chains

A chain is an array of writs, root first, in which each writ after the first is a child of the one before it. A chain is valid when every writ verifies (section 6.1) and every adjacent pair satisfies the attenuation rule (section 4).

The authority under a chain is the leaf writ's bounds. Because the attenuation rule requires a child to carry every bound of its parent no wider, the leaf's bounds are at least as tight as every ancestor's.

## 3. Bounds

`bnd` is an object whose members are bound names and whose values are objects `{"t": <type>, "v": <value>}` with no other members. Version 1 defines six types. A verifier MUST reject a bound of any other type, reason `unknown_bound`. A bound a verifier cannot compare is a bound it cannot enforce.

| Type | Value | Child narrows parent when | Argument satisfies when |
|---|---|---|---|
| `max` | integer >= 0 | child <= parent | 0 <= arg <= v |
| `count` | integer >= 0 | child <= parent | not by argument: consumed by the executor, section 7.3 |
| `total` | integer >= 0 | child <= parent | 0 <= arg <= v; the sum of arguments across calls is consumed by the executor, section 7.3 |
| `prefix` | string | parent matches child (section 3.1) | v matches arg (section 3.1) |
| `set` | array of strings or integers, no duplicates | every child element is in parent | arg is an element of v |
| `window` | `[lo, hi]` integers, lo <= hi | parent.lo <= child.lo and child.hi <= parent.hi | lo <= arg <= hi |

A `set` element that is the integer 1 and one that is the string `"1"` are different elements; a set MAY mix strings and integers. Bound rejections are classified as follows: a bound that is not an object, has members other than exactly `t` and `v`, or whose `v` has the wrong JSON type for `t` is `malformed`; a `max`, `count`, or `total` below zero, a `window` with lo above hi, or a `set` with a duplicate element is `noncanonical`; a `t` outside this table is `unknown_bound`. A verifier checks one bound in this order and reports the first failure: it is an object, its members are exactly `t` and `v`, and `t` is a string (`malformed`); `t` is in this table (`unknown_bound`); `v` has the JSON type for `t` (`malformed`); the value rule (`noncanonical`). A `set` is checked element by element in array order, each element's type (`malformed`) before whether it repeats an earlier element (`noncanonical`). A `window` is checked for its shape, an array of two integers (`malformed`), before `lo` is compared with `hi`. The "argument satisfies" column is not defined for `count`, and section 7.2 never applies it. For `total`, section 7.2 applies the column to one call's argument, and section 7 step 10 applies the running sum.

### 3.1 Prefix matching

A prefix value P matches a string S when one of the following holds:

1. S equals P;
2. P ends with `/` and S begins with P;
3. S begins with P followed by `/`.

So `travel` matches `travel` and `travel/charge`; `travel/` matches `travel/charge` but not `travel`; `travel/charge` matches `travel/charge` and `travel/charge/retry` but not `travel/chargeback`. There is no value that matches every string.

### 3.2 Reserved bound names

| Name | Type | Required | Meaning |
|---|---|---|---|
| `act` | `prefix` | yes | operations the holder may perform. A forward call's `op` MUST be matched by the leaf's `act` |
| `hld` | `set` of keys | no | keys that may hold a child of this writ; an empty set forbids further delegation |
| `depth` | `max` | no | maximum number of writs below this one in any chain |

An `act` that is not of type `prefix`, an `hld` that is not a `set` of keys, or a `depth` that is not a `max` is a rejection with reason `malformed` (`bad_key` when an `hld` element is not a valid key). All other names are application bounds and are compared against the call's `args` by name (section 7.2). Operation names under `act` are a convention between the parties; this protocol assigns them no meaning beyond string matching. Names beginning with `sys/` are reserved for this protocol and are never matched by `act` (section 8).

## 4. Attenuation

A writ C is a valid child of a writ P when all of the following hold. A verifier MUST check them in this order and report the first failure.

1. `C.iss` equals `P.hld`. Reason on failure: `chain_broken`.
2. `C.prv` equals the identity of P. Reason: `chain_broken`.
3. `C.exp` <= `P.exp`. Reason: `not_narrowed`.
4. For every member name N of `P.bnd`: `C.bnd` has a member N, of the same type, whose value narrows `P.bnd[N]` under that type's rule in section 3. Reason: `not_narrowed`. C MAY have members P lacks.
5. If `P.bnd` has `hld`, then `C.hld` is an element of `P.bnd.hld.v`. Reason: `not_narrowed`.

The `depth` bound is checked over the whole chain after every adjacent pair has passed: for the writ at zero-based index i in a chain of n writs, if it carries `depth`, then (n minus 1 minus i) <= `depth.v`. Reason: `not_narrowed`.

Chain verification, as an operation, is: the chain is an array (`malformed`) of at most 8 elements (`too_large`, checked before any signature), each an object (`malformed`), and not empty (`malformed`), which are the rules section 6.1 step 5 applies to a call's `chain`; every writ passes section 6.1, in array order; the root's `prv` is null (`chain_broken`); every adjacent pair passes steps 1 to 5 above, root first; `depth` holds. Expiry (section 7 step 4) is a separate check because it needs a clock.

Authority never widens: a child cannot drop, retype, or loosen a bound, cannot outlive its parent, and cannot be issued by anyone but the parent's holder. A holder MAY issue a child to itself; doing so gains nothing, because `count` is consumed against every writ in the chain (section 7.3).

## 5. The call

A call assigns work under a chain.

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `typ` | string | yes | `"call"` |
| `id` | string | yes | at least 16 random bytes, base64url; the idempotency key |
| `chain` | array of writ | yes | one to eight writs, root first |
| `from` | key | yes | the caller, who signs |
| `op` | string | yes | the operation |
| `args` | object | yes | operation inputs |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by `from` |

There are two kinds of call, distinguished by `op`.

**Forward call.** `op` does not begin with `sys/`. `from` MUST equal the leaf writ's `iss`. The executor is the leaf writ's `hld`. `op` MUST be matched by the leaf's `act`. `args` MUST satisfy the leaf's bounds (section 7.2).

**Standing call.** `op` begins with `sys/`. `from` MUST equal the `iss` of some writ in `chain`. The executor is the leaf writ's `hld`. Bounds are not applied. Expiry and revocation of the chain are not applied either (section 7 steps 4 and 7): the signed chain is historical proof that `from` had standing, and what a standing call may still do after `exp` is bounded by the operation itself (section 8). The defined standing operations are in section 8; their argument checks need the executor's own key, clock, and stores, so a verifier that is not the executor checks only standing.

A chain MUST NOT be empty for any call (`malformed`). Checks on a call after section 6.1 apply in this order: chain verification (section 4); for a forward call, expiry of every writ, then `no_standing`, `forbidden_op`, `missing_arg`, `out_of_bounds`; for a standing call, `no_standing`, then `forbidden_op` if the `sys/` operation is not one defined in section 8. Expiry is not checked for a standing call.

Example, B assigns C the payment step under a child writ narrowed to `travel/charge`:

```json
{"v":1,"typ":"call","id":"b7f1c0a3Ln2k9QpXs4vYzw",
 "chain":[{"...writ_1..."},{"...writ_2, iss B, hld C, prv hash(writ_1)..."}],
 "from":"did:key:z6MkfrJQSdQ9ZhAhzYuA2n6nLAKmg5LQ2YNZE1U8wCkXm4Ez",
 "op":"travel/charge",
 "args":{"amount":58900,"currency":"USD","fare":"refundable","date":20261015,"pnr":"K7Q2ZD"},
 "sig":"..."}
```

## 6. The tally

A tally is the executor's signed account of one call.

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `typ` | string | yes | `"tally"` |
| `call` | hash | yes | identity of the call answered |
| `writ` | hash | yes | identity of the leaf writ of that call's chain |
| `op` | string | yes | the call's `op` |
| `acc` | integer | yes | the time the executor accepted the call; for a forward call, bounds and expiry are judged at this time. A tally that refuses a call at section 7 steps 3 to 10 has the time the executor received the call |
| `st` | string | yes | `ok`, `failed`, `canceled`, or `pending` |
| `err` | object or null | yes | null when `st` is `ok`; otherwise `{"code": <reason>}` with optional `ref` (a hash) |
| `out` | hash or null | yes | hash of the canonical form of the result body, or null when there is none |
| `used` | object | yes | for each `max` or `total` bound name in the leaf writ that the operation consumed, the integer consumed, including what was consumed under the writs this executor issued for it, so never less than the sum over the tallies in `sub` (see below); absent names mean zero |
| `rev` | object or null | yes | `{"until": <time>}` when the effect can be reversed by `sys/undo` until that time; else null |
| `sub` | array of tally | yes | every tally this executor received from calls it made under child writs, signed members only; empty array if none |
| `wrt` | array of writ | yes | every writ this executor issued under the leaf writ; empty array if none |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by the leaf writ's `hld` |

The result body travels beside the tally, never inside it (section 10). `out` commits to it.

`sub` and `wrt` are REQUIRED even when empty, so that "I delegated nothing" is a signed statement. Every tally in `sub` MUST name in its `writ` member a writ present in `wrt`; a verifier MUST reject a tally violating this, reason `sub_unmatched` (section 6.2 step 9).

`used` is inclusive of the subtree. A tally's `used[N]` is what the operation consumed of N in total: the executor's own effects plus everything its sub-tallies report. It is never less than the sum of `S.used[N]` over the tallies S in `sub` (section 6.2 step 10), and the executor's own additional consumption is the difference. One effect is therefore counted once at each level and never added across levels: when C charges 58900 for B's booking, C's tally reports 58900 and so does B's, not 117800. Every entry in `sub` counts as listed, so an executor that lists a tally twice covers it twice. A retried sub-call answered from the sub-executor's call store returns the same tally, which is listed once (section 7.5); two sub-calls with different `id` are two effects and both count. A reversal does not reduce `used`: `used` records what was consumed under forward authority, and `sys/undo` is a separate standing operation whose effect a verifier cannot see settle. Sums are per bound name. The protocol adds integers under one name and assigns them no unit; the application fixes the unit by convention, for example minor units of the currency named in a `currency` bound.

A tally with `st` `pending` is not final: the executor has accepted the call and cannot yet report the outcome. A later tally with the same `call` from the same executor supersedes it. A pending tally has `err` `{"code":"pending"}`, `used` `{}`, `rev` null, `out` null, `sub` `[]`, `wrt` `[]`, and the `acc` at which the call was accepted.

Example, C's tally for the call above:

```json
{"v":1,"typ":"tally","call":"<hash of call>","writ":"<hash of writ_2>",
 "op":"travel/charge","acc":1788400415,"st":"ok","err":null,
 "out":"<hash of {\"charge\":\"ch_8813\"}>","used":{"amount":58900},
 "rev":{"until":1788486400},"sub":[],"wrt":[],"sig":"..."}
```

B's tally for A's call embeds C's tally in `sub` and writ_2 in `wrt`.

### 6.1 Verifying a single signed object

For a writ, call, tally, revoke, or ack, in this order:

1. Byte length within section 1.6: the received bytes before parsing and the canonical bytes after; and nesting depth within section 1.1 rule 7. Reason `too_large`.
2. Parse; section 1.1 rules 2 to 4 anywhere in the object, then rule 5 for the object's own binary members whose value is a string: `sig` of every type; a writ's `prv` and `nnc`; a call's `id`; a tally's `call`, `writ`, and `out`, and the `ref` member of its `err` when `err` is an object; a revoke's `writ` unless it is `"*"`; an ack's `revoke` and `out`. Reason `noncanonical`. A binary member that is not a string is left to step 5, and a writ or tally nested in `chain`, `sub`, or `wrt` meets rule 5 when it passes this section itself.
3. `v` is the integer 1; anything else, including a missing `v`, is `unsupported_version`. `typ` is the expected type; anything else, including a missing `typ`, is `wrong_type`.
4. `crit`, section 1.7: first, `crit` is an array of strings (`malformed`); then each name in array order is one the verifier understands (`unsupported_critical`) and is present in the object (`malformed`).
5. The remaining members, in the order of the object's member table (sections 2, 5, 6, 9.1, and 9.4). Each member is checked completely before the next: present, of the required type, a valid key where the table says key (`bad_key`), the decoded length of a binary member, and the member's own rules below. Reason `malformed` unless stated otherwise.
    - A writ's `bnd`: an object; `act` is present; every bound, in canonical member-name order, passes section 3; then `act` is a `prefix`, `hld` if present is a `set` whose elements, in array order, are strings and valid keys (`bad_key`), and `depth` if present is a `max` (section 3.2).
    - A call's or revoke's `chain`: an array; at most 8 elements (`too_large`); every element an object. A call's chain is not empty. A revoke's chain is empty exactly when its `writ` is `"*"`. The writs themselves are verified afterwards (section 7 step 2, section 9.1 step 2).
    - A tally's `err`: null when `st` is `ok`; otherwise an object whose `code` is a string and whose `ref`, if present, is a hash. `used`: an object whose members are integers of zero or more. `rev`: null, or an object whose `until` is an integer.
    - A tally's `sub` and `wrt`: arrays of objects. Their elements are checked at section 6.2 steps 8 and 9, after the tally's own signature.
    - After a tally's `wrt`: when `st` is `pending`, `err.code` is `pending`, `used` is empty, `rev` and `out` are null, and `sub` and `wrt` are empty (section 6).
6. Signature verifies under the signer's key (writ: `iss`; call: `from`; tally: `hld` of the writ named; revoke: `iss`; ack: `iss`). Reason `bad_signature`.

A tally names its writ by hash, so a tally can only be verified by a party holding that writ (section 6.2). A refusal with reason `wrong_executor` is signed by the party that received the call, which is not the leaf holder; it is evidence of the refusal but does not verify under section 6.2.

### 6.2 Verifying a tally tree

A verifier V that made a call K under a chain whose leaf writ is W, and received a tally T with an optional result body R, checks in this order:

1. T passes section 6.1 with signer `W.hld`. There, `T.sub` and `T.wrt` are only checked to be arrays of objects; their elements are checked at steps 8 and 9.
2. `T.call` equals the identity of K. Reason `tally_mismatch`.
3. `T.writ` equals the identity of W. Reason `tally_mismatch`.
4. `T.op` equals `K.op`. Reason `tally_mismatch`.
5. If `T.op` does not begin with `sys/`: `T.acc` < `W.exp`. Reason `expired`. A tally for a standing operation is not bound to `W.exp`, because the operation was authorized after it (section 7 step 4); its time bound is operation-specific (section 8), and a verifier that holds the target of a `sys/undo` MAY additionally check the undo tally's `acc` against that target's `rev.until`.
6. If R is present, `T.out` is not null and equals the hash of R's canonical form. Reason `tally_mismatch`. A non-null `out` with no R is accepted; the verifier simply has no body to check.
7. For each `max` or `total` bound N in `W.bnd`: `T.used[N]` (zero if absent) <= `W.bnd[N].v`. Reason `out_of_bounds`.
8. Every writ X in `T.wrt`, in array order: X passes section 6.1; X is a valid child of W under section 4 steps 1 to 5; and section 4's `depth` rule holds over the chain to W followed by X. The chain to W is `K.chain`; at step 9, the chain to a sub-tally's writ X is the chain to its parent's writ followed by X. Each writ is checked completely before the next. Reason as reported.
9. Every tally S in `T.sub`, in array order: S is an object whose `writ` member names a writ X in `T.wrt` (`sub_unmatched` otherwise, checked before anything else about S); S passes section 6.1 with signer `X.hld`; then steps 3, 5, 7, 8, 9, and 10 apply to S with X in place of W and are completed for S's whole subtree before the next element of `T.sub` is examined.
10. After every element of `T.sub`: for each `max` or `total` bound N in `W.bnd`, the sum of `S.used[N]` over the tallies in `T.sub` <= `T.used[N]` (zero if absent). Reason `out_of_bounds`. Because step 7 applies to every tally in the tree and each tally's `used` covers its sub-tallies', everything reported anywhere below W is bounded by `W.bnd[N].v`, however deep the tree. This is the executors' own accounting and it is evidence, not enforcement (section 7.3).

Names in `used` that are not `max` or `total` bounds of the writ are ignored. This procedure does not compare `S.op` against `X.act`; that check was the sub-executor's job at request time (section 7), and a sub-executor that signed a tally for an operation outside its writ has produced a signed admission.

A verifier cannot check `S.call` for a sub-tally because it does not hold the call B made; the sub-tally binds C to a call that B can produce in a dispute.

The result of verification for each tally is one of `valid`, `signed_unauthorized` (section 6.1 passed for T but a later step failed, anywhere in the tree, including a `sub_unmatched` in T itself: an admission by a signer), or `unverifiable` (T itself fails section 6.1). A verifier MUST NOT treat a result body whose tally is absent or `unverifiable` as a completed result; the task is `unverified`.

Revocation is not an input to this procedure. A revoke takes effect at each executor when that executor records it (section 9.1) and carries no time, and a tally does not say whether its call was accepted before or after that moment. A tally that passes this procedure is therefore `valid` whether or not a writ in its chain has since been revoked: it proves the work was accepted under a chain its signer then honored, which is what a revoker needs in order to account for the work and to reverse it (section 8). A verifier that holds an executor's ack of a revoke checks that executor's tallies against it (section 9.4); a tally reporting forward work the ack does not account for is `signed_unauthorized`, with reason `revoked`.

## 7. Executing a call

An executor E receiving a call K over a transport binding (section 10) proceeds in this order, stopping at the first failure. A failure at step 1 or 2 MUST be answered with an unsigned error, because until the call's signature has verified no signed statement can bind the executor to it; every later failure MUST be answered with a signed tally with `st` `failed` and the reason in `err.code`, so that a refusal is evidence.

1. K passes section 6.1 steps 1 to 5, which include the chain's length, 1 to 8, and that each element is an object.
2. Every writ in `K.chain` passes section 6.1, in array order. Then `K.sig` verifies under `K.from`.
3. The rest of section 4's chain verification, in its order: the root's `prv` is null (`chain_broken`), every adjacent pair passes section 4 steps 1 to 5, root first, and `depth` holds over the chain.
4. Forward call only: for every writ in the chain, `now` < `exp`, by E's own clock (`expired`). No member of any message is used as the current time. A standing call skips this step; see the note after step 12.
5. E accepts the root issuer `chain[0].iss` (section 7.1). Reason `root_not_accepted`.
6. E is the leaf `hld`. Reason `wrong_executor`.
7. Forward call only: no writ in the chain is revoked in E's store, by identity or by a key-wide revoke of its issuer (section 9). Reason `revoked`. A standing call skips this step.
8. Both kinds: when the transport authenticated the peer that delivered K (section 10), E holds a binding of that peer to `K.from` (section 7.6) (`peer_mismatch`). Then, forward call: `K.from` equals the leaf `iss` (`no_standing`); `K.op` does not begin with `sys/` and is matched by the leaf `act` (`forbidden_op`); section 7.2 holds. Standing call: `K.from` is the `iss` of some writ in the chain (`no_standing`); `K.op` is an operation defined in section 8 (`forbidden_op`). The operation's own checks (sections 8.1 and 8.2) are part of performing it at step 11, after replay: a failure among them is the operation's `failed` outcome, signed, stored, and answered to a retry like any other.
9. Replay: if E's call store has an entry for (identity of leaf writ, `K.id`), E does not execute. An entry holding a final tally is answered with that tally, byte for byte, and the result body stored with it. An entry still pending is answered with a pending tally (section 6) carrying the entry's `acc`. Otherwise E records the entry with state pending.
10. `count` and `total`, forward call only. First, for every writ in the chain that carries a `count` bound, E's count store entry for that writ's identity is below the value of every `count` bound that writ carries, so a writ with several is limited by the smallest (`count_exhausted`). Then, for every writ in the chain and every `total` bound N it carries, E's total store entry for that writ's identity and N, plus `K.args[N]`, is at most the bound's value (`total_exhausted`). Only when every check passes does E increment each such count entry once, add `K.args[N]` to each such total entry, and record step 9's pending entry. Rejection at this step consumes nothing and leaves no entry in the call store. `K.args[N]` is present and within the leaf's value, because section 4 step 4 puts every `total` bound of the chain on the leaf and step 8 has checked the leaf's bounds.
11. E records `acc` = now, persists the pending record, and performs the operation.
12. E signs and persists the tally, then returns it with the result body.

Steps 4 and 7 are what end forward authority: at `exp`, and on revocation, no forward call is accepted anywhere, and nothing in this section reopens that. A standing call is exempt from both because it does not exercise the authority the chain grants; it exercises the standing the chain proves, which is a fact about the past. The chain still has to be structurally valid, signed, attenuated, rooted at an accepted issuer, and addressed to this executor (steps 1 to 3, 5, 6), `from` still has to be an issuer on it and bound to the peer that delivered the call, and the operation's own checks (section 8) still bound what it may do. The alternative, checking expiry for every call, made `sys/undo` impossible after the leaf expired even when `rev.until` was later, made `sys/tallies` useless for recovering the tally of a call whose writ has since expired, and let a revoke that raced a completion lock the revoker out of reversing the completed effect.

Steps 9 and 10 are one atomic operation with respect to other calls: two calls with the same (leaf writ identity, `id`) MUST NOT both pass step 9, even when they arrive at the same instant, two calls whose chains share a writ with a `count` bound MUST NOT both consume its last use, and two calls whose chains share a writ with a `total` bound MUST NOT together take it past its value. A refusal signed at steps 3 to 10 is returned and not recorded in any store (section 9).

Steps 7 to 11 of a forward call are likewise atomic with respect to recording a revoke (section 9.1). Either the revoke is recorded first and the call is refused at step 7, or the call is accepted first and is among the calls the revoke answers for and tells to stop. No forward call may pass step 7 before a revoke is recorded, miss that revoke's answer, and run.

### 7.1 Root acceptance

A self-issued root writ proves only that a key signed it. E MUST hold, from outside the chain, a decision that it will act under writs rooted at `chain[0].iss`: a configured list, a transport-authenticated identity, an Agent Card binding, or a contract. This protocol defines the check and its reason code, not the policy.

### 7.2 Applying bounds to arguments

Let the application bounds be every member N of the leaf's `bnd` other than `act`, `hld`, `depth`, and any bound of type `count`, taken in canonical member-name order. Two passes:

1. For every application bound N, `K.args` MUST have a member N. Reason `missing_arg`.
2. Then, for every application bound N, `K.args[N]` MUST satisfy the bound under section 3. Reason `out_of_bounds`.

Presence is checked for all bounds before satisfaction is checked for any, so a missing argument is always reported before an out-of-range one.

Members of `args` with no corresponding bound are unconstrained. A `total` bound is an application bound: here its argument is checked against its value one call at a time, and the running sum at section 7 step 10.

### 7.3 What `count`, `total`, and `max` mean

`count` N on a writ means: each executor performs at most N operations under that writ or any writ below it, for as long as the executor's count store persists. It is consumed at acceptance, against every writ in the chain, so a holder cannot reset it by delegating to itself.

A `total` bound named N with value v on a writ means: at each executor, the arguments named N of all the operations it accepts under that writ or any writ below it sum to at most v, for as long as the executor's total store persists. Like `count`, it is consumed at acceptance against every writ in the chain that carries it, so a holder cannot reset it by delegating to itself, and a child's smaller `total` is a share that still draws on every ancestor's. What is consumed is the argument, at acceptance, not what the operation later reports in `used`: an operation that fails, consumes less than its argument, or is reversed by `sys/undo` does not give any of it back. The tally's `used` reports what the operation consumed, as it does for a `max` bound, and may be less than the argument the total store took. A total therefore never overspends and may underspend; a delegator that wants the remainder back issues a new writ.

`max` is checked per call against the leaf writ, and `count` and `total` are consumed per executor. None of them is a global limit. A holder that has been given `count` 1 can issue two children to two different executors and each executor, seeing only its own store, will accept one call; the same holds for `max` and for `total`. The protocol does not enforce a sum across sibling writs or sibling executors at request time, and cannot without coordination between executors, which it does not define. A delegator that needs a total across several delegations issues one writ per delegation with the total split between them, or names one executor in `hld`. Cross-executor fan-out is detected after the fact, and only if evidence surfaces: a verifier audits totals from `used` in the tally tree, where every tally's `used` must cover its sub-tallies' (section 6.2 step 10), so consumption over a bound anywhere in a complete tree surfaces as `out_of_bounds` at the writ it exceeds; and `sys/tallies` lets it ask any executor it learns of. An honest holder's tally lists every child it issued in `wrt`; a dishonest one's omission is a signed false statement, but the verifier cannot find it without a second source.

Nothing in this protocol is exactly-once. An executor executes at most once per (leaf writ identity, `id`) while its call store persists, and at most `count` times per writ while its count store persists. A caller retries the identical signed bytes until it holds a final tally or the leaf expires. When an executor cannot determine whether an effect occurred, it says so with `st` `pending` or `err.code` `unknown_outcome`; store loss is never proof that nothing happened.

### 7.4 Expiry during execution

E MUST NOT accept a forward call at or after the leaf `exp`. E MAY complete an operation it accepted before `exp`. A verifier judges `acc`, not the time the tally was signed. Standing calls are accepted after `exp` (section 7 step 4) and are bounded by section 8 instead.

### 7.5 Delegating onward

An executor that delegates part of its work issues a child writ (section 4) and makes a forward call under the extended chain. It MUST construct the child by narrowing a writ it holds; it MUST NOT sign a writ object received as data from any source, including the output of a language model. It MUST persist each writ it issues before sending it to anyone, and each sub-tally it receives before acting on the sub-tally's contents, so that a crash cannot lose evidence of work done below it. It MUST include every sub-tally in `sub` and every issued writ in `wrt`, whatever its own `st`, MUST report a `used` that covers its sub-tallies' (section 6), and MUST return a tally even when a sub-call never answers (section 9.2). A sub-tally is one that passes section 6.1 under the child writ's holder; an object that does not proves nothing and is left out. One that passes and then fails a later check of section 6.2 is included, as the sub-executor's signed admission. A pending sub-tally superseded by a final one (section 6) is replaced by it, so `sub` holds one tally per sub-call.

### 7.6 Peer binding

A call proves which key signed it, not which party delivered it. Transport authentication (section 10) proves which party is connected, not which keys it speaks for. When the transport authenticated the peer, E MUST hold, from outside the call, a decision that the peer speaks for `K.from`. The sources are those of section 7.1: a credential the transport verified that names the did:key (an X.509 or JWT SVID or a client certificate carrying it as a URI subject alternative name, or an OAuth token whose `cnf` or subject is the did:key), a configured map from transport identities to keys, or an Agent Card E has verified. A peer MAY speak for several keys, as a gateway relaying for its own agents does; which keys is E's decision. A peer E holds no binding for fails exactly as one bound to other keys does: the check fails closed. So does a peer the transport authenticated but cannot name, such as a verified client certificate that carries no identity E recognizes, or two: it is a peer E holds no binding for. A binding MUST NOT present such a connection to E as one that authenticated no peer, and MUST NOT take the missing identity from any other source, such as a header, because either would skip this check.

This is where a workload identity system (SPIFFE, WIMSE, an enterprise directory) meets Writ. The directory decides which workloads exist and what they are called, the binding ties that name to the key that signs calls, and the chain decides what that key may do. None of the three replaces another. This protocol defines the check and its reason code, not the directory.

The check runs before replay (section 7 step 9) on purpose. Without it, anyone who captured a call's bytes could present them over a different connection and receive the stored tally and result body. With it, a captured call is useful only to a peer that already speaks for its signer.

When the transport authenticated no peer, as on a plain local connection, the check is skipped, and the audit record (section 9.3) SHOULD say so. A revoke is not subject to it: any key may revoke its own writs, a revoke carries its own signature, and executors forward revokes they did not sign (section 9.1).

## 8. Standing operations

Standing operations are authorized by position in the chain, not by `act`. A forward `act` prefix never matches them, and they never satisfy a forward `act`.

A standing call is accepted after every writ in its chain has expired and after any of them has been revoked (section 7 steps 4 and 7). The chain is evidence that `from` was an issuer above the executor at the time the work was assigned; expiry and revocation end the holder's authority to do new work, not the issuer's standing to ask about or reverse work already done. What bounds a standing operation in time is stated per operation below. Expiry or revocation never restores forward authority: a forward call under an expired or revoked chain is refused whether or not a standing call has been made under it.

### 8.1 `sys/undo`

Reverses the effect recorded by a tally. `args` is `{"tally": <the tally object, signed members>}`. The chain is the chain the tally's call ran under, verbatim. `from` is any `iss` on that chain.

When it performs the operation at section 7 step 11 (steps 4 and 7 having been skipped, as for every standing call), the executor checks in this order: `args.tally` is an object (`malformed`); it passes section 6.1 with this executor's own key as signer, any failure there being `not_reversible`; the identity of the leaf writ in `chain` equals `tally.writ` (`tally_mismatch`); `tally.rev` is not null, now < `tally.rev.until` by the executor's own clock, and `tally.st` is `ok` (`not_reversible`); the tally is held in the executor's tally store (`not_reversible`). It then reverses the effect at most once per tally identity. Only a reversal that succeeded counts: once one has, a later `sys/undo` for the same tally, under any call `id`, performs nothing and is answered `ok` with the successful reversal's result body, while a reversal that failed consumes nothing and a later `sys/undo` may try again. Reversals of one tally MUST NOT run concurrently, and the executor MUST durably record that a reversal of the tally has begun before it performs one. A `sys/undo` for a tally whose reversal is running waits for it: if that reversal succeeds, the waiting call performs nothing and is answered `ok` with its result body; if it fails, the waiting call runs its own. A record of a reversal that began and never reported, found after a restart, means its outcome is unknown: every later `sys/undo` for that tally fails with `unknown_outcome`, because store loss is never proof that nothing happened. A retry of the same signed call is answered from the call store (section 7 step 9), whatever has changed since, including the passing of `rev.until`. The undo tally has `rev` null and `out` committing to any body the executor returns.

The time bound on reversal is `tally.rev.until`, which the executor chose when it signed the tally, not the writ's `exp`. An undo MAY therefore arrive after the leaf, or the whole chain, has expired or been revoked, and MUST be honored if the checks above pass. The executor's own signature on the target proves the effect is its own; the chain proves `from` had standing over it; `rev.until` proves the executor promised reversibility until then.

Because every ancestor issuer has standing, the original delegator can reverse an effect three hops down without the intermediate hop being reachable, and an intermediate hop can reverse its own sub-delegate's effect during its own compensation.

### 8.2 `sys/tallies`

Returns every tally the executor still holds whose chain included a given writ. `args` is `{"writ": <hash>}`; a `writ` member that is absent, not a string, or not the identity of a writ in `chain` that `from` issued or of one below it is `tally_mismatch`, checked when the operation is performed (section 7 step 11). `from` is any `iss` on the chain. A writ above the one `from` issued is refused because the executor's index under it also holds work under sibling delegations that `from` never issued. The result body is `{"tallies": [<tally>...]}`, listing every tally in the executor's tally store indexed under that writ (section 9) in ascending order of `acc`, ties in ascending order of tally identity compared as the ASCII bytes of the identity string, so that one store state always yields one body; the returned tally's `out` commits to it. The list is computed before the `sys/tallies` call's own tally is signed and so never contains it. This is the recovery path when an executor acted but its caller never received the tally, and it works after the writ has expired or been revoked, which is exactly when a caller most needs it: the executor answers with whatever its tally store retains under the retention rule of section 9, and an empty list is a signed statement that nothing is retained, not proof that nothing ran.

## 9. State an executor holds

| Store | Key | Lifetime | Durable | If lost |
|---|---|---|---|---|
| call store | (leaf writ identity, `id`) with state pending or the final tally; while pending, the writs issued and sub-tallies received for the call (section 7.5) | forward call: until leaf `exp`; standing call: as long as the tally store retains any record under that leaf | MUST survive restart | a retried call may execute twice; the protocol does not hide this |
| count store | writ identity, integer consumed | until that writ's `exp` | MUST survive restart | `count` may be exceeded |
| total store | writ identity and bound name, integer consumed | until that writ's `exp` | MUST survive restart | `total` may be exceeded |
| tally store | tally identity; indexed by every writ identity in its chain | until the later of leaf `exp` and `rev.until`, and SHOULD be longer where recovery matters | MUST survive restart | `sys/undo` and `sys/tallies` fail with `not_reversible` or return less |
| revoke store | writ identity; for a key-wide revoke, the revoking key | until that writ's `exp`; a key-wide revoke is kept indefinitely, because it covers writs issued after it arrived | MUST survive restart | a revoked writ is honored again until `exp`; a withdrawn key is honored again with no end |
| reversal store | target tally identity: that a reversal began and under which call, or that one succeeded and its result body | as long as the tally store holds the target | MUST survive restart | a reversal may run twice |

A pending call record found after a restart MUST be resolved to a final tally: `ok` or `failed` when the outcome can be determined, otherwise `failed` with `unknown_outcome`. The resolved tally keeps the record's `acc`, carries in `wrt` and `sub` every writ and sub-tally persisted for the call (section 7.5), with a `used` that covers those sub-tallies, is stored in the call store and the tally store like any final tally, and answers every later retry of the call.

An executor persists what step 10 consumes from its count and total stores no later than step 9's pending entry, so a crash between the two writes leaves a use or an amount consumed with nothing run, which underspends, and never an operation running against a limit it did not record. An executor that cannot write its call store, count store, or total store at section 7 steps 9 and 10 MUST NOT perform the operation. It refuses with a signed `failed` tally whose `err.code` is an implementation code (section 11), recording nothing. An executor that performed the operation and then cannot persist the final tally MUST NOT answer as if it had: it answers with a pending tally, which is what its durable record will resolve to after a restart.

An executor that cannot persist a revoke MUST keep honoring it for as long as it runs and MUST NOT answer as if it were recorded: it answers with an unsigned error whose code is an implementation code (section 11), and the sender retries. A revoke lost at a restart silently re-admits what it withdrew: a writ until its `exp`, and a stolen or retired key with no end.

The tally store holds every final tally the executor signs at section 7 step 12 and every tally it signs resolving a pending record, forward and standing alike. It holds no refusal: a tally signed for a failure at section 7 steps 3 to 10 is returned to the caller and not recorded (a failed check of section 8.1 or 8.2 is an outcome at step 11, not a refusal, and is held), so a party without standing cannot fill an executor's stores, and a retry of a refused call is checked afresh.

### 9.1 Revocation

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `typ` | string | yes | `"revoke"` |
| `writ` | hash or `"*"` | yes | the writ revoked, or every writ `iss` ever issued |
| `iss` | key | yes | the revoker, who signs |
| `chain` | array of writ | yes | root to the revoked writ inclusive; empty when `writ` is `"*"` |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by `iss` |

A verifier checks a revoke in this order, which is the order of section 7 steps 1 to 3 for a call:

1. Section 6.1 steps 1 to 5 on the revoke. Here step 5 requires `writ` to be a hash or the string `"*"`, `iss` to be a key, and `chain` to be an array of at most 8 elements (`too_large`), each an object, that is empty exactly when `writ` is `"*"` (`malformed`).
2. Every writ in `chain` passes section 6.1, in array order.
3. The revoke's signature verifies under `iss` (`bad_signature`).
4. Unless `writ` is `"*"`: the chain is valid (section 4, with its reasons); the identity of its leaf equals `writ` (`chain_broken`); `iss` is the `iss` of some writ in `chain` (`no_standing`).

For `"*"`, `iss` is the key every one of whose writs is revoked. Expiry is not checked on a revoke. An invalid revoke is not recorded and changes nothing.

An executor that receives a valid revoke MUST record it and MUST NOT accept new forward calls under the revoked writ or any writ below it (section 7 step 7). A revoke does not withdraw standing: `sys/undo` and `sys/tallies` under the revoked chain are still accepted (section 8), so the revoker can reverse or recover what completed before the revoke arrived. It SHOULD forward the revoke to the `hld` of every writ it issued under the revoked writ, and relay the acks they return (section 9.4). It answers with the tallies of every forward call it holds under the revoked writ that is not yet final, in ascending order of call identity compared as the ASCII bytes of the identity string: for each, either the final tally when the operation completes or a `pending` tally. Every such call was accepted before the revoke was recorded (section 7). An executor that answers with a `pending` tally MUST tell the running operation to stop, and the call's final tally follows when the operation returns. An executor MUST NOT report `canceled` for an operation it has already started unless it actually stopped it. Calls already final are not in the answer; `sys/tallies` recovers them. A standing call in flight is neither stopped nor listed, because a revoke ends forward authority and not standing: a revoker racing its own `sys/undo` must not cancel it. With the answer, it returns its ack of the revoke (section 9.4).

Safety MUST NOT depend on a revoke arriving. `exp` is the hard bound. A key-wide revoke (`"*"`) signed by a key is honored by every verifier that sees it, and a compromised key cannot undo it.

### 9.2 Silence

A caller whose call receives no tally by the leaf `exp` treats the call as `unacknowledged`. It MAY recover through `sys/tallies` to the executor, or to any executor further down that it learns of. An executor whose own sub-call is unacknowledged MUST still return a tally: `failed` with `undeliverable`, with `wrt` and `sub` complete for everything it did learn.

A revoke that races completion is answered with the completed tally, and the caller proceeds to `sys/undo` if `rev` permits. Both outcomes are named; silence is never read as stopped.

### 9.3 Audit record

The stores above hold what the checks of this protocol need, for as long as they need it. They are not an audit log: a refusal is returned and not stored, and retention ends at `exp` or `rev.until`. An executor SHOULD keep, separately, an append-only audit record with one entry for every call and revoke it receives, whatever the outcome, holding at least: the time by E's clock; the identity of the call or revoke, or the reason it could not be parsed; `from`, or the revoke's `iss`; the transport-authenticated peer, or that there was none; the root issuer and the leaf writ's identity; `op`; the outcome, with the reason code of a refusal; and the identity of the tally, when one was signed.

No check in this protocol consults the audit record, `sys/tallies` does not return it, and an entry confers no standing. Anyone can send a call or a revoke, so the record's growth is bounded the way revoke intake is (section 12), by rate per transport-authenticated peer. How long it is kept is deployment policy; an executor that keeps it longer than its tally store SHOULD keep tallies as long, so an entry naming a tally can still produce it. Evidence meant to outlive the executor belongs in a transparency log: a tally can be registered with a SCITT log (section 13).

### 9.4 Acknowledging a revoke

A tally does not say whether its call was accepted before or after a revoke reached its executor, and neither party's clock settles it. So an executor that records a revoke says, under its own signature, when it recorded it and exactly which work under the revoked writ it held at that moment. Any tally it produces for other forward work under that writ contradicts that statement, however the tally's `acc` is dated.

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | integer | yes | `1` |
| `typ` | string | yes | `"ack"` |
| `revoke` | hash | yes | identity of the revoke recorded |
| `iss` | key | yes | the executor that recorded it, who signs |
| `rcv` | integer | yes | the time the executor recorded the revoke, by its own clock |
| `out` | hash | yes | hash of the canonical form of the ack's body |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by `iss` |

The body travels beside the ack, as a result body travels beside a tally (section 10). It is the object `{"held": [...], "open": [...]}`:

- `held` has one element `{"call": <call identity>, "tally": <tally identity>}` for every tally in the executor's tally store (section 9) under the revoked writ, in ascending order of call identity compared as the ASCII bytes of the identity string. A tally is under the revoked writ when the chain of the call it answers includes that writ or, for a key-wide revoke, includes a writ whose `iss` is the revoke's `iss`.
- `open` has the call identity of every tally in the revoke's answer (section 9.1), in the answer's order: the forward calls under the revoked writ that the executor had accepted and were not final.

An executor that records a valid revoke MUST sign an ack for it and return it with its answer. It sets `rcv`, and computes `held` and `open`, atomically with recording the revoke, under the rule of section 7 that makes recording a revoke atomic with steps 7 to 11 of a forward call. Every forward call under the revoked writ that it ever accepts was then accepted before the revoke was recorded, and at that moment was either final, and so in `held`, or not, and so in `open`. A revoke received again is recorded again and answered with a new ack; each ack stays true of its own `rcv`. A revoke the executor could not persist is answered with the error of section 9 and no ack, because an ack says the revoke was recorded.

A verifier holding a revoke R, an ack A with its body B, and a tally T answering a call under the chain C, root to T's writ, checks T against A in this order:

1. R passes the checks of section 9.1, with their reasons.
2. A passes section 6.1 with signer `A.iss`.
3. `A.revoke` is the identity of R. Reason `ack_mismatch`.
4. `A.out` is the hash of B's canonical form (`ack_mismatch`), and B is an object whose `held` and `open` are arrays (`malformed`).
5. C passes chain verification (section 4), with its reasons; T passes section 6.1 with signer the `hld` of C's last writ; and `T.writ` is the identity of that writ (`tally_mismatch`).
6. A says nothing about T, and the check accepts, unless all of these hold: `A.iss` is the `hld` of C's last writ, so A and T have one signer; `T.op` does not begin with `sys/`; T reports work, meaning its `st` is `ok`, `pending`, or `canceled`, or a member of its `used` is above zero, or its `sub` or `wrt` is not empty; R covers C, meaning `R.writ` is the identity of a writ in C, or `R.writ` is `"*"` and a writ in C has `iss` equal to `R.iss`; and the `exp` of C's last writ is after `A.rcv`, so a final T was still in the tally store at `A.rcv`.
7. T is accounted for: `T.call` is an element of `B.open`; or `B.held` has an element whose `call` is `T.call` and whose `tally` is the identity of T; or `T.st` is `pending` and `B.held` has an element whose `call` is `T.call`, the call having finished before `A.rcv`. Otherwise reason `revoked`.

A tally that fails step 7 is `signed_unauthorized`: its signer made two statements that cannot both be true. A refusal reports no work and a standing call is not forward work, so neither can fail it; a revoke ends forward authority and not standing (section 8). A verifier checks T against every ack it holds that names R, and one contradiction is enough. An ack without its body proves only that R reached its signer by `rcv`.

An executor that forwards a revoke SHOULD keep each ack it receives in answer that passes steps 2 to 4 for that revoke, those in the answer's own `fwd` included, and from then on return every ack it keeps for a revoke, with its body, in `fwd` of each answer to that revoke, including the answer during which it forwarded (section 10). A delegator then learns that its revoke reached executors it never contacted, and holds the acks to check their tallies against. A relay cannot forge an ack, because each is signed by the executor that recorded the revoke.

## 10. HTTP binding

Every implementation MUST support this binding. Other bindings carry the same objects.

Request: `POST` to the executor's endpoint with `Content-Type: application/writ+json` and a body that is one call or one revoke object.

Response to a call: status 200 and body

```json
{"tally": <tally>, "res": <result body or absent>}
```

`res`, when present, is the object whose canonical form hashes to `tally.out`. Rejections before signature verification (section 7 steps 1 and 2) are status 400 with body `{"error": <reason>}`. Every other rejection is status 200 with a `failed` tally.

Response to a revoke: status 200 and body

```json
{"tallies": [<tally>...], "ack": <ack>, "res": <ack body>, "fwd": [{"ack": <ack>, "res": <ack body>}...]}
```

`tallies` is in the order of section 9.1, `ack` is the executor's own ack of the revoke and `res` its body (section 9.4), and `fwd`, present only when the executor holds acks relayed from executors below it, is in ascending order of ack identity compared as the ASCII bytes of the identity string. An invalid revoke MAY be answered with status 400 and body `{"error": <reason>}`. A valid revoke the executor could not persist (section 9) is answered with status 503 and body `{"error": <implementation code>}`.

Transport authentication (TLS, OAuth, mTLS) is outside this protocol and MUST NOT be replaced by it: a writ is authority to act, not proof of who is connecting. When the transport authenticates the peer, the binding MUST pass that identity to the executor, which checks it against the call's `from` (section 7.6). A writ MUST NOT be sent in an `Authorization` header.

## 11. Reason codes

| Code | Meaning |
|---|---|
| `too_large` | byte length or chain length over section 1.6 |
| `noncanonical` | section 1.1 violation, including duplicate members, surrogates, non-integers |
| `unsupported_version` | `v` is not 1 |
| `wrong_type` | `typ` is not the expected object type |
| `unsupported_critical` | a `crit` member is not understood |
| `malformed` | a required member is missing or of the wrong type |
| `bad_key` | an identifier is not an Ed25519 did:key |
| `bad_signature` | signature does not verify |
| `chain_broken` | issuer or `prv` mismatch, or non-null root `prv` |
| `not_narrowed` | a child widens, drops, or retypes a bound, outlives its parent, or violates `hld` or `depth` |
| `unknown_bound` | bound type not in section 3 |
| `expired` | a forward call arrives, or a forward tally's `acc` is, at or after a writ's `exp`; never raised for a standing call |
| `root_not_accepted` | executor does not act under this root |
| `wrong_executor` | the receiving party is not the leaf `hld` |
| `peer_mismatch` | the transport-authenticated peer is not bound to the call's `from` (section 7.6) |
| `revoked` | a forward call names a chain with a revoked writ, or a tally reports forward work under a revoked writ that its signer's ack does not account for (section 9.4); never raised for a standing call |
| `no_standing` | `from` is not the required issuer |
| `forbidden_op` | `op` not matched by `act`, or a forward `op` under `sys/` |
| `missing_arg` | a bound name absent from `args` |
| `out_of_bounds` | an argument or a `used` value violates a bound |
| `count_exhausted` | a `count` bound in the chain is used up |
| `total_exhausted` | the call's argument would take a `total` bound in the chain past its value at this executor (section 7.3) |
| `tally_mismatch` | a tally does not name the expected call, writ, op, or output |
| `sub_unmatched` | a sub-tally names a writ absent from `wrt` |
| `ack_mismatch` | an ack does not name the revoke, or its body does not hash to its `out` (section 9.4) |
| `not_reversible` | `sys/undo` target has no `rev`, is past `until`, is not `ok`, or is not this executor's |
| `undeliverable` | a sub-call never answered |
| `unknown_outcome` | the executor cannot determine whether its effect occurred |
| `pending` | not a rejection: the `err.code` of every pending tally (section 6) |

Application failures use `failed` with a code outside this table; such codes SHOULD be prefixed with an application namespace and MUST NOT collide with the codes above.

## 12. Security considerations

**Enforcement point.** Every check in sections 4, 6, 7, 8, and 9 MUST be performed by deterministic code in the receiving implementation before any effect, independent of any language model. A model may decide whether to delegate and to whom; it never decides whether a chain is valid. An implementation MUST NOT sign a writ received as data (section 7.5). Conformance tests present a literal writ to an issuing implementation and expect refusal.

**Fixed verification order.** Two implementations MUST reject the same object for the same reason. The orders in sections 3, 4, 6.1, 6.2, 7, 9.1, and 14 are normative.

**Canonical bytes.** Signatures cover canonical bytes with a type prefix (section 1.4). Duplicate members, unpaired surrogates, non-integer numbers, and padded base64url are rejections, because a lenient parser would verify a signature over one reading and enforce another.

**One algorithm.** There is no algorithm member and no unsigned variant. A writ is not a JWS or a JWT; implementations MUST NOT present a writ as an OAuth assertion or accept a JWT as a writ. The type prefix in the signing input prevents a signature from being reused across object types or across protocols that also sign canonical JSON.

**Authority never amplifies.** Section 4 makes the leaf's bounds a subset of every ancestor's. An executor enforces the leaf. A verifier re-checks the chain. A prompt-injected holder that issues a wider child produces a chain every executor rejects and every verifier can prove invalid. What the protocol cannot see is a within-bounds delegation to an unwanted key; the `hld` bound closes that when the delegator cares, and `wrt` records it when the delegator does not.

**Holder binding.** Possession of writ objects confers nothing: a call is signed by the leaf issuer, a tally by the leaf holder, a child by the parent's holder. Replay of a signed call is stopped by the call store (section 7 step 9) and bounded by `count` and `exp`.

**Standing after expiry.** Forward authority ends at `exp` and on revocation, at every executor, for every forward call. Standing does not, because it is not authority to act: it is the fact, proven by the signed chain, that `from` issued a writ above this executor. What an expired or revoked chain still permits is exactly two things, both already the issuer's: to ask an executor what ran under its writ, and to reverse an effect the executor itself signed as reversible, within the `rev.until` the executor chose. Neither creates work, spends `count`, or touches a bound. An attacker holding an old chain but not an issuer's key can do nothing with it; an attacker holding an issuer's key could have issued and revoked freely anyway, and a key-wide revoke ends that key's forward authority without ending its standing to clean up. Checking expiry on standing calls, as the first draft of this section did, produced the opposite failure: a delegator could not reverse a charge it was promised it could reverse, because the writ under which the charge was made had run out an hour earlier.

**Root acceptance.** A chain proves attenuation from its root, not that the root matters. Section 7.1 is what stops a stranger from minting a root to an executor.

**Identity of every hop.** Three keys in a call are tied to something outside the protocol: the root issuer, by root acceptance (section 7.1); the caller, by peer binding when the transport authenticates one (section 7.6); and the executor, by whoever chose to call it. The keys between are known only through the delegation that names them: C learns B's key because A delegated to it, and trusts that choice exactly as far as it trusts A. That is the design, not an oversight, because across organizations there is no single directory in which C could look B up. A deployment that requires every key in a chain to be a registered workload checks each `iss` and `hld` against its own registry when it performs the operation, and fails it with an application code (section 11); a delegator that wants particular executors names them in `hld`.

**Time.** Verifiers use their own clock. `exp` is exclusive and strict for forward authority. Bounds are judged at `acc`. Issuers SHOULD keep root writs short-lived; verifiers SHOULD reject a root whose `exp` is more than 24 hours ahead unless configured otherwise, with reason `expired`. Safety never depends on a revoke arriving.

**Keys.** A did:key cannot rotate; a new key is a new principal. Rotating an agent's key is therefore three ordinary acts: issuers write new writs to the new key, executors bind the agent's transport identity to it (section 7.6), and the old key signs a key-wide revoke of itself. That two keys belonged to one agent is a statement this protocol does not make; a signed Agent Card or a directory entry listing both makes it, and an audit record that stores the peer beside the key (section 9.3) keeps the question answerable afterwards. Damage from a stolen key is bounded by `exp` and `count` on outstanding writs and ended by a key-wide revoke, which the thief cannot undo and executors MUST keep across restarts (section 9). Binding a key to a vendor for liability is the job of a signed Agent Card or equivalent listing the did:key (section 13); a verifier that has not checked such a binding MUST report the executor as a key, never as a name taken from a result body.

**Receipts.** A tally is evidence, not truth. It proves that the holder of a key signed a statement about a call under a writ. It does not prove the executor's account of the world is accurate. `sub` and `wrt` are REQUIRED even when empty, so an omitted sub-delegation is a signed false statement, and `sys/tallies` lets a delegator ask any executor it learns of what ran under its writ.

**Fabricated sub-executors.** A holder can issue a child to a throwaway key it controls and sign a sub-tally as that key. Every check passes, because every statement is true: it delegated to that key and that key signed. What the verifier learns is exactly the executor set. A delegator that requires particular executors names them in `hld`.

**Confidentiality.** Signed objects commit to results by hash; bodies travel beside them and any hop MAY withhold a body from a party that does not need it. Applications whose results have low entropy SHOULD include a random member in the body so the hash cannot be guessed. Bound values and `args` are visible to every executor on the chain; do not put secrets in them; commit to them by hash where the executor does not need the plaintext.

**Denial of service.** Section 1.6 limits are checked before any signature. Verification cost is linear in chain length and tally tree size. A valid key-wide revoke needs no accepted root, since any key may revoke itself, so anyone can send revokes. An executor records every valid one, because a key-wide revoke is how a stolen key is withdrawn from executors that have not yet seen it, and SHOULD bound the rate at which it accepts revokes from each transport-authenticated peer (section 10), and store them so that recording one does not rewrite the others.

**Revocation evidence.** A revoke ends forward authority at each executor when that executor records it, so a tally for work accepted before the revoke reached its executor is valid, and the revoker needs it (section 6.2). An ack makes work accepted afterwards a contradiction in its signer's own hand (section 9.4); dating `acc` earlier does not help, because the ack lists every call the signer accounted for, not only a time. It cannot catch everything. An executor the revoke never reached is doing nothing wrong: `exp` bounds that case, and a revoker that learns of an executor from `wrt` can send the revoke to it directly. An executor that lost its tally store signs acks that omit work it did, and each omission surfaces as a contradiction, which it is. `rcv` is the signer's own claim, and a later `rcv` exempts work under writs that expired before it (section 9.4 step 6); a party that receives an ack from its signer SHOULD compare `rcv` with its own clock, and a relayed ack is only as fresh as its relay.

**Residual risks.** The protocol does not detect an executor that lies within its bounds, an executor colluding with a resource that does not check chains, or a sub-delegation that never surfaces because the sub-executor stays silent and the holder omits it. It makes each of these a signed statement its author cannot disown, bounds the damage by `exp`, `count`, and typed bounds, and leaves attribution to key bindings and liability to contract.

## 13. Relationship to other protocols

| Function | Owner | Writ's position |
|---|---|---|
| endpoint discovery, capability description | A2A Agent Cards, MCP `server/discover` | a card lists the did:key; Writ objects reference keys only |
| transport authentication | TLS, OAuth 2.1, mTLS, DPoP | required beneath Writ; never replaced by it; the authenticated peer is bound to `from` (section 7.6) |
| workload identity, directories | SPIFFE/SPIRE, WIMSE, enterprise identity providers | supplies the peer bindings of section 7.6 and the root decisions of section 7.1; Writ objects name keys only |
| task lifecycle, streaming, push | A2A tasks, MCP Tasks extension | a Writ call is one unit of work inside a task; the tally is the task's evidence |
| tool schemas | MCP | `op` and `args` are opaque to Writ |
| structured permission values | OAuth RAR (RFC 9396) | `bnd` reuses the idea and adds the comparison |
| delegation with attenuation | UCAN, Biscuit, macaroons, ZCAP-LD, Tenuo | Writ is the JSON-only, DID-key-only, six-comparison subset, plus receipt trees |
| receipts | UCAN Receipt, in-toto, SCITT | a UCAN Receipt signs an invocation's result and the tasks it enqueues; a tally also embeds the tallies of the work delegated below it and accounts for consumption across them. A tally can be wrapped as an in-toto statement or registered with a SCITT log by an extension |
| payment mandates | AP2 | an AP2 mandate can be carried as an application bound; Writ does not settle payments |
| hash-linked attenuated agent delegation | draft-asor-wimse-agent-delegation-chain, draft-hamr-oauth-agent-delegation, AgentROA, AIP/IBCT | same shape (parent hash, subset per hop, offline check); Writ differs in carrying no OAuth or JWT envelope, in a closed six-type bound algebra, and in binding the receipt tree to the chain. A JWS profile is the bridge |
| per-action authorization receipts and tool-call binding | draft-schrock-ep-authorization-receipts, draft-das-agentic-tool-binding | pre-execution approval of one action; a tally is post-execution and MAY carry such a receipt's hash in `err.ref` or the result body |

Bindings for MCP (`_meta` members on `tools/call` and its result) and A2A (a `DataPart` of media type `application/writ+json` and an Agent Card extension) are specified in the adoption document and are not part of this core.

## 14. Conformance

An implementation conforms when it passes the conformance corpus: a directory of JSON vectors, each an object with `name`, `op`, `input`, `expect` (`accept` or `reject`), `reason` (on reject, a code from section 11), and optionally `now` (integer, the verifier's clock for that vector). Operations and their `input` shapes:

| `op` | `input` | Checks |
|---|---|---|
| `canonicalize` | `{"raw": <JSON text>, "canonical": <expected text>}` | section 1.1 and 1.2 |
| `narrows` | `{"child": <bound>, "parent": <bound>}` | section 3 on the child, then on the parent, then a type change (`not_narrowed`), then the narrowing rule (`not_narrowed`) |
| `satisfies` | `{"bound": <bound>, "arg": <value>}` | section 3 on the bound, then the satisfaction rule (`out_of_bounds`); never `count` |
| `verify_writ` | `{"writ": <writ>}` | section 6.1 |
| `verify_chain` | `{"chain": [<writ>...]}` | section 4 as an operation, then expiry at `now` if given |
| `verify_call` | `{"call": <call>}` | section 7 steps 1 and 2 (section 6.1 steps 1 to 5 on the call, section 6.1 on each writ of its chain, then the call's signature), section 4 on its chain, expiry at `now` if given and the call is forward, then section 5's forward or standing rules in the stated order; not root acceptance, executor identity, revocation, or replay, which need executor state, and not section 8's argument checks |
| `verify_tally` | `{"writ": <leaf writ>, "call": <call>, "tally": <tally>, "res": <body, optional>}` | section 6.2 |
| `verify_revoke` | `{"revoke": <revoke>}` | section 9.1's checks, in its order |
| `check_ack` | `{"revoke": <revoke>, "ack": <ack>, "res": <ack body>, "chain": [<writ>...], "tally": <tally>}` | section 9.4, steps 1 to 7; `accept` when T is accounted for or the ack says nothing about it |

A vector without `now` is evaluated with no clock: expiry is not checked. A vector with `now` uses that value as the verifier's current time and never the real clock, so the corpus is stable forever. Keys in the corpus derive from fixed seeds and fixed nonces so any implementation can regenerate every vector byte for byte. Executor behavior that needs state (count, replay, undo, revoke, recovery) is exercised by the scenarios of section 14.1.

Two implementations are interoperable when each accepts every object the other produces from the same seeds, rejects every vector in the corpus with the same reason, and passes every scenario.

### 14.1 Executor scenarios

A scenario tests one executor over a sequence of steps. It is an object with `name`, `executor`, and `steps`. `executor` is `{"seed": <64 hex digits>, "accept": [<key>...]}`, with an optional `peers` member: the implementation under test runs one executor whose Ed25519 private key is that 32-byte seed (RFC 8032 section 5.1.5), which acts under writs rooted at exactly the listed keys (section 7.1) and starts with empty stores. `peers` maps each transport identity the executor holds a binding for, an opaque string, to the array of keys that peer speaks for (section 7.6); absent, the executor holds none. Steps run in array order, each against the state the previous ones left.

| `do` | Members | What the executor does | `expect` |
|---|---|---|---|
| `call` | `now`, `call`, optional `app`, optional `peer` | receives `call` (section 7) with its clock at `now`, delivered by the transport-authenticated peer `peer`, or over a transport that authenticated no peer when `peer` is absent | `{"error": <reason>}` for an unsigned rejection at section 7 steps 1 and 2; `{"tally": <tally>}` or `{"tally": <tally>, "res": <body>}` for a reply; `{"inflight": true}` when the call was accepted and its operation has not returned |
| `revoke` | `now`, `revoke` | receives the revoke (section 9.1) with its clock at `now`, and persists it | `{"error": <reason>}` for an invalid revoke; otherwise `{"tallies": [<tally>...], "ack": <ack>, "res": <ack body>}` (section 10; a single executor relays nothing, so never `fwd`) |
| `finish` | `call` (a call identity), `app`, `signaled` | the held operation of that call returns `app` | as for `call` |
| `restart` | none | loses everything not in a durable store, so an operation still running is lost as in a crash; reopens its stores; resolves pending records (section 9) | `{"resolved": <count of pending records resolved>}` |

`app` scripts the application. It is the outcome the operation returns when the executor performs it at section 7 step 11: the forward operation for a forward call, the reversal for `sys/undo`. Its members are `st` (`ok`, `failed`, or `canceled`), `code` (the `err.code`, present exactly when `st` is not `ok`), and optionally `res` (the result body), `used` (the `used` object), `rev` (the `rev.until` time), and `hold` (true when the operation does not return until a `finish` step names the call). A held operation's outcome comes from that `finish` step, so its `app` has `st` the empty string and no `code`. A `call` step with no `app` asserts that the executor performs no operation: an implementation that invokes its application for that step fails it. `sys/tallies` never invokes the application. `signaled` is true when the executor must have told the held operation to stop (section 9.1) before it returns, and false when it must not have.

A step passes when the executor's answer equals `expect`. Tallies, acks, and bodies compare by canonical form, so every member, `acc`, `rcv`, `out`, and `sig` included, must match: Ed25519 signatures are deterministic, every member of a tally is fixed by the executor's key, its clock, the call, and the scripted outcome, and every member of an ack by the key, the clock, the revoke, and the stores, so two conforming executors given the same scenario sign the same bytes. A reply with no result body has no `res` member. Scripted outcomes carry no `sub` or `wrt`; tally trees are tested by `verify_tally` vectors.

## Appendix A. Worked example

The demo in the reference implementation runs this exchange between three processes.

1. A reads B's well-known document and learns B's did:key and endpoint (Appendix B).
2. A issues writ_1 (section 2 example) to B and sends a forward call `travel/book` with args within bounds.
3. B issues writ_2 to C: `act` `travel/charge`, `amount` 58900, `uses` 1, `prv` the identity of writ_1, `exp` earlier than writ_1's, and sends a forward call `travel/charge`.
4. C verifies the chain, accepts root A, enforces the leaf, charges, and returns tally_C with `rev.until`.
5. B books, returns tally_B with `sub` `[tally_C]`, `wrt` `[writ_2]`, and `used` `{"amount":58900}`: the fare C charged is what B's booking consumed, counted once at each level (section 6).
6. A verifies tally_B and tally_C with nothing but writ_1, its own call, and the keys inside the objects.
7. A sends `sys/undo` to C directly, carrying `[writ_1, writ_2]` and tally_C. C reverses the charge and returns an undo tally.
8. In a second run, A sends a revoke for writ_1 to B while B is working; B forwards it to C; the responses are `canceled` tallies. B's answer carries its own ack and, in `fwd`, the ack C returned to B, so A holds C's signed record of the revoke without ever having called C.

Rejected attempts in the same demo: writ_2 with `amount` 65000 (`not_narrowed`), a call with `amount` 61000 (`out_of_bounds`), a second call under writ_2 (`count_exhausted`), a call with no `amount` (`missing_arg`), a chain re-rooted at a stranger (`root_not_accepted`), and a call whose `op` is `travel/chargeback` under `act` `travel/charge` (`forbidden_op`).

## Appendix B. Well-known document (non-normative)

Where no Agent Card exists, an executor MAY publish `/.well-known/writ`:

```json
{"v":1,"did":"did:key:z6Mk...","endpoint":"https://b.example/writ","act":["travel"]}
```

`act` lists prefixes the executor is willing to accept. This document is a convenience for standalone use; it is not signed and asserts nothing a verifier relies on.

## Appendix C. Design notes

Why integers only: RFC 8785 number formatting is the one part of canonical JSON implementers get wrong, and no bound needs a fraction. Money is minor units; time is seconds; dates are integers.

Why did:key only: the identifier is the key, so verification has no network step and no trust list. A later version can admit did:web by `crit`.

Why bare Ed25519 over canonical JSON instead of JWS or COSE: the objects stay readable in a log, there is no algorithm field to attack, and the whole envelope is four lines in any language. A JWS profile is the intended bridge to IETF bodies once the members are stable.

Why six bound types and no policy language: each comparison is total and decidable; subset of a glob is not. New types enter only with two independent implementations and published vectors.

Why `total` is a type and not a convention: a payment needs a running total, and `max` with `count` bounds only their product, so a delegator that meant "600 in all" had to choose between one call of 600 and several calls that could reach several times 600. `total` reuses `max`'s subset rule and `count`'s store, so it adds no new kind of comparison and no new kind of state. It entered on 2026-10-01 with both implementations and its vectors, as the note above requires.

Why `count` needs state: any at-most-N rule does. The state is named, keyed, and given a lifetime, and the spec says what happens when it is lost.

Why the tally embeds sub-tallies verbatim: a summary is B's word; an embedded signed object is C's word, and A can check it without B's help.

Why no `nbf`: it adds a second clock comparison and only prevents early use, which the issuer controls by not issuing early.

Why reversal is a standing call and not a new writ: the chain the tally names already proves who had standing, the executor's own signature on the tally proves the effect is its own, and one verification path is easier to get right in 2046 than two.

Why an ack lists the work it held and not only a time: a time alone lets its signer date a later tally's `acc` before it. A list of every call accounted for at that moment leaves nothing to redate: work absent from it was accepted afterwards, or not accepted at all.

Why standing survives expiry and revocation: `exp` and revoke bound the holder's authority to start work; `rev.until` bounds the executor's promise to undo it; the tally store's retention bounds what can be recovered. Tying the second and third to the first made the promise in `rev` a lie whenever `until` was later than `exp`, which in the demo it always is.

## Appendix D. JWS profile (non-normative)

For tooling and standards bodies that expect JOSE, a Writ object may travel as the payload of an RFC 7515 JWS in compact serialization. The profile changes nothing a verifier checks:

- The payload is the complete signed object, `sig` included, in canonical form (section 1.2). Its identity, and every `prv` naming it, is computed on that object as always, never on the JWS.
- The protected header has exactly three members: `alg` `"EdDSA"`, `typ` `"writ-<object type>+jws"`, and `kid`, the did:key of the key that signed the object: `iss` for a writ or a revoke, `from` for a call, the executor for a tally. A header with any other member, or any other `alg`, is rejected.
- The JWS signature is a second Ed25519 signature by that same key over the JWS signing input. It lets JOSE tooling authenticate the envelope; it is not a substitute for the object's own signature, which a Writ verifier checks exactly as section 6.1 says, ignoring the envelope.

So a JWS-carried object and a bare one are the same object: a verifier unwraps, checks that `kid` is the object's signer, and verifies the object. The reference implementation is `impl/go/jws`, whose output an unrelated Ed25519 implementation (Python's `cryptography`) verified as ordinary JWS on 2026-09-30.

## Appendix E. Approval as delegation (non-normative)

A deployment that wants a person to approve an action above an agent's limits needs nothing beyond sections 4 and 7. The agent's writ is its limit, and each writ above it in the chain is at least as wide (section 4). When a forward call is refused with `forbidden_op`, `missing_arg`, or `out_of_bounds`, the first writ in the chain, root first, whose `act` and application bounds do not admit the call names the approver: its `iss`, who holds the writ above it, or for a root, issued it. Every writ above it admits the call, and every writ below it refuses.

The approver issues a writ in that one's place to the same holder, as a child of the writ above (none for a root): `act` the call's `op`; every bound of the writ above pinned to the call's argument; every other argument pinned by a one-element `set`; a `count` of 1; and an `exp` no later than the writ above. Each holder below re-issues its own writ under it the same way, and the call is made again under the new chain. The executor applies sections 4 and 7 as always. The approval cannot exceed what its approver holds, because section 4 refuses a child that widens its parent, and the approver's signature stays in the chain of every tally done under it.

Two pins are ceilings, not values, because a child keeps its parent's bound types: a `max` or `total` pinned to an amount admits any smaller amount, and an `act` pinned to an operation admits the operations below it (section 3.1). With the `count` of 1 and every other argument pinned, the approval admits one action of at most that size.

