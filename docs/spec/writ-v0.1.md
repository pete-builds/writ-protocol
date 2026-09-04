# The Writ Protocol, version 0.1

Status: draft for independent implementation. Date: 2026-09-04.

Writ: pass narrowable authority between agents and bring back a signed account of what was done under it.

## Abstract

Writ defines four signed JSON objects and the rules for checking them. A **writ** is a grant of bounded authority from one key to another that the holder can narrow and pass on without contacting the original issuer. A **call** assigns work under a chain of writs. A **tally** is the executor's signed account of what it did under exactly which writ, including the tallies of everyone it delegated to. A **revoke** withdraws a writ. Verification needs only the objects and the public keys embedded in them.

Writ is not a transport, a discovery mechanism, a task lifecycle, or a tool schema. Those belong to existing protocols (HTTP, A2A Agent Cards, A2A and MCP tasks, MCP tools). Writ carries the one thing they do not: an authority object that survives a hop into a foreign trust domain, can be narrowed by its holder under a mechanical subset rule, and is named by the receipt that comes back.

In terms of prior work: a writ is an OAuth Rich Authorization Request value set plus a comparison table, signed by the delegator instead of an authorization server; a tally is a UCAN-style receipt with consumption accounting and an embedded sub-tree.

## 1. Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be interpreted as in RFC 2119 and RFC 8174.

**Object** means a JSON object. **Member** means a name and value pair in an object. **Hash** means the base64url encoding, without padding, of the SHA-256 of a byte string: 43 characters. **Key** means a did:key identifier of an Ed25519 public key.

### 1.1 Encoding rules

1. Every protocol object is UTF-8 JSON (RFC 8259).
2. Numbers MUST be integers in the range negative (2^53 minus 1) to positive (2^53 minus 1), written without fraction or exponent. Any other number is a rejection with reason `noncanonical`. The literal `-0` is accepted and canonicalizes to `0`.
3. Strings MUST be valid UTF-8. A `\u` escape MUST NOT encode an unpaired surrogate. Producers SHOULD emit NFC-normalized strings. Verifiers compare bytes and MUST NOT normalize.
4. An object MUST NOT repeat a member name at any depth.
5. Binary values (signatures, hashes, nonces, identifiers) are base64url (RFC 4648 section 5) without padding. A verifier MUST reject, with reason `noncanonical`, a value containing padding, characters outside the base64url alphabet, or an encoding that does not re-encode to the same string (non-zero trailing bits, or a length congruent to 1 modulo 4), so that every byte string has exactly one encoding. A value that decodes to the wrong number of bytes for its member (32 for a hash, 64 for a signature, fewer than 16 for `nnc` or `id`) is a rejection with reason `malformed`.
6. Times are integer Unix seconds, UTC.

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

The identity of a signed object is the hash of the canonical form of the whole object, `sig` included. Every reference from one object to another (`prv`, `call`, `writ`) is such a hash.

### 1.6 Limits

| Limit | Value |
|---|---|
| chain length | at most 8 writs |
| writ, canonical bytes | at most 4096 |
| call, canonical bytes | at most 65536 |
| tally, canonical bytes | at most 262144 |
| revoke, canonical bytes | at most 65536 |
| `id` and `nnc` | at least 16 random bytes (22 characters) |

A verifier MUST check byte length and chain length before verifying any signature, reason `too_large`.

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

Example, A grants B the authority to book travel for at most 60000 minor units, once, refundable fares only, within a date window:

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

`bnd` is an object whose members are bound names and whose values are objects `{"t": <type>, "v": <value>}` with no other members. Version 1 defines five types. A verifier MUST reject a bound of any other type, reason `unknown_bound`. A bound a verifier cannot compare is a bound it cannot enforce.

| Type | Value | Child narrows parent when | Argument satisfies when |
|---|---|---|---|
| `max` | integer >= 0 | child <= parent | 0 <= arg <= v |
| `count` | integer >= 0 | child <= parent | not by argument: consumed by the executor, section 7.3 |
| `prefix` | string | parent matches child (section 3.1) | v matches arg (section 3.1) |
| `set` | array of strings or integers, no duplicates | every child element is in parent | arg is an element of v |
| `window` | `[lo, hi]` integers, lo <= hi | parent.lo <= child.lo and child.hi <= parent.hi | lo <= arg <= hi |

A `set` element that is the integer 1 and one that is the string `"1"` are different elements; a set MAY mix strings and integers. Bound rejections are classified as follows: a bound that is not an object, has members other than exactly `t` and `v`, or whose `v` has the wrong JSON type for `t` is `malformed`; a `max` or `count` below zero, a `window` with lo above hi, or a `set` with a duplicate element is `noncanonical`; a `t` outside this table is `unknown_bound`. The "argument satisfies" column is not defined for `count`, and section 7.2 never applies it.

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

Chain verification, as an operation, is: the chain is non-empty (`malformed`) and at most 8 writs (`too_large`, checked before any signature); every writ passes section 6.1; the root's `prv` is null (`chain_broken`); every adjacent pair passes steps 1 to 5 above, root first; `depth` holds. Expiry (section 7 step 4) is a separate check because it needs a clock.

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

**Standing call.** `op` begins with `sys/`. `from` MUST equal the `iss` of some writ in `chain`. The executor is the leaf writ's `hld`. Bounds are not applied. The defined standing operations are in section 8; their argument checks need the executor's own key, clock, and stores, so a verifier that is not the executor checks only standing.

A chain MUST NOT be empty for any call (`malformed`). Checks on a call after section 6.1 apply in this order: chain verification (section 4), expiry of every writ, then for a forward call `no_standing`, `forbidden_op`, `missing_arg`, `out_of_bounds`; for a standing call `no_standing`, then `forbidden_op` if the `sys/` operation is not one defined in section 8.

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
| `acc` | integer | yes | the time the executor accepted the call; bounds and expiry are judged at this time |
| `st` | string | yes | `ok`, `failed`, `canceled`, or `pending` |
| `err` | object or null | yes | null when `st` is `ok`; otherwise `{"code": <reason>}` with optional `ref` (a hash) |
| `out` | hash or null | yes | hash of the canonical form of the result body, or null when there is none |
| `used` | object | yes | for each `max` bound name in the leaf writ that the operation consumed, the integer consumed; absent names mean zero |
| `rev` | object or null | yes | `{"until": <time>}` when the effect can be reversed by `sys/undo` until that time; else null |
| `sub` | array of tally | yes | every tally this executor received from calls it made under child writs, signed members only; empty array if none |
| `wrt` | array of writ | yes | every writ this executor issued under the leaf writ; empty array if none |
| `crit` | array of strings | no | section 1.7 |
| `sig` | string | yes | by the leaf writ's `hld` |

The result body travels beside the tally, never inside it (section 10). `out` commits to it.

`sub` and `wrt` are REQUIRED even when empty, so that "I delegated nothing" is a signed statement. Every tally in `sub` MUST name in its `writ` member a writ present in `wrt`; a verifier MUST reject a tally violating this, reason `sub_unmatched`.

A tally with `st` `pending` is not final: the executor has accepted the call and cannot yet report the outcome. A later tally with the same `call` from the same executor supersedes it. A pending tally has `used` `{}`, `rev` null, and `out` null.

Example, C's tally for the call above:

```json
{"v":1,"typ":"tally","call":"<hash of call>","writ":"<hash of writ_2>",
 "op":"travel/charge","acc":1788400415,"st":"ok","err":null,
 "out":"<hash of {\"charge\":\"ch_8813\"}>","used":{"amount":58900},
 "rev":{"until":1788486400},"sub":[],"wrt":[],"sig":"..."}
```

B's tally for A's call embeds C's tally in `sub` and writ_2 in `wrt`.

### 6.1 Verifying a single signed object

For a writ, call, tally, or revoke, in this order:

1. Byte length within section 1.6: the received bytes before parsing and the canonical bytes after. Reason `too_large`.
2. Parse; section 1.1 rules 2 to 4, and rule 5 for every binary member the expected type defines. Reason `noncanonical`.
3. `v` is the integer 1; anything else, including a missing `v`, is `unsupported_version`. `typ` is the expected type; anything else, including a missing `typ`, is `wrong_type`.
4. `crit`, section 1.7. Reason `unsupported_critical`; a `crit` that is not an array of strings, or that names an absent member, is `malformed`.
5. Every required member present with the required type; bound rules of section 3 and 3.2; identifiers are valid keys (`bad_key`); decoded lengths of binary members (`malformed`). Bounds are checked in canonical member-name order after the presence of `act`. Reason `malformed` unless stated otherwise.
6. Signature verifies under the signer's key (writ: `iss`; call: `from`; tally: `hld` of the writ named; revoke: `iss`). Reason `bad_signature`.

A tally names its writ by hash, so a tally can only be verified by a party holding that writ (section 6.2). A refusal with reason `wrong_executor` is signed by the party that received the call, which is not the leaf holder; it is evidence of the refusal but does not verify under section 6.2.

### 6.2 Verifying a tally tree

A verifier V that made a call K under a chain whose leaf writ is W, and received a tally T with an optional result body R, checks in this order:

1. T passes section 6.1 with signer `W.hld`.
2. `T.call` equals the identity of K. Reason `tally_mismatch`.
3. `T.writ` equals the identity of W. Reason `tally_mismatch`.
4. `T.op` equals `K.op`. Reason `tally_mismatch`.
5. `T.acc` < `W.exp`. Reason `expired`.
6. If R is present, `T.out` is not null and equals the hash of R's canonical form. Reason `tally_mismatch`. A non-null `out` with no R is accepted; the verifier simply has no body to check.
7. For each `max` bound N in `W.bnd`: `T.used[N]` (zero if absent) <= `W.bnd[N].v`. Reason `out_of_bounds`.
8. Every writ in `T.wrt` passes section 6.1 and is a valid child of W under section 4. Reason as reported.
9. Every tally S in `T.sub`, in array order: S is an object whose `writ` member names a writ X in `T.wrt` (`sub_unmatched` otherwise, checked before anything else about S); S passes section 6.1 with signer `X.hld`; then steps 3, 5, 7, 8, 9, and 10 apply to S with X in place of W and are completed for S's whole subtree before the next element of `T.sub` is examined.
10. After every element of `T.sub`: for each `max` bound N in `W.bnd`, the sum of `S.used[N]` over the tallies in `T.sub` <= `W.bnd[N].v`. Reason `out_of_bounds`. This is the executor's own accounting and it is evidence, not enforcement (section 7.3).

Names in `used` that are not `max` bounds of the writ are ignored. This procedure does not compare `S.op` against `X.act`; that check was the sub-executor's job at request time (section 7), and a sub-executor that signed a tally for an operation outside its writ has produced a signed admission.

A verifier cannot check `S.call` for a sub-tally because it does not hold the call B made; the sub-tally binds C to a call that B can produce in a dispute.

The result of verification for each tally is one of `valid`, `signed_unauthorized` (section 6.1 passed for T but a later step failed, anywhere in the tree: an admission by a signer), or `unverifiable` (T itself fails section 6.1, including `sub_unmatched` found while parsing it). A verifier MUST NOT treat a result body whose tally is absent or `unverifiable` as a completed result; the task is `unverified`.

## 7. Executing a call

An executor E receiving a call K over a transport binding (section 10) proceeds in this order, stopping at the first failure. A failure at step 1 or 2 MAY be answered with an unsigned error; every later failure MUST be answered with a signed tally with `st` `failed` and the reason in `err.code`, so that a refusal is evidence.

1. K passes section 6.1 steps 1 to 5. Chain length 1 to 8.
2. Every writ in `K.chain` passes section 6.1. `K.sig` verifies under `K.from`.
3. For each adjacent pair in the chain, section 4 holds. Root: `chain[0].prv` is null (`chain_broken`).
4. For every writ in the chain, `now` < `exp`, by E's own clock (`expired`). No member of any message is used as the current time.
5. E accepts the root issuer `chain[0].iss` (section 7.1). Reason `root_not_accepted`.
6. E is the leaf `hld`. Reason `wrong_executor`.
7. No writ in the chain is revoked in E's store (section 9). Reason `revoked`.
8. Forward call: `K.from` equals the leaf `iss` (`no_standing`); `K.op` does not begin with `sys/` and is matched by the leaf `act` (`forbidden_op`); section 7.2 holds. Standing call: `K.from` is the `iss` of some writ in the chain (`no_standing`); section 8 applies.
9. Replay: if E's call store has an entry for (identity of leaf writ, `K.id`), E returns the stored tally without executing. Otherwise E records the entry with state pending.
10. `count`: for every writ in the chain that carries a `count` bound, E's count store entry for that writ's identity is below the bound's value (`count_exhausted`); E increments each. Rejection at this step consumes nothing.
11. E records `acc` = now, persists the pending record, and performs the operation.
12. E signs and persists the tally, then returns it with the result body.

### 7.1 Root acceptance

A self-issued root writ proves only that a key signed it. E MUST hold, from outside the chain, a decision that it will act under writs rooted at `chain[0].iss`: a configured list, a transport-authenticated identity, an Agent Card binding, or a contract. This protocol defines the check and its reason code, not the policy.

### 7.2 Applying bounds to arguments

Let the application bounds be every member N of the leaf's `bnd` other than `act`, `hld`, `depth`, and any bound of type `count`, taken in canonical member-name order. Two passes:

1. For every application bound N, `K.args` MUST have a member N. Reason `missing_arg`.
2. Then, for every application bound N, `K.args[N]` MUST satisfy the bound under section 3. Reason `out_of_bounds`.

Presence is checked for all bounds before satisfaction is checked for any, so a missing argument is always reported before an out-of-range one.

Members of `args` with no corresponding bound are unconstrained.

### 7.3 What `count` and `max` mean

`count` N on a writ means: each executor performs at most N operations under that writ or any writ below it, for as long as the executor's count store persists. It is consumed at acceptance, against every writ in the chain, so a holder cannot reset it by delegating to itself.

`max` is checked per call against the leaf writ. The protocol does not enforce a sum across sibling writs or sibling executors at request time. A delegator that needs a total across several delegations issues one writ per delegation with the total split between them. A verifier audits totals from `used` after the fact (section 6.2 step 10).

Nothing in this protocol is exactly-once. An executor executes at most once per (leaf writ identity, `id`) while its call store persists, and at most `count` times per writ while its count store persists. A caller retries the identical signed bytes until it holds a final tally or the leaf expires. When an executor cannot determine whether an effect occurred, it says so with `st` `pending` or `err.code` `unknown_outcome`; store loss is never proof that nothing happened.

### 7.4 Expiry during execution

E MUST NOT accept a call at or after the leaf `exp`. E MAY complete an operation it accepted before `exp`. A verifier judges `acc`, not the time the tally was signed.

### 7.5 Delegating onward

An executor that delegates part of its work issues a child writ (section 4) and makes a forward call under the extended chain. It MUST construct the child by narrowing a writ it holds; it MUST NOT sign a writ object received as data from any source, including the output of a language model. It MUST persist each sub-tally it receives before acting on the sub-tally's contents, MUST include every sub-tally in `sub` and every issued writ in `wrt`, whatever its own `st`, and MUST return a tally even when a sub-call never answers (section 9.2).

## 8. Standing operations

Standing operations are authorized by position in the chain, not by `act`. A forward `act` prefix never matches them, and they never satisfy a forward `act`.

### 8.1 `sys/undo`

Reverses the effect recorded by a tally. `args` is `{"tally": <the tally object, signed members>}`. The chain is the chain the tally's call ran under, verbatim. `from` is any `iss` on that chain.

The executor checks, after section 7 steps 1 to 8: the tally's signature verifies under its own key (`not_reversible`); the identity of the leaf writ in `chain` equals `tally.writ` (`tally_mismatch`); `tally.rev` is not null and now < `tally.rev.until` (`not_reversible`); `tally.st` is `ok` (`not_reversible`). It then reverses the effect at most once per tally identity: a second `sys/undo` for the same tally returns the first undo tally. The undo tally has `rev` null and `out` committing to any body the executor returns.

Because every ancestor issuer has standing, the original delegator can reverse an effect three hops down without the intermediate hop being reachable, and an intermediate hop can reverse its own sub-delegate's effect during its own compensation.

### 8.2 `sys/tallies`

Returns every tally the executor holds whose chain included a given writ. `args` is `{"writ": <hash>}`; the hash MUST be the identity of a writ in `chain` (`tally_mismatch`). `from` is any `iss` on the chain. The result body is `{"tallies": [<tally>...]}` and the returned tally's `out` commits to it. This is the recovery path when an executor acted but its caller never received the tally.

## 9. State an executor holds

| Store | Key | Lifetime | Durable | If lost |
|---|---|---|---|---|
| call store | (leaf writ identity, `id`) with state pending or the final tally | until leaf `exp` | MUST survive restart | a retried call may execute twice; the protocol does not hide this |
| count store | writ identity, integer consumed | until that writ's `exp` | MUST survive restart | `count` may be exceeded |
| tally store | tally identity; indexed by every writ identity in its chain | until the later of leaf `exp` and `rev.until` | MUST survive restart | `sys/undo` and `sys/tallies` fail with `not_reversible` or return less |
| revoke store | writ identity | until that writ's `exp` | SHOULD survive restart | a revoked writ is honored again until `exp` |

A pending call record found after a restart MUST be resolved to a final tally: `ok` or `failed` when the outcome can be determined, otherwise `failed` with `unknown_outcome`.

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

A revoke is valid when it passes section 6.1, `chain` is a valid chain (section 4, with its reasons), the leaf identity equals `writ` (`chain_broken` otherwise), and `iss` is the `iss` of some writ in `chain` (`no_standing` otherwise). For `"*"`, `chain` MUST be empty (`malformed`) and `iss` is the key itself. Expiry is not checked on a revoke.

An executor that receives a valid revoke MUST record it and MUST NOT accept new calls under the revoked writ or any writ below it (section 7 step 7). It SHOULD forward the revoke to the `hld` of every writ it issued under the revoked writ. It answers with the tallies of every call it holds under the revoked writ that is not yet final: `canceled` for calls not yet accepted, and for accepted calls either the final tally when the operation completes or a `pending` tally. An executor MUST NOT report `canceled` for an operation it has already started unless it actually stopped it.

Safety MUST NOT depend on a revoke arriving. `exp` is the hard bound. A key-wide revoke (`"*"`) signed by a key is honored by every verifier that sees it, and a compromised key cannot undo it.

### 9.2 Silence

A caller whose call receives no tally by the leaf `exp` treats the call as `unacknowledged`. It MAY recover through `sys/tallies` to the executor, or to any executor further down that it learns of. An executor whose own sub-call is unacknowledged MUST still return a tally: `failed` with `undeliverable`, with `wrt` and `sub` complete for everything it did learn.

A revoke that races completion is answered with the completed tally, and the caller proceeds to `sys/undo` if `rev` permits. Both outcomes are named; silence is never read as stopped.

## 10. HTTP binding

Every implementation MUST support this binding. Other bindings carry the same objects.

Request: `POST` to the executor's endpoint with `Content-Type: application/writ+json` and a body that is one call or one revoke object.

Response to a call: status 200 and body

```json
{"tally": <tally>, "res": <result body or absent>}
```

`res`, when present, is the object whose canonical form hashes to `tally.out`. Rejections before signature verification (section 7 steps 1 and 2) MAY be status 400 with body `{"error": <reason>}`. Every other rejection is status 200 with a `failed` tally.

Response to a revoke: status 200 and body `{"tallies": [<tally>...]}`.

Transport authentication (TLS, OAuth, mTLS) is outside this protocol and MUST NOT be replaced by it: a writ is authority to act, not proof of who is connecting. A writ MUST NOT be sent in an `Authorization` header.

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
| `expired` | now, or `acc`, is at or after `exp` |
| `root_not_accepted` | executor does not act under this root |
| `wrong_executor` | the receiving party is not the leaf `hld` |
| `revoked` | a writ in the chain is revoked |
| `no_standing` | `from` is not the required issuer |
| `forbidden_op` | `op` not matched by `act`, or a forward `op` under `sys/` |
| `missing_arg` | a bound name absent from `args` |
| `out_of_bounds` | an argument or a `used` value violates a bound |
| `count_exhausted` | a `count` bound in the chain is used up |
| `tally_mismatch` | a tally does not name the expected call, writ, op, or output |
| `sub_unmatched` | a sub-tally names a writ absent from `wrt` |
| `not_reversible` | `sys/undo` target has no `rev`, is past `until`, is not `ok`, or is not this executor's |
| `undeliverable` | a sub-call never answered |
| `unknown_outcome` | the executor cannot determine whether its effect occurred |

Application failures use `failed` with a code outside this table; such codes SHOULD be prefixed with an application namespace and MUST NOT collide with the codes above.

## 12. Security considerations

**Enforcement point.** Every check in sections 4, 6, 7, 8, and 9 MUST be performed by deterministic code in the receiving implementation before any effect, independent of any language model. A model may decide whether to delegate and to whom; it never decides whether a chain is valid. An implementation MUST NOT sign a writ received as data (section 7.5). Conformance tests present a literal writ to an issuing implementation and expect refusal.

**Fixed verification order.** Two implementations MUST reject the same object for the same reason. The orders in sections 4, 6.1, 6.2, and 7 are normative.

**Canonical bytes.** Signatures cover canonical bytes with a type prefix (section 1.4). Duplicate members, unpaired surrogates, non-integer numbers, and padded base64url are rejections, because a lenient parser would verify a signature over one reading and enforce another.

**One algorithm.** There is no algorithm member and no unsigned variant. A writ is not a JWS or a JWT; implementations MUST NOT present a writ as an OAuth assertion or accept a JWT as a writ. The type prefix in the signing input prevents a signature from being reused across object types or across protocols that also sign canonical JSON.

**Authority never amplifies.** Section 4 makes the leaf's bounds a subset of every ancestor's. An executor enforces the leaf. A verifier re-checks the chain. A prompt-injected holder that issues a wider child produces a chain every executor rejects and every verifier can prove invalid. What the protocol cannot see is a within-bounds delegation to an unwanted key; the `hld` bound closes that when the delegator cares, and `wrt` records it when the delegator does not.

**Holder binding.** Possession of writ objects confers nothing: a call is signed by the leaf issuer, a tally by the leaf holder, a child by the parent's holder. Replay of a signed call is stopped by the call store (section 7 step 9) and bounded by `count` and `exp`.

**Root acceptance.** A chain proves attenuation from its root, not that the root matters. Section 7.1 is what stops a stranger from minting a root to an executor.

**Time.** Verifiers use their own clock. `exp` is exclusive and strict. Bounds are judged at `acc`. Issuers SHOULD keep root writs short-lived; verifiers SHOULD reject a root whose `exp` is more than 24 hours ahead unless configured otherwise, with reason `expired`. Safety never depends on a revoke arriving.

**Keys.** A did:key cannot rotate; a new key is a new principal. Damage from a stolen key is bounded by `exp` and `count` on outstanding writs and ended by a key-wide revoke, which the thief cannot undo. Binding a key to a vendor for liability is the job of a signed Agent Card or equivalent listing the did:key (section 13); a verifier that has not checked such a binding MUST report the executor as a key, never as a name taken from a result body.

**Receipts.** A tally is evidence, not truth. It proves that the holder of a key signed a statement about a call under a writ. It does not prove the executor's account of the world is accurate. `sub` and `wrt` are REQUIRED even when empty, so an omitted sub-delegation is a signed false statement, and `sys/tallies` lets a delegator ask any executor it learns of what ran under its writ.

**Fabricated sub-executors.** A holder can issue a child to a throwaway key it controls and sign a sub-tally as that key. Every check passes, because every statement is true: it delegated to that key and that key signed. What the verifier learns is exactly the executor set. A delegator that requires particular executors names them in `hld`.

**Confidentiality.** Signed objects commit to results by hash; bodies travel beside them and any hop MAY withhold a body from a party that does not need it. Applications whose results have low entropy SHOULD include a random member in the body so the hash cannot be guessed. Bound values and `args` are visible to every executor on the chain; do not put secrets in them; commit to them by hash where the executor does not need the plaintext.

**Denial of service.** Section 1.6 limits are checked before any signature. Verification cost is linear in chain length and tally tree size.

**Residual risks.** The protocol does not detect an executor that lies within its bounds, an executor colluding with a resource that does not check chains, or a sub-delegation that never surfaces because the sub-executor stays silent and the holder omits it. It makes each of these a signed statement its author cannot disown, bounds the damage by `exp`, `count`, and typed bounds, and leaves attribution to key bindings and liability to contract.

## 13. Relationship to other protocols

| Function | Owner | Writ's position |
|---|---|---|
| endpoint discovery, capability description | A2A Agent Cards, MCP `server/discover` | a card lists the did:key; Writ objects reference keys only |
| transport authentication | TLS, OAuth 2.1, mTLS, DPoP | required beneath Writ; never replaced by it |
| task lifecycle, streaming, push | A2A tasks, MCP Tasks extension | a Writ call is one unit of work inside a task; the tally is the task's evidence |
| tool schemas | MCP | `op` and `args` are opaque to Writ |
| structured permission values | OAuth RAR (RFC 9396) | `bnd` reuses the idea and adds the comparison |
| delegation with attenuation | UCAN, Biscuit, macaroons, ZCAP-LD | Writ is the JSON-only, DID-key-only, five-comparison subset, plus receipts |
| receipts | in-toto, SCITT | a tally can be wrapped as an in-toto statement or registered with a SCITT log by an extension |
| payment mandates | AP2 | an AP2 mandate can be carried as an application bound; Writ does not settle payments |

Bindings for MCP (`_meta` members on `tools/call` and its result) and A2A (a `DataPart` of media type `application/writ+json` and an Agent Card extension) are specified in the adoption document and are not part of this core.

## 14. Conformance

An implementation conforms when it passes the conformance corpus: a directory of JSON vectors, each an object with `name`, `op`, `input`, `expect` (`accept` or `reject`), `reason` (on reject, a code from section 11), and optionally `now` (integer, the verifier's clock for that vector). Operations and their `input` shapes:

| `op` | `input` | Checks |
|---|---|---|
| `canonicalize` | `{"raw": <JSON text>, "canonical": <expected text>}` | section 1.1 and 1.2 |
| `narrows` | `{"child": <bound>, "parent": <bound>}` | section 3 |
| `satisfies` | `{"bound": <bound>, "arg": <value>}` | section 3, never `count` |
| `verify_writ` | `{"writ": <writ>}` | section 6.1 |
| `verify_chain` | `{"chain": [<writ>...]}` | section 4 as an operation, then expiry at `now` if given |
| `verify_call` | `{"call": <call>}` | section 6.1 on the call, section 4 on its chain, expiry at `now` if given, then section 5's forward or standing rules in the stated order; not root acceptance, executor identity, revocation, or replay, which need executor state |
| `verify_tally` | `{"writ": <leaf writ>, "call": <call>, "tally": <tally>, "res": <body, optional>}` | section 6.2 |

A vector without `now` is evaluated with no clock: expiry is not checked. A vector with `now` uses that value as the verifier's current time and never the real clock, so the corpus is stable forever. Keys in the corpus derive from fixed seeds and fixed nonces so any implementation can regenerate every vector byte for byte. Executor behavior that needs state (count, replay, undo, revoke, recovery) is exercised by scenario tests rather than by the stateless corpus.

Two implementations are interoperable when each accepts every object the other produces from the same seeds and rejects every vector in the corpus with the same reason.

## Appendix A. Worked example

The demo in the reference implementation runs this exchange between three processes.

1. A reads B's well-known document and learns B's did:key and endpoint (Appendix B).
2. A issues writ_1 (section 2 example) to B and sends a forward call `travel/book` with args within bounds.
3. B issues writ_2 to C: `act` `travel/charge`, `amount` 58900, `uses` 1, `prv` the identity of writ_1, `exp` earlier than writ_1's, and sends a forward call `travel/charge`.
4. C verifies the chain, accepts root A, enforces the leaf, charges, and returns tally_C with `rev.until`.
5. B books, returns tally_B with `sub` `[tally_C]` and `wrt` `[writ_2]`.
6. A verifies tally_B and tally_C with nothing but writ_1, its own call, and the keys inside the objects.
7. A sends `sys/undo` to C directly, carrying `[writ_1, writ_2]` and tally_C. C reverses the charge and returns an undo tally.
8. In a second run, A sends a revoke for writ_1 to B while B is working; B forwards it to C; the responses are `canceled` tallies.

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

Why five bound types and no policy language: each comparison is total and decidable; subset of a glob is not. New types enter only with two independent implementations and published vectors.

Why `count` needs state: any at-most-N rule does. The state is named, keyed, and given a lifetime, and the spec says what happens when it is lost.

Why the tally embeds sub-tallies verbatim: a summary is B's word; an embedded signed object is C's word, and A can check it without B's help.

Why no `nbf`: it adds a second clock comparison and only prevents early use, which the issuer controls by not issuing early.

Why reversal is a standing call and not a new writ: the chain the tally names already proves who had standing, the executor's own signature on the tally proves the effect is its own, and one verification path is easier to get right in 2046 than two.
