# 04. Six architectures for cross-vendor agent delegation


> **Historical document (2026-09-03).** This records the six candidate designs as proposed, before the kill round. Terminology here is superseded by the v0.1 specification: `recall` became `revoke`; the tally members `exe`, `in`, `res`, and `ts`, and the call member `ts`, were cut (decision record item 4); the Behalf header form is not the HTTP binding of v0.1 (spec section 10 is a POST body; the header form is a possible extension). Nothing below is normative.

Status: design note, 2026-09-03. Role: Protocol Architect. Inputs: `01-history.md` (ten principles with tests), `02-prior-art.md` (matrix, gap, taken names), `03-skeptic-opening.md` (where MCP, A2A, and OAuth break; IN/OUT scope; eleven standing questions). Nothing here was fetched from the network.

## The fixed scenario and wire conventions

Every architecture below runs the skeptic's scenario, with integers only.

Agent A (vendor 1, travel assistant, key `did:key:z6MkA`) delegates to Agent B (vendor 2, booking, `did:key:z6MkB`): book one refundable flight for passenger P on 2026-10-15 to 2026-10-19, at most 60000 cents USD. B sub-delegates to Agent C (vendor 3, payments, `did:key:z6MkC`) with strictly less: charge at most 60000 cents, once, refundable fare only, same passenger. C and B return signed receipts. A verifies offline. A then compensates by refunding the charge (or cancels while work is in flight).

Conventions used in every example. DIDs are abbreviated to `did:key:z6MkA`, `did:key:z6MkB`, `did:key:z6MkC`; a real did:key for Ed25519 is 48 characters after the method prefix. Signatures appear as `<sigA1>` and hashes as `<h1>`; on the wire they are 86 and 43 base64url characters respectively. Timestamps are Unix seconds: 1788400000 is 2026-09-03T01:46:40Z, and the delegation expires one hour later at 1788403600. Passenger P is never sent in the clear; `pax` is the SHA-256 of a canonical passenger record that A and B already share. Amounts are minor units. Where an object is signed, the signature is Ed25519 over the JCS (RFC 8785) canonical form of the object with the `sig` member removed, unless the architecture says otherwise.

The phrase "bound registry" below means the small table of constraint types with fixed comparison semantics; it is specified once in the cross-cutting section and shared by every architecture that needs it.

---

## Architecture 1: Writ

Holder-attenuated capability chain plus signed receipts. UCAN and Biscuit lineage, offline, no authority server.

**Definition.** Writ: carry a delegator-signed, holder-narrowable authority across trust domains, and bring back a signed account of what was done under exactly which link of it.

**Core objects.**

`writ` (the authority link):
- `v` integer, protocol version, 1
- `typ` string, always `"writ"`
- `iss` string, did:key of the delegator, who signs
- `hld` string, did:key of the holder, the only principal that may present or narrow this writ
- `bnd` object, map from bound key to `{t, v}` where `t` is a registry type (`max`, `count`, `prefix`, `set`, `window`) and `v` is integer, string, or array per type; the key `act` is mandatory and always type `prefix`
- `prv` string or null, hash of the parent writ, null at the root
- `nbf` integer, `exp` integer, validity window in Unix seconds
- `nnc` string, 16 random bytes base64url, makes every writ unique
- `sig` string, Ed25519 by `iss`

`call` (the exercise of a writ):
- `v`, `typ` = `"call"`, `id` string unique per caller
- `chain` array of `writ` objects, root first, leaf last
- `from` string, did:key, must equal the leaf `hld`
- `op` string, must satisfy the leaf `act` prefix
- `args` object, the operation inputs, keys compared against `bnd` where names coincide
- `ts` integer, `sig` by `from`

`tally` (the receipt):
- `v`, `typ` = `"tally"`
- `call` string, hash of the `call` this answers
- `writ` string, hash of the leaf writ the executor honored
- `exe` string, did:key of the executor
- `op` string, `in` string hash of `args`, `res` object result body (or `out` hash if the body travels separately)
- `used` object, map bound key to integer consumed (`amount`, `count`)
- `st` string, one of `ok`, `failed`, `canceled`
- `err` object or null, `{code: string, msg: string}`
- `rev` object or null, `{op: string, ref: string, until: integer}` reversal handle
- `sub` array of `tally`, the receipts of every sub-delegate, embedded verbatim
- `wrt` array of `writ`, every writ this executor issued to sub-delegates, so the verifier holds every link of the chain
- `ts` integer, `sig` by `exe`

`recall` (cancellation of authority):
- `v`, `typ` = `"recall"`, `writ` string hash, `iss` string did:key (must be an issuer somewhere above the recalled writ in its chain), `reason` string, `ts` integer, `sig`

**Wire example.**

A issues writ_1 to B:

```json
{"v":1,"typ":"writ","iss":"did:key:z6MkA","hld":"did:key:z6MkB",
 "bnd":{"act":{"t":"prefix","v":"travel/"},
        "amount":{"t":"max","v":60000},
        "currency":{"t":"set","v":["USD"]},
        "count":{"t":"count","v":1},
        "fare":{"t":"set","v":["refundable"]},
        "pax":{"t":"set","v":["<h_pax>"]},
        "dates":{"t":"window","v":[20261015,20261019]}},
 "prv":null,"nbf":1788400000,"exp":1788403600,"nnc":"Qm3bq8w1s5XK7jZR","sig":"<sigA1>"}
```

B narrows to writ_2 for C (hash of writ_1 is `<h1>`):

```json
{"v":1,"typ":"writ","iss":"did:key:z6MkB","hld":"did:key:z6MkC",
 "bnd":{"act":{"t":"prefix","v":"travel/charge"},
        "amount":{"t":"max","v":60000},
        "currency":{"t":"set","v":["USD"]},
        "count":{"t":"count","v":1},
        "fare":{"t":"set","v":["refundable"]},
        "pax":{"t":"set","v":["<h_pax>"]},
        "dates":{"t":"window","v":[20261015,20261019]}},
 "prv":"<h1>","nbf":1788400000,"exp":1788402000,"nnc":"aZ0pLw9cR2tNv4Hy","sig":"<sigB1>"}
```

B calls C (hash of writ_2 is `<h2>`):

```json
{"v":1,"typ":"call","id":"b-7f1c","chain":[{"...writ_1..."},{"...writ_2..."}],
 "from":"did:key:z6MkB","op":"travel/charge",
 "args":{"amount":58900,"currency":"USD","fare":"refundable","pax":"<h_pax>","pnr":"K7Q2ZD"},
 "ts":1788400412,"sig":"<sigB2>"}
```

C returns tally_C:

```json
{"v":1,"typ":"tally","call":"<h_call_bc>","writ":"<h2>","exe":"did:key:z6MkC",
 "op":"travel/charge","in":"<h_args_bc>","res":{"charge":"ch_8813","amount":58900,"currency":"USD"},
 "used":{"amount":58900,"count":1},"st":"ok","err":null,
 "rev":{"op":"travel/refund","ref":"ch_8813","until":1788486400},
 "sub":[],"wrt":[],"ts":1788400415,"sig":"<sigC1>"}
```

B returns tally_B to A, embedding tally_C and the writ it issued to C:

```json
{"v":1,"typ":"tally","call":"<h_call_ab>","writ":"<h1>","exe":"did:key:z6MkB",
 "op":"travel/book","in":"<h_args_ab>","res":{"pnr":"K7Q2ZD","fare":58900,"currency":"USD","charge":"ch_8813"},
 "used":{"amount":58900,"count":1},"st":"ok","err":null,
 "rev":{"op":"travel/cancel_booking","ref":"K7Q2ZD","until":1788486400},
 "sub":[{"...tally_C verbatim..."}],"wrt":[{"...writ_2 verbatim..."}],"ts":1788400418,"sig":"<sigB3>"}
```

A compensates by calling C directly with the reversal handle. No new writ is minted; the authority to reverse is the chain root's, proven by the tally:

```json
{"v":1,"typ":"call","id":"a-0c31","chain":[],"from":"did:key:z6MkA","op":"travel/refund",
 "args":{"tally":"<h_tally_C>","ref":"ch_8813"},"ts":1788401100,"sig":"<sigA2>"}
```

C looks up `<h_tally_C>` in its own tally store, finds the chain root `iss` is `did:key:z6MkA`, checks `from` matches and `until` has not passed, refunds, and returns a tally with `st: ok` and `rev: null`.

**IN and OUT.** IN: the four objects, the attenuation rule, the verification order, the bound registry, the reversal-by-tally rule, the chain-return rule (a tally must embed every sub-tally verbatim). OUT: discovery and endpoint location (A2A Agent Card, MCP `server/discover`); transport authentication (OAuth 2.1, DPoP, mTLS); task lifecycle and streaming (A2A task states, MCP Tasks extension); tool schemas (MCP); key-to-vendor binding (A2A signed Agent Card carrying the did:key); human approval (WebAuthn); payment settlement (x402, AP2); transparency logging (SCITT, optional overlay).

**Attenuation rule.** writ_2 is valid under writ_1 only if: `writ_2.iss == writ_1.hld`; `writ_2.prv == hash(writ_1)`; `writ_2.nbf >= writ_1.nbf` and `writ_2.exp <= writ_1.exp`; every key in `writ_1.bnd` appears in `writ_2.bnd` with the same `t`, and the child value is at most the parent value under that type's comparison (`max`: child integer ≤ parent; `count`: child ≤ parent; `prefix`: child string starts with parent string; `set`: child array ⊆ parent array; `window`: child interval inside parent interval); `writ_2.bnd` may add keys the parent lacks. Omitting a parent key, changing a type, or presenting an unknown type is a rejection. C checks this mechanically by walking the chain root to leaf, verifying each signature with the `iss` key decoded from the did:key itself, then applying the five comparisons. There is no policy language and no evaluation order to get wrong. In the example, C rejects a call with `amount: 65000` (violates `max`), a second call under `<h2>` (violates `count`, tracked in C's replay store keyed by writ hash), and any chain where writ_2 tried to lift `act` back to `travel/`.

**Verification procedure for A.** A needs on hand: its own writ_1, its own key, and the tallies it received. Nothing else, because did:key embeds the public key. Steps: (1) verify `tally_B.sig` with the key inside `tally_B.exe`; (2) check `tally_B.writ == hash(writ_1)` and `tally_B.call` equals the hash of the call A sent; (3) for each element of `tally_B.sub`, verify its signature with its own `exe` key; (4) for each sub-tally, find the writ it names by hash inside `tally_B.wrt`; a sub-tally whose writ is absent from `wrt` makes tally_B invalid, so B cannot hide a link; (5) run the attenuation rule on writ_1 → writ_2; (6) check `sub[i].used` totals do not exceed the leaf bounds and that `tally_B.used` covers the sum; (7) check every `ts` inside the writ window; (8) confirm `tally_B.exe == writ_1.hld` and `sub[i].exe == writ_2.hld`. Only Agent Cards are needed if A also wants to map a did:key to a vendor name, and that step is optional.

**Failure handling.** B crashes mid-task: A's call has no reply; A times out at `exp`, issues a `recall` for writ_1 to B's endpoint and, if the tally tree later arrives with a `sub` under writ_2, to C. C honors a recall by refusing further calls under `<h2>` and any descendant. Duplicate delivery: `call.id` plus `from` is the idempotency key; a duplicate returns the stored tally byte-for-byte, and `count` bounds prevent double execution even if the store is lost, because a writ hash can be consumed only `count` times. Cancel racing completion: a recall arriving after the tally was signed is answered with the existing tally (`st: ok`), and A moves to compensation using `rev`; a recall arriving before returns a tally with `st: canceled`. Both outcomes are named. Expired authority: any hop rejects a call after `exp` with `err.code = "expired"`; a tally signed after `exp` is invalid to A. Revoked key: a did:key cannot be revoked; the mitigation is short `exp` and the recall object; a key-compromise notice is out of scope and belongs to the Agent Card that binds the key to the vendor.

**Value at N=2.** A and B alone: B's runtime enforces a bound A signed, instead of a number inside a prompt; A holds a signed tally as evidence in any dispute; replay is stopped by `nnc` and `count`. Day one, with no C and no AS.

**Dependencies.** Ed25519, SHA-256, base64url, JCS canonical JSON, did:key. No online party at any step.

**Size and effort.** About 25 pages: objects 6, registry 4, attenuation and verification 5, failure semantics 5, examples 5. One strong developer: 4 weeks for a conformant library with test vectors, half of it on the replay store and the failure matrix.

**Weaknesses.** `count` bounds require per-verifier state (a replay store with a lifetime equal to `exp`), which is explicit but is state nonetheless. The chain grows linearly with hops and is repeated in every call; at ten hops a call carries ten kilobytes of writs. did:key gives no path from a key to a vendor without an Agent Card, so "who is C" needs the OUT layer. The `travel/` action namespace is a convention between A and B, and nothing prevents two vendors from disagreeing on what `travel/charge` means, though the bounds are typed and the tally is evidence regardless. Passes all ten tests; test 6 passes only because the replay store is named with a lifetime, and test 1 depends on keeping the registry at five types.

---

## Architecture 2: Voucher

Receipt-only. No new authority object. OAuth 2.1 with RFC 9396 Rich Authorization Requests carries authority; the standard defines only a signed, chainable receipt.

**Definition.** Voucher: return a signed, nestable statement of what an executor did, under which access token, enforcing which authorization details.

**Core objects.**

`voucher`:
- `v` integer 1, `typ` = `"voucher"`
- `exe` string, did:key of the executor (also published as a JWK in the executor's Agent Card)
- `tok` object, `{iss: string, jti: string, h: string}`: the issuer, `jti`, and SHA-256 of the access token the executor honored
- `det` array, the `authorization_details` objects the executor actually enforced, copied from the token
- `op` string, `in` string hash of request body, `res` object result
- `used` object, integers consumed against `det` fields
- `st`, `err`, `rev` as in Writ
- `sub` array of `voucher`, embedded verbatim
- `ts` integer, `sig` by `exe`

That is the entire standard, plus one rule: a voucher with `sub` entries is invalid unless each sub-voucher's `det` is a subset of the parent's `det` under the bound registry comparisons, applied field by field where the RAR `type` matches.

**Wire example.**

A's access token for B, issued by AS1, decoded JWT claims (RFC 9068, DPoP-bound):

```json
{"iss":"https://as1.example","sub":"did:key:z6MkA","aud":"https://b.example","jti":"t-41a9",
 "exp":1788403600,"cnf":{"jkt":"<thumbA>"},
 "authorization_details":[{"type":"travel.book","max_amount_cents":60000,"currency":"USD",
   "count":1,"fare":["refundable"],"pax":"<h_pax>","dates":[20261015,20261019]}]}
```

B requests a token from AS3 (C's authorization server) using B's standing client credentials, asking for narrowed details. AS3 issues a token with `jti: "t-90ee"`. Whether AS3 honored the narrowing is invisible to A; the voucher is where it becomes visible.

C's voucher to B:

```json
{"v":1,"typ":"voucher","exe":"did:key:z6MkC",
 "tok":{"iss":"https://as3.example","jti":"t-90ee","h":"<h_tok3>"},
 "det":[{"type":"travel.charge","max_amount_cents":60000,"currency":"USD","count":1,
         "fare":["refundable"],"pax":"<h_pax>"}],
 "op":"travel/charge","in":"<h_args_bc>","res":{"charge":"ch_8813","amount":58900,"currency":"USD"},
 "used":{"max_amount_cents":58900,"count":1},"st":"ok","err":null,
 "rev":{"op":"travel/refund","ref":"ch_8813","until":1788486400},"sub":[],"ts":1788400415,"sig":"<sigC1>"}
```

B's voucher to A:

```json
{"v":1,"typ":"voucher","exe":"did:key:z6MkB",
 "tok":{"iss":"https://as1.example","jti":"t-41a9","h":"<h_tok1>"},
 "det":[{"type":"travel.book","max_amount_cents":60000,"currency":"USD","count":1,
         "fare":["refundable"],"pax":"<h_pax>","dates":[20261015,20261019]}],
 "op":"travel/book","in":"<h_args_ab>","res":{"pnr":"K7Q2ZD","fare":58900,"charge":"ch_8813"},
 "used":{"max_amount_cents":58900,"count":1},"st":"ok","err":null,
 "rev":{"op":"travel/cancel_booking","ref":"K7Q2ZD","until":1788486400},
 "sub":[{"...C voucher verbatim..."}],"ts":1788400418,"sig":"<sigB3>"}
```

Compensation: A has no token for C. A asks AS1 for a token with `authorization_details: [{type: "travel.refund", ref: "ch_8813"}]` and `resource: https://c.example`, which works only if AS1 and AS3 federate. Otherwise A asks B to refund, and B uses its standing credential.

**IN and OUT.** IN: the voucher object, the nesting subset rule, the key discovery rule (executor JWK in its Agent Card), and the bound registry used for the subset comparison. OUT: authority (OAuth 2.1, RFC 9396, RFC 8693, RFC 9449); discovery (A2A); lifecycle (A2A, MCP Tasks); reversal authority (OAuth; a refund needs a new grant); federation between authorization servers (the identity-chaining draft, or a contract).

**Attenuation rule.** There is none at request time. AS3 decides what C's token says, by policy A cannot see. The standard's only lever is after the fact: A compares `sub[0].det` against its own `det` using the registry (`max_amount_cents` 60000 ≤ 60000, `count` 1 ≤ 1, `fare` subset, `pax` equal). If C's signed `det` is wider than A's, A has proof that B obtained more authority than A gave, signed by C. C itself checks nothing beyond its own token.

**Verification procedure for A.** On hand: A's own token (or its hash), B's and C's Agent Cards for their JWKs (or did:keys inline). Steps: (1) verify `voucher_B.sig`; (2) check `voucher_B.tok.h` equals the hash of the token A sent; (3) check `voucher_B.det` equals the `authorization_details` in that token; (4) verify each sub-voucher's signature; (5) run the registry subset check `sub.det ⊆ det`; (6) check `used` within `det`; (7) check timestamps within token `exp`.

**Failure handling.** B crashes: A gets no voucher, times out, and has nothing to cancel with except B's task API (A2A `CancelTask`), which reaches C only if B implements it. Duplicate delivery: no idempotency key in the standard; the DPoP `jti` on B's request to C is single-use, which stops exact replay but not a re-issued request. Cancel racing completion: whichever B's task state machine reports; the voucher records the outcome. Expired authority: C rejects the token; A learns nothing until B reports. Revoked key: OAuth revocation at AS3 for the token; the executor signing key is revoked by rotating the Agent Card JWK, and old vouchers become unverifiable unless A cached the key.

**Value at N=2.** The largest of the six, per line of spec. A and B already speak OAuth; adding one signed object to each response gives A signed evidence tied to a token hash, with two weeks of work and no new authority model.

**Dependencies.** Ed25519, SHA-256, JCS. Online parties: AS1 for issuance, AS3 for hop two, and both again for compensation.

**Size and effort.** About 12 pages. Two weeks for one developer, because everything except the voucher already exists.

**Weaknesses.** It does not close the gap in `02-prior-art.md` section 4: C still cannot refuse an over-limit charge on the strength of A's bound, only on the strength of whatever AS3 minted. It fails test 2 (offline verification of authority; A verifies evidence, not authorization) and test 8 (two authorization servers must be up, and federated, for hop two). The subset check exists but runs at audit time, after the money has moved. Skeptic question 3 (the request C rejects) has no answer. This is the design to ship if the team decides the steelman wins.

---

## Architecture 3: Tether

Session protocol. A TCP-like bidirectional agent session with an identity handshake, sequence numbers, task frames, and cancel frames, over any byte transport.

**Definition.** Tether: hold an authenticated, ordered, resumable two-way stream between two agents in which tasks, progress, results, and cancellations are frames.

**Core objects.** Frames are newline-delimited JSON, one per line. Every frame after the handshake carries `seq` (integer, per direction, starting at 1) and `mac` (HMAC-SHA256 under the session key over the JCS bytes of the frame minus `mac`). Frames marked portable also carry `sig` under the sender's identity key so they can leave the session.

- `hello`: `{typ, id: did:key, eph: string X25519 public key, nnc: string, ts: integer, sig}`; both sides send one; session key = HKDF(X25519 shared secret, both nonces)
- `ack`: `{typ, seq, upto: integer}` acknowledges all frames up to `upto`
- `task` (portable): `{typ, seq, tid: string, op: string, bnd: object (registry bounds), args: object, deadline: integer, lineage: array of task frames from upstream sessions, sig}`
- `progress`: `{typ, seq, tid, pct: integer, note: string}`
- `result` (portable): `{typ, seq, tid, st: ok|failed|canceled, res: object, used: object, rev: object|null, sub: array of result frames, sig}`
- `cancel` (portable): `{typ, seq, tid, reason: string, sig}`
- `canceled`: `{typ, seq, tid, at: integer}`
- `error`: `{typ, seq, code: string, ref: integer (offending seq), msg: string}`
- `resume`: `{typ, id, sid: string, last: integer, sig}`; reopens a session after transport loss, replaying frames above `last`
- `close`: `{typ, seq, reason: string}`

**Wire example.** Session A→B, A's direction only, then B→C, then results flowing back. Lines are literal wire bytes.

```
{"typ":"hello","id":"did:key:z6MkA","eph":"<xA>","nnc":"nA1","ts":1788400000,"sig":"<sigA1>"}
{"typ":"hello","id":"did:key:z6MkB","eph":"<xB>","nnc":"nB1","ts":1788400001,"sig":"<sigB1>"}
{"typ":"task","seq":1,"tid":"t1","op":"travel/book","bnd":{"amount":{"t":"max","v":60000},"count":{"t":"count","v":1},"fare":{"t":"set","v":["refundable"]},"pax":{"t":"set","v":["<h_pax>"]},"dates":{"t":"window","v":[20261015,20261019]}},"args":{"pax":"<h_pax>"},"deadline":1788403600,"lineage":[],"sig":"<sigA2>","mac":"<m1>"}
{"typ":"ack","seq":1,"upto":1,"mac":"<m2>"}
```

B opens a session to C and forwards the task frame as lineage:

```
{"typ":"hello","id":"did:key:z6MkB","eph":"<xB2>","nnc":"nB2","ts":1788400400,"sig":"<sigB2>"}
{"typ":"hello","id":"did:key:z6MkC","eph":"<xC>","nnc":"nC1","ts":1788400401,"sig":"<sigC1>"}
{"typ":"task","seq":1,"tid":"t1.1","op":"travel/charge","bnd":{"amount":{"t":"max","v":60000},"count":{"t":"count","v":1},"fare":{"t":"set","v":["refundable"]},"pax":{"t":"set","v":["<h_pax>"]}},"args":{"amount":58900,"currency":"USD","pnr":"K7Q2ZD"},"deadline":1788402000,"lineage":[{"...A's task frame t1 with sigA2, mac stripped..."}],"sig":"<sigB3>","mac":"<m3>"}
{"typ":"progress","seq":2,"tid":"t1.1","pct":50,"note":"authorizing","mac":"<m4>"}
{"typ":"result","seq":3,"tid":"t1.1","st":"ok","res":{"charge":"ch_8813","amount":58900},"used":{"amount":58900,"count":1},"rev":{"op":"travel/refund","ref":"ch_8813","until":1788486400},"sub":[],"sig":"<sigC2>","mac":"<m5>"}
```

B returns to A on the first session:

```
{"typ":"result","seq":2,"tid":"t1","st":"ok","res":{"pnr":"K7Q2ZD","fare":58900,"charge":"ch_8813"},"used":{"amount":58900,"count":1},"rev":{"op":"travel/cancel_booking","ref":"K7Q2ZD","until":1788486400},"sub":[{"...C's result frame with sigC2, mac stripped..."}],"sig":"<sigB4>","mac":"<m6>"}
```

A cancels while work is in flight, or compensates afterward by opening a session to C and sending a `task` with `op: "travel/refund"`, `args: {result: "<h_resultC>"}`, and `lineage` containing the original chain so C can see A at the root:

```
{"typ":"cancel","seq":2,"tid":"t1","reason":"user_abort","sig":"<sigA3>","mac":"<m7>"}
{"typ":"canceled","seq":3,"tid":"t1","at":1788400900,"mac":"<m8>"}
```

**IN and OUT.** IN: handshake, frame set, sequencing and acknowledgment, resume, cancel semantics, lineage rule, bound registry. OUT: discovery (A2A); how to find a byte transport (WebSocket, TCP, stdio, a pair of HTTP streams); tool schemas (MCP); persistence of results after the session (the caller's problem); payment.

**Attenuation rule.** A `task` frame with non-empty `lineage` is valid only if its `bnd` is a subset of `lineage[last].bnd` under the registry, its `deadline` is no later, and `lineage[last].sig` verifies under the `id` that sent it and that `id` is the peer who opened the current session (B). C checks the lineage frames' identity signatures, then the five comparisons, before executing. Mechanically identical to Writ, but the authority object is a task frame rather than a standalone writ, and the session identity replaces `hld`.

**Verification procedure for A.** On hand: the result frames received (identity-signed, so they survive the session), the task frames A sent, the did:keys. Steps: (1) verify `result.sig` under B's session identity; (2) match `tid` to A's task and `used` to A's `bnd`; (3) for each `sub`, verify `sig` under its `id`; (4) A does not have B's task frame to C unless B includes it, so the standard requires `sub[i]` to carry `task` (the frame that produced it) so A can run the subset check; (5) compare sub-task `bnd` against A's `bnd`. A cannot verify that B and C's session actually happened, only that C signed a result consistent with a task B signed.

**Failure handling.** B crashes mid-task: A's session drops; A retries `resume` with `last`; if B's state is gone, B answers `error code: "unknown_session"` and A reissues the task under the same `tid`, which is the idempotency key. B's session to C also dropped; C keeps running or times out at `deadline`; nobody tells A until B resumes. Duplicate delivery: sequence numbers reject duplicates within a session; across sessions `tid` is the key. Cancel racing completion: whichever frame has the lower `seq` in the receiver's direction wins; a `cancel` after `result` is answered with `error code: "already_complete"` and the result's `rev`. Expired authority: `deadline` in the task frame; a result after it is rejected. Revoked key: close the session; a compromised identity key has no revocation path except the Agent Card.

**Value at N=2.** High for interactive work: streaming progress, backpressure via acks, cancel with a defined answer, resume after transport loss. Two agents get a better MCP transport on day one.

**Dependencies.** Ed25519, X25519, HKDF, HMAC-SHA256, JCS, a bidirectional byte transport.

**Size and effort.** About 40 pages, because a state machine must be written down completely (test 6 demands it). Six weeks for one developer, most of it on resume and the cancel race.

**Weaknesses.** It fails test 3: the same messages do not work over a message queue or a directory of files, because the session key, sequence numbers, and acks assume a live pair. It fails test 6 in spirit: authority lives in "the peer who opened this session," so evidence of who authorized what has to be reconstructed from lineage copies. It duplicates what A2A streaming and MCP already do, which is the worst place to spend a standard. The portable frames (task, result, cancel with `sig`) are the good part, and they are Writ's objects wearing a session.

---

## Architecture 4: Docket

Log-anchored. Every delegation and result is registered in a transparency log (SCITT RFC 9943 style); verification is log inclusion plus signature.

**Definition.** Docket: make every delegation, result, and cancellation a registered, timestamped statement in an append-only log, so the record of who authorized and who did what is public and non-repudiable.

**Core objects.**

`statement` (the payload SCITT signs):
- `v` integer 1, `typ` one of `"delegation"`, `"result"`, `"void"`
- `iss` string did:key of the signer
- `sub` string, the subject: for a delegation, the holder's did:key; for a result, the delegation entry it executed under; for a void, the entry being voided
- `at` string or null, log entry reference of the parent (`"<log>/<index>"`)
- `body` object: for delegation, `{hld, bnd, nbf, exp}` as in Writ; for result, `{op, in, res, used, st, err, rev, sub_entries: array of entry references}`; for void, `{reason}`
- `ts` integer

`signed_statement`: COSE_Sign1 over CBOR of `statement`, per SCITT, base64url when carried in JSON.

`entry` (what a party keeps):
- `stmt` string, the signed statement base64url
- `log` string, URL of the transparency service
- `idx` integer, leaf index
- `rcpt` string, the SCITT Receipt (COSE, base64url) proving inclusion under a signed tree head

**Wire example.** A registers its delegation to B, gets entry 8812 on log L1 (A's vendor runs L1):

```json
{"stmt":"<cose:{v:1,typ:delegation,iss:did:key:z6MkA,sub:did:key:z6MkB,at:null,body:{hld:did:key:z6MkB,bnd:{act:{t:prefix,v:travel/},amount:{t:max,v:60000},count:{t:count,v:1},fare:{t:set,v:[refundable]},pax:{t:set,v:[<h_pax>]},dates:{t:window,v:[20261015,20261019]}},nbf:1788400000,exp:1788403600},ts:1788400000}>",
 "log":"https://log.vendor1.example","idx":8812,"rcpt":"<cose_receipt_L1_8812>"}
```

B registers its narrowed delegation to C on L1 as well (the rule: register on the parent's log, so a chain lives in one log):

```json
{"stmt":"<cose:{v:1,typ:delegation,iss:did:key:z6MkB,sub:did:key:z6MkC,at:\"https://log.vendor1.example/8812\",body:{hld:did:key:z6MkC,bnd:{act:{t:prefix,v:travel/charge},amount:{t:max,v:60000},count:{t:count,v:1},fare:{t:set,v:[refundable]},pax:{t:set,v:[<h_pax>]},dates:{t:window,v:[20261015,20261019]}},nbf:1788400000,exp:1788402000},ts:1788400402}>",
 "log":"https://log.vendor1.example","idx":8813,"rcpt":"<cose_receipt_L1_8813>"}
```

B calls C over any transport, passing both entries. C checks inclusion (offline, from the receipts and L1's public key, which C must already trust), checks no `void` for 8812 or 8813 exists (online query to L1, or accept a tree head no older than 60 seconds), executes, and registers its result:

```json
{"stmt":"<cose:{v:1,typ:result,iss:did:key:z6MkC,sub:\"https://log.vendor1.example/8813\",at:\"https://log.vendor1.example/8813\",body:{op:travel/charge,in:<h_args_bc>,res:{charge:ch_8813,amount:58900},used:{amount:58900,count:1},st:ok,err:null,rev:{op:travel/refund,ref:ch_8813,until:1788486400},sub_entries:[]},ts:1788400415}>",
 "log":"https://log.vendor1.example","idx":8814,"rcpt":"<cose_receipt_L1_8814>"}
```

B registers its result at 8815 with `sub_entries: ["https://log.vendor1.example/8814"]` and hands A the entry references. A compensates by registering a `void` for 8812 (which stops all descendants) and then a delegation to itself or to C for `travel/refund` at 8816, calling C with it.

**IN and OUT.** IN: the three statement types, the parent-link rule, the "register on the parent's log" rule, the void rule, the freshness window, the bound registry, the attenuation comparison. OUT: the log itself and its receipt format (SCITT RFC 9943, SCRAPI for the API); COSE (RFC 9052); discovery (A2A); transport; log operator governance.

**Attenuation rule.** Same five comparisons as Writ, applied between `body.bnd` of the delegation at `at` and the new delegation. Additionally, the log refuses registration of a delegation whose `at` is voided or expired, which is enforcement by an online party as well as by C. C checks: both receipts verify under L1's key, `at` linkage matches, bounds subset holds, and no void is known within the freshness window.

**Verification procedure for A.** On hand: L1's public key (its own vendor's), the entry references B returned. Steps: (1) fetch or already hold entries 8812 to 8815; (2) verify each `rcpt` under L1's key; (3) verify each COSE signature under the `iss` did:key; (4) walk `at` links and run the subset comparison; (5) check `used` against bounds; (6) check that no `void` precedes the result index. Everything after fetching is offline.

**Failure handling.** B crashes: A registers a `void` for 8812; C, on its next freshness check, refuses further work; anything C already completed is at 8814 with a `rev` A can act on. Duplicate delivery: the log deduplicates identical statements by hash, and a result statement for an already-consumed `count` is refused at registration. Cancel racing completion: strictly ordered by log index, which is the cleanest answer among the six: if the void's index is lower than the result's, the result is invalid. Expired authority: `exp` in the statement plus the log's timestamp; no clock argument. Revoked key: a `void` from any ancestor, or a key-revocation statement type in a later version.

**Value at N=2.** Weak. Two agents need a log, so one of them must run it, and then the other must trust it. The benefit, a timestamped non-repudiable record, is real but is an audit feature, not a first-call feature.

**Dependencies.** COSE_Sign1, CBOR, SHA-256 Merkle trees, Ed25519, a transparency service with a signed tree head, its public key distribution. Online at every registration.

**Size and effort.** About 20 pages on top of RFC 9943. Five weeks: COSE libraries exist, but a conformant registration client with freshness handling and a test log is real work.

**Weaknesses.** Fails test 8: the list of entities whose downtime stops A and B is non-empty (L1). Fails test 5. Fails test 7 as specified, because COSE and CBOR are not readable in a log file; a JSON profile would fix that at the cost of leaving SCITT. Partially fails test 2: verification is offline, registration is not. Cross-domain logs are the unsolved part: "register on the parent's log" means C must trust vendor 1's log, and a chain through three vendors is one vendor's record. Its cancel and freshness semantics are excellent and worth stealing as an optional anchor.

---

## Architecture 5: Behalf

Pure HTTP profile. The protocol is a small set of HTTP header fields plus a well-known document, with RFC 9421 message signatures. Nothing exists outside HTTP.

**Definition.** Behalf: let an HTTP request carry a chain of delegator-signed grant headers, and let its response carry executor-signed return headers, so authority and evidence ride the messages that already exist.

**Core objects.** All are HTTP fields using RFC 9651 Structured Fields.

- `Behalf-Grant-N` (Dictionary), N = 1 for the root, increasing toward the leaf: members `iss` (String, did:key), `hld` (String), `nbf` (Integer), `exp` (Integer), `nnc` (Byte Sequence), `act` (String, prefix), and one member per bound with a type suffix: `amount.max=60000`, `count.count=1`, `fare.set=("refundable")`, `pax.set=(:<h_pax>:)`, `dates.window=(20261015 20261019)`, `currency.set=("USD")`
- `Signature-Input` and `Signature` (RFC 9421), with one label per grant (`g1`, `g2`) whose covered components are exactly `("behalf-grant-N")`, tagged `behalf-grant`, plus the requester's label `req` covering method, authority, path, `Content-Digest`, and every grant field
- `Behalf-Return-N` (Dictionary) on responses: `exe` (String), `grant` (Integer, which N was honored), `st` (Token), `used.amount` (Integer), `used.count` (Integer), `rev.op` (String), `rev.path` (String), `rev.until` (Integer), `err` (String or absent)
- Response `Signature-Input` and `Signature` with a label per return (`r1`, `r2`), each covering `@status`, `Content-Digest`, its own `behalf-return-N`, and the grant fields from the request via the `;req` parameter
- `/.well-known/behalf` (JSON): `{v: 1, id: did:key, keys: [JWK], bounds: [supported bound keys], reverse: {path_template: string}, max_chain: integer}`

**Wire example.** A calls B:

```
POST /book HTTP/1.1
Host: b.example
Content-Type: application/json
Content-Digest: sha-256=:<h_body_ab>:
Behalf-Grant-1: iss="did:key:z6MkA", hld="did:key:z6MkB", nbf=1788400000, exp=1788403600, nnc=:Qm3bq8w1s5XK7jZR:, act="travel/", amount.max=60000, currency.set=("USD"), count.count=1, fare.set=("refundable"), pax.set=(:<h_pax>:), dates.window=(20261015 20261019)
Signature-Input: g1=("behalf-grant-1");keyid="did:key:z6MkA";created=1788400000;tag="behalf-grant", req=("@method" "@authority" "@path" "content-digest" "behalf-grant-1");keyid="did:key:z6MkA";created=1788400005
Signature: g1=:<sigA1>:, req=:<sigA2>:

{"pax":"<h_pax>"}
```

B calls C, copying `Behalf-Grant-1` and its `g1` signature verbatim and adding its own grant:

```
POST /charge HTTP/1.1
Host: c.example
Content-Type: application/json
Content-Digest: sha-256=:<h_body_bc>:
Behalf-Grant-1: (identical bytes to above)
Behalf-Grant-2: iss="did:key:z6MkB", hld="did:key:z6MkC", nbf=1788400000, exp=1788402000, nnc=:aZ0pLw9cR2tNv4Hy:, act="travel/charge", amount.max=60000, currency.set=("USD"), count.count=1, fare.set=("refundable"), pax.set=(:<h_pax>:), dates.window=(20261015 20261019)
Signature-Input: g1=("behalf-grant-1");keyid="did:key:z6MkA";created=1788400000;tag="behalf-grant", g2=("behalf-grant-2");keyid="did:key:z6MkB";created=1788400402;tag="behalf-grant", req=("@method" "@authority" "@path" "content-digest" "behalf-grant-1" "behalf-grant-2");keyid="did:key:z6MkB";created=1788400412
Signature: g1=:<sigA1>:, g2=:<sigB1>:, req=:<sigB2>:

{"amount":58900,"currency":"USD","fare":"refundable","pax":"<h_pax>","pnr":"K7Q2ZD"}
```

C responds:

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-256=:<h_res_c>:
Behalf-Return-2: exe="did:key:z6MkC", grant=2, st=ok, used.amount=58900, used.count=1, rev.op="travel/refund", rev.path="/charges/ch_8813/refund", rev.until=1788486400
Signature-Input: r2=("@status" "content-digest" "behalf-return-2" "behalf-grant-1";req "behalf-grant-2";req "content-digest";req);keyid="did:key:z6MkC";created=1788400415
Signature: r2=:<sigC1>:

{"charge":"ch_8813","amount":58900,"currency":"USD"}
```

B responds to A, forwarding `Behalf-Return-2` and `r2` verbatim (with C's response body digest as `Behalf-Return-2` already binds it, and the body itself under `sub` in B's JSON):

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-256=:<h_res_b>:
Behalf-Return-1: exe="did:key:z6MkB", grant=1, st=ok, used.amount=58900, used.count=1, rev.op="travel/cancel_booking", rev.path="/bookings/K7Q2ZD", rev.until=1788486400
Behalf-Return-2: (identical bytes to C's)
Behalf-Grant-2: (identical bytes, so A has the child grant)
Signature-Input: r1=("@status" "content-digest" "behalf-return-1" "behalf-return-2" "behalf-grant-2" "behalf-grant-1";req);keyid="did:key:z6MkB";created=1788400418, r2=(...C's entry verbatim...), g2=(...verbatim...)
Signature: r1=:<sigB3>:, r2=:<sigC1>:, g2=:<sigB1>:

{"pnr":"K7Q2ZD","fare":58900,"charge":"ch_8813","sub":[{"charge":"ch_8813","amount":58900,"currency":"USD"}]}
```

A compensates directly at C:

```
POST /charges/ch_8813/refund HTTP/1.1
Host: c.example
Behalf-Return-2: (C's bytes verbatim)
Behalf-Grant-1: (verbatim)
Behalf-Grant-2: (verbatim)
Signature-Input: g1=(...), g2=(...), r2=(...), req=("@method" "@authority" "@path" "behalf-return-2" "behalf-grant-1" "behalf-grant-2");keyid="did:key:z6MkA";created=1788401100
Signature: g1=:<sigA1>:, g2=:<sigB1>:, r2=:<sigC1>:, req=:<sigA3>:
```

C verifies that `req` is signed by the `iss` of `Behalf-Grant-1`, the root, and that `rev.until` has not passed.

**IN and OUT.** IN: the field definitions, the signature label conventions, the chain-copy rule, the return-copy rule, the well-known document, the reversal request shape, the bound registry expressed as Structured Field member types. OUT: HTTP itself, RFC 9421, RFC 9651, RFC 9530 Content-Digest, TLS, discovery (A2A card can point at `/.well-known/behalf`), OAuth for any additional transport authentication the resource wants, tool schemas.

**Attenuation rule.** `Behalf-Grant-2` is valid under `Behalf-Grant-1` iff `iss` of 2 equals `hld` of 1, `nbf` and `exp` nest, `act` of 2 starts with `act` of 1, and for every bound member `k.t` in 1 there is `k.t` in 2 with the child at most the parent under type `t`. Because the root grant's bytes are copied verbatim and covered by `g1`, C verifies A's signature over the exact header value, and there is no parent hash: the parent is present. C checks with a Structured Field parser and five comparisons.

**Verification procedure for A.** On hand: nothing beyond the response, since keys are inside the did:keys and A's own grant bytes are in the request A sent. Steps: (1) verify `r1` under `exe` of `Behalf-Return-1`; (2) verify `r2` under `exe` of `Behalf-Return-2`, reconstructing the `;req` components from A's stored request plus the `Behalf-Grant-2` copy; (3) verify `g2` under `iss` of grant 2 and run the attenuation rule against grant 1; (4) check `used` totals against grant 1; (5) check `created` values inside the grant windows.

**Failure handling.** B crashes: A's request fails or times out; A retries with the same `nnc`, and B treats `(iss, nnc)` as the idempotency key; if B lost state, `count.count=1` stops C from charging twice, because C keyed its replay store on the bytes of `Behalf-Grant-2`. Duplicate delivery: same key. Cancel racing completion: cancel is `DELETE` on the task resource B exposed, signed by A; a `409 Conflict` with `Behalf-Return-1` means it completed and A must use `rev`. Expired authority: `401` with `Behalf-Error: expired`. Revoked key: rotate the JWK in `/.well-known/behalf`; grants under the old key are refused after the document's cache TTL.

**Value at N=2.** The highest developer-facing value of the six: `curl` shows the whole exchange, RFC 9421 libraries already exist in most languages, no new body format, and the first hop is literally putting strings in headers, which is OAuth's adoption lesson kept.

**Dependencies.** Ed25519 through RFC 9421's `ed25519` algorithm, SHA-256, RFC 9651 parsing, did:key. No online party.

**Size and effort.** About 18 pages. Three weeks, mostly test vectors for the `;req` response signatures, which implementers get wrong.

**Weaknesses.** Fails test 3: the messages do not work over a queue or a file drop without inventing a serialization of HTTP fields, at which point it is Writ with a worse encoding. Header size limits (8 KB at most proxies) cap chain depth at roughly six hops. Structured Fields have no nested dictionaries, so the bound registry is flattened into member names, which is legible but brittle. Response signatures covering request components (`;req`) are the least-implemented corner of RFC 9421. Reverse proxies strip or reorder unknown headers often enough that `g1` verification will fail in production for reasons unrelated to the protocol.

---

## Architecture 6: Pouch

Store-and-forward envelope. SMTP-like signed envelopes with per-hop stamps (like `Received:` headers), transport-agnostic, asynchronous by default.

**Definition.** Pouch: relay a sealed, signed work order through any number of hops, each of which stamps acceptance of responsibility, and return a sealed, signed report or a bounce along the same path.

**Core objects.**

`pouch` (the envelope):
- `v` integer 1, `typ` = `"pouch"`
- `id` string, unique per originator
- `kind` string, one of `order`, `report`, `cancel`, `bounce`
- `from`, `to` strings, did:keys
- `re` string or null, `id` of the pouch this answers
- `ttl` integer, absolute Unix seconds after which any hop must bounce instead of forwarding
- `budget` integer, remaining delivery attempts; decremented per attempt, bounce at 0
- `auth` array of `writ` objects (Architecture 1 objects, unchanged), root first; empty for a `bounce`
- `body` object: for `order`, `{op, args}`; for `report`, a `tally`; for `cancel`, `{writ: hash, reason}`; for `bounce`, `{code, msg, last_stamp: integer}`
- `stamps` array of `stamp`, appended in order, never modified
- `sig` string by `from`, over everything except `stamps`

`stamp`:
- `by` string did:key, `at` integer, `act` string one of `accepted`, `forwarded`, `executed`, `bounced`, `next` string did:key or null, `prev` string hash of the previous stamp or of the pouch body for the first, `sig` by `by`

**Wire example.** A drops an order for B into B's inbox (an HTTP POST, a queue, or a file):

```json
{"v":1,"typ":"pouch","id":"a-001","kind":"order","from":"did:key:z6MkA","to":"did:key:z6MkB","re":null,
 "ttl":1788403600,"budget":5,"auth":[{"...writ_1..."}],
 "body":{"op":"travel/book","args":{"pax":"<h_pax>"}},
 "stamps":[{"by":"did:key:z6MkB","at":1788400020,"act":"accepted","next":null,"prev":"<h_body_a001>","sig":"<sigB1>"}],
 "sig":"<sigA1>"}
```

B stamps `accepted` and returns the stamped envelope to A immediately (the acknowledgment). B then originates its own order to C:

```json
{"v":1,"typ":"pouch","id":"b-014","kind":"order","from":"did:key:z6MkB","to":"did:key:z6MkC","re":"a-001",
 "ttl":1788402000,"budget":3,"auth":[{"...writ_1..."},{"...writ_2..."}],
 "body":{"op":"travel/charge","args":{"amount":58900,"currency":"USD","fare":"refundable","pax":"<h_pax>","pnr":"K7Q2ZD"}},
 "stamps":[{"by":"did:key:z6MkC","at":1788400412,"act":"accepted","next":null,"prev":"<h_body_b014>","sig":"<sigC1>"},
           {"by":"did:key:z6MkC","at":1788400415,"act":"executed","next":null,"prev":"<h_stamp_c1>","sig":"<sigC2>"}],
 "sig":"<sigB2>"}
```

C sends a report to B:

```json
{"v":1,"typ":"pouch","id":"c-330","kind":"report","from":"did:key:z6MkC","to":"did:key:z6MkB","re":"b-014",
 "ttl":1788486400,"budget":5,"auth":[],
 "body":{"...tally_C exactly as in Architecture 1..."},
 "stamps":[{"by":"did:key:z6MkB","at":1788400416,"act":"accepted","next":null,"prev":"<h_body_c330>","sig":"<sigB3>"}],
 "sig":"<sigC3>"}
```

B sends its report to A with `body` = tally_B embedding tally_C, and A's acceptance stamp comes back. A cancels while in flight by sending `kind: "cancel"` with `body: {writ: "<h1>", reason: "user_abort"}` to B; B forwards it to C with its own stamp, and C stamps `executed` on the cancel or, if the charge already ran, bounces the cancel with `code: "already_executed"` and the tally reference, after which A sends an `order` with `op: travel/refund` and `auth: []` plus `args.tally` as in Architecture 1.

**IN and OUT.** IN: the envelope, the stamp, the four kinds, the bounce rule, the ttl and budget rules, the forwarding rule (a hop that forwards must stamp `forwarded` with `next`), plus the Writ objects by reference. OUT: inbox location (A2A card or `.well-known`), transport (HTTP, AMQP, files, email), retry timing (recommended backoff in an appendix), payment, discovery.

**Attenuation rule.** Identical to Writ; `auth` is a Writ chain and C runs the same five comparisons. The envelope adds only that `ttl` of an order must not exceed the leaf writ's `exp`.

**Verification procedure for A.** On hand: the stamped envelopes A received back, the did:keys within. Steps: (1) verify `pouch.sig` under `from`; (2) verify each stamp's `sig` under `by` and that `prev` hashes chain; (3) run the Writ verification on the tally in `body`; (4) for a bounce, verify the last stamp is `bounced` by the party that gave up; (5) check every `at` before `ttl`.

**Failure handling.** This is the architecture that handles it best. B crashes: A holds B's `accepted` stamp, which is B's signed promise; A retries delivery of the same `id` until `budget` is exhausted, then treats silence as a bounce and issues a cancel plus, if a report from C surfaces later, a refund order. Duplicate delivery: `id` plus `from` is the key; a hop that has already stamped `accepted` returns the stamped copy. Cancel racing completion: stamps are ordered by `prev` hashes on each hop; a cancel that arrives after an `executed` stamp is bounced with `already_executed`, which is a defined message with a next action. Expired authority: `ttl` and writ `exp` both force a bounce with `expired`. Revoked key: a `cancel` from any ancestor; key revocation itself belongs to the Agent Card.

**Value at N=2.** Good for long-running work: an order that takes hours survives either party's restart, and every silence becomes a bounce with a reason. Weak for interactive work: no streaming, no progress except by polling for a report.

**Dependencies.** Ed25519, SHA-256, JCS, did:key, plus an inbox per agent, which is one more thing to stand up than an HTTP endpoint.

**Size and effort.** About 30 pages, since it contains Writ plus the envelope. Five weeks.

**Weaknesses.** It is Writ plus routing. The stamps prove that a hop said "accepted," which is a promise, not a fact; SMTP taught that "I accepted responsibility" is unenforceable and led to thirty years of bounce spam. The report path retraces hops, so a report is delayed by every intermediary's queue, and A cannot short-circuit to C without leaving the envelope model. Test 1 is at risk: the mandatory core is larger than one week of work. Tests 2, 3, 6, 7, 8, 10 pass strongly.

---

## Cross-cutting decisions

**Identifier scheme: did:key, with an optional binding to a URL.** did:key is self-certifying: the identifier is the public key, so verification needs no resolution, no DNS, no CA, and no registry, which is what tests 2, 5, and 8 demand. A raw multibase key carries the same bits but loses the method prefix that lets did:web or another method appear in a later version without a flag day (test 9). A URL identifier forces an online fetch and a TLS trust list into every verification. The one thing did:key cannot say is which vendor stands behind the key; that binding belongs to the A2A signed Agent Card, which lists the did:key, and it is optional for verification and mandatory only for liability. Do not invent an identifier.

**Signature envelope: bare detached Ed25519 over JCS-canonical JSON, with `sig` as a sibling field.** JWS compact serialization base64-encodes the payload, which destroys log readability (test 7) and invites algorithm confusion through `alg`. COSE is CBOR, which is binary-first, and the historian's rule is that semantics must survive a year in a readable form before a binary encoding is earned. DSSE is close, but its PAE also base64-encodes the payload, and it exists to serve in-toto, whose ecosystem is not this one. A bare signature over RFC 8785 canonical bytes keeps the object readable, has one algorithm (no negotiation, no downgrade), and is four lines of code in any language with an Ed25519 library. Two rules make JCS safe: no floating point anywhere in a signed object (integers only, which the examples already obey), and strings must be NFC-normalized by the producer, with verifiers comparing bytes, never re-normalizing. A JWS or COSE profile can be added later as a non-mandatory extension once the fields have stabilized.

**Timestamp format: integer Unix seconds, UTC.** Not ISO 8601 strings, not milliseconds. Comparisons are integer comparisons, canonicalization is trivial, and there is no timezone or fractional-second parse to disagree on. Skew tolerance: a verifier accepts `ts` up to 120 seconds in the future; validity windows are checked strictly.

**How receipts reference authority: SHA-256 of the canonical bytes of the whole signed writ, including `sig`, base64url without padding, written as the bare 43-character string.** Hashing the signed object rather than the unsigned payload binds the receipt to one specific signature, so a re-signed writ with identical fields is a different authority and a tally cannot be re-pointed at it. The hash algorithm is fixed by `v`; a `sha256:` prefix is unnecessary while `v` is 1 and can be introduced when `v` is 2, under the rule that unknown prefixes are rejected.

**Bound registry for v0.1: five types, five comparisons, no policy language.**

| type | value | child valid under parent when | consumed by executor? |
|---|---|---|---|
| `max` | integer | child ≤ parent | yes, `used.<key>` ≤ leaf value |
| `count` | integer | child ≤ parent | yes, executor replay store per writ hash |
| `prefix` | string | child starts with parent (byte comparison) | no |
| `set` | array of strings or integers | every child element is in parent | no; the call value must be in the leaf set |
| `window` | two integers, inclusive | parent[0] ≤ child[0] and child[1] ≤ parent[1] | no; the call value must fall inside |

Equality is a `set` of one element. Glob and regex are deliberately excluded: deciding whether one glob is a subset of another is not a comparison, and a verifier that cannot decide subset cannot enforce attenuation. Numeric minimums are excluded because they widen, not narrow; "at least" constraints are expressed as a `window`. Any bound type a verifier does not recognize is a rejection, never an ignore, which is the one place the protocol is strict about unknown fields, because a bound you cannot compare is a bound you cannot enforce. New types enter the registry only after two independent implementations agree on the comparison and publish test vectors.

Two consequences follow. First, every bound is checked twice: at request time by the executor, and at audit time by the delegator, using the same table, so a divergence between them is a bug in one implementation rather than a matter of policy. Second, the skeptic's question 2 has an honest answer: RAR can express every value in this table, since RAR values are arbitrary JSON, but RAR defines no comparison for any of them, and the comparison is the whole point.

---

## Architect's ranking

Scoring: P passes the test, p passes with a named caveat, F fails. The ten tests are the historian's; the eleven questions are the skeptic's, scored on whether the architecture has a concrete answer.

| | Writ | Voucher | Tether | Docket | Behalf | Pouch |
|---|---|---|---|---|---|---|
| 1 minimal core, one week | P | P | F | p | P | F |
| 2 offline end-to-end verify | P | F | p | p | P | P |
| 3 narrow waist, any transport | P | P | F | P | F | P |
| 4 strict core, one parse | P | P | P | P | p | P |
| 5 value at N=2 | P | P | P | F | P | p |
| 6 state explicit or absent | p | P | F | P | p | P |
| 7 readable wire format | P | P | P | F | P | P |
| 8 no mandatory central authority | P | F | P | F | P | P |
| 9 versioning without flag day | P | P | p | P | P | P |
| 10 failure is a defined message | P | p | P | P | p | P |
| Q1 day-one benefit at N=2 | yes | yes | yes | no | yes | yes |
| Q2 a bound RAR cannot express | comparison, not value | none | comparison | comparison | comparison | comparison |
| Q3 request C rejects that 8693 allows | 65000 or second charge | none | same | same | same | same |
| Q4 B attenuates offline | yes | no | yes | no, log online | yes | yes |
| Q5 verify with cards only | yes, cards optional | no, needs AS | mostly | needs log key | yes | yes |
| Q6 bytes for one hop | ~1.1 KB | ~0.6 KB | ~0.9 KB | ~2.5 KB | ~0.9 KB | ~1.6 KB |
| Q7 who enforces | C's runtime | AS3 policy | C's runtime | C plus log | C's runtime | C's runtime |
| Q8 cancel vs compensate, no new grant | recall and rev | no | cancel and rev | void and new entry | DELETE and rev | cancel and rev |
| Q9 host body | A2A ext or IETF | A2A ext | new | IETF SCITT | IETF HTTP | new |
| Q10 replay stopped by | nnc, count store | DPoP jti only | seq and tid | log dedup | nnc, count store | id and stamps |
| Q11 load-bearing field | `prv` | `tok.h` | `lineage` | `at` | `Behalf-Grant-1` | `auth` |

**Ranking.** 1. Writ. 2. Behalf. 3. Pouch. 4. Voucher. 5. Tether. 6. Docket.

Writ passes every test and answers every question, with one honest caveat: `count` bounds need a replay store at the executor with a lifetime equal to the writ's expiry. Behalf is Writ's best binding and the most attractive day-one experience, but it is not the protocol, because a protocol that only exists inside HTTP headers fails the narrow-waist test the moment a task runs through a queue. Pouch is Writ with the right failure semantics and the wrong amount of mandatory machinery. Voucher is the fallback if the team concludes the steelman wins; it is cheap and useful and does not close the gap. Tether re-implements A2A streaming. Docket requires an operator.

**What I would build: Writ, with Behalf as its mandatory HTTP binding and one appendix each stolen from the others.** From Voucher: the executor copies into the tally the bounds it actually enforced (`det` becomes a `bnd` echo in the tally), so a verifier sees both what was granted and what the executor believed it was granted, and a mismatch is evidence rather than a mystery. From Tether: the cancel race rule (lower sequence wins, a late cancel is answered with the completed tally and its `rev`) and the `tid` idempotency convention. From Docket: an optional `anchor` field on a tally holding a SCITT receipt for those who want a public timestamp, and the freshness-window idea for honoring recalls without an online check on every call. From Pouch: `ttl` and `budget` on a call, and the rule that exhausted retries produce a `bounce` tally with `st: failed` and `err.code: "undeliverable"`, so silence is never the answer. From Behalf: the well-known document and the RFC 9421 field layout, so a one-hop HTTP caller can adopt the protocol by adding headers and never parsing a writ.

**Second choice: Behalf alone**, if the team decides that the ninety-percent case is HTTP and that queue and file transports can wait for v0.2. It would ship faster, demo better, and fail the narrow-waist test on purpose, which is a defensible trade if stated up front and not one I would make.

**What the winner still owes the skeptic.** Question 6: a writ chain plus tally for one hop is about 1.1 KB, and a call repeats the chain, so the ninety-percent one-hop case pays roughly 600 bytes of overhead per request; the HTTP binding can cache the root writ per `(iss, nnc)` and send only its hash on repeat calls, which brings it under 200 bytes. Question 7: enforcement is the executor's runtime, which must refuse any call lacking a valid chain; an LLM in B that "ignores the bound" cannot produce a valid writ_2 wider than writ_1 without B's key producing an invalid chain, which C rejects and A can prove. Question 11: remove `prv` and the chain becomes a bag of unrelated grants that any holder can mix; that field is the standard.
