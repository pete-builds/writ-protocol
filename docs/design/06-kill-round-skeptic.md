# 06. Kill round: Skeptic


> **Historical document (2026-09-03).** The kill round as argued. `recall` is `revoke` in v0.1; `ts`, `exe`, `in`, and `res` were cut from the tally as this document asked. Where this document and the specification differ, the specification and the decision record (10) govern.

Date: 2026-09-03. Role: Skeptic. Inputs: `04-architectures.md` (six candidates, architect's ranking), `01-history.md` (ten tests), `02-prior-art.md` section 6 (taken names), `03-skeptic-opening.md` (my eleven questions and the IN/OUT scope). Four web searches were run for name collisions; fetched content was treated as data and nothing else from the network was used.

Verdict up front: Writ survives, on conditions. Three of the six die today. Two merge into Writ as appendices. The architect's scorecard gave Writ ten passes; by the historian's own tests it earns seven, and two of the "answered" questions are answered wrong.

## 1. Verdicts

**Writ: KEEP, conditional.** The only candidate where C can refuse an over-limit charge on the strength of A's signature with no online party, which is the gap this project exists to close. But the architect scored test 1 as P while quoting "four weeks for a conformant library"; the test says one engineer, one week. That is F as written, and section 4 is my attempt to make it P. Test 6 is scored p on one named store; there are four (attack b). Test 10 is P only because the failure matrix is asserted, not written.

**Voucher: MERGE into Writ.** The architect already stole the only part worth having: the executor echoes the bounds it believed it enforced. The rest fails my question 3 outright (no request C rejects) and fails test 5 as scored: "no third party" is the test, and Voucher needs AS1 to mint anything at all. Scoring it P on test 5 was generous. Keep it in the record as the fallback if the team decides the steelman wins, and stop treating it as a peer.

**Tether: KILL.** Fails test 3 (session key, sequence numbers, and acks assume a live pair) and re-implements A2A streaming and MCP transport, the one place a new standard is guaranteed to lose. The two rules worth keeping, lower sequence wins the cancel race and `tid` as the idempotency key, are two sentences in Writ's failure section, not an architecture.

**Docket: KILL as core, one optional field survives.** Fails tests 5, 7, and 8 by the architect's own scoring, and the "register on the parent's log" rule makes a three-vendor chain one vendor's record, which is a trust-domain violation dressed as transparency. The log-ordered cancel race is the cleanest answer among the six, and an optional `anchor` on a tally is the right place for it. Nothing else survives.

**Behalf: MERGE into Writ as a binding, demoted from mandatory.** Two encodings of one authority object means two canonical forms and two hashes: a tally's `writ` hash is SHA-256 of JCS bytes, a `Behalf-Grant-2` header is Structured Field bytes, so the hash in a JSON tally cannot match the header form C verified. The architect missed it because the example never crosses encodings. Fix: the binding carries the JCS writ base64url in one header per link, and the Structured Field flattening dies. It is not the protocol, by the architect's own admission on test 3.

**Pouch: KILL.** It is Writ plus routing, and the routing part is the unenforceable part: an `accepted` stamp is a promise, which the architect concedes is SMTP's thirty-year lesson. `ttl`, `budget`, and the bounce-with-reason rule are already stolen for Writ's call object. Fails test 1 on the architect's own numbers.

## 2. Attacking Writ

### The eleven questions, graded

1. **Day-one benefit at N=2: ANSWERED.** B's runtime enforces a number A signed. True, and it is the whole pitch.
2. **A bound RAR cannot express: ANSWERED, and it is a concession.** "Comparison, not value." So the writ is RAR's value set plus a five-row comparison table, signed by the delegator instead of an AS. The spec must say this in its first paragraph, because every OAuth person who reads it will say it otherwise.
3. **Request C rejects that 8693 allows: HAND-WAVED.** "65000 or a second charge." Under 8693, AS3 may also reject 65000 if it honored the narrowing. The honest answer is: the same requests, rejected on A's signature rather than on AS3's unseen policy, which A can then prove. That is a verifiability claim, not a rejection claim, and the document conflates them.
4. **Offline attenuation: ANSWERED.** Genuinely yes.
5. **Verify with cards only: ANSWERED.** Cards are optional for verification, mandatory for liability. Correct and honest.
6. **Bytes for one hop: HAND-WAVED.** "About 1.1 KB" with no count. Mine, with real 56-character did:keys, 86-character signatures, and 43-character hashes: writ_1 about 560 bytes, call plus chain about 850, tally_C about 450, so 1.3 KB per one-hop round trip and about 600 bytes of overhead per request. The mitigation, cache the root writ by `(iss, nnc)` and send its hash, is a new mechanism, a fifth store, and a new failure (cache miss on resend), and it is not in the spec.
7. **Who enforces when B's LLM ignores the bound: HAND-WAVED.** The answer covers the case where B tries to widen writ_2, which C rejects. It does not cover the case that actually happens: B's LLM calls C with B's standing OAuth credential and no writ at all. C accepts, because B is a registered client. Writ enforces only if C refuses non-writ calls for that operation, which means C turns off its existing auth path for its existing customers. The enforcement story depends on a deployment decision the spec cannot make.
8. **Cancel versus compensate without a new grant: ANSWERED for the mechanism, WRONG in the detail.** See attack d: the reversal call carries an empty chain, which is a second parse path and an unbounded privilege.
9. **Host body: WRONG.** "A2A ext or IETF" is two answers, and neither fits. The cross-cutting section rejects JWS and COSE, which are the only envelopes an IETF working group will accept, and A2A extensions are JSON-RPC shaped. By choosing bare Ed25519 over JCS the architect chose "a new one" and did not say so.
10. **Replay: WRONG in one sentence.** "count bounds prevent double execution even if the store is lost, because a writ hash can be consumed only count times." If the store is lost, the count is lost. The sentence contradicts itself. The honest statement: `count` is exactly as durable as C's store, and a store loss is a double-spend window until `exp`.
11. **Load-bearing field: ANSWERED,** `prv`. Good. Then apply the same test to the rest of the object set, and about a third of it is not load-bearing. Section 4 does that.

### New attacks

**a. `act` is an ontology wearing a prefix.** The attenuation rule requires the leaf `act` to start with the root `act`, and the leaf `op` to satisfy the leaf `act`. So A's namespace must be C's namespace, and A and C have never met. If C's vendor names the operation `pay/charge`, B cannot narrow `travel/` to it; B must either lie about the op name or the whole market agrees on one namespace before the first call. That is the Semantic Web trap at small scale, and the "bounds are typed values, not ontologies" line in my own scope is violated by the one mandatory bound. Second, byte-prefix comparison has no separator rule: a grant for `travel/charge` authorizes `travel/chargeback`. Fix: prefix comparison on `/`-separated segments, and `act` documented as a bilateral convention whose only guarantee is that the tally names it.

**b. The replay store is honest but under-counted.** C holds: consumed `count` per writ hash (lifetime `exp`), the tally per `call.id` plus `from` for idempotent resend (lifetime unstated), every tally it signed so reversal-by-hash can find it (lifetime `rev.until`, 24 hours in the example and 90 days in a real refund window), and the recall list. One of four has a named lifetime. Test 6 fails as written; scored p.

**c. Fan-out breaks `max`.** B issues writ_2a to C1 and writ_2b to C2, each `amount max 60000, count 1`. Both pass the attenuation rule, which is per-link and sibling-blind, since C1 and C2 never see each other. Both charge 60000. Total 120000 against a 60000 grant, and A learns at audit (verification step 6) after the money moved. This is inherent to offline attenuation; Macaroons and UCAN have the same property. It is not a bug in the design, it is a bug in the claim "C refuses an over-limit charge." The spec must state that `max` and `count` are per-leaf at request time and per-root only at audit time, and that a delegator who cares about the total issues one writ per subtask itself.

**d. The reversal call is a privilege hole and a second parse.** The refund call has `chain: []` and is authorized by C looking up `<h_tally_C>` in its own store and checking `from` equals the chain root `iss`. Three problems. The call object now has two semantics, chain non-empty means capability exercise and chain empty means tally-authority exercise, which is two parses of the core object and fails test 4. The reversal carries no bounds: no `count`, no amount, no `exp` beyond `until`, so the root can refund as many times as C's implementation tolerates. And "the root may reverse" is asserted, not derived: in a chain A→B→C→D where D's `rev.op` is `payments/refund`, A never held `payments/` and reverses anyway. The obtain-the-hash worry is smaller than it looks, since the call is signed by `from`, so an attacker needs A's key. The fix is in section 4: the executor issues a reversal writ, and no chain is ever empty.

**e. `res` leaks across trust domains.** A→B→C→D: D's tally carries D's raw result body, C embeds it verbatim, B embeds C verbatim, A reads D's PSP identifiers and card metadata although A contracted with B only. The `out` hash alternative exists as an option, and an option in the core object is the WS-* matrix in miniature. Make `res` OUT of the tally: the tally carries `out` (hash) only, and the body travels in the reply where the direct counterparty can strip it.

**f. B issues writ_2 to itself and resets `count`.** `hld == iss` is not forbidden. B mints writ_2 (B→B, `prv: h1`, `count 1`), then writ_3 (B→C) from it, charges; then writ_2' with a fresh `nnc`, writ_3', charges again. C's store is keyed on the leaf hash, and every leaf is fresh. The root's `count 1` is never consumed at C. This is attack c done serially against one executor, and it is a real double-charge. Fix: the executor consumes `count` against every writ hash in the chain, root included. That closes the serial case; the cross-executor case in attack c stays open and must be documented.

**g. The chain-return rule is hoped for.** Step 4 catches a sub-tally whose writ is missing from `wrt`. Nothing catches a sub-delegation never mentioned: B returns `sub: [], wrt: []` and A believes B worked alone, my A2A step 6 failure again. What Writ adds is that the omission is a signed lie, evidence if C's tally ever surfaces. A liability improvement, not a verification improvement, and the spec must say "A sees the tree B chooses to show, signed."

**h. Ten hops, ten kilobytes, ten signature checks per call.** The chain rides every call and is re-verified at every hop, and the hash-caching mitigation adds state and a failure mode. Ten hops is not the ninety-percent case: put `max_chain` in the spec, default 4, and make deeper chains an extension.

**i. Timestamps are assertions, not facts.** did:key gives no clock. A tally's `ts` is chosen by the executor, so verification step 7, "check every `ts` inside the writ window," is theater against an executor who backdates. The 120-second future skew has no bound on the past. Whether a recall "arrived before" a tally was signed is whatever C's clock says; Docket's log order is the only honest fix and it is online. The spec must say `exp` is checked by executors against their own clocks and every other timestamp is informational.

**j. did:key makes rotation a new identity.** Rotate C's key and every writ with `hld: did:key:old` is unexercisable by the new key, and every reversal handle pointing at C's old tallies names a principal that no longer signs. Short `exp` saves writs; it does not save reversal windows (days to months) or long-running orders. Recall covers writs, not keys, so a compromised key has no revocation path inside the protocol. The architect pushes this to the Agent Card, which is OUT, so the OUT layer is load-bearing for any agent that outlives an `exp`. Say so in bold, or allow `did:web` in `hld` as an extension with a resolution rule.

**k. Enforcement by name coincidence.** `args` keys are "compared against `bnd` where names coincide." If B's call names the amount `amt`, no bound applies and C charges any amount. And a `set` bound on `fare` only bites if `fare` is present in `args`; presence is implied, never stated. Rule needed: every `max`, `set`, and `window` key in the leaf must appear in `args`, and a missing key is a rejection.

**l. Two time formats in one object set.** `dates` is `[20261015, 20261019]`, a YYYYMMDD integer, in a document whose cross-cutting rule is Unix seconds. Two implementations will disagree on what `window` compares. Fix: `window` compares integers and says nothing about what they mean; the meaning is the key's, by bilateral convention, like `act`.

**m. Is this just UCAN with receipts?** Yes, in the sense that matters. UCAN 1.0 has issuer and audience (`iss`, `hld`), abilities (`act`), proofs by parent hash (`prv`), `nbf`, `exp`, `nnc`, DID keys, an Invocation (`call`), a Receipt (`tally`), and a Revocation (`recall`). The mapping is one to one. Writ differs in three places: JSON with JCS and bare Ed25519 instead of DAG-CBOR and IPLD, a closed five-type bound table instead of UCAN's policy language, and consumption accounting (`used`, `count`) plus a reversal handle in the receipt. For extending UCAN: identical shape, a group that has already done the revocation and receipt failure work, and a new name for an old object is governance cost with no technical return. Against: the IPLD dependency fails test 7 and drags a content-addressed store into every verifier, the policy language is exactly what the registry refuses, and the community is small enough that "extend UCAN" may mean "become UCAN's maintainers." Honest answer: write Writ as a JSON profile of UCAN 1.0 with a closed registry and consumption receipts, ask the UCAN group to host it, and take a separate name only if the IPLD dependency cannot be dropped. Not asking is how you get a fourth thing to implement.

## 3. Is this just another abstraction layer?

**Strongest yes.** The market already runs the scenario. Expedia's agent calls Stripe's agent under a contract; the bound is in the contract, the receipt is in the dashboard, disputes go to a human. RAR carries bounds one hop, token exchange carries `act` chains, and Vouchers would give A signed evidence in two weeks. The remaining gap, AS federation, is a business gap vendors close with paper. Macaroons have been deployable since 2014 and nobody deploys them across organizations, which is the strongest available evidence that portable attenuation is a solution without demand. Writ asks C to reject calls it would otherwise accept, from a customer it already trusts, on the strength of a signature from a party it has never met. Most delegations are one hop, and a one-hop caller pays 600 bytes and a signature check for a chain of length one. A fourth authority model is a fourth thing for every security reviewer to learn, and its first production failure will be a stripped header or a clock off by two minutes, blamed on the protocol.

**Strongest no.** Every objection above is about receipts and liability after the fact. None of them lets C refuse an over-limit charge at request time on evidence A signed, and none of them lets A verify without trusting B's summary. Contracts are a mechanism for humans to settle disputes at a rate of a few per month; agents will produce disputes at a rate of thousands per hour, and a mechanism that needs a human per dispute does not scale. The sentence "an argument is a request, not a constraint" from my own opening is still true and still unanswered by any other stack. The steelman's Macaroon evidence cuts the other way: Macaroons had no receipt, no consumption accounting, and no cross-domain key discovery, and no one built the three-vendor scenario with them because no one was building three-vendor agent chains in 2014. The `prv` field is thirty bytes of hash that makes a chain of signed statements into a chain of authority, and nothing else in the current ecosystem does that job across a trust boundary.

**Where I land.** The no wins on the narrow question: a delegator-signed, holder-narrowable, offline-verifiable authority object named by its receipt is not a layer over anything, because nothing underneath expresses it. The yes wins on everything else the architect packed in: the HTTP binding, recall, the reversal handle as a special call, the `res` body. Those are conveniences over things that exist. The standard is the writ, the call, and the tally; everything else is an extension until two implementations prove otherwise.

## 4. Minimum viable standard

The target is the smallest object set another engineer can implement from the spec in 2046 with an Ed25519 library, SHA-256, and a JSON canonicalizer.

**writ.** `v` KEEP: versioning without a flag day. `typ` KEEP: four bytes that make a log readable. `iss` KEEP. `hld` KEEP. `bnd` KEEP, with `act` mandatory and segment-prefix comparison. `prv` KEEP: the standard. `nbf` CUT: it only prevents early use, adds a second clock check, and UCAN made it optional for the same reason. `exp` KEEP. `nnc` KEEP: two otherwise identical grants must be distinct objects. `sig` KEEP.

**call.** `v`, `typ` KEEP. `id` KEEP: the idempotency key. `chain` KEEP, never empty. `from` CUT: it must equal the leaf `hld`, so derive it and remove a place for two implementations to disagree. `op` KEEP. `args` KEEP, with the presence rule from attack k. `ts` CUT: an unverifiable assertion; the leaf `exp` is the deadline. `sig` KEEP.

**tally.** `v`, `typ` KEEP. `call` KEEP: the one hash that binds the receipt to the request. `writ` CUT: derivable from the call, which embeds the chain. `exe` CUT: must equal the leaf `hld`. `op` CUT: in the call. `in` CUT: the call hash already binds `args`. `res` CUT from the tally, replaced by `out`, a hash; the body travels in the reply. `used` KEEP: consumption is the accounting that makes `max` and `count` auditable. `st` KEEP. `err.code` KEEP; `err.msg` CUT, free text is not protocol. `rev` REPLACE: instead of `{op, ref, until}`, the executor issues an ordinary writ with `iss` the executor, `hld` the chain root, `bnd` naming the reversal op and `count 1`, `exp` equal to the old `until`, and `prv` null. A exercises it with a normal call, so the empty chain vanishes, the reversal is bounded, C needs no tally store to authorize it, and A can delegate the refund to a support agent by ordinary attenuation. `sub` KEEP. `wrt` KEEP, with the honesty note from attack g. `ts` CUT. `sig` KEEP.

**recall.** MOVE to an extension. It requires a recall store at every executor and an endpoint A can reach, which is discovery, which is OUT. Short `exp` is the v0.1 answer to revocation, and the scenario's in-flight cancel is A2A's `CancelTask`, which owns task lifecycle. If the team keeps it, cut `reason` and `ts`.

**Registry.** `max`, `count`, `set`, `window` KEEP. `prefix` KEEP with segment comparison. `count` consumed against every hash in the chain, per attack f. Add nothing.

**Cross-cutting.** Bare Ed25519 over JCS KEEP for v0.1, with the consequence of question 9 stated: this is a new body until a JWS profile exists. Hash over signed bytes KEEP. Unix seconds KEEP, and `window` values are opaque integers. `max_chain` 4.

**Moved to extensions.** The HTTP binding, rewritten to carry JCS bytes. Recall. The SCITT `anchor`. `ttl` and `budget`. The root-writ hash cache. Voucher's bounds echo, useful evidence and not load-bearing. `did:web` in `hld`.

That leaves three objects, nineteen mandatory fields, five comparisons, one signature algorithm, one hash, one canonicalization. A week is plausible.

## 5. Name

"Writ" is a court order compelling an act: close to the object's meaning, wrong in one way, since a writ comes from an authority to a subordinate and this object comes from a peer narrowing its own power. The search for "Writ protocol" returned only court procedure pages and no technology collision, so the name is free and will be buried under legal results for years. "Tally" is fine as a field name. "Recall" is the wrong word: it means vehicle safety notices and memory before it means revocation, and UCAN's "revoke" is unambiguous.

Alternatives checked, one search each:

* **Warrant.** Best semantic fit, an instrument that authorizes a named party to act. Dead: Warrant is a Zanzibar-style authorization service acquired by WorkOS, and "warrant protocol" already means lawful-intercept tooling.
* **Marque.** Letters of marque were exactly holder-narrowable authority across sovereign boundaries. Dead: marque.at is a domain registrar for the AT Protocol, and the metaphor is licensed piracy, which a payments vendor will not put in a press release.
* **Deed.** A signed instrument that conveys a right and can be chained through successive holders. No collision found. Generic enough to be searchable only as "Deed protocol," and it works as a verb ("deeded to C").

Recommendation: keep **Writ** for the protocol and the authority object, rename `recall` to `revoke` if it survives at all, and hold Deed as the fallback if the UCAN conversation in attack m produces a profile that needs its own name. Do not spend another hour on this.

Surfaced by the searches, unverified: arXiv 2604.24920 (SUDP, secret-use delegation for agents) and arXiv 2602.20493 (AWCP, workspace delegation). Neither is in `02-prior-art.md`; the historian should read both.

Sources consulted: https://www.saccourt.ca.gov/civil/writ-departments.aspx, https://en.wikipedia.org/wiki/Writ_(disambiguation), https://github.com/warrant-dev/warrant, https://workos.com/blog/workos-acquires-warrant, https://blog.citp.princeton.edu/2014/04/02/secure-protocols-for-accountable-warrant-execution/, https://marque.at/, https://arxiv.org/pdf/2604.24920, https://arxiv.org/pdf/2602.20493.

## 6. Conditions for KEEP

1. Consume `count` against every writ hash in the chain, root included, so a holder cannot reset a bound by delegating to itself (attack f).
2. State in normative text that `max` and `count` are per-leaf at request time and per-root only at audit, that fan-out amplification is inherent, and that a delegator who needs a total issues one writ per subtask (attack c).
3. Replace the reversal handle with an executor-issued writ to the chain root; no call ever carries an empty chain (attack d).
4. `prefix` compares on `/`-separated segments, and `act` is documented as a bilateral convention with no cross-vendor meaning (attack a).
5. Name every store an executor holds, with its lifetime, including the idempotency cache and any tally retention, or drop the features that need them (attack b).
6. Remove `res` from the tally; the tally carries `out` only (attack e).
7. Missing `args` for any `max`, `set`, or `window` key in the leaf is a rejection (attack k).
8. Delete the sentence claiming `count` survives store loss, and write the double-spend window honestly (question 10).
9. Timestamps other than `exp` are declared informational; no verification step depends on a signer's own clock (attack i).
10. Move `recall`, the HTTP binding, `ttl`, `budget`, `anchor`, and the hash cache to extensions; v0.1 is writ, call, tally (section 4).
11. The HTTP binding, when written, carries the JCS bytes of each writ in a header rather than re-encoding fields, so one hash serves both forms (Behalf verdict).
12. Add `max_chain` with a default of 4 (attack h).
13. State in the abstract that the writ is RAR's value set plus a comparison table signed by the delegator, and that the tally is a UCAN receipt with consumption accounting, and record the outcome of asking the UCAN group to host a JSON profile before choosing a name (question 2, attack m).
14. Pick one host body and accept its envelope constraints, or say "new body" and justify it against question 9.
15. Re-score tests 1, 6, and 10 against the trimmed object set, with the failure matrix actually written, not asserted.

When these fifteen are in the next draft, I stop objecting to Writ and start objecting to its implementation.
