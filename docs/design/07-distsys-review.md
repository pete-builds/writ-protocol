# 07. Distributed systems review of Writ

Status: design review, 2026-09-03. Role: Distributed Systems Engineer. Inputs: `04-architectures.md` (Writ, Architecture 1, with Behalf as HTTP binding and the failure semantics borrowed from Tether and Pouch), `01-history.md` principles 6 (state is explicit or absent) and 10 (failure is a defined message, not an absence), `05-threat-model.md` where its rules overlap. Nothing here was fetched from the network.

Method. Every attack below is a message trace with timestamps against the fixed scenario: A (`did:key:z6MkA`) issues writ_1 to B, B narrows writ_2 to C, C charges 58900 and returns tally_C, B returns tally_B. T0 is 1788400000; all times are T0 plus seconds. writ_1 expires at T0+3600, writ_2 at T0+2000. For each attack I say what each party holds on disk at the moment of failure, what Writ as written does, whether it SURVIVES or FAILS, and the smallest rule that closes it. "As written" means the text of Architecture 1 plus the cross-cutting section; the stolen appendices from Tether and Pouch are noted where they change the answer.

Two sentences in Writ's failure handling carry most of the weight and most of the trouble. First: "a duplicate returns the stored tally byte-for-byte, and `count` bounds prevent double execution even if the store is lost, because a writ hash can be consumed only `count` times." Second: "C honors a recall by refusing further calls under `<h2>` and any descendant." The first is false as stated, and the second says nothing about how the recall gets to C. Most of the failures below trace back to one or the other.

## 1. State inventory

Writ claims to be stateless except for the replay store. It is not. Here is every piece of state each party must hold for the protocol to deliver what it promises, with lifetime, durability, and the consequence of loss. "Durable" means it survives a process restart; "MUST" means the protocol's own guarantees depend on it.

**A, the root delegator.**

| State | Keyed by | Lifetime | Durable | If lost |
|---|---|---|---|---|
| Signing key | | permanent | MUST | A cannot issue, recall, or reverse; loss of the principal |
| Issued-writ store: writ_1 bytes, its hash, `hld`, `exp` | writ hash | until max(`exp`, `rev.until` of any tally under it) | MUST | A cannot compute `<h1>` to recall, cannot run verification step 2 (`tally_B.writ == hash(writ_1)`), cannot prove what it authorized |
| Outstanding-call store: call bytes, call hash, `id`, send time | (`from`, `id`) | until a final tally arrives or `exp` plus recovery | MUST | A cannot retry with identical bytes (a retry with a new `id` is a new call), cannot match `tally_B.call` |
| Received tally tree | tally hash | until `rev.until` of every embedded tally | MUST | A cannot compensate: the reversal call names `<h_tally_C>` and `ref` |
| Recall store: recalls issued, target `exp` | writ hash | until `exp` | SHOULD | A re-issues; recall is idempotent by design if the fix in section 4 is adopted |
| Clock | | | no | every window check is wrong; see attack (g) |

**B, the middle hop.** B is both an executor (of `travel/book` under writ_1) and an issuer (of writ_2), so it holds both halves.

| State | Keyed by | Lifetime | Durable | If lost |
|---|---|---|---|---|
| Signing key | | permanent | MUST | loss of principal |
| Call idempotency store: state `pending` or the tally bytes | (`from`, `id`) | until leaf writ `exp`, then the tally moves to the tally store | MUST | a retried call re-executes; the "byte-for-byte" promise is void |
| Count store: consumed count | writ hash, one entry per writ in the chain (section 4 rule 3) | that writ's `exp` | MUST | double execution; the spec's claim that `count` survives loss is false, attack (c) |
| Issued-writ store: writ_2 bytes and `hld` | parent writ hash | child `exp` | MUST | a recall of `<h1>` cannot be forwarded to C, attack (e); `wrt` cannot be filled |
| Sub-tally store: tally_C as received | call hash of B's call to C | until `rev.until` | MUST, written before B acts on it | the only record that ch_8813 exists dies with B, attack (a) |
| Own tally store | call hash and every writ hash in the chain | until `rev.until` | MUST | reversal lookup fails, attack (h); lookup by ancestor hash fails |
| Recall store: recalled hashes and their `exp` | writ hash | recalled writ `exp` | MUST | after restart B honors a call under a recalled writ |
| Clock | | | no | see (g) and (n) |

**C, the leaf executor.** Identical to B's executor half: key, call idempotency store, count store, own tally store, recall store, clock. Plus one thing the protocol does not name but depends on: the **effect ledger**, the payment system's own record of ch_8813 and whether it has been refunded. That ledger is the only ground truth in the system; every Writ object is a claim about it. Section 4 rule 2 ties the two together.

Three observations. The tally store must outlive the writ (`rev.until` is 24 hours here, `exp` is one hour), so "replay store with a lifetime equal to `exp`" understates the retention by a day. The issued-writ store at B is what makes recall propagation possible at all, and the spec never mentions it. And nothing at A records that C exists until tally_B arrives, which is the root of attack (a).

## 2. Attack traces

### (a) B crashes after C executed, before B signs tally_B

Preconditions: honest parties, B keeps task state in memory.

```
T0+0     A→B  call a-1 {chain:[writ_1], op:travel/book}
T0+402   B    mints writ_2, B disk: nothing (writ_2 in memory)
T0+412   B→C  call b-7f1c {chain:[writ_1,writ_2], op:travel/charge, amount:58900}
T0+415   C    charges ch_8813, C disk: tally_C, count[<h2>]=1
T0+415   C→B  tally_C
T0+416   B    receives tally_C, begins composing tally_B, crashes. B disk: nothing.
T0+3600  A    exp; A→B recall <h1>. B (restarted) has never heard of <h1>, "honors" it.
```

Outcome as written: ch_8813 is charged. A's recall reaches B; the spec routes A's recall to C only "if the tally tree later arrives with a `sub` under writ_2," and it never arrives. A does not know C exists, does not know `<h2>`, does not know ch_8813. C holds a perfect signed record nobody will ever ask for. **FAILS.** Principle 6 (state explicit) and 10 (failure is a message) both violated: the failure is an absence.

Fix: three rules. Executor MUST persist a `pending` call record before any side effect and MUST persist every received sub-tally before acting on it (rule 1). On restart, an executor MUST answer every `pending` record with a final tally, and a tally with `st: failed` MUST still carry `wrt` (every writ issued) and `sub` (every sub-tally held), so A learns `<h2>` and C's key even when B's own work failed (rule 13). And a reserved lookup operation `writ/tallies` lets any issuer in a chain ask an executor for every tally under a writ hash (rule 8).

### (b) A retries after timeout while B is still working

```
T0+0     A→B  call a-1
T0+30    A    client timeout, resends call a-1, same bytes
T0+30    B    a-1 is in flight, no stored tally exists
```

Outcome as written: "a duplicate returns the stored tally byte-for-byte," but there is no tally yet. The spec has no answer. An implementation will either block A on the first attempt (fine until the connection drops), return an error A cannot distinguish from rejection, or, if B's dedupe is keyed on completion rather than acceptance, start the task a second time and call C twice under two call ids. **FAILS** on principle 10: no defined message.

Fix: record `(from, id)` at acceptance; a duplicate of an in-flight call returns a signed tally with `st: pending`, `res: null`, `acc` set (rule 6). This is Pouch's `accepted` stamp in tally clothing, and it is also the ack that makes retry safe. Retry MUST reuse the same `id` and the same bytes (rule 5).

### (c) Duplicate delivery to C via two paths, replay store lost between them

Preconditions: C's replay store is in memory, or written after the effect.

```
T0+412   B→C  call b-7f1c via path 1
T0+415   C    charges ch_8813; memory: count[<h2>]=1, dedupe[b-7f1c]=tally_C
T0+415   C→B  tally_C (lost in transit)
T0+420   C    crashes and restarts; memory empty
T0+425   B→C  call b-7f1c via path 2 (or B's retry). Chain valid, window open, count store empty.
T0+428   C    charges ch_8814
```

Outcome as written: double charge. The claim that `count` prevents double execution "even if the store is lost" is wrong, because `count` is enforced by the same store. **FAILS.**

Fix: the count and dedupe stores MUST be durable and MUST be written before the side effect (rule 1). Belt and braces: the executor SHOULD use hash(call) as the idempotency key of the underlying effect (the payment processor's idempotency key), so that even a lost store cannot duplicate the charge (rule 2). On restart, a `pending` record with no tally MUST be resolved against the effect ledger, or answered `st: failed, err.code: unknown_outcome`, never silently dropped.

### (d) Recall races completion at C

```
T0+412   B→C  call b-7f1c
T0+413   C    sends authorization to card network, awaits response
T0+414   C    receives recall <h2> (forwarded by B)
T0+415   card network confirms ch_8813
```

Outcome as written: "a recall arriving before [the tally was signed] returns a tally with `st: canceled`." At T0+414 nothing is signed, so C says canceled; at T0+415 the charge lands anyway. A holds a signed `canceled` and a live charge. **FAILS**: the binary before/after has a middle, and the spec's answer for the middle is a lie.

Fix: three states, not two (rule 7). Not yet accepted: reject, `st: canceled`, no count consumed. Accepted, effect unresolved: C MUST NOT answer until the effect resolves, then answers with the real tally (`ok` with `rev`, or `failed`), carrying `rcl` = hash of the recall so the verifier can see the recall was received. Complete: return the existing tally. Every recall response is a signed tally; repeated recalls return identical bytes. Tether's "lower sequence wins" is not usable here because there is no sequence between A and C.

### (e) Recall reaches B but never C

Preconditions: B is the only party that knows C's endpoint (discovery is OUT).

```
T0+412   B→C  call b-7f1c, C begins a slow charge (3-D Secure, 90 s)
T0+430   A→B  recall <h1>
T0+430   B    marks <h1> recalled, refuses new calls under it. B's link to C is down.
T0+505   C    charges ch_8813, returns tally_C to B (queued)
```

Outcome as written: the spec says C honors a recall, and says nothing about B forwarding one. B's recall handling is complete by its own lights at T0+430. A gets whatever B answers, which the spec also does not define. **FAILS.**

Fix (rule 7): a holder receiving a recall MUST forward it to the `hld` of every writ it issued under the recalled writ (this is why the issued-writ store is MUST), retrying until acknowledged or that child's `exp` passes. B's response to A is a signed tally listing, per forwarded recall, `acked` or `unacked`. A's resulting state for C is "unacknowledged," not "canceled" (threat model rule 34), and A's next action is to wait for writ_2's `exp` (which A can compute from `wrt` once it has it, or from writ_1's `exp` as an upper bound) and then run `writ/tallies`.

### (f) Partition between B and C mid-call, B retries with a new `call.id`

```
T0+412   B→C  call b-7f1c
T0+415   C    charges ch_8813, tally_C cannot be delivered (partition)
T0+445   B    times out, mints call b-9a02, same writ_2, same args
T0+446   B→C  call b-9a02 (partition heals for the request)
T0+446   C    count[<h2>]=1 already consumed. Rejects: err.code count_exhausted.
```

Outcome as written: no double charge, because the count store is keyed by `<h2>` and is intact. **SURVIVES** on the money, citing the bound registry row for `count` ("executor replay store per writ hash"). But B learns only "count exhausted," not what consumed it, and unless B re-sends the original `b-7f1c` bytes it never learns ch_8813.

Variant that FAILS: an honest but naive B, having timed out, re-narrows a fresh writ_2' (new `nnc`, hash `<h2'>`) and calls with it. `<h2'>` has its own count of 1 at C. C charges again. Same outcome as (m) below, reached by an honest path. The fix is the count rule in (m).

Fix for the recovery gap: a `count_exhausted` rejection MUST carry `prior`: the tally (or tallies) that consumed the count (rule 9). B then holds tally_C and recovers. Plus rule 5: a retry is the same `id` and the same bytes; a new `id` is a new call and consumes count.

### (g) Clock skew: C is 10 minutes behind, writ_2 has `nbf` = B's now

```
T0+402   B    mints writ_2 with nbf=T0+402 (B's clock)
T0+412   B→C  call b-7f1c
T0+412   C    C's clock reads T0-188. nbf is 590 s in the future.
```

Outcome as written: "validity windows are checked strictly"; the 120 s skew tolerance is stated only for `ts`. C rejects. The only named error code is `expired`, which is the wrong word. B gets an error it cannot interpret and will likely retry into the same wall until either clock moves. **FAILS** on principle 10 (no defined message), though it fails safe.

Fix (rule 11): apply the skew tolerance to `nbf` as well (accept when `nbf ≤ now + 120`), check `exp` strictly, and define `err.code: not_yet_valid` carrying `now` (the rejecter's clock) so the caller can see the skew instead of guessing. Issuers SHOULD set `nbf` to now minus 300. With 600 s of skew and this fix, C still rejects, correctly, and B's error tells it why. A ten-minute clock error is a broken deployment, not a protocol case, and the verifier MUST use only its own clock (threat model rule 20).

### (h) C returns tally then loses its tally store; A reverses later

```
T0+415   C→B  tally_C, C disk: in-memory tally map only
T0+418   B→A  tally_B (embedding tally_C)
T0+900   C    restarts, tally map empty
T0+1100  A→C  call a-0c31 {op:travel/refund, args:{tally:<h_tally_C>, ref:ch_8813}}
T0+1100  C    "looks up <h_tally_C> in its own tally store": not found. Refuses.
```

Outcome as written: refund impossible, though A holds tally_C bearing C's own signature. **FAILS.** This is a direct principle 6 violation: the state needed to resume is on the wire in A's hands and the spec makes C depend on its own copy.

Fix (rule 12): the reversal call MUST carry the tally verbatim and the chain it was executed under; C MUST verify its own signature on the tally, verify `from` equals the chain root `iss`, and MUST NOT require a stored copy. The tally store still MUST be durable until `rev.until`, for one reason: refund idempotency (threat model T18) keyed by tally hash. If that too is lost, the effect ledger (does ch_8813 show a refund?) is the fallback, which is why rule 2 keys the effect on the tally hash.

### (i) Fan-out to C1 and C2 under one writ_1, `max` 60000 each

```
T0+402   B    mints writ_2a (hld C1, amount.max 60000, count 1), writ_2b (hld C2, same)
T0+412   B→C1 charge 58900 → ch_8813
T0+413   B→C2 charge 58900 → ch_8814
T0+418   B→A  tally_B {used:{amount:117800}, sub:[tally_C1, tally_C2], wrt:[writ_2a, writ_2b]}
```

Outcome as written: both children pass the attenuation rule (child ≤ parent per link), so C1 and C2 each correctly execute. A's verification step 6 catches it: `sub[i].used` totals 117800 against a leaf bound of 60000. Detection at audit, after 117800 has moved. **FAILS at enforcement time, SURVIVES as evidence.** And the evidence only exists if B is honest enough to include both tallies; a B that omits tally_C2 and writ_2b passes verification cleanly (threat model, "omission with no counter-evidence"). The answer to the question in the brief: `max` is per call, enforced by the executor against the leaf writ it holds. Aggregate across siblings is not enforceable by executors who cannot see each other, and cannot be made enforceable without either an online party or A-side state.

Fix (rule 4): say so in the spec. `max` and `count` are per-executor bounds. The issuer of sibling writs is responsible for the sum; a tally whose `used` exceeds its own writ's bound, or whose `sub[*].used` sum exceeds it, is a spec violation signed by the issuer. Reject a `total` bound type: it would promise something no offline verifier can check at request time. The one enforceable narrowing is the same-executor case, handled in (m).

### (j) Byzantine B forges a sub-tally with a throwaway key

```
T0+402   B    generates key K, mints writ_2 with hld=K
T0+415   B    signs tally_K as K: {exe:K, res:{charge:"ch_fake"}, used:{amount:58900}}
T0+418   B→A  tally_B {sub:[tally_K], wrt:[writ_2]}
```

Outcome as written: every verification step passes. Step 8 checks `sub[i].exe == writ_2.hld`, and B chose `hld`. A learns: B delegated to key K, K signed a claim, B signed a tally embedding it and reporting ch_fake in its own `res`. A cannot learn that K is not vendor 3, because did:key carries no vendor binding (the spec puts that in the Agent Card, OUT). What A can prove: B's signature over `res.charge: ch_fake` and `st: ok`. When A's refund to the real C fails with "unknown tally," B is caught by its own signature. **SURVIVES** as an attribution protocol; it never promised more. The spec should say plainly that a sub-tally proves what a key signed, not who the key is, and that the issuer of a tally is liable for its `res` regardless of what `sub` says.

Optional narrowing: a reserved bound key `hld` of type `set` on a writ, listing the keys a child writ may name as holder; attenuation applies as for any `set`. It lets A pin the executor set when it knows it. I would leave it out of v0.1.

### (k) Byzantine C signs `used.amount` smaller than it charged

```
T0+415   C    charges 65000 to the card, signs tally_C used:{amount:58900}, res:{amount:58900}
```

Outcome: nothing in the tally tree can see the card statement. **SURVIVES** in the only sense available: C's signature over 58900 is evidence against C when the statement shows 65000. The bounds constrain an honest executor's runtime; a dishonest executor is constrained by liability, not by the protocol. This belongs in section 5.

### (l) Ordering: recall of writ_1, then a fresh writ_1', C receives them reversed

```
T0+500   A→B  recall <h1>
T0+501   A    mints writ_1' (new nnc, hash <h1'>), A→B call a-2
T0+520   B→C  call under [writ_1', writ_2'] arrives first
T0+540   B→C  recall <h1> arrives second
```

Outcome as written: recall names a hash. `<h1>` and `<h1'>` differ by `nnc`. The recall touches nothing under `<h1'>`. **SURVIVES**, citing `recall.writ` as a hash and `nnc` making every writ unique.

Two real holes appear on the way, though. A recall for a hash C has never seen: C cannot verify that `recall.iss` is "an issuer somewhere above the recalled writ in its chain" without the chain, and cannot bound the record's lifetime without the writ's `exp`. C either drops it (then a late call under `<h1>` executes) or stores it forever. Fix (rule 7): a recall MUST carry `chain`, the writs from root to the recalled writ; the receiver verifies `iss` is an issuer in that chain, and expires the record at the recalled writ's `exp`.

### (m) Exponential fan-out: root `count` 1, B mints 100 child writs each `count` 1

```
T0+402   B    mints writ_2[1..100], each hld=C, count 1, distinct nnc
T0+412   B→C  100 calls, each under a distinct leaf hash
T0+415   C    count[<h2_i>]=1 for each i. 100 charges.
```

Outcome as written: `count` is "tracked in C's replay store keyed by writ hash," and the writ hash is the leaf. Each leaf is fresh. A's step 6 catches the sum at audit, if B reports it. **FAILS.** This is the hole the brief suspected: `count` is consumed by executing under a leaf, and any issuer can mint unlimited leaves. As a bound it constrains nothing the issuer cannot reset. The honest variant in (f) reaches the same double charge without malice.

Fix (rule 3): an executor MUST keep a count entry for every writ hash in the chain, and one execution consumes one from each. Under this rule C's entry for `<h1>` reaches 1 after the first charge and the other 99 are rejected `count_exhausted`, and B's retry under writ_2' in (f) is rejected too. The semantics become honest and stateable: "`count` N on a writ means each executor may execute at most N operations under that writ or any descendant of it." It does not bound the sum across different executors; (i) already established that nothing offline can.

### (n) Long-running task, `exp` mid-execution

```
T0+3500  B→C  call, C accepts (100 s before writ_2 would... use writ_1 exp for the example: exp T0+3600)
T0+3550  C    starts a 300 s settlement operation
T0+3850  C    completes, ch_8813 charged, signs tally_C ts=T0+3850
T0+3900  A    receives tally tree. Step 7: ts outside window. Tally "invalid to A".
```

Outcome as written: "a tally signed after `exp` is invalid to A." The charge is real, the receipt is declared invalid, and A's verifier gives no next action. A is holding C's signed admission and calling it garbage. **FAILS.**

Fix (rule 10, matching threat model T38): add `acc`, the acceptance time, to the tally. An executor MUST NOT accept a call after `exp` by its own clock and MAY complete an operation it accepted before `exp`. The verifier judges `acc` against the window, requires `call.ts ≤ acc ≤ exp` and `acc ≤ ts`, and accepts `ts` after `exp`. Issuers set `exp` to cover expected duration. And the verifier's output for a tally that fails the window check must be three-valued (rule 15): valid, signed-but-unauthorized (an admission, proceed to `rev`), or unverifiable.

### (o) A's key compromised after the fact

```
T0+86400 attacker (holding A's key) mints writ_x nbf=T0, exp=T0+3600, hld=accomplice B'
         B' signs tally_x acc=T0+400, ts=T0+420, res:{charge:"ch_9999"}
         attacker presents the tree as evidence that A authorized ch_9999 yesterday
```

Two questions. Can the attacker cause an honest executor to act? No: an honest C at T0+86400 checks `exp` against its own clock and rejects. Backdated authority is dead authority at every honest hop. Can the tally tree detect a fabricated backdated tree? No: every timestamp is a claim, and A's issued-writ store showing no such `nnc` is A's word against a valid signature. **SURVIVES** for authority, **FAILS** for evidence. The only detector is an external timestamp, which is exactly the optional `anchor` (SCITT receipt) the architect proposed stealing from Docket. The spec should say that without an anchor, a tally proves that the signer of each object signed it, not when.

### (p) Tally reuse: B embeds yesterday's tally_C under today's writ

```
day 1    tally_C1 {writ:<h2_old>} under writ_2_old {prv:<h1_old>}
day 2    B→A tally_B {sub:[tally_C1], wrt:[writ_2_old]}, claiming today's charge happened
```

Outcome: step 4 finds writ_2_old in `wrt`; step 5 runs attenuation writ_1 → writ_2_old and fails on `prv` (`<h1_old> ≠ <h1>`). **SURVIVES**, citing `prv` and hashing the signed writ including `sig`. This is the load-bearing field the architect named, and it holds.

### (q) Partial failure in fan-out: C1 succeeds, C2 fails, B reports failure

```
T0+415   C1→B tally_C1 st:ok rev:{refund ch_8813}
T0+416   C2→B tally_C2 st:failed
T0+418   B→A  tally_B st:failed, sub:[]   (B "summarizes")
```

Outcome as written: the chain-return rule says a tally must embed every sub-tally verbatim, but nothing says a `failed` tally must, and an implementation that only fills `sub` on success is the natural one to write. A sees failure, does nothing, ch_8813 stands. **FAILS** by omission in the text.

Fix (rule 14): `sub` and `wrt` MUST be complete regardless of `st`; a verifier MUST walk `sub` for `rev` handles regardless of the parent's `st`; a failed tally with a successful child is the normal shape of a partial failure, not an anomaly.

### (r) C never replies and never will

```
T0+412   B→C  call; C is down for the day
T0+2000  writ_2 exp
```

Outcome as written: nothing. B has no defined thing to say to A. With the Pouch appendix (`ttl`, `budget`, `bounce`), B's retries exhaust and B returns `st: failed, err.code: undeliverable`. **FAILS as written, SURVIVES with the stolen appendix**, which therefore is not optional. Rule 13 makes it mandatory and requires `wrt` to be filled in that tally so A can later run `writ/tallies` against C in case C did execute before going dark.

### Summary

| | Attack | Verdict |
|---|---|---|
| a | B crashes after C executed | FAILS |
| b | A retries while B in flight | FAILS |
| c | duplicate to C, store lost | FAILS |
| d | recall races completion | FAILS |
| e | recall stops at B | FAILS |
| f | partition, retry with new id | SURVIVES (variant with re-narrowed writ FAILS) |
| g | C clock 10 min behind | FAILS (safe direction, undefined message) |
| h | C loses tally store before reversal | FAILS |
| i | fan-out exceeds aggregate `max` | FAILS at enforcement, evidence only |
| j | throwaway-key sub-tally | SURVIVES (attribution only) |
| k | C under-reports `used` | SURVIVES (attribution only) |
| l | recall and fresh writ reordered | SURVIVES (recall lifetime hole fixed separately) |
| m | 100 child writs, count 1 each | FAILS |
| n | `exp` mid-execution | FAILS |
| o | backdated writs from a stolen key | SURVIVES for authority, FAILS for evidence |
| p | stale tally_C under new writ | SURVIVES |
| q | partial fan-out failure hidden | FAILS |
| r | C silent forever | FAILS without the Pouch appendix |

## 3. What Writ can honestly promise about idempotency

Nothing in Writ is exactly-once, and the spec must not use the phrase. Every guarantee below is conditioned on a durable store, and the durability is a conformance requirement, not an assumption. Proposed text:

> An executor executes a call at most once per (`from`, `id`) and at most `count` times per writ hash in the chain, for as long as its call record and count record persist; both records MUST survive restart until the writ's `exp`. A caller retries the identical call bytes until it holds a final tally or the writ expires, so tallies are delivered at least once and a duplicate always returns the same bytes. When an executor cannot determine whether a side effect occurred, it says so in a signed tally (`st: pending` while unresolved, `err.code: unknown_outcome` if unresolvable); the protocol never treats silence or store loss as proof that nothing happened.

Two corollaries the spec should also state. At-most-once at the executor does not compose into at-most-once across executors: sibling executors under one writ cannot see each other, so aggregate bounds are the issuer's responsibility and the verifier's audit. And at-least-once delivery of tallies is only true while someone is retrying; after every retry budget is exhausted the protocol's promise is a signed `undeliverable`, and after that the only recovery is `writ/tallies`.

## 4. Recommended spec additions

Sized for a minimal spec; each is one paragraph in the failure-semantics section.

1. **Write-ahead persistence.** An executor MUST persist a call record keyed `(from, id)` with state `pending` and acceptance time `acc` before starting any side effect, MUST persist every sub-tally it receives before acting on its contents, and MUST persist its own tally before returning it. Persist means survives process restart. On restart, every `pending` record MUST be resolved to a final tally.

2. **Effect idempotency.** An executor SHOULD key each side effect on the hash of the call that caused it (for example, as the idempotency key passed to a payment processor), and SHOULD key each reversal on the hash of the tally reversed. This is what makes rule 1's durability a defense in depth rather than the only defense.

3. **`count` semantics.** `count` is consumed at acceptance, per executor, for every writ hash in the chain: an executor MUST hold a count entry per writ hash in the presented chain, an accepted call consumes one from each, and a call is rejected `count_exhausted` if any is exhausted. Rejection before acceptance consumes nothing. Entries expire at their writ's `exp`. Plain-language meaning: "`count` N on a writ means each executor may execute at most N operations under that writ or any descendant."

4. **`max` is per call.** `max` is checked per call against the leaf writ by the executor. The protocol does not enforce a sum across sibling writs at request time. The issuer of a writ is responsible for the `used` sum of everything it issues under it; a verifier MUST check that `used` of a tally, and the sum of `sub[*].used` for each key, does not exceed the bounds of the writ named in `tally.writ`, and a tally that violates this is a spec violation by its signer. No `total` bound type in v0.1.

5. **Retry rule.** A retry MUST reuse the same `id` and the same signed bytes. A call with a new `id` is a new call and consumes count. An executor answers a duplicate of a `pending` call with the `pending` tally and a duplicate of a completed call with the stored tally byte-for-byte.

6. **Tally fields added.** `st` gains `pending`. `acc` (integer) records acceptance time and is REQUIRED. `rcl` (string or null) is the hash of the recall the executor honored or received before completion. A `pending` tally has `res: null`, `rev: null`, `used: {}`, and is non-final.

7. **Recall propagation.** A `recall` MUST carry `chain`, the writs from the root to the recalled writ. A receiver verifies `recall.iss` is an `iss` within `chain`, stores the recalled hash until that writ's `exp`, and rejects new calls under it or any descendant with `err.code: recalled`. A holder that issued writs under the recalled writ MUST forward the recall to each child's `hld`, retrying until acknowledged or the child's `exp`. The response to a recall is a signed tally per affected call: `canceled` if not yet accepted, the final tally once an accepted effect resolves (the responder MUST NOT answer `canceled` for an accepted call), or the existing tally if complete; each carries `rcl`. A holder's response also lists each forwarded recall as `acked` or `unacked`. No response within the caller's timeout leaves the caller's state `unacknowledged`; silence never means stopped.

8. **Tally lookup.** Reserved op `writ/tallies` with `args: {writ: <hash>}`, `chain: []`, signed by a principal that is `iss` of that writ or of any ancestor, proven the same way as a reversal. The executor MUST index stored tallies by every writ hash in the chain they ran under and returns every matching tally, signed. This is the recovery path for orphaned effects.

9. **Rejections carry evidence.** A `count_exhausted` rejection MUST include `prior`, the tallies (or their hashes) that consumed the count.

10. **Expiry mid-execution.** An executor MUST NOT accept a call after the leaf `exp` by its own clock and MAY complete an operation it accepted before `exp`. A verifier judges `acc`: it MUST reject a tally with `acc < call.ts`, `acc > exp`, or `ts < acc`, and MUST accept `ts` after `exp` when `acc` is inside the window.

11. **Clock rule.** Verifiers use their own clock only and never a message field as the current time. `nbf` is accepted when `nbf ≤ now + 120`; `exp` is strict. A call rejected for `nbf` returns `err.code: not_yet_valid` with `now` set to the rejecter's clock. Issuers SHOULD set `nbf` to now minus 300.

12. **Reversal from the wire.** A reversal call MUST carry the tally verbatim and the chain it ran under. The executor MUST verify its own signature on the tally, that `from` equals the chain root `iss`, and that `rev.until` has not passed, and MUST NOT require a stored copy to proceed. Repeated reversals of one tally hash return the same reversal tally. Tally records MUST persist until `rev.until`.

13. **Undeliverable is a tally.** A caller whose retries are exhausted (`ttl` or `budget`, from the Pouch appendix, now mandatory) MUST produce a tally with `st: failed`, `err.code: undeliverable`, with `wrt` listing every writ it issued and `sub` listing every sub-tally it holds.

14. **Completeness regardless of status.** `sub` and `wrt` MUST be complete in every tally, whatever its `st`. A verifier MUST walk `sub` for `rev` handles regardless of the parent's `st`.

15. **Three-valued verification.** A verifier's result for each tally is `valid`, `signed_unauthorized` (signature verifies, window or chain check fails; treat as an admission by `exe` and proceed to `rev`), or `unverifiable` (signature fails or writ absent from `wrt`). A tally whose `ts` is outside the window but whose `acc` is inside is `valid`; one whose `acc` is outside is `signed_unauthorized`.

## 5. What Writ should explicitly not promise

Plain language for the spec's non-goals paragraph.

Writ does not provide exactly-once execution. It provides at-most-once per executor while the executor's records survive, and a named message when they do not.

Writ does not enforce a spending or count limit across different executors. If a holder splits work among several executors, each enforces its own writ, and only the holder and the root verifier can see the sum. A holder that exceeds the sum has broken the rules and signed the proof.

Writ does not tell you who a key belongs to. A tally proves that a key signed a statement; binding that key to a vendor is the Agent Card's job.

Writ does not make a dishonest executor honest. Bounds constrain what an honest runtime will do; a dishonest one is constrained by the signature it leaves behind, not by the protocol.

Writ does not prove when anything happened. Every timestamp in a writ or tally is the signer's claim. An honest executor will not act on an expired or backdated writ, but a fabricated tree under a stolen key is indistinguishable from a real one without an external anchor.

Writ does not guarantee a recall reaches every executor. It guarantees that every holder tries, reports what it could not reach, and that after `exp` no new work starts anywhere.

Writ does not discover endpoints. A root issuer that learns of an executor only through a tally cannot ask that executor anything until it has an address, and getting the address is outside the protocol.

Writ does not replace the effect ledger. The payment system's own record of ch_8813 is the ground truth; every Writ object is a signed claim about that ground truth, kept so that claims can be checked against it later.
