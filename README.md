# Writ

**Writ lets one AI agent hand another a limited piece of its authority, lets that agent pass an even smaller piece along, and brings back a signed record of what each one did with it.**

Writ is a draft protocol, not a product. This repository holds its specification (v0.1), two implementations that check each other (Go and Python), a shared test suite, a runnable three-agent demo, and the research and design record behind it, all under the Apache 2.0 license.

In one line, next to the protocols it sits beside: TCP/IP moves packets between networks, HTTP fetches resources, DNS resolves names, and Writ delegates bounded authority and returns evidence.

## Three ways in

**Or start with no install at all:** the [playground](https://pete-builds.github.io/writ-protocol/) runs the travel example below in your browser. You set A's limit and try to cheat: widen a slip, overcharge, send a charge twice, fake a receipt, or lose B and undo through C. Every answer comes from the Go reference implementation compiled to WebAssembly (`impl/go/cmd/writ-playground`), with fresh keys each run.

You need Go 1.25 or newer, or none at all for the programs themselves: every release on the repository's Releases page carries them built for Linux and macOS, amd64 and arm64, with SHA-256 checksums and, from the next release on, SLSA build provenance. The Python implementation also needs Python 3.12 or newer and `pip install "cryptography>=42,<47"`.

1. **Watch it run, about ten minutes.**

   ```
   git clone https://github.com/pete-builds/writ-protocol.git
   cd writ-protocol
   sh demo/run.sh
   ```

   Three small programs start on your machine and act out the travel example below. A hands B a booking, B hands C the payment, C charges, A checks every receipt, reverses the charge directly with C, and tries seven things it is not allowed to do, each refused with a reason. No AI model runs anywhere: the three agents are plain Go programs with scripted behavior and fake charges, talking over localhost, because the protocol is about what passes between agents, not how they decide. Afterwards `demo/out/` holds every object exchanged, the transcript, and each agent's audit record. [Try it](#try-it) has the details.

2. **Try to break it, an afternoon.** Read the specification, `docs/spec/writ-v0.1.md`, starting with section 12, and the threat model, `docs/design/05-threat-model.md`. If you find a way to widen authority, forge or hide a receipt, replay a call, or make two careful readers disagree, open an issue with the steps. An operator's objection counts as much as an attack: the peer binding and the audit record in section 7.6 and 9.3 came from one.

3. **Build your own from the spec, the test that matters most.** Without reading `impl/`, write a verifier in any language from the specification alone, then run it against the corpus. `conformance/vectors/` holds 288 objects, each with the answer a verifier must give and, for a rejection, the reason it must name (section 14 gives the format). If you also build an executor, `conformance/scenarios/` holds 25 multi-step cases whose answers are compared byte for byte (section 14.1). Every disagreement is either a place the spec is unclear or a bug in these implementations, and finding those is the point. Open a *stranger test* issue (the template asks for what matters) naming each vector and what your implementation answered. CONTRIBUTING.md has the rest, and SECURITY.md says how to report a vulnerability privately. Until someone outside the project has done this, Writ is one author's reading of one text; see the [roadmap](#roadmap-to-an-ietf-quality-standard).

4. **Put your own Claude Code under a grant.** `writ-hook` checks every tool call a Claude Code session makes against a grant you sign, blocks what the grant does not cover, and signs a receipt for what ran. [docs/claude-code.md](docs/claude-code.md) has the setup and, just as plainly, what it does not protect against.

## The problem

Say you ask your assistant, agent A, to book a trip and spend at most $600. A passes the booking to a travel agent, B. B passes the payment to a card processor, C. Each of the three runs a different company's software.

Today's agent protocols carry the messages from A to B to C. They leave three questions open:

1. **Can C trust the limit?** When B tells C "you may charge up to $589", C cannot check that the limit came from you, or that B did not raise it on the way.
2. **What actually happened?** You learn what C did only if B tells you, in B's own words.
3. **Can you undo it?** If the trip falls through, reversing C's charge needs B's help, and B may be gone.

Writ answers all three with signed objects that anyone can check offline, without asking a server.

The project started from one question: what is the smallest thing MCP, A2A, and OAuth still cannot express? After a step-by-step attempt to build this scenario on each of them (docs/research/03-skeptic-opening.md), the answer was that none of the three gives an object, owned by no vendor and checkable offline, that ties a chain of delegations (each hop narrowing what it passes on, without asking anyone) to a signed receipt from each hop saying what it did under exactly which link of that chain. Everything else in the scenario, from discovery and transport security to task tracking and tool descriptions, is already standardized, and Writ leaves it where it is.

## How Writ works

Writ defines four kinds of signed JSON object.

- **A writ is a signed permission slip.** "A lets B do `travel`, spend at most 60000 cents on any one call, one call at each agent that runs it, until 3 pm." B can write C a slip that is narrower (`travel/charge`, at most 58900 cents, one call, until 2:30) but never wider. Each slip names the one before it by hash, so C receives the whole chain and checks every step itself. The limits hold at each agent that does the work, not as a total across agents: if B split the job between two payment processors, each could charge up to its own limit, and the receipts are how the total gets audited afterward (see "Limits no design here removes").
- **A call asks for work** under a chain of writs, signed by whoever issued the last writ in the chain.
- **A tally is the receipt.** The agent that did the work signs what it did, when, how much of each limit it used, and under exactly which writ. If it passed part of the job on, it attaches the receipts it got back, unchanged, so you can check the whole tree yourself.
- **A revoke withdraws a writ**, which stops new work under it wherever the revoke reaches. Each executor that records a revoke answers with a signed **ack** listing the work under that writ it held at that moment, so any later tally it signs for other work under the writ contradicts its own ack, however that tally is dated.

Limits, called bounds, come in six types, each with a mechanical rule for "is this narrower?" and "does this argument fit?": a maximum per call, a count of uses, a running total, a name prefix, a set of allowed values, and a numeric window. A bound that a verifier does not understand is rejected, never ignored.

Two more properties matter in practice:

- **Nothing runs twice by accident.** A retried call gets the original receipt back, byte for byte, instead of causing a second charge.
- **Issuers keep a say after the fact.** Anyone above an agent in the chain can ask it what ran under their writ (`sys/tallies`), or reverse an effect it promised it could reverse (`sys/undo`), even after the writ has expired or been revoked.

Every check needs only the objects themselves. Identities are public keys written into the objects (did:key, Ed25519), so there is no registry to look up and no central party. Where the transport does authenticate the caller (mTLS, a SPIFFE ID, an OAuth token), the executor also checks that the caller speaks for the key that signed the call, before it answers from its stores. That binding is where a directory or workload identity system meets Writ (spec section 7.6); [docs/directories.md](docs/directories.md) shows the two ways the reference implementation connects one, an mTLS certificate or a bindings file exported from the directory.

### The whole exchange, drawn out

```
  A (delegator)                  B (holder of writ_1)              C (holder of writ_2)
  key a                          key b                             key c
  ─────────────────────────────  ────────────────────────────────  ─────────────────────────
  writ_1 {iss a, hld b,
          act travel, amount<=60000,
          uses 1, exp} ────────► holds writ_1
  call {chain [writ_1],                                         
        from a, op travel/book} ─► verifies chain, root a accepted,
                                   bounds on args, count, replay
                                   narrows: writ_2 {iss b, hld c,
                                     prv h(writ_1), act travel/charge,
                                     amount<=58900, uses 1, exp'<=exp}
                                   call {chain [writ_1, writ_2],
                                         from b, op travel/charge} ──► verifies chain root to leaf,
                                                                       enforces leaf bounds, charges
                                   ◄─ tally_C {call, writ h(writ_2), acc, ok,
                                                out, used {amount 58900},
                                                rev {until}, sub [], wrt []} sig c
                                   books
  ◄─ tally_B {call, writ h(writ_1), acc, ok, out, used,
              rev, sub [tally_C], wrt [writ_2]} sig b
  verifies tally_B under writ_1, then writ_2 as a child of writ_1,
  then tally_C under writ_2: who did what, under which link, with
  nothing but writ_1, its own call, and the keys inside the objects.
  call {chain [writ_1, writ_2], from a, op sys/undo,
        args {tally: tally_C}} ──────────────────────────────────────► verifies own signature on
                                                                        tally_C, a is an issuer on
                                                                        the chain, rev.until: refunds
  revoke {writ h(writ_1), iss a, chain [writ_1]} ─► stops new work, forwards ─► stops new work
```

Writ sits between layers that already exist. Transport security (TLS, OAuth, mutual TLS) runs beneath it, discovery (A2A Agent Cards, or a well-known document) beside it, and task tracking and tool schemas (A2A, MCP) above it. Writ adds the authority and the evidence, the way TLS adds security between TCP and HTTP. In the demo, a writ is about 600 bytes, a call carrying two writs about 1.5 KB, and B's tally with C's receipt inside it about 2.5 KB.

### Words used here

| Word | Meaning |
|---|---|
| issuer, holder | the key that signs a writ, and the key it is granted to |
| narrow, attenuate | pass on less authority than you hold, never more |
| chain | the writs from the first grant to the last, each naming its parent |
| executor | the agent holding the last writ, which does the work and signs the tally |
| bound | one limit in a writ, of one of the six types |
| forward call | a request for new work, which needs a live, unrevoked chain |
| standing call | `sys/tallies` or `sys/undo`, which an issuer on the chain may send even after the chain has expired or been revoked |
| first-failure order | the fixed order of checks, so two implementations reject the same bad object for the same reason |

### The name

A writ is a written command that grants authority to act. The receipt is a **tally**, after the tally stick, a split record whose two halves had to match. Cancelling is a **revoke**. Packages and domains use `writ-protocol`, because the bare word collides with an unrelated coding tool (docs/adoption.md section 7).

## Where the project stands

- **A specification**, docs/spec/writ-v0.1.md: fourteen sections and three appendices, about 11,000 words, covering the objects, the bounds, how narrowing is checked, the order of every check, the state an executor keeps and for how long, the standing operations, an HTTP binding, the reason codes, security considerations, how Writ relates to other protocols, and conformance.
- **Two implementations that check each other.** The Go reference and a Python second implementation of both the verifier and the executor agree on every test.
- **A shared test suite**: 288 test vectors for checking objects, 25 scenarios for executor behavior that needs memory, and a fuzzer that compares the two implementations on tens of thousands of generated inputs.
- **A runnable demo** of three agents in three processes.
- **CI** that fails on any disagreement between the two implementations.

A review dated 2026-09-29 found that the tally-tree check summed consumption only one level down, so a complete receipt tree two levels deep could report twice the root's limit and still verify. The fix, its test vectors, and two executor fixes the same review prompted are in the specification's revision note for that day.

One implementation so far comes from outside the project, with caveats. Griffin Long's [writ-ts](https://github.com/griffinwork40/writ-ts), a TypeScript verifier and executor, was written by an AI coding agent he directed (a Claude model), from the spec and the corpus at commit 6552968 without reading either implementation here ([issue #22](https://github.com/pete-builds/writ-protocol/issues/22)). Its executor was built with every scenario's expected answer removed, and its first run passed 19 of 22 scenarios (136 of 140 steps); the three misses had one cause, in writ-ts. Its verifier passed all 213 vectors of that corpus, but it saw them while it was being built, so that count is not blind. And it no longer conforms: it predates the ack a revoke's answer now carries (spec section 9.4) and the `total` bound. The Go and Python implementations come from one author's tooling, so they show that the spec can be read the same way twice. An unaffiliated implementation that interoperates with the current text is still the next milestone (see the roadmap below).

## Try it

The demo builds the binaries, starts B (booking, port 8081) and C (payment, port 8082) as separate processes with file-backed stores, and runs A:

```
sh demo/run.sh
```

It runs eight steps with twenty-three checked expectations: discovery, issuing, the two-hop call, checking the tally tree offline, A reversing C's charge directly without B, an undo that is safe to repeat, seven rejected attempts each answered with a signed refusal and its reason code, a revoke that cancels work in flight at B and is forwarded to C, and recovery through `sys/tallies`. Every object exchanged is written to `demo/out/` as JSON, with the transcript in `demo/out/demo.log`. That directory is generated on each run and not committed. Each agent also keeps its audit record (spec section 9.3), one JSON line per call or revoke, refusals included, in `demo/out/audit-B.jsonl` and `demo/out/audit-C.jsonl`; the script checks that B's holds the seven refusals. `WRIT_C=python sh demo/run.sh` runs C from the Python implementation instead, so the two implementations talk to each other over the HTTP binding; CI runs both. The script exits non-zero if any expectation fails, and CI runs it.

The tests and the shared suite:

```
cd impl/go && go test ./...
cd impl/go && go run ./cmd/writ conformance ../../conformance/vectors
cd impl/go && go run ./cmd/writ scenarios ../../conformance/scenarios
```

## What is new here, and what is not

Several 2026 drafts and papers now cover parts of the same gap, and Writ does not claim their ideas as its own:

- **Chains that holders narrow offline, linked by hash:** draft-asor-wimse-agent-delegation-chain, AgentROA, and AIP's Biscuit-chained tokens.
- **A closed set of comparison rules for narrowing:** draft-hamr-oauth-agent-delegation.
- **Bindings to MCP and A2A:** AIP and AgentROA.
- **Evidence of completion or approval:** AIP completion blocks, AgentROA execution receipts, and draft-schrock authorization receipts.

Writ's own contribution is a compact protocol you can run: offline delegation that narrows at every hop, a small closed set of bound types that compare mechanically, signed receipt trees returned after the work, and explicit rules for replay, failure, recovery, revocation, and reversal.

**Already present in neighboring work:** chains narrowed offline and linked by hash, typed comparator registries, MCP and A2A bindings, signed refusals, completion and approval evidence, and binding one action to its exact arguments. Since 2026-09-04, also:

- A post-execution result that names the delegation leaf, with `succeeded`, `failed`, or `unknown`, signed by the enforcement boundary; revocation that cascades to every descendant with a signed completion record; and spend reserved against every bounded ancestor (draft-pidlisnyi-aps-03).
- At-most-once execution as normative text (draft-schrock-action-evidence-boundary-07, APS-03).
- A normative first-failure order with named refusal codes, which five implementations by one author must agree on (decionis `agent-safe.verifying-provider/1`).
- A signed receipt from the executor naming the invocation it ran, with its result and the tasks it enqueues: UCAN's Receipt specification, run in production by Storacha's ucanto. Earlier versions of this README said UCAN had a promise and no receipt; that was wrong.
- Task-scoped warrants that narrow at every hop, bound to the holder's key, checked offline against a tool and its arguments, with MCP middleware and opt-in signed receipts of why a call was allowed or denied (Tenuo, v0.3.2). Each receipt can carry the hash of the one its signer issued before, and since v0.3.2 `receipt::verify_chain` checks that a run of them has one signer and no gap, so an enforcement point cannot quietly drop a decision.

**Combined differently in Writ:**

- One comparison table serves both narrowing and the executor's check of a call's arguments.
- The delegator signs the bounds in a bare JSON envelope, with did:key as the only identity and no JWT.
- A `count` is used up against every writ in the chain at every executor, much as APS-03 reserves spend against every bounded ancestor at one boundary.
- The receipt is signed by the executor of each hop, as a UCAN Receipt is, rather than by an enforcement boundary. Unlike a UCAN Receipt it names the exact writ and carries the child writs and sub-receipts verbatim. Unlike a Tenuo receipt it is signed after the work, about what was done. A Tenuo receipt chain is one enforcement point's allow and deny decisions in the order it made them; a Writ receipt tree is the receipts of every agent a delegation reached, each signed by the agent that did the work and embedded in the receipt of the agent that delegated to it.

**Distinctive as of 2026-09-29:**

- The receipt tree: sub-receipts embedded verbatim, each receipt's consumption required to cover the ones below it, so an overspend anywhere in a complete tree surfaces at the limit it exceeds, and a verdict with three values. The first version checked only one level down, which the 2026-09-29 review caught.
- A retry answered with the stored tally byte for byte, where the neighbors refuse the repeat.
- `sys/tallies` recovery and `sys/undo` reversal as standing operations, which survive expiry and revocation and are bounded by the executor's own `rev.until`.
- A revoke that cancels work in flight at the executor and is forwarded down, as a wire mechanism rather than a model.
- A full first-failure order, exercised by test vectors with two faults each and by a differential fuzzer.

That last claim is narrower than it was: others pin an order too, and neither Writ nor they have an independent implementation scoring it yet.

**Limits no design here removes:**

- **Hidden sub-delegation.** A holder can delegate to a key it controls, or leave a delegation out. `wrt`, `sub`, `hld`, and `sys/tallies` turn that into a signed statement or a policy choice, not an impossibility.
- **Fan-out across executors.** `max` is checked per call, and `count` and `total` per executor, so none of them is a budget across executors. A `total` caps the running sum at each executor, which is where a payment is usually made; a total across sibling executors needs coordination the protocol does not define, such as a shared ledger or a total split between the writs issued, and is otherwise audited from `used` in the receipt tree after the fact.
- **Offline checking is not stateless running.** `count`, replay protection, recovery, and reversal need durable executor state. Several workers sharing one executor key need shared state, or are a deployment this spec does not support.
- **A signature is a signed claim.** A valid tally proves that a key signed a statement. It does not prove that a payment happened, that `used` is accurate, that the tree is complete, who owns the key, or when anything happened. Timestamps are the signer's word.
- **Bounds need the application's meaning.** A numeric `amount` argument is not automatically the real charge, a date argument does not prove a query read only those dates, and a path prefix does nothing about `..` or symlinks. The adapter must tie the argument it checked to the effect it caused.
- **Undo is application compensation.** It works only where the application supplies a reversal and promises a window in `rev.until`. It cannot unsend an email.
- **Recovery needs routes.** Knowing an executor's key is not knowing its endpoint, and recovery needs evidence someone kept. Discovery and retention are operational work.
- **Standing outlives revocation, and so does a stolen issuer key's standing.** `sys/tallies` and `sys/undo` skip expiry and revocation on purpose, so an issuer can clean up after withdrawing future work. The same rule lets whoever steals an issuer's key query and reverse work done under that issuer's writs, within each `rev.until`, even after a key-wide revoke. Whether withdrawal and compromise need different rules is open, and wants review by someone outside the project.
- **No key rotation.** A did:key cannot rotate.
- **Root acceptance is policy.** Whether a chain's first issuer matters is a decision each executor makes outside the protocol.

The compressed comparison below is as of 2026-09-04, with the UCAN row corrected and a Tenuo row added on 2026-09-29, and the Tenuo row updated to v0.3.2 on 2026-10-04. The full matrix, with citations and 31 rows including the six 2026 agent-delegation sources, is in docs/research/02-prior-art.md sections 2 and 7, re-checked against newer drafts on 2026-09-28 in section 8.

| | Identity | Authority object | Holder can narrow offline | Hash-linked chain | Executor enforces at request time | Signed receipt per hop | Sub-tree of receipts | Replay and failure named | Recovery and reversal | No online party |
|---|---|---|---|---|---|---|---|---|---|---|
| MCP 2026-07-28 | OAuth client | OAuth token, must not transit | no | no | scope only | no | no | no | no | AS required |
| A2A 1.0 | signed Agent Card | out of scope | no | no | no | no | no | task id | cancel only | card host |
| OAuth 2.1 + RAR + token exchange | AS-issued | RAR details | no, AS re-issues | no | yes, one hop | no | no | no | no | AS required |
| UCAN 1.0 | DID | delegation | yes | yes, CID | yes | yes, Receipt names the invocation (ucanto ships it) | no, `fx` enqueues tasks rather than embedding receipts | invocation CID | revocation only | no |
| Tenuo v0.3.2 (2026-10) | public key | warrant | yes | yes, chain to a trusted root | yes, tool and arguments | opt-in, of the authorization decision, not the outcome | no; `prev_receipt_hash` chains one signer's receipts in time order, not the receipts of the agents a warrant reached | per-call proof of possession in a short window | local revocation state | no |
| Biscuit 3 | root key | token blocks | yes | block chain | yes | no | no | no | no | no |
| AIP / IBCT (2026-03) | JWT or Biscuit ids | capability token | yes, Biscuit blocks | yes | resource | self-reported completion block | no | no | no | no |
| AgentROA draft (2026-04) | registry | ROA envelope | yes, ARA per hop | yes | gateway | gateway execution receipt | no | session cache | revocation via registry | policy engine, registry |
| WIMSE agent delegation chain draft (2026-09) | JWT sub, cnf | JWT with RAR details | yes | yes, `par_hash` | resource | no | no | jti, DPoP | status list | no, optional status list |
| OAuth agent delegation profile draft (2026-09) | keyid per link | header link | yes | no | resource | no | out of scope | nonce, write budget | none | trust source for root |
| EP authorization receipts draft (2026-08) | approver directory | per-action approval | no | Merkle log | pre-execution | approval receipt, not execution | no | one-time consumption | no | log checkpoint |
| Agentic tool-call binding draft (2026-08) | host-local | authority id | depth field only | no | host dispatcher | no | no | single-use CAS | no | authority store |
| **Writ v0.1** | did:key | writ | yes, six-type subset rule | yes, `prv` | yes, leaf bounds and `count` across the chain | tally by the executor, naming the exact writ | yes, embedded verbatim, summed | (leaf writ, `id`); `pending`, `unknown_outcome`, `undeliverable` | `sys/tallies`, `sys/undo` by any issuer, revoke with in-flight cancel | none |

## What the demo shows that the incumbents cannot

The skeptic's walk-through (docs/research/03-skeptic-opening.md) hit the same first hard failure in MCP, A2A, and OAuth. At the second hop, nothing lets B hand C strictly less authority than A gave B in a form C can check without an authorization server all three share, and nothing returns signed evidence that A can verify. The demo transcript in `demo/out/demo.log` shows each gap closed, and by which object:

| Where the incumbents fail (the skeptic's step) | What the demo shows | Object |
|---|---|---|
| MCP: a server MUST NOT pass A's token along, so C cannot tell B's relayed 60000 limit from a number B invented | C rejects a 61000 charge and a second charge with signed refusals naming `out_of_bounds` and `count_exhausted`; B could not have widened writ_2 without producing a chain C rejects | writ_2 with `prv`, leaf bounds enforced at C |
| A2A: downstream credentials are "outside the protocol", and artifacts are unsigned | tally_B carries tally_C verbatim and the writ C ran under; A verifies both with only writ_1 and its own call | tally with `sub` and `wrt` |
| OAuth: token exchange needs a shared or federated authorization server, and the `act` chain lives in a token A never sees | no authorization server exists in the demo; every check runs offline against keys inside the objects | did:key identities, offline chain walk |
| All three: A never learns C existed unless B says so in prose | A asks C directly what ran under writ_1 and gets a signed answer, with B out of the path | `sys/tallies` |
| All three: reversal needs a new credential and B's cooperation | A reverses C's charge directly, safely repeatable, by standing as an issuer on the chain | `sys/undo` |
| All three: cancel reaches one hop, and silence looks like stopped | a revoke cancels B's task in flight, is forwarded to C, and a later call under the writ is refused with `revoked` | revoke, `canceled` tally |

## Why it could matter

- **It passes the ten tests** distilled from nine protocols that lasted (docs/research/01-history.md): a core buildable in a week, offline verification, independence from transport, one way to parse, value with only two parties, explicit state, a readable wire format, no central authority, no flag day, and named failures.
- **It standardizes one narrow layer and nothing else.** Discovery, task tracking, transport security, and schemas stay with their owners, so no incumbent is a competitor, and the neighboring delegation drafts are candidates for a JWS profile rather than rivals.
- **The comparison table is the standard.** Six comparisons, each always decidable; a bound a verifier cannot compare is rejected. That is what lets two strangers' software agree on "strictly less" without a policy language.
- **Receipts contain receipts.** Provenance is a tree of signed objects, not a log someone has to run.
- **Every field has a reason to exist, and a reason code for its absence.** Two implementations reject the same object for the same reason, which is what makes conformance mean something.

## Why it will probably fail

- **Nobody asked for it.** Vendors settle disputes by contract and dashboard. Macaroons have existed since 2014, and nobody deploys them across organizations. Portable narrowing of authority may be an answer waiting for a demand that the market keeps meeting with liability instead.
- **Most cases are one hop.** One hop with OAuth RAR already carries a limit. Writ's benefit at one hop is the signed tally, which is real but modest, and the multi-hop case that needs Writ is still rare.
- **`act` is a private convention.** `travel/charge` means whatever A and C agreed it means. Typed bounds travel between organizations; operation names do not, and a registry of names is the ontology trap that killed FIPA and the Semantic Web agents.
- **Bare Ed25519 over canonical JSON is a new envelope.** The IETF has JWS and COSE. Refusing them keeps the wire readable and closes every existing working group's door at once. The JWS profile is planned, not built.
- **Executors need durable state.** `count`, replay protection, and reversal need stores that survive a restart. Stateless deployments will drop those features, and a Writ without `count` is closer to a signed RAR than to a capability.
- **A made-up sub-executor cannot be detected, by design.** A holder can delegate to a key it controls and produce a perfect tally tree. The protocol tells the truth about keys, and nothing about who holds them.
- **Two implementations, one author; one outside, not current.** The Python verifier and executor show that one author's tooling read the spec the same way twice. The executor was written by an agent kept away from the Go code, which found real gaps, but it is not a stranger. writ-ts comes from outside the project, but an AI agent wrote it, possibly from the same model family as this project's tooling; its verifier saw the vectors it passes; its executor's blind first run passed 19 of 22 scenarios (136 of 140 steps); and it no longer conforms, since it does not sign the ack a revoke's answer now carries. Until an unaffiliated implementer builds from the current spec and interoperates, every claim above is a claim.
- **The neighbors are close and better connected.**
  - draft-asor-wimse-agent-delegation-chain has chains narrowed offline and linked by hash, inside the JWT and DPoP ecosystem the IETF already runs.
  - draft-hamr has a comparator registry, and AgentROA has receipts.
  - draft-pidlisnyi-aps-03 already signs a post-execution result that names the delegation leaf, cascades revocation, and reserves spend up the chain.
  - attenu-guard, APS's interop partner, has outside implementers running its vectors.
  - Tenuo ships task-scoped narrowing warrants with MCP middleware and SDKs in three languages today, and UCAN already specifies signed receipts, which ucanto runs in production.

  If one of them adds an executor-signed receipt tree, what is left of Writ is its rules for replay, recovery, and reversal, which are easier to add to a draft than a wire format is.

## Where Writ stops

**Bounds are not a prompt-injection defense.** An agent whose model has been hijacked, and that acts inside its writ, is acting lawfully as far as the protocol can see; the threat model says so. Writ limits what a hijacked agent can do (`max`, `set`, `count` and `total` per executor, a short `exp`) and records exactly what it did. It does not stop the hijack. [docs/where-writ-stops.md](docs/where-writ-stops.md) has the full argument and its sources.

- **CaMeL and Writ compose.** CaMeL's "capabilities" track where each value came from and where it may go, inside one interpreter. Writ checks who may perform what, within which limits, at an executor that may belong to someone else, and returns signed receipts. A CaMeL-style interpreter decides whether a value may flow into a call; Writ enforces and records the call.
- **Commit before ingest.** Mint the writs from a plan made before the agent reads anything untrusted, as narrow as the plan allows, so injected text can only choose among actions the plan already permitted, and the receipt tree can be checked against the plan.
- **Cut the exfiltration leg.** A `set` bound on the argument that names a recipient or host removes attacker-chosen destinations, but only if every channel is a bounded argument. `writ-mcp-proxy -closed` refuses arguments the grant does not bound; a shell or a generic fetch tool stays a channel whatever its arguments say.
- **Pin tool descriptions.** A poisoned MCP tool description steers the model before any argument exists. `writ-mcp-proxy -pins` lists and calls only tool definitions a person approved ([docs/bindings.md](docs/bindings.md)).
- **Rule of Two labels, proposed.** Meta's Agents Rule of Two (no more than two of: untrusted input, private data, external effects) maps onto narrowing, since a child writ can only drop authority. A `crit` member carrying the allowed properties is sketched in the page above as a proposal, not part of v0.1.

Against the OWASP Top 10 for Agentic Applications (2026), names from a secondary summary and to be re-checked against OWASP's text:

| Writ addresses | Writ partly addresses | Writ does not address |
|---|---|---|
| ASI03 Identity & Privilege Abuse; ASI07 Insecure Inter-Agent Communication | ASI02 Tool Misuse, where an argument carries the meaning; ASI08 Cascading Failures and ASI10 Rogue Agents, through limits, revocation, and undo; ASI04 Supply Chain, for MCP tool descriptions only | ASI01 Agent Goal Hijack within bounds; ASI05 Unexpected Code Execution; ASI06 Memory & Context Poisoning; ASI09 Human-Agent Trust Exploitation |

## The specification and the threat model

The specification is docs/spec/writ-v0.1.md. The threat model, docs/design/05-threat-model.md, catalogues 41 threats, 45 pass/fail requirements, and 20 adversarial seeds. The security review of the six candidate designs against that checklist is docs/design/09-security-review.md, and the spec's Security Considerations (section 12) distill both. conformance/ADVERSARIAL.md maps every seed to the vector or test that demonstrates it.

## The implementations

### Go, the reference

`impl/go`, Go 1.26, with no dependencies outside the standard library.

| Package | What it does | Tests |
|---|---|---|
| `jcs` | RFC 8785 canonical JSON, integers only, strict (duplicate keys and lone surrogates rejected), nesting limit of 64 levels | vectors from RFC 8785, nesting at 64 and 65 |
| `keys` | did:key Ed25519, base58btc | W3C spec vector, Bitcoin base58 vectors |
| `bound` | the six bound types, narrows and satisfies | 40 comparisons in both directions; `total` through the corpus |
| `wire` | the signed-object envelope, type-prefixed signing input, identity hash | tamper, reorder, padding |
| `writ` | objects, chain attenuation, tally-tree verification, issuance, and approval as delegation (`ApprovalPoint`, `Approve`, [docs/approval.md](docs/approval.md)) | happy path plus 45 reason-coded rejections; approval pinned to one call, bounded by the approver, and its two ceilings |
| `exec` | the executor: durable stores, count and total across the chain, atomic replay and count, undo serialized and durably claimed, tallies lookup, revoke with in-flight cancel, crash recovery that keeps delegation evidence, standing calls after expiry and revocation, peer binding, the audit record with each entry linked to the one before, and operations performed outside the executor (`Begin` and `Complete`) | 27 tests, including concurrency, store-failure, and revoke-flooding regressions from the security review, the crash, revoke-race, and accounting regressions from the 2026-09-29 review, the unsaved key-wide revoke, audit, and `Begin`/`Complete` tests from 2026-09-30, a revoke answering for calls running outside the executor, and a peer the transport could not name binding nothing |
| `httpbind` | one POST endpoint that passes the transport-authenticated peer to the executor and audits what it rejects before decoding, the well-known document, a client | round trip, request size and nesting limits, peer binding and the 503 for an unsaved revoke, audit entries, a per-peer rate limit, mTLS peers and directory bindings through a real TLS handshake, and certificates with no usable identity failing closed against a captured-call replay |
| `jws` | the JWS profile of spec Appendix D: a Writ object as the payload of a compact JWS, for JOSE tooling | 2 tests; its output verified by Python's `cryptography` as plain JWS |
| `filebind` | a second transport: calls and revokes as files in a directory, claimed by rename, recovered after a crash; `writ-agent -files DIR` | 1 test including both crash cases |
| `conformance` | vector and scenario runners | |
| `cmd/writ` | CLI: keygen, issue, call, send, verify, revoke, approve, inspect, audit, conformance | |
| `mcpbind`, `cmd/writ-mcp` | Writ over MCP: the call in `tools/call` `_meta`, the tally in the result, a stdio MCP server that enforces it ([docs/bindings.md](docs/bindings.md)) | 5 tests, including every way a result can contradict its tally; also run with Claude Code as the MCP client |
| `cmd/writ-gate` | a reverse proxy that enforces Writ in front of an API that has never heard of it ([docs/writ-gate.md](docs/writ-gate.md)) | 8 tests: end to end against a fake orders API, including undo, a request contract checked against an API that decodes like `encoding/json` (case aliases, duplicates, trailing JSON, unbound members, query strings, path parameters, method overrides), and the API credential held by the gate alone |
| `cmd/writ-mcp-proxy` | the MCP client side for any client: fronts a real MCP server, signs each tool call under a grant, and passes a result on only if it verifies, rebuilt from what its tally authenticates; reads both sides at once, so the server can ask the client something mid-call; optionally lists and calls only pinned tool definitions and refuses arguments the grant does not bound | 17 tests, including forged results and bounded tests for server requests mid-call, interleaving, cancellation, and either side leaving; run with Claude Code as the client |
| `a2abind` | Writ over A2A: the call in a message part or metadata, the tally as the task's last artifact | 1 test, message level |
| `cmd/writ-hook` | the Claude Code adapter: a grant checked before every tool call, a signed receipt after it, and an audit record ([docs/claude-code.md](docs/claude-code.md)) | 8 tests, including parallel hook processes, a tampered receipt, failing closed, named grants per tool, and the gate running as its own process behind a socket; also run against Claude Code itself |
| `cmd/writ-agent` | executor binary with booking and payment roles | |
| `cmd/writ-demo` | agent A | |
| `cmd/writ-vectors` | regenerates the vector corpus from fixed seeds | |
| `cmd/writ-scenarios` | regenerates the executor scenarios, stopping if the Go executor answers any step other than as the spec requires | |
| `cmd/writ-bench` | the concurrency proof: runs `writ-agent` as its own process and races it over HTTP (see [The test suite](#the-test-suite)) | runs in CI with the race detector on the executor |
| `cmd/writ-fuzz` | the differential fuzzer: mutates valid objects, has this verifier judge each one, and writes the verdicts as vectors for another implementation to run | |

### Python, the second implementation

`impl/python` has a verifier, an executor, and the HTTP binding (`writ.httpbind`, served by `python3 -m writ.cli serve`), 151 unit tests, runners for vectors and scenarios, and 28 vectors of its own. Both halves were written from the spec text without consulting the Go code, but by the same author's tooling, so they check that one text reads the same way twice rather than standing as an independent implementation. The roadmap's stranger test is still open.

Writing them found real gaps. The verifier surfaced 35 spec ambiguities, listed in its README. The executor, written by an agent from the spec alone on 2026-09-28, logged ten more places where the text left it to guess, plus one real disagreement with the Go executor that no scenario had caught (`impl/python/DIVERGENCES.md`). Every one is now answered in the spec text, and the disagreement is pinned by a scenario.

Three of the earlier differences were Go bugs against the spec: the literal `-0`, padded base64url classed as `malformed`, and a bound-shape error classed as `noncanonical`. A fourth was a check order in Go's argument check that changed from run to run. All four are fixed and pinned by vectors.

The cross-runs, which CI repeats on every push:

| Direction | Result |
|---|---|
| Python verifier on the 288 Go-generated vectors | 288 passed, 0 failed |
| Go verifier on the 28 Python-generated vectors | 28 passed, 0 failed |
| Go and Python executors on the 25 scenarios | 25 passed, 0 failed, each |
| Python verifier on 20,000 inputs the Go verifier judged (fuzz, seed 1) | 20,000 passed, 0 failed |

So the consistency claim rests on two implementations in two languages, written by one author from the same text without the second consulting the first. They agree on all 288 vectors, including the reason code for every rejection, on 25 executor scenarios byte for byte, and on 80,000 fuzzed inputs, and CI fails on any divergence. It is not yet a claim that unaffiliated implementers interoperate.

## The test suite

- **Vectors,** `conformance/vectors/`: 288 of them, regenerated byte for byte from fixed seeds and fixed nonces, 69 that must be accepted and 219 that must be rejected, each rejection naming its reason code. They cover canonicalization, every bound type in both directions, every chain rule, signatures, expiry, size, depth, and nesting limits, forward and standing calls (including standing calls after expiry), tally trees with sub-tally accounting, and revokes. Most of the 42 added on 2026-09-28 carry two faults each, which pins the reason a verifier must report first (spec section 12 makes that order normative); the rest pin the nesting limit, the full shape of a pending tally, and `depth` on delegated writs. The four added on 2026-09-29 pin tally-tree accounting two levels deep, including the review's reproduction, which both verifiers accepted before the fix. The 28 added on 2026-09-30 pin section 9.4, checking a tally against its signer's ack of a revoke: work the ack holds or lists is accounted for, and work accepted after the revoke is caught, including a tally whose `acc` is dated before it. The 28 added on 2026-10-01 pin the `total` bound: its narrowing, its value rule, one call's argument against it, and tally trees whose `used` it bounds; its running sum is executor state, pinned by scenario 025. The 19 added on 2026-10-04 pin the small-order rules of spec sections 1.3 and 1.4: a writ, a delegated call, and a sub-tally in a receipt tree, each signed by the identity-point key with one fixed signature, which both verifiers accepted before the fix; each of the fourteen small-order encodings as a holder, and one in an `hld` bound; and an honest key's signature made with the nonce r = 0.
- **Scenarios,** `conformance/scenarios/`: 25 of them, 160 steps in all, for executor behavior that needs memory: count, a running total, replay, undo and how reversals are serialized, `sys/tallies`, revoke with in-flight cancel, crash recovery, binding the transport's authenticated peer to the caller's key, revokes of a key and of one writ that outlive a restart, and the ack a revoke is answered with, byte for byte. Each step is a call, a revoke, the end of a held operation, or a restart, and the expected tally is compared byte for byte (spec section 14.1).
- **The fuzzer,** `cmd/writ-fuzz`, goes beyond hand-written cases. It mutates valid objects one to three faults at a time, records the Go verifier's verdict on each as a vector, and lets another implementation run the directory. Before the 2026-09-28 revision pinned every open ordering question, 60,000 inputs produced about 2,470 disagreements between Go and Python. After it, seeds 1 to 4 at 20,000 inputs each produce none, revokes included.
- **Native fuzz targets** (`go test -fuzz`) cover what the differential fuzzer does not: whatever `jcs.Canonicalize` accepts must be a fixed point, whatever `wire.Decode` accepts must round-trip to the same bytes and identity, and the tally checker must never call a tally valid without the executor's signature, never give two verdicts for one input, and always name a reason. A planted bug that skipped the tally signature was found in four seconds.
- **The concurrency proof,** `cmd/writ-bench`, checks the rules concurrency is most likely to break against a real executor: it runs `writ-agent` as its own process with a durable file store, drives it over HTTP on loopback with 256 requests in flight, verifies every tally it gets back, asks the executor itself with `sys/tallies` how many operations it performed, then kills it and starts it again on the same store. The full run, `go run ./cmd/writ-bench -claims 100000 -totals 100000 -fits 1000 -replays 1000000 -workers 256`, on an Apple M2 with 8 cores and Go 1.25.6, 2026-10-01:

  | Check | Result |
  |---|---|
  | 100,000 distinct calls race for a writ with `count` 1 | exactly 1 accepted, 99,999 `count_exhausted`; `sys/tallies` lists 1 (15.0 s, 6,675 calls/s) |
  | 100,000 calls of 7 race for a `total` of 7,000 | exactly 1,000 accepted, 99,000 `total_exhausted`; `sys/tallies` lists 1,000, so 7,000 spent of 7,000 (48.8 s, 2,051 calls/s) |
  | 1,000,000 copies of one signed call | the charge ran once (`sys/tallies` lists 1); 999,998 got the stored tally and every one is byte for byte the same; 2 arrived while the first was still running and got the `pending` tally spec 7 step 9 requires (1 min 36 s, 10,466 calls/s) |
  | the executor killed and restarted on the same store | the spent count and the spent total stay spent, and the replayed call is still answered from the store |

  The numbers are correctness under load on one machine, not capacity: the file store rewrites itself on every accepted call, by design (spec section 9 asks for durability, not throughput), which is why the totals run is the slowest. CI runs it smaller on every change, with the executor built under the race detector. The first such run found a data race in `writ-agent`'s demo payment handler, whose charge counter was not atomic, so two concurrent charges could share an identifier; with the old handler restored, the race detector reports two races.
- **Schemas,** `conformance/schema/`: the shape of a vector (section 14) and of a scenario (section 14.1) as JSON Schema, for implementers in languages with a validator, the way Wycheproof ships its vectors. They describe the harness, not the protocol: the objects inside a vector are left unconstrained, because many are deliberately malformed.

## How it could be adopted

docs/adoption.md has the full plan. The first users are enterprise platform teams that already run an API gateway and are being asked by audit to prove what their agents may do. Both ends are theirs, so nobody else has to agree to anything. The first adapter is a reverse proxy that verifies the chain, enforces the last writ's bounds against the request body, and signs a tally on the way back, so a legacy API changes zero lines. An MCP binding through `_meta` members, an A2A binding through a DataPart and an Agent Card extension, a CLI wrapper, and framework hooks follow.

## Roadmap to an IETF-quality standard

1. **Now.** The v0.1 spec, the Go reference, a Python second implementation of both the verifier and the executor, a 288-vector corpus and 25 executor scenarios, a differential fuzzer, the demo, and CI. The ambiguities the Python port found are fixed, and so is the standing-operation rule: expiry and revocation now end forward authority only, so `sys/undo` and `sys/tallies` still work after a writ expires or is revoked.
2. **Stranger test.** One engineer who has seen neither implementation builds a verifier from the spec and runs the corpus. Every divergence becomes a spec fix and a vector. Move on after zero divergences from two strangers in a row.
3. **Second transport.** Run the demo over a message queue and over files in a directory, with the same objects, to prove the protocol does not depend on HTTP. *Files are done (`filebind`, 2026-09-30); a message queue is not, since it needs a broker the reference implementation does not ship.*
4. **Adapters.** The reverse proxy, then the MCP `_meta` binding as an MCP extension proposal, then the A2A DataPart binding as an A2A extension. Move on once one production pair runs between two organizations that are not the authors.
5. **JWS profile.** Publish the mapping from the bare envelope to a JWS with a fixed `alg`, so IETF bodies have a familiar container without changing a single member. *Drafted 2026-09-30 as spec Appendix D and `impl/go/jws`.* Ask the UCAN community whether a JSON-only, did:key-only profile with receipt trees belongs under their umbrella, and record the answer either way.
6. **Individual draft.** After six months of the production pair, an Internet-Draft in the OAuth or a new working group, with the corpus as the interoperability appendix and the threat model as Security Considerations. Registries for bound types and reason codes under Specification Required, with the two-implementation rule. *The draft text is generated from the spec as `docs/ietf/draft-stergion-writ-00.md` (2026-09-30) and renders cleanly; it is not submitted.*
7. **Standards track.** Two independent implementations that interoperate, an interop report, and a security review by people who did not write it.

## Repository map

```
README.md                          this file
docs/research/                     01 history, 02 prior art, 03 skeptic opening
docs/design/                       04 six architectures, 05 threat model, 06 kill round,
                                   07 distributed systems review, 08 builder review,
                                   09 security review, 10 decision record, 11 open decisions
docs/spec/writ-v0.1.md             the specification
docs/adoption.md                   adoption strategy and adapter designs
docs/claude-code.md                Writ for Claude Code: the writ-hook adapter
docs/enterprise.md                 Writ across an organization: one recommended path, built parts marked
docs/directories.md                connecting a directory: mTLS certificates and bindings files
docs/bindings.md                   Writ over MCP and A2A: what is built and what was tested
docs/writ-gate.md                  writ-gate: Writ in front of an existing API
docs/approval.md                   a call above an agent's limits, approved as a one-use delegation
docs/x402.md                       Writ as the authorization layer in front of an x402 signer: the field mapping
docs/where-writ-stops.md           what bounds cannot stop, and how Writ sits beside injection defenses
docs/aims-audit-mapping.md         a receipt tree mapped to the WIMSE AIMS audit requirements, gaps included
docs/ietf/                         the spec as an Internet-Draft, generated; not submitted
impl/go/                           reference implementation and CLI
impl/python/                       second implementation (verifier and executor), from the spec text
conformance/vectors/               288 vectors
conformance/scenarios/             25 executor scenarios
conformance/ADVERSARIAL.md         threat seeds mapped to vectors and tests
demo/run.sh                        three-process demo; transcript in demo/out/ (generated)
scripts/build-release.sh           builds the release archives; .github/workflows/release.yml publishes them on a v* tag
.github/workflows/ci.yml           CI: tests, cross-conformance, scenarios, fuzz, regeneration, demo
.github/workflows/fuzz-weekly.yml  differential fuzz on a fresh seed, and the native fuzz targets, each week
.github/workflows/scorecard.yml    OpenSSF Scorecard on main and weekly
conformance/schema/                JSON schemas for vectors and scenarios; scripts/check-schemas.py checks them
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, and fails on any divergence:

| Job | What must hold |
|---|---|
| go test | `gofmt`, `go vet`, and `go test ./...` on the Go version pinned by `impl/go/go.mod` (1.25; developed on 1.26) |
| python unit tests | `unittest` on Python 3.12, 3.13, and 3.14 (developed on 3.14) |
| cross-implementation conformance | the Go verifier on every Go and Python vector, the Python verifier on every Go and Python vector, and both executors on every scenario |
| differential fuzz, fixed seed | the Go verifier judges 20,000 mutated inputs from seed 1, and the Python verifier reaches the same verdict and reason on every one |
| native Go fuzz targets | `testing.F` targets for canonicalization (`jcs`), object decoding (`wire`), and the tally checker (`writ`), seeded from the corpus, 30 seconds each |
| vector and scenario schemas | every vector and scenario validates against `conformance/schema/`, the schema's rejection reasons match spec section 11, and broken copies of real files are rejected (`scripts/check-schemas.py --control`) |
| deterministic vector regeneration | all three generators rerun, and `git diff` of the vector and scenario directories is empty |
| three-process demo | `demo/run.sh` exits zero and the transcript says every expectation held |
| concurrency proof | `cmd/writ-bench` against `writ-agent` built with the race detector: 2,000 calls race for one use and one wins, 2,000 race for a total that fits 50 and 50 win, 10,000 copies of one call charge once, the spent count and total survive a kill and restart, and the race detector reports nothing |

`.github/workflows/fuzz-weekly.yml` runs the same fuzz job every Monday on 50,000 inputs from a fresh seed, which it prints first so a failure can be reproduced locally, and each native fuzz target for ten minutes, keeping any failing input as an artifact.

`.github/workflows/scorecard.yml` runs OpenSSF Scorecard on every push to main and weekly, and publishes the result. `.github/workflows/release.yml` attaches SLSA build provenance, `writ-<tag>.intoto.jsonl`, to every release beside `SHA256SUMS`; the workflow's header shows the `slsa-verifier` command that checks an archive against it.

## License

Apache License 2.0, which carries an explicit patent grant. That matters more for a protocol than for ordinary code: an implementer's legal review needs to see that adopting the wire format cannot cost them later. The specification and the test corpus are under the same license, so anyone can write, sell, and ship a conforming implementation without asking.

## How this was built

Nine roles ran as separate agents: Protocol Historian, Prior-Art Researcher, Skeptic (twice), Protocol Architect, Security Architect (twice), Distributed Systems Engineer, Builder, Adoption Strategist, and a Prototype Team split between the Go implementation and the Python second implementation. All of them were the same author's tooling; none was an outside party. Six architectures were generated along six structural axes; four were killed, and two were merged into the winner as extensions. The decision record, docs/design/10-decision-record.md, lists every conflict between reviewers and how it was resolved.
