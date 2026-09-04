# Writ

**Writ: pass narrowable authority between agents and bring back a signed account of what was done under it.**

A candidate protocol primitive for agents from different vendors and trust domains. Four signed JSON objects, five bound types with mechanical subset comparison, one signature algorithm, one hash, one canonicalization, no central party. This repository holds the research, the design record, the v0.1 specification, a Go reference implementation, a second implementation in Python written from the spec, a conformance corpus, a three-agent demo, and the CI that keeps them agreeing.

Started from one question: what is the smallest thing MCP + A2A + OAuth still cannot express cleanly? The answer, after a step-by-step attempt to build the scenario on each of them (docs/research/03-skeptic-opening.md): none of the three gives a vendor-neutral, offline-verifiable object that binds a task-scoped delegation chain, which each hop can narrow without contacting any issuer, to a signed receipt from each hop stating what it did under exactly which link of that chain. Everything else in the scenario (discovery, transport auth, task lifecycle, tool schemas) is already standardized and stays where it is.

Outside those three, several 2026 drafts and papers now cover parts of that gap: hash-linked offline attenuation (draft-asor-wimse-agent-delegation-chain, AgentROA, AIP's Biscuit-chained tokens), closed comparator registries for narrowing (draft-hamr-oauth-agent-delegation), MCP and A2A bindings (AIP, AgentROA), and completion or approval evidence (AIP completion blocks, AgentROA execution receipts, draft-schrock authorization receipts). Writ does not claim any of those as its own. **Writ's specific contribution is a compact, executable protocol for offline attenuated delegation with a closed mechanically comparable bound algebra, signed post-execution tally trees, and explicit replay, failure, recovery, revocation, and reversal semantics.** Section 4 below says what is borrowed, what is combined differently, what is distinctive, and what no design in this space fixes; docs/research/02-prior-art.md section 7 has the source-by-source comparison.

## The thirteen outputs

### 1. One-sentence definition

Writ: pass narrowable authority between agents and bring back a signed account of what was done under it.

For comparison: TCP/IP moves packets between heterogeneous networks. HTTP requests and transfers resources. DNS resolves names. Writ delegates bounded authority and returns evidence.

### 2. Name

**Writ.** A writ is a written command granting authority to act. The receipt is a **tally** (from the tally stick, a split record whose halves must match). Cancellation is a **revoke**. Packages and domains use `writ-protocol`; the bare word collides with an unrelated coding harness (docs/adoption.md section 7).

### 3. Architecture

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

Layering: transport authentication (TLS, OAuth, mTLS) below; discovery (A2A Agent Cards, well-known document) beside; task lifecycle and tool schemas (A2A, MCP) above. Writ is the authority-and-evidence layer between them, the way TLS is the layer between TCP and HTTP.

Objects and their sizes on the wire for the demo: writ_1 about 600 bytes, the two-writ call about 1.5 KB, tally_B with its embedded sub-tree about 2.5 KB.

### 4. Standards comparison

Full matrix with citations, 31 rows including the six 2026 agent-delegation sources: docs/research/02-prior-art.md sections 2 and 7. The compressed view for the functions Writ cares about:

| | Identity | Authority object | Holder can narrow offline | Hash-linked chain | Executor enforces at request time | Signed receipt per hop | Sub-tree of receipts | Replay and failure named | Recovery and reversal | No online party |
|---|---|---|---|---|---|---|---|---|---|---|
| MCP 2026-07-28 | OAuth client | OAuth token, must not transit | no | no | scope only | no | no | no | no | AS required |
| A2A 1.0 | signed Agent Card | out of scope | no | no | no | no | no | task id | cancel only | card host |
| OAuth 2.1 + RAR + token exchange | AS-issued | RAR details | no, AS re-issues | no | yes, one hop | no | no | no | no | AS required |
| UCAN 1.0 | DID | delegation | yes | yes, CID | yes | promise, not receipt | no | invocation CID | revocation only | no |
| Biscuit 3 | root key | token blocks | yes | block chain | yes | no | no | no | no | no |
| AIP / IBCT (2026-03) | JWT or Biscuit ids | capability token | yes, Biscuit blocks | yes | resource | self-reported completion block | no | no | no | no |
| AgentROA draft (2026-04) | registry | ROA envelope | yes, ARA per hop | yes | gateway | gateway execution receipt | no | session cache | revocation via registry | policy engine, registry |
| WIMSE agent delegation chain draft (2026-09) | JWT sub, cnf | JWT with RAR details | yes | yes, `par_hash` | resource | no | no | jti, DPoP | status list | no, optional status list |
| OAuth agent delegation profile draft (2026-09) | keyid per link | header link | yes | no | resource | no | out of scope | nonce, write budget | none | trust source for root |
| EP authorization receipts draft (2026-08) | approver directory | per-action approval | no | Merkle log | pre-execution | approval receipt, not execution | no | one-time consumption | no | log checkpoint |
| Agentic tool-call binding draft (2026-08) | host-local | authority id | depth field only | no | host dispatcher | no | no | single-use CAS | no | authority store |
| **Writ v0.1** | did:key | writ | yes, five-type subset rule | yes, `prv` | yes, leaf bounds and `count` across the chain | tally by the executor, naming the exact writ | yes, embedded verbatim, summed | (leaf writ, `id`); `pending`, `unknown_outcome`, `undeliverable` | `sys/tallies`, `sys/undo` by any issuer, revoke with in-flight cancel | none |

**Already present in neighboring work:** hash-linked offline attenuation, typed comparator registries, MCP and A2A bindings, signed refusals, completion and approval evidence, per-action argument binding.

**Combined differently in Writ:** one comparison table serves both narrowing and request-time argument checks; bounds are signed by the delegator in a bare JSON envelope with did:key and no JWT; `count` is consumed against every writ in the chain at every executor; the receipt is signed by the executor, names the exact link, and embeds the child writs and sub-receipts verbatim.

**Distinctive as of 2026-09-04:** the post-execution tally tree with consumption accounting and a three-valued verdict; idempotency as a protocol rule with byte-identical replay; `sys/tallies` recovery and `sys/undo` reversal as standing operations that survive expiry and revocation and are bounded by `rev.until`; revoke with in-flight cancellation and forwarding; a normative first-failure order pinned by a cross-implementation corpus.

**Fundamental limitations shared with every design here:** hidden sub-delegation (a holder can delegate to a key it controls, or omit a delegation; `wrt`, `sub`, `hld`, and `sys/tallies` make it a signed statement or a policy choice, not an impossibility), cross-executor fan-out (`max` and `count` are per executor; a total across sibling executors needs coordination the protocol does not define and is audited from `used` after the fact), timestamps as the signer's claims, no key rotation for did:key, and root acceptance as policy outside the protocol.

### 5. Threat model

docs/design/05-threat-model.md: 41 catalogued threats, 45 pass/fail requirements, 20 adversarial seeds. The security review of the six candidates against that checklist is docs/design/09-security-review.md. The spec's Security Considerations (section 12) distill both. conformance/ADVERSARIAL.md maps every seed to the vector or test that demonstrates it.

### 6. Specification

docs/spec/writ-v0.1.md. Fourteen sections and three appendices, about 6,500 words. Objects, bounds, attenuation, verification orders, executor state with lifetimes, standing operations, HTTP binding, reason codes, security considerations, relationship to other protocols, conformance.

### 7. Reference implementation

`impl/go`, Go 1.26, zero dependencies outside the standard library.

| Package | What | Tests |
|---|---|---|
| `jcs` | RFC 8785 canonical JSON, integer-only, strict (duplicate keys and lone surrogates rejected) | vectors from RFC 8785 |
| `keys` | did:key Ed25519, base58btc | W3C spec vector, Bitcoin base58 vectors |
| `bound` | five bound types, narrows and satisfies | 40 comparisons both directions |
| `wire` | signed-object envelope, type-prefixed signing input, identity hash | tamper, reorder, padding |
| `writ` | objects, chain attenuation, tally-tree verification, issuance | happy path plus 45 reason-coded rejections |
| `exec` | executor: four durable stores, count across the chain, replay, undo, tallies lookup, revoke with in-flight cancel, crash recovery, standing calls after expiry and revocation | nine scenario tests |
| `httpbind` | one POST endpoint, well-known document, client | round trip |
| `conformance` | corpus runner | |
| `cmd/writ` | CLI: keygen, issue, call, send, verify, revoke, inspect, conformance | |
| `cmd/writ-agent` | executor binary with booking and payment roles | |
| `cmd/writ-demo` | agent A | |
| `cmd/writ-vectors` | regenerates the corpus from fixed seeds | |

```
cd impl/go && go test ./...
```

A second implementation in Python is in `impl/python`: 75 unit tests, a conformance runner, and 26 vectors of its own. It was written from the spec text without consulting the Go code, but by the same author, so it is a consistency check between two readings of one text rather than an externally independent implementation; the stranger test in the roadmap is still open. It surfaced 35 spec ambiguities (listed in its README), every one of which is now resolved in the spec text. Cross-run results, which CI repeats on every push:

| Direction | Result |
|---|---|
| Python verifier on the 145 Go-generated vectors | 145 passed, 0 failed |
| Go verifier on the 26 Python-generated vectors | 26 passed, 0 failed |

Three of the divergences found on the way were Go bugs against the spec (the literal `-0`, padded base64url classed as `malformed`, and a bound-shape error classed as `noncanonical`); one was a non-deterministic first-failure order in Go's argument check. All four are fixed and pinned by vectors.

### 8. Demo

```
sh demo/run.sh
```

Builds the binaries, starts B (booking, port 8081) and C (payment, port 8082) as separate processes with file-backed stores, and runs A. Eight steps, nineteen checked expectations: discovery, issuing, the two-hop call, offline verification of the tally tree, A reversing C's charge directly without B, idempotent undo, seven rejected attempts each answered with a signed refusal and its reason code, a revoke that cancels in-flight work at B and is forwarded to C, and recovery via `sys/tallies`. Every object exchanged is written to `demo/out/` as JSON, with the transcript in `demo/out/demo.log`; that directory is generated on each run and not committed. The script exits non-zero if any expectation fails, and CI runs it.

### 9. Conformance suite

`conformance/vectors/`: 145 vectors regenerated byte for byte from fixed seeds and fixed nonces, 41 accept and 104 reject, every rejection naming its reason code. Covers canonicalization, every bound type in both directions, every chain rule, signatures, expiry, size and depth limits, forward and standing calls including standing calls after expiry, and tally trees including sub-tally accounting. Executor behavior that needs state (count, replay, undo, revoke, recovery, and the standing-after-expiry rule) is covered by the nine scenario tests in `impl/go/exec`.

```
cd impl/go && go run ./cmd/writ conformance ../../conformance/vectors
```

### 10. Adoption strategy

docs/adoption.md. The wedge is the enterprise platform team already running an API gateway that is being asked by audit to prove what its agents may do; both endpoints are theirs, so nobody else must agree. The first adapter is a reverse proxy that verifies the chain, enforces the leaf bounds against the request body, and signs a tally on the way back, so a legacy API changes zero lines. MCP binding via `_meta` members, A2A binding via a DataPart and an Agent Card extension, CLI wrapper, and framework hooks follow.

### 11. Why this could become infrastructure

- It passes the ten tests distilled from nine durable protocols (docs/research/01-history.md): one-week core, offline verification, transport independence, one parse, value at N=2, explicit state, readable wire, no central authority, no flag day, named failure.
- It standardizes one narrow layer and refuses everything else. Discovery, lifecycle, transport auth, and schemas stay with their owners, so no incumbent is a competitor, and the neighboring delegation drafts are candidates for a JWS profile rather than rivals.
- The comparison table is the standard. Five total, decidable comparisons; a bound a verifier cannot compare is rejected. That is what lets two strangers' runtimes agree on "strictly less" without a policy language.
- Receipts embed receipts. Provenance is a tree of signed objects, not a log someone must operate.
- Every field has a reason to exist and a reason code for its absence. Two implementations reject the same object for the same reason, which is what makes conformance meaningful.

### 12. Why this will probably fail

- **Nobody asked for it.** Vendors settle disputes by contract and dashboard. Macaroons have existed since 2014 and nobody deploys them across organizations. Portable attenuation may be a solution waiting for a demand that the market keeps meeting with liability instead.
- **The ninety percent case is one hop.** One hop with OAuth RAR already carries a bound. Writ's benefit at one hop is the signed tally, which is real but modest, and the multi-hop case that needs Writ is still rare.
- **`act` is a bilateral convention.** `travel/charge` means whatever A and C agreed. Typed bounds are portable; operation names are not, and a registry of names is exactly the ontology trap that killed FIPA and the Semantic Web agents.
- **Bare Ed25519 over canonical JSON is a new envelope.** The IETF has JWS and COSE. Refusing them keeps the wire readable and closes every existing working group's door at once. The JWS profile is planned, not built.
- **Executors need durable state.** `count`, replay, and reversal require stores that survive restart. Stateless deployments will drop those features, and a Writ without `count` is closer to a signed RAR than to a capability.
- **Fabricated sub-executors are undetectable by design.** A holder can delegate to a key it controls and produce a perfect tally tree. The protocol tells the truth about keys, and nothing about who holds them.
- **Two implementations, one author, two days.** The Python port checks that one author read the spec the same way twice. Until a stranger implements from the spec and interoperates, every claim above is a claim.
- **The neighbors are close and better connected.** draft-asor-wimse-agent-delegation-chain has hash-linked offline attenuation inside the JWT and DPoP ecosystem the IETF already runs; draft-hamr has a comparator registry; AgentROA has receipts. If one of them adds an executor-signed receipt tree, Writ's remaining distinction is its semantics for replay, recovery, and reversal, which are easier to add to a draft than a wire format is.

### 13. Roadmap to an IETF-quality standard

1. **Now.** v0.1 spec, Go reference, Python second implementation, 145-vector corpus, demo, CI. The spec ambiguities the Python port found are fixed, and so is the standing-operation rule: expiry and revocation now end forward authority only, so `sys/undo` and `sys/tallies` work after a writ expires or is revoked.
2. **Stranger test.** One engineer who has not seen either implementation builds a verifier from the spec and runs the corpus. Every divergence becomes a spec fix and a vector. Trigger to advance: zero divergences on two consecutive strangers.
3. **Second transport.** Run the demo over a message queue and over files in a directory, using the same objects. Proves the narrow waist.
4. **Adapters.** The reverse proxy, then the MCP `_meta` binding as an MCP extension proposal, then the A2A DataPart binding as an A2A extension. Trigger: one production pair between two organizations that are not the authors.
5. **JWS profile.** Publish the mapping from the bare envelope to a JWS with a fixed `alg`, so IETF bodies have a familiar container without changing a single member. Ask the UCAN community whether a JSON-only, did:key-only profile with receipts belongs under their umbrella; record the answer either way.
6. **Individual draft.** After six months of the production pair, an Internet-Draft in the OAuth or a new working group, with the corpus as the interoperability appendix and the threat model as Security Considerations. Registries (bound types, reason codes) under Specification Required with the two-implementation rule.
7. **Standards track.** Two independent interoperable implementations, an interop report, a security review by people who did not write it.

## What the demo proves against the incumbents

The skeptic's opening (docs/research/03-skeptic-opening.md) found the same first hard failure in MCP, A2A, and OAuth: at hop two, nothing lets B hand C strictly less authority than A gave B in a form C can check without an authorization server all three share, and nothing returns signed evidence A can verify. The demo run in `demo/out/demo.log` shows each of those gaps closed, with the object that closes it:

| Incumbent failure (skeptic's step) | What the demo shows | Object |
|---|---|---|
| MCP: a server MUST NOT transit A's token, so C cannot tell B's relayed 60000 bound from a number B invented | C rejects a 61000 charge and a second charge with signed refusals naming `out_of_bounds` and `count_exhausted`; B could not have widened writ_2 without producing a chain C rejects | writ_2 with `prv`, leaf bounds enforced at C |
| A2A: downstream credentials are "outside the protocol"; artifacts are unsigned | tally_B embeds tally_C verbatim and the writ C ran under; A verifies both with only writ_1 and its own call | tally with `sub` and `wrt` |
| OAuth: token exchange needs a shared or federated AS; the `act` chain lives in a token A never sees | no authorization server exists in the demo; every check is offline against keys inside the objects | did:key identities, offline chain walk |
| All three: A never learns C existed unless B says so in prose | A asks C directly what ran under writ_1 and gets a signed answer, with B out of the path | `sys/tallies` |
| All three: reversal needs a new credential and B's cooperation | A reverses C's charge directly, idempotently, by standing as an issuer on the chain | `sys/undo` |
| All three: cancel is one hop and silence looks like stopped | a revoke cancels B's in-flight task, is forwarded to C, and a later call under the writ is refused with `revoked` | revoke, `canceled` tally |

The consistency claim rests on two implementations in two languages, written by one author from the same text without the second consulting the first, agreeing on all 171 vectors including the reason code for every rejection, and on CI that fails on any divergence. It is not yet an interoperability claim between unaffiliated implementers.

## Repository map

```
README.md                          this file
docs/research/                     01 history, 02 prior art, 03 skeptic opening
docs/design/                       04 six architectures, 05 threat model, 06 kill round,
                                   07 distributed systems review, 08 builder review,
                                   09 security review, 10 decision record
docs/spec/writ-v0.1.md             the specification
docs/adoption.md                   adoption strategy and adapter designs
impl/go/                           reference implementation and CLI
impl/python/                       second implementation, from the spec text
conformance/vectors/               145 vectors
conformance/ADVERSARIAL.md         threat seeds mapped to vectors and tests
demo/run.sh                        three-process demo; transcript in demo/out/ (generated)
.github/workflows/ci.yml           CI: tests, cross-conformance, vector regeneration, demo
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, and fails on any divergence:

| Job | What must hold |
|---|---|
| go test | `gofmt`, `go vet`, and `go test ./...` on the Go version pinned by `impl/go/go.mod` (1.25; developed on 1.26) |
| python unit tests | `unittest` on Python 3.12, 3.13, and 3.14 (developed on 3.14) |
| cross-implementation conformance | the Go verifier on every Go and Python vector, and the Python verifier on every Go and Python vector |
| deterministic vector regeneration | both generators rerun and `git diff` of both vector directories is empty |
| three-process demo | `demo/run.sh` exits zero and the transcript says every expectation held |

## License

Apache License 2.0, which carries an explicit patent grant. That matters more for a protocol than for ordinary code: an implementer's legal review needs to see that adopting the wire format cannot be made to cost them later. The specification text and the test corpus are under the same license, so a conforming implementation can be written, sold, and shipped by anyone without asking.

## Process record

Nine roles ran as separate agents: Protocol Historian, Prior-Art Researcher, Skeptic (twice), Protocol Architect, Security Architect (twice), Distributed Systems Engineer, Builder, Adoption Strategist, and a Prototype Team split between the Go implementation and the Python second implementation. All of them were the same author's tooling; none was an outside party. Six architectures were generated on six structural axes; four were killed and two merged into the winner as extensions. The decision record (docs/design/10-decision-record.md) lists every conflict between reviewers and how it was resolved.
