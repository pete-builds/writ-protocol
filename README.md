# Writ

**Writ: pass narrowable authority between agents and bring back a signed account of what was done under it.**

A candidate protocol primitive for agents from different vendors and trust domains. Four signed JSON objects, five bound types with mechanical subset comparison, one signature algorithm, one hash, one canonicalization, no central party. This repository holds the research, the design record, the v0.1 specification, a Go reference implementation, an independent Python verifier, a conformance corpus, and a three-agent demo.

Started from one question: what is the smallest thing MCP + A2A + OAuth still cannot express cleanly? The answer, after a step-by-step attempt to build the scenario on each of them (docs/research/03-skeptic-opening.md): there is no vendor-neutral, offline-verifiable object that binds a task-scoped delegation chain, which each hop can narrow without contacting any issuer, to a signed receipt from each hop stating what it did under exactly which link of that chain. Everything else in the scenario (discovery, transport auth, task lifecycle, tool schemas) is already standardized and stays where it is.

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

Full 25-standard matrix with citations: docs/research/02-prior-art.md section 2. The compressed view for the functions Writ cares about:

| | Identity | Authority object | Holder can narrow offline | Executor enforces at request time | Signed receipt per hop | Sub-tree of receipts | Reversal standing | No online party |
|---|---|---|---|---|---|---|---|---|
| MCP 2026-07-28 | OAuth client | OAuth token, must not transit | no | scope only | no | no | no | AS required |
| A2A 1.0 | signed Agent Card | out of scope | no | no | no | no | cancel only | card host |
| OAuth 2.1 + RAR + token exchange | AS-issued | RAR details | no, AS re-issues | yes, one hop | no | no | no | AS required |
| UCAN 1.0 | DID | delegation | yes | yes | promise, not receipt | no | revocation only | no |
| Biscuit 3 | root key | token blocks | yes | yes | no | no | no | no |
| macaroons | HMAC root | caveats | yes | root only can verify | no | no | no | no |
| AP2 mandates | VC | purchase mandates | no | merchant | final mandate | no | dispute | payments network |
| SCITT | any | none | no | no | signed statement plus log receipt | no | no | log required |
| **Writ v0.1** | did:key | writ | yes, subset rule | yes, leaf bounds | tally | yes, embedded verbatim | any issuer on the chain | none |

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
| `exec` | executor: four durable stores, count across the chain, replay, undo, tallies lookup, revoke with in-flight cancel, crash recovery | two scenario tests |
| `httpbind` | one POST endpoint, well-known document, client | round trip |
| `conformance` | corpus runner | |
| `cmd/writ` | CLI: keygen, issue, call, send, verify, revoke, inspect, conformance | |
| `cmd/writ-agent` | executor binary with booking and payment roles | |
| `cmd/writ-demo` | agent A | |
| `cmd/writ-vectors` | regenerates the corpus from fixed seeds | |

```
cd impl/go && go test ./...
```

An independent Python verifier written from the spec text alone, without reading the Go code, is in `impl/python` (see its README for the spec ambiguities it surfaced).

### 8. Demo

```
sh demo/run.sh
```

Builds the binaries, starts B (booking, port 8081) and C (payment, port 8082) as separate processes with file-backed stores, and runs A. Eight steps, nineteen checked expectations: discovery, issuing, the two-hop call, offline verification of the tally tree, A reversing C's charge directly without B, idempotent undo, seven rejected attempts each answered with a signed refusal and its reason code, a revoke that cancels in-flight work at B and is forwarded to C, and recovery via `sys/tallies`. Every object exchanged is written to `demo/out/` as JSON. The last run's transcript is in `demo/out/demo.log`.

### 9. Conformance suite

`conformance/vectors/`: 138 vectors regenerated byte for byte from fixed seeds and fixed nonces, 38 accept and 100 reject, every rejection naming its reason code. Covers canonicalization, every bound type in both directions, every chain rule, signatures, expiry, size and depth limits, forward and standing calls, and tally trees including sub-tally accounting.

```
cd impl/go && go run ./cmd/writ conformance ../../conformance/vectors
```

### 10. Adoption strategy

docs/adoption.md. The wedge is the enterprise platform team already running an API gateway that is being asked by audit to prove what its agents may do; both endpoints are theirs, so nobody else must agree. The first adapter is a reverse proxy that verifies the chain, enforces the leaf bounds against the request body, and signs a tally on the way back, so a legacy API changes zero lines. MCP binding via `_meta` members, A2A binding via a DataPart and an Agent Card extension, CLI wrapper, and framework hooks follow.

### 11. Why this could become infrastructure

- It passes the ten tests distilled from nine durable protocols (docs/research/01-history.md): one-week core, offline verification, transport independence, one parse, value at N=2, explicit state, readable wire, no central authority, no flag day, named failure.
- It standardizes the one thing nobody else does and refuses everything else. Discovery, lifecycle, transport auth, and schemas stay with their owners, so no incumbent is a competitor.
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
- **One implementation, one author, one week.** The Python verifier is a start on independence. Until a stranger implements from the spec and interoperates, every claim above is a claim.

### 13. Roadmap to an IETF-quality standard

1. **Now.** v0.1 spec, Go reference, Python verifier, 138-vector corpus, demo. Fix the spec ambiguities the Python port found.
2. **Stranger test.** One engineer who has not seen either implementation builds a verifier from the spec and runs the corpus. Every divergence becomes a spec fix and a vector. Trigger to advance: zero divergences on two consecutive strangers.
3. **Second transport.** Run the demo over a message queue and over files in a directory, using the same objects. Proves the narrow waist.
4. **Adapters.** The reverse proxy, then the MCP `_meta` binding as an MCP extension proposal, then the A2A DataPart binding as an A2A extension. Trigger: one production pair between two organizations that are not the authors.
5. **JWS profile.** Publish the mapping from the bare envelope to a JWS with a fixed `alg`, so IETF bodies have a familiar container without changing a single member. Ask the UCAN community whether a JSON-only, did:key-only profile with receipts belongs under their umbrella; record the answer either way.
6. **Individual draft.** After six months of the production pair, an Internet-Draft in the OAuth or a new working group, with the corpus as the interoperability appendix and the threat model as Security Considerations. Registries (bound types, reason codes) under Specification Required with the two-implementation rule.
7. **Standards track.** Two independent interoperable implementations, an interop report, a security review by people who did not write it.

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
impl/python/                       independent verifier from the spec text
conformance/vectors/               138 vectors
conformance/ADVERSARIAL.md         threat seeds mapped to vectors and tests
demo/run.sh                        three-process demo; transcript in demo/out/
```

## Process record

Nine roles ran as separate agents: Protocol Historian, Prior-Art Researcher, Skeptic (twice), Protocol Architect, Security Architect (twice), Distributed Systems Engineer, Independent Builder, Adoption Strategist, and a Prototype Team split between the Go implementation and an independent Python verifier. Six architectures were generated on six structural axes; four were killed and two merged into the winner as extensions. The decision record (docs/design/10-decision-record.md) lists every conflict between reviewers and how it was resolved.
