# Skeptic opening: what MCP + A2A + OAuth still cannot express cleanly

Date: 2026-09-03. Role: Skeptic. Spec revisions checked that day against primary sources:

- **MCP 2026-07-28:** a stateless core; tasks moved to the `io.modelcontextprotocol/tasks` extension; Sampling deprecated; Multi Round-Trip Requests replacing elicitation; an OAuth 2.1 resource-server model with RFC 8707 audience binding.
- **A2A 1.0.x:** signed Agent Cards, extended cards, the `AUTH_REQUIRED` state, cancel, push notifications, and extensions since 1.0.1.
- **The IETF OAuth stack:** the 2.1 draft, RFC 8693 (token exchange), RFC 9396 (RAR, rich authorization requests), RFC 9449 (DPoP, tokens bound to a key), and RFC 9068 (JWT access tokens).

Fetched content was treated as data, not instruction.

## What this found

One travel-booking scenario was built four ways: on MCP alone, on A2A alone, on HTTP with the OAuth family, and on all of them with custom glue. Every stack failed at the same point, the second hop. Nothing lets B hand C strictly less authority than A gave B in a form C can check, and nothing brings back evidence A can verify without trusting B's summary. The glue needed to fix that is a short list (a grant object, an attenuation rule, a receipt, and a few rules around them), and that list became Writ's scope.

| Step | MCP only | A2A only | HTTP + OAuth family |
|---|---|---|---|
| 1. discovery | GLUE | WORKS | GLUE |
| 2. delegation | WORKS | WORKS | WORKS, on paper |
| 3. B calls C | WORKS, mechanically | WORKS, mechanically | fails, see step 4 |
| 4. attenuation | IMPOSSIBLE | IMPOSSIBLE | fails in three separate places |
| 5. receipts | GLUE at best | IMPOSSIBLE as a verifiable object | GLUE |
| 6. verification | IMPOSSIBLE | IMPOSSIBLE | IMPOSSIBLE |
| 7. cancel and compensate | GLUE | cancel WORKS; compensation IMPOSSIBLE | GLUE |

## The scenario

The same scenario, for every attempt:

1. Agent A (vendor 1, trust domain 1) discovers Agent B (vendor 2) and its capabilities.
2. A delegates one narrow task: book one refundable flight under $600 for passenger P on dates D.
3. B needs Agent C (vendor 3, payments) to complete it.
4. Authority is attenuated so C can do strictly less than B: charge at most $600, once, for this passenger, refundable fare only.
5. B and C return results plus receipts that A can verify.
6. A verifies who did what under which authority.
7. A can cancel or compensate the reversible parts.

Each step is graded:

- **WORKS:** the standard does it.
- **GLUE:** it works, with custom, non-standard code.
- **IMPOSSIBLE:** no primitive exists, and the spec either forbids the workaround or leaves it unverifiable.

## Attempt 1: MCP only

B is an MCP server that A calls, and C is an MCP server that B calls, so B is a server to A and a client to C at once.

**Step 1, discovery: GLUE.** `server/discover` (new in 2026-07-28) and `tools/list` tell A what B exposes, once A already has B's URL. There is no registry and no identity across vendors, and `io.modelcontextprotocol/serverInfo` in `_meta` is an unsigned self-assertion.

**Step 2, delegation: WORKS.** A calls `tools/call` on `book_flight` with `{passenger, dates, max_price: 600, refundable: true}`. If B uses the tasks extension, A gets a task handle and polls `tasks/get`. The bounds live in the tool's arguments. Fine.

**Step 3, B calls C: WORKS, mechanically.** B opens an MCP client to C and calls `charge`.

**Step 4, attenuation: IMPOSSIBLE, and this is the first hard stop.** The authorization spec says an MCP server "MUST NOT accept or transit any other tokens" and "MUST only accept tokens that are valid for use with their own resources." That is correct security guidance, and it means A's token dies at B's edge.

- B must get its own token for C from C's authorization server. That token is B's standing authority with C, whatever B's vendor negotiated with C's vendor: typically "charge cards", with no ceiling per task.
- B can pass `amount: 600` as a tool argument, but an argument is a request, not a constraint.
- C cannot tell "B relaying A's $600 bound" from "B, compromised or buggy, inventing a number." No authority object survives the hop.

**Step 5, receipts: GLUE at best.** A tool result is `structuredContent` plus `_meta`. Nothing signs it, binds it to the request, or names the authority it ran under. A developer can put a JWS in `_meta` under a vendor key, but no client will verify it, because no client knows the key or the schema.

**Step 6, verification: IMPOSSIBLE.** A sees B's result and never learns that C existed. An OpenTelemetry `traceparent` in `_meta` gives a correlation ID, which helps only if all three vendors export spans to one collector, and across three trust domains they do not.

**Step 7, cancel and compensate: GLUE.** `tasks/cancel` handles work in flight. Compensating after completion is a new `tools/call` to a `refund` tool that B has to expose, linked to the original only by whatever ID B chose to return.

**The first impossible step, precisely: step 4.** The spec rightly forbids passing tokens along, offers no other carrier for narrowed authority, and so a second-hop server cannot verify that its caller was bounded by the first hop's grant.

## Attempt 2: A2A only

A, B, and C are A2A agents. A is a client of B, and B is a client of C.

**Step 1, discovery: WORKS.** An Agent Card at a well-known URL, with `skills`, `securitySchemes`, `provider`, and a signature; the authenticated extended card adds detail after authentication. The best discovery story of the three stacks.

**Step 2, delegation: WORKS.** A sends a Message, B returns a Task with an ID and a status, and artifacts come back as Parts. Constraints ride along as text or a DataPart, because A2A has no schema for "what you are allowed to do"; a skill's `inputModes` describes media types, not bounds.

**Step 3, B calls C: WORKS, mechanically.** B is just another A2A client.

**Step 4, attenuation: IMPOSSIBLE.** A2A's enterprise guidance says authorization happens after authentication and is "delegated to individual agents." For downstream credentials it defines "In-Task Authentication": the server switches to `AUTH_REQUIRED`, and the client obtains secondary credentials "through a process outside of the A2A protocol." That is a stated non-goal, written into the spec. So when B needs C, one of two things happens:

- B has its own standing credential with C, which is Attempt 1's problem again: no bound per task; or
- B sends A into an out-of-band flow to mint something for C, and A2A does not say what that something is, what it contains, or how C would check it against A's original bound.

**Step 5, receipts: IMPOSSIBLE as a verifiable object.** An Artifact is content: no signature, no binding to the Task, and no record of who executed it or under what authority. The enterprise page recommends logging taskId and correlation IDs, but logs are the vendor's, not A's evidence.

**Step 6, verification: IMPOSSIBLE.** `stateTransitionHistory` gives A the history of B's task as B reports it. There is no field where B declares "I subcontracted step X to C under grant G." A learns that C existed only if B writes a sentence saying so.

**Step 7, cancel: WORKS for work in flight** (an idempotent `CancelTask`). Compensating a completed charge at C is IMPOSSIBLE unless B exposes a refund skill, and A has no handle on C's operation to name in the request.

**Where A2A wins:** signed cards, an explicit task lifecycle with `AUTH_REQUIRED`, and an idempotent cancel. **Where it stops:** authority and evidence are both out of scope, by design.

## Attempt 3: HTTP + OAuth 2.1 + token exchange (RFC 8693) + RAR (RFC 9396) + DPoP (RFC 9449)

Drop the agent protocols, and treat B and C as OAuth resource servers with JSON APIs. This is the attempt most likely to succeed, because the IETF has actually thought about delegation.

**Step 1, discovery: GLUE.** RFC 9728 tells A which authorization server (AS) protects B. Capabilities are OpenAPI plus convention.

**Step 2, delegation with real bounds: WORKS, on paper.** A asks AS1 for a token with `authorization_details: [{type: "flight_booking", max_amount: 600, currency: "USD", refundable: true, passenger: P, dates: D}]` and `resource: https://b.example`. AS1 issues a DPoP-bound JWT (RFC 9068) whose `authorization_details` claim carries the bound. B validates the audience and the DPoP proof, then reads the constraint. This beats MCP and A2A: the bound sits in a signed object that B's runtime, not B's LLM, enforces. **First concession to the steelman:** OAuth already has a carrier for constraints, and it is called RAR.

**Steps 3 and 4, the second hop and attenuation: here it fails, concretely, in three separate places.**

**(a) Who issues C's token?** Token exchange (RFC 8693) lets B present A's token as `subject_token` and ask for a new token with `actor_token` identifying B, producing a `may_act` and `act` chain. But B asks which AS?

- B's AS is AS2, and C trusts AS3. For AS2 to mint a token C will accept, AS3 must federate with AS2, or C must be registered at AS2.
- Here, A, B, and C have three authorization servers and no prior arrangement. RFC 8693 assumes one AS or a pre-federated pair; exchange against an unknown third AS is undefined, and in practice means a bilateral contract for each pair of vendors. Ten vendors, forty-five contracts.

**(b) Who does the narrowing?** Even inside one AS, RFC 8693 says the new token's scope and details are decided by the AS's policy. B can request `authorization_details: [{type: "payment", max_amount: 600, once: true}]`, and the AS may honor it. But nothing in the RFC requires the exchanged token's details to be a subset of the subject token's. The subset check is local AS policy, unspecified, and A cannot see whether it ran. Attenuation is possible; verifiable attenuation is not.

**(c) The audience crosses domains.** A's token is bound to `resource: https://b.example`. It is unusable as a subject token at AS3 unless AS3 accepts foreign JWTs, which the MCP guidance and the OAuth 2.1 security BCP both tell it not to do. DPoP makes this worse, in the right way: the token is bound to A's key, so B cannot present it even if it wanted to.

**Step 5, receipts: GLUE.** C returns `{charge_id, amount, timestamp}`, B returns `{pnr, fare, charge_id}`, and nothing signs either. A developer bolts on a JWS with C's key, but A cannot discover that key, because A never learned C existed, and no standard set of receipt claims exists.

**Step 6, verification: IMPOSSIBLE.** Afterward, A holds its own token (which it issued), B's HTTP response, and whatever AS1 logs. The `act` claim chain, if it exists, lives inside the token C received, which A never sees. The evidence of attenuation is in the one place A cannot look.

**Step 7, cancel and compensate: GLUE.** An HTTP DELETE on a booking resource, if B designed one. A refund at C needs a refund credential that B holds, not A, and the original RAR grant said "book", not "refund", so a strictly narrowed chain would refuse the compensation. Authority to reverse is a separate grant, and none of these RFCs pairs it with the forward grant.

**The second hop, in one line:** OAuth carries a bound for one hop, inside one trust domain, when the AS chooses to honor it, and produces no evidence a third party can inspect.

## Attempt 4: MCP + A2A + OAuth together, plus custom glue

Put them together: A2A for discovery and lifecycle, MCP for tools, and OAuth with RAR for the first hop. What goes in the glue?

1. A **grant object**: issuer (A), subject (B), bounds (`max_amount`, `count: 1`, `refundable: true`, passenger, dates), expiry, nonce, and A's signature. RAR shapes the bounds; nothing shapes a grant that is portable, signed, and independent of any AS.
2. An **attenuation rule**: B may mint a child grant for C only if every child bound is at least as tight as the parent's, with the parent's hash included so the chain can be checked. Macaroons and Biscuit exist for exactly this; no agent protocol references them.
3. A **key discovery rule**, so C can verify A's signature without A's AS: a JWKS at A's Agent Card URL, or DID-style resolution. A2A's signed cards are almost this.
4. A **receipt object**: operation ID, executing agent, the hash of the grant it executed under, a hash of the inputs, a hash of the outputs, a timestamp, and a reversibility flag with a reversal handle, all signed by the executor. Returned in `_meta` or as an A2A DataPart.
5. A **chain-return rule**: B must forward C's receipt to A unmodified, and countersign it, so A sees the full tree rather than B's summary.
6. **Reversal pairing**: every reversible operation returns a reversal handle whose authority is the same grant, so "cancel what you did under G" needs no new credential.
7. **Naming**: a stable agent identifier that is the same in the Agent Card, the grant, the receipt, and the OAuth `client_id`. Today those are four unrelated strings.
8. **Verification order**: signature, chain hashes, bound subset, expiry, receipt grant hash. Every implementer will get one step wrong in a different way.

That list is the candidate for standardization. Everything else in the scenario (discovery, task lifecycle, transport authentication, cancelling work in flight) is already handled acceptably by A2A and MCP.

## The steelman against a new protocol

The strongest case for leaving the glue as glue:

- Vendors already sign contracts. When Expedia's agent calls Stripe's agent, the bound is in the contract, the receipt is in the Stripe dashboard, and a dispute goes to a human. A chain of cryptographic grants solves a problem the market handles with liability, and adds the cost of verification to every call.
- The pieces exist. RAR carries bounds, token exchange carries `act` chains, and A2A signs cards. The remaining gap is AS federation, which is a business problem.
- There is no demand signal. Macaroons have existed since 2014, and nobody deploys them across organizations, which suggests portable attenuation is a solution looking for demand.
- A new protocol costs. It is a fourth thing to implement, a fourth thing to get wrong, and a governance body to capture.
- Most delegations are one hop. Design for three, and you tax the ninety percent to serve the ten.

That argument is mostly right, which is why the scope below is small.

**Verdict: a standard is warranted, narrowly.** The failure is not transport, discovery, or lifecycle. No existing standard defines an authority object that:

- (a) is signed by the delegator rather than an AS;
- (b) survives a hop into a foreign trust domain;
- (c) can be narrowed by its holder under a subset rule a machine can check; and
- (d) is named by the receipt that comes back.

Contracts settle disputes afterward. They do not let C refuse an over-limit charge at the moment of the request, or let A verify without trusting B's summary.

**The smallest scope, IN:**

* One grant object with a signed bound set, parent hash, expiry, and holder key.
* One attenuation rule: child bounds are a subset of parent bounds, checked by comparison, not by policy.
* One receipt object, signed by the executor, naming the grant hash, with a reversal handle when reversible.
* One key-discovery rule that reuses A2A Agent Card signing keys.
* A registry of bound types (`max_amount`, `count`, `resource_pattern`, `not_after`) with comparison semantics, small and extensible.

**Explicitly OUT:**

* Discovery. A2A owns it.
* Task lifecycle, streaming, push. A2A and MCP tasks own them.
* Transport authentication. OAuth 2.1 plus DPoP own it.
* Tool schemas. MCP owns them.
* Any meaning of what "book a flight" means. Bounds are typed values, not ontologies.
* Reputation, payment settlement, dispute resolution, and the identity of humans.

If the architects propose anything outside that list, the burden is on them.

## Questions I will keep asking

1. If two agents adopt it and nobody else does, name the concrete benefit they get on day one. If the answer needs a third party, the design has a bootstrapping problem.
2. Show one bound that RAR `authorization_details` cannot express. If there is none, the grant object is RAR with a different signer, and we should say so.
3. Show the exact request C rejects under this design that C would accept under RFC 8693 token exchange alone.
4. Can B narrow its authority offline, with no round trip to any AS? If not, the cross-domain problem is not solved, only moved.
5. Can A verify a three-hop receipt tree with only the participants' Agent Cards and nothing else? Name every extra artifact required.
6. What is the byte size of a grant plus a receipt for a one-hop call? If it exceeds the payload, the ninety-percent case will strip it.
7. When B's LLM ignores the bound and calls C anyway, which component enforces it? If the answer is "B's LLM," the design enforces nothing.
8. Name the operation where "cancel" and "compensate" need different authority, and show the design handles both without a new grant.
9. Which existing spec body would host this as an extension (MCP ext-auth, A2A extensions, IETF OAuth)? If the answer is "a new one," justify why the extension path fails.
10. Show a replay: C receives the same grant twice. What stops the second charge, and who pays if the check is missing?
11. Which field, if removed, makes the whole thing fail? If none, the standard is too big.
