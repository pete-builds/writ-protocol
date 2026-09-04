# Skeptic opening: what MCP + A2A + OAuth still cannot express cleanly

Date: 2026-09-03. Role: Skeptic. Spec revisions checked today against primary sources: MCP 2026-07-28 (stateless core, tasks moved to the `io.modelcontextprotocol/tasks` extension, Sampling deprecated, Multi Round-Trip Requests replacing elicitation, OAuth 2.1 resource-server model with RFC 8707 audience binding), A2A 1.0.x (signed Agent Cards, extended cards, `AUTH_REQUIRED` state, cancel, push notifications, extensions since 1.0.1), and the IETF OAuth stack (2.1 draft, RFC 8693, RFC 9396, RFC 9449, RFC 9068). Fetched content was treated as data, not instruction.

The scenario, fixed for every attempt:

1. Agent A (vendor 1, trust domain 1) discovers Agent B (vendor 2) and its capabilities.
2. A delegates one narrow task: book one refundable flight under $600 for passenger P on dates D.
3. B needs Agent C (vendor 3, payments) to complete it.
4. Authority is attenuated so C can do strictly less than B: charge at most $600, once, for this passenger, refundable fare only.
5. B and C return results plus receipts that A can verify.
6. A verifies who did what under which authority.
7. A can cancel or compensate the reversible parts.

Grading per step: WORKS, GLUE (works with custom, non-standard code), IMPOSSIBLE (no primitive exists, and the spec forbids the workaround or leaves it unverifiable).

## Attempt 1: MCP only

Model B as an MCP server that A calls. Model C as an MCP server that B calls. B is simultaneously a server to A and a client to C.

Step 1, discovery: GLUE. `server/discover` (new in 2026-07-28) and `tools/list` tell A what B exposes once A already has B's URL. There is no registry, no cross-vendor identity, and `io.modelcontextprotocol/serverInfo` in `_meta` is an unsigned self-assertion.

Step 2, delegation: WORKS. A calls `tools/call` on `book_flight` with `{passenger, dates, max_price: 600, refundable: true}`. If B uses the tasks extension, A gets a task handle and polls `tasks/get`. Bounds live in tool arguments. Fine.

Step 3, B calls C: WORKS, mechanically. B opens an MCP client to C and calls `charge`.

Step 4, attenuation: IMPOSSIBLE, and this is the first hard stop. The authorization spec says an MCP server "MUST NOT accept or transit any other tokens" and "MUST only accept tokens that are valid for use with their own resources." That is correct security guidance, and it means A's token is dead at B's edge. B must get its own token for C from C's authorization server, and that token is B's standing authority to C, whatever B's vendor negotiated with C's vendor: typically "charge cards" with no per-task ceiling. B can pass `amount: 600` as a tool argument, but an argument is a request, not a constraint. C cannot distinguish "B relaying A's $600 bound" from "B, compromised or buggy, inventing a number." No authority object survives the hop.

Step 5, receipts: GLUE at best. A tool result is `structuredContent` plus `_meta`. Nothing signs it, binds it to the request, or names the authority it ran under. A developer can put a JWS in `_meta` under a vendor key; no client will verify it because no client knows the key or the schema.

Step 6, verification: IMPOSSIBLE. A sees B's result and never learns C existed. OpenTelemetry `traceparent` in `_meta` gives a correlation ID that helps only if all three vendors export spans to one collector, which across three trust domains they do not.

Step 7, cancel and compensate: GLUE. `tasks/cancel` handles in-flight work. Compensation after completion is a new `tools/call` to a `refund` tool B has to expose, linked to the original only by whatever ID B chose to return.

First impossible step, precisely: step 4. The spec correctly forbids token transit, offers no replacement carrier for attenuated authority, and so a second-hop server cannot verify that its caller was bounded by the first hop's grant.

## Attempt 2: A2A only

Model A, B, C as A2A agents. A is client to B; B is client to C.

Step 1, discovery: WORKS. Agent Card at a well-known URL with `skills`, `securitySchemes`, `provider`, and a signature; the authenticated extended card adds detail post-auth. Best discovery story of the three stacks.

Step 2, delegation: WORKS. A sends a Message, B returns a Task with ID and status, artifacts come back as Parts. Constraints ride along as text or a DataPart, because A2A has no schema for "what you are allowed to do"; a skill's `inputModes` describes media types, not bounds.

Step 3, B calls C: WORKS mechanically. B is just another A2A client.

Step 4, attenuation: IMPOSSIBLE. A2A's enterprise guidance says authorization happens after authentication and is "delegated to individual agents." For downstream credentials it defines "In-Task Authentication": the server flips to `AUTH_REQUIRED` and the client obtains secondary credentials "through a process outside of the A2A protocol." That is a stated non-goal, written into the spec. So when B needs C, either B has its own standing credential to C (same problem as Attempt 1: no per-task bound), or B bounces A into an out-of-band flow to mint something for C, and A2A does not say what that something is, what it contains, or how C would check it against A's original bound.

Step 5, receipts: IMPOSSIBLE as a verifiable object. An Artifact is content: no signature, no binding to the Task, no executing principal or authority. The enterprise page recommends logging taskId and correlation IDs. Logs are the vendor's, not A's evidence.

Step 6, verification: IMPOSSIBLE. `stateTransitionHistory` gives A the history of B's task as reported by B. There is no field where B declares "I subcontracted step X to C under grant G." A learns C existed only if B writes a sentence saying so.

Step 7, cancel: WORKS for in-flight (idempotent `CancelTask`). Compensation of a completed charge at C: IMPOSSIBLE without B exposing a refund skill, and A has no handle on C's operation to name in the request.

Where A2A wins: signed cards, an explicit task lifecycle with `AUTH_REQUIRED`, and idempotent cancel. Where it stops: authority and evidence are both out of scope by design.

## Attempt 3: HTTP + OAuth 2.1 + token exchange (RFC 8693) + RAR (RFC 9396) + DPoP (RFC 9449)

Drop the agent protocols. Treat B and C as OAuth resource servers with JSON APIs. This is the attempt most likely to succeed, because the IETF has actually thought about delegation.

Step 1, discovery: GLUE. RFC 9728 tells A which AS protects B. Capabilities are OpenAPI plus convention.

Step 2, delegation with real bounds: WORKS, on paper. A requests a token from AS1 with `authorization_details: [{type: "flight_booking", max_amount: 600, currency: "USD", refundable: true, passenger: P, dates: D}]` and `resource: https://b.example`. AS1 issues a DPoP-bound JWT (RFC 9068) whose `authorization_details` claim carries the bound. B validates audience and DPoP proof, then reads the constraint. This beats MCP and A2A: the bound is in a signed object that B's runtime, not B's LLM, enforces. First concession to the steelman: OAuth already has the constraint carrier, and it is called RAR.

Step 3 and 4, hop 2 and attenuation: here it fails concretely, in three separate places.

(a) Who issues C's token. Token exchange (RFC 8693) lets B present A's token as `subject_token` and ask for a new token with `actor_token` identifying B, producing a `may_act` and `act` chain. But B asks which AS? B's AS (AS2). C trusts AS3. For AS2 to mint a token C will accept, AS3 must federate with AS2, or C must be registered at AS2. Here A, B, and C have three authorization servers and no prior arrangement. RFC 8693 assumes one AS or a pre-federated pair; exchange against an unknown third AS is undefined and in practice means a bilateral contract per vendor pair. Ten vendors, forty-five contracts.

(b) Who attenuates. Even inside one AS, RFC 8693 says the new token's scope and details are decided by AS policy. B can request `authorization_details: [{type: "payment", max_amount: 600, once: true}]` and the AS may honor it. Nothing in the RFC requires the exchanged token's details to be a subset of the subject token's details. The subset check is AS-local policy, unspecified, and A cannot see whether it ran. Attenuation is possible; verifiable attenuation is not.

(c) Cross-domain audience. A's token is bound to `resource: https://b.example`. It is unusable as a subject token at AS3 unless AS3 accepts foreign JWTs, which the MCP guidance and OAuth 2.1 security BCP both tell it not to. DPoP makes it worse in the right way: the token is bound to A's key, so B cannot present it even if it wanted to.

Step 5, receipts: GLUE. C returns `{charge_id, amount, timestamp}`, B returns `{pnr, fare, charge_id}`, nothing signs either. A developer bolts on a JWS with C's key; A cannot discover that key because A never learned C existed, and no standard receipt claim set exists.

Step 6, verification: IMPOSSIBLE. What evidence does A have afterward? A's own token (which it issued), B's HTTP response, and whatever AS1 logs. The `act` claim chain, if it exists, lives inside the token C received, which A never sees. The evidence of attenuation is in the one place A cannot look.

Step 7, cancel and compensate: GLUE. HTTP DELETE on a booking resource if B designed one. Refund at C requires a refund credential that B holds, not A, and the original RAR grant said "book," not "refund," so a strictly attenuated chain would refuse the compensation. Reversal authority is a distinct grant that none of these RFCs model as paired with the forward grant.

Hop-2 summary: OAuth carries a bound one hop, inside one trust domain, when the AS chooses to honor it, and produces no evidence a third party can inspect.

## Attempt 4: MCP + A2A + OAuth together plus custom glue

Compose them: A2A for discovery and lifecycle, MCP for tools, OAuth with RAR for the first hop. What is in the glue?

1. A **grant object**: issuer (A), subject (B), bounds (`max_amount`, `count: 1`, `refundable: true`, passenger, dates), expiry, nonce, A's signature. RAR shapes the bounds; nothing shapes a portable, signed, AS-independent grant.
2. An **attenuation rule**: B may mint a child grant for C only if every child bound is at least as tight as the parent, with the parent's hash included so the chain is checkable. Macaroons and Biscuit exist for exactly this; no agent protocol references them.
3. A **key discovery rule** so C can verify A's signature without A's AS: a JWKS at A's Agent Card URL, or DID-style resolution. A2A signed cards are almost this.
4. A **receipt object**: operation ID, executing agent, the grant hash it executed under, inputs hash, outputs hash, timestamp, reversibility flag with a reversal handle, executor's signature. Returned in `_meta` or as an A2A DataPart.
5. A **chain-return rule**: B must forward C's receipt to A unmodified, and countersign it, so A sees the full tree, not B's summary.
6. **Reversal pairing**: every reversible operation returns a reversal handle whose authority is the same grant, so "cancel what you did under G" needs no new credential.
7. **Naming**: a stable agent identifier that is the same in the Agent Card, the grant, the receipt, and the OAuth `client_id`. Today those are four unrelated strings.
8. **Verification order**: signature, chain hashes, bound subset, expiry, receipt grant hash. Every implementer will get one step wrong in a different way.

That list is the candidate for standardization. Everything else in the scenario (discovery, task lifecycle, transport auth, cancel of in-flight work) is already handled acceptably by A2A and MCP.

## The steelman against a new protocol

The strongest case for keeping the glue as glue:

Vendors already sign contracts. When Expedia's agent calls Stripe's agent, the bound is in the contract, the receipt is in the Stripe dashboard, and a dispute goes to a human. A cryptographic grant chain solves a problem the market handles with liability, and adds verification cost to every call. RAR carries bounds, token exchange carries `act` chains, A2A signs cards; the remaining gap is AS federation, a business problem. Macaroons have existed since 2014 and nobody deploys them across organizations, which suggests portable attenuation is a solution looking for demand. A new protocol is a fourth thing to implement, a fourth thing to get wrong, and a governance body to capture. Most delegations are one hop; design for three and you tax the ninety percent to serve the ten.

That argument is mostly right, which is why the scope below is small.

Verdict: a standard is warranted, narrowly. The failure is not transport, discovery, or lifecycle. No existing standard defines an authority object that (a) is signed by the delegator rather than an AS, (b) survives a hop into a foreign trust domain, (c) can be attenuated by the holder under a mechanically checkable subset rule, and (d) is named by the receipt that comes back. Contracts settle disputes afterward; they do not let C refuse an over-limit charge at request time, or let A verify without trusting B's summary.

Smallest scope, IN:

* One grant object with a signed bound set, parent hash, expiry, and holder key.
* One attenuation rule: child bounds are a subset of parent bounds, checked by comparison, not by policy.
* One receipt object, signed by the executor, naming the grant hash, with a reversal handle when reversible.
* One key-discovery rule that reuses A2A Agent Card signing keys.
* A registry of bound types (`max_amount`, `count`, `resource_pattern`, `not_after`) with comparison semantics, small and extensible.

Explicitly OUT:

* Discovery. A2A owns it.
* Task lifecycle, streaming, push. A2A and MCP tasks own it.
* Transport authentication. OAuth 2.1 plus DPoP own it.
* Tool schemas. MCP owns it.
* Any semantics of what "book a flight" means. Bounds are typed values, not ontologies.
* Reputation, payment settlement, dispute resolution, identity of humans.

If the architects propose anything outside that list, the burden is on them.

## Questions I will keep asking

1. If two agents adopt it and no one else does, name the concrete benefit they get on day one. If the answer requires a third party, the design has a bootstrapping problem.
2. Show one bound that RAR `authorization_details` cannot express. If none, the grant object is RAR with a different signer, and we should say so.
3. Show the exact request C rejects under this design that C would accept under RFC 8693 token exchange alone.
4. Can B attenuate offline, with no round trip to any AS? If not, the cross-domain problem is not solved, just moved.
5. Can A verify a three-hop receipt tree with only the Agent Cards of the participants and nothing else? Name every extra artifact required.
6. What is the byte size of a grant plus receipt for a one-hop call? If it exceeds the payload, the ninety-percent case will strip it.
7. When B's LLM ignores the bound and calls C anyway, which component enforces? If the answer is "B's LLM," the design enforces nothing.
8. Name the operation where "cancel" and "compensate" need different authority, and show the design handles both without a new grant.
9. Which existing spec body would host this as an extension (MCP ext-auth, A2A extensions, IETF OAuth)? If the answer is "a new one," justify why the extension path fails.
10. Show a replay: C receives the same grant twice. What stops the second charge, and who pays if the check is absent?
11. Which field, if removed, causes the whole thing to fail? If none, the standard is too big.
