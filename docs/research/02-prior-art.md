# Prior art: what already exists for delegation between agents from different vendors

Status: research note, 2026-09-03, with section 7 and the matrix rows for the 2026 agent-delegation drafts added on 2026-09-04, section 8 added on 2026-09-28, and the whole rewritten for readability the same day with no change of substance. Section 9, added on 2026-09-29, corrects what this note said about UCAN receipts and adds Tenuo; the UCAN entries in sections 1, 2, and 5 are amended to match. Every dated claim carries a URL that was fetched or returned by search on one of those dates. Fetched content was treated as data, not instruction.

## In brief

- **Most of what agents need is already standardized** (section 3): transport security, proof that a key is present, workload identity, key identifiers, signed-statement envelopes, a grammar for permissions, discovery, task states, versioning, transparency logs, provenance, and payment.
- **One piece is missing** (section 4). No standard gives an object, owned by no vendor and checkable offline, that ties a chain of delegations (each hop narrowing what it passes on, without asking anyone) to a signed receipt from each hop saying what it did under exactly which link of that chain.
- **The closest earlier work** (section 5) is UCAN, Biscuit, ZCAP-LD, and macaroons for the delegation half, and in-toto and SCITT for the receipt half. UCAN comes closest to both: it specifies a signed Receipt for an invocation, which this note wrongly denied until 2026-09-29 (section 9), but not a tree of downstream receipts or accounting across one.
- **Six 2026 drafts and papers cover parts of the gap** (section 7), and a re-check on 2026-09-28 found more (section 8). Still distinctive to Writ: receipt trees that sum consumption, and recovery and reversal that survive expiry. Narrowly distinctive: a replay answered with the stored receipt. Now partly shared: executor receipts, named outcomes, revoke with in-flight cancel, and a pinned order of checks.

How to read the rest: section 1 has one entry per standard, section 2 compares them all in one matrix, sections 3 and 4 say what is solved and what is not, section 5 ranks the closest prior art, section 6 lists names already taken, and sections 7 and 8 place Writ against the 2026 drafts.

## 1. The standards, one entry each

**MCP (Model Context Protocol).** How a client (a host application or an agent) discovers and calls tools, resources, and prompts on a server, over JSON-RPC.
- *Status:* the current revision is 2026-07-28. It removed protocol-level sessions and the initialize handshake, added `server/discover` for advertising version and capabilities, moved Tasks into an official extension (`io.modelcontextprotocol/tasks`), and introduced a formal extensions framework and a twelve-month deprecation policy (https://modelcontextprotocol.io/specification/2026-07-28/changelog).
- *Governance:* the Agentic AI Foundation under the Linux Foundation, formed December 2025 with Anthropic, OpenAI, and Block as founders (https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation).
- *Adoption:* the default tool protocol in every major model vendor's client.
- *Where it stops:* strictly one hop, client to server. There is no notion of a server acting for an upstream principal, no signed results, and cancellation in the Tasks extension is cooperative and reaches one hop (https://modelcontextprotocol.io/extensions/tasks/overview).

**MCP Authorization.** A profile of OAuth 2.1 for HTTP transports.
- *What it requires:* servers MUST publish RFC 9728 Protected Resource Metadata, clients MUST send RFC 8707 `resource`, and Client ID Metadata Documents replace Dynamic Client Registration, which is now deprecated (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- *Status:* the Enterprise-Managed Authorization extension (often called Cross App Access) is stable as of July 2026, adopted by Okta, Microsoft, and Anthropic (https://www.datawiza.com/blog/mcp-authentication-explained).
- *Where it stops,* quoted from the spec: "MCP servers MUST NOT accept or transit any other tokens." Authority cannot flow through a server to a downstream server. Each hop needs its own grant from its own authorization server, online.

**A2A (Agent2Agent).** Peer discovery through Agent Cards, creating and streaming tasks, and returning artifacts between agents.
- *Status:* v1.0.0 shipped 2026-03-12 and v1.0.1 on 2026-05-28 (https://github.com/a2aproject/A2A/releases). v1.0 added JWS-signed Agent Cards, three formal bindings (JSON-RPC, gRPC, HTTP+JSON), eight task states including `TASK_STATE_CANCELED` and `TASK_STATE_AUTH_REQUIRED`, `CancelTask`, versioned extensions, and a `tenant` routing field (https://a2a-protocol.org/latest/whats-new-v1/).
- *Governance:* moved from the Linux Foundation project to the Agentic AI Foundation in August 2026 (https://www.axios.com/2026/08/17/a2a-agentic-ai-foundation-open-ai-standards, https://aaif.io/projects/agent2agent).
- *Adoption:* 150+ organizations, and production use at Microsoft, AWS, and Google, as of April 2026 (https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year).
- *Where it stops:* only the Agent Card is signed. Messages, parts, and artifacts carry no signature, `tenant` is "an opaque routing identifier," and nothing in a task says under whose authority the callee acts (https://a2a-protocol.org/latest/specification/).

**ACP (IBM BeeAI Agent Communication Protocol).** REST-based agent invocation for the BeeAI platform, launched March 2025.
- *Status:* merged into A2A under the Linux Foundation on 2025-08-29; IBM took a seat on the A2A TSC, and BeeAI now ships an A2A adapter (https://lfaidata.foundation/communityblog/2025/08/29/acp-joins-forces-with-a2a-under-the-linux-foundations-lf-ai-data/). Treat it as historical.
- *Where it stops:* where A2A stops.

**ANP (Agent Network Protocol).** An open protocol of Chinese origin with three layers: `did:wba` identity (a did:web derivative, v0.2), agent descriptions in JSON-LD, and discovery through `.well-known` files.
- *Status:* the current line is ANP 1.1 (https://agent-network-protocol.com/specs/did-method.html, https://agentnetworkprotocol.com/en/specs/01-agentnetworkprotocol-technical-white-paper/).
- *Governance and adoption:* a small GitHub community, with thin adoption outside China.
- *Where it stops:* each request is authenticated by a DID signature, but authorization is out of scope. There is no delegation object and no receipts.

**AP2 (Agent Payments Protocol).** Google's open extension for A2A that represents a purchase as a chain of signed mandates, described at launch as Intent, Cart, and Payment Mandates backed by verifiable digital credentials (https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol).
- *Status:* v0.1.0 shipped 2025-09-16, and v0.2.0 on 2026-04-28, "focused on providing Human Not Present flows" (https://github.com/google-agentic-commerce/AP2/releases). The v0.2 docs reorganize around Checkout and Payment Mandates, each with Open and Closed stages, and say standardization "will continue within the Agentic Authentication Technical and Payments Technical Working Groups in FIDO" (https://ap2-protocol.org/).
- *Where it stops:* the mandate chain is the closest shipped analog of a chain of task receipts, but every object is shaped like a payment, and the chain runs from user to agent to merchant, not from agent to sub-agent.

**x402.** An HTTP 402 payment handshake: the server returns `PAYMENT-REQUIRED`, the client retries with `PAYMENT-SIGNATURE`, and a facilitator verifies and settles.
- *Status:* v1 launched 2025-05-06, and v2 on 2025-12-11 with CAIP-2 network ids and de-prefixed headers (https://x402.org/x402-v2-launch/).
- *Governance:* the x402 Foundation under the Linux Foundation became operational on 2026-07-14, with Visa, Mastercard, Stripe, AWS, Google, and Microsoft among its members (https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications).
- *Where it stops:* pure metering. No identity beyond a wallet key, no delegation, no task semantics.

**DIDs (did:key, did:web, DID Core 1.1).** A URI scheme that resolves to a document holding verification keys.
- *Status:* DID 1.1 reached Candidate Recommendation on 2026-03-05 (https://www.w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifiers-dids-v1-1/). did:key (https://w3c-ccg.github.io/did-key-spec/) and did:web (https://w3c-ccg.github.io/did-method-web/) remain Credentials Community Group drafts, not Recommendations, yet they are what UCAN, ZCAP, ANP, and AP2 all actually use.
- *Where it stops:* identity only. A DID says who signed, never what they were allowed to do.

**W3C Verifiable Credentials Data Model 2.0.** A JSON-LD envelope for signed claims by an issuer about a subject.
- *Status:* a Recommendation since 2025-05-15; v2.1 had a First Public Working Draft in 2026 (https://www.w3.org/TR/vc-data-model-2.0/, https://www.w3.org/news/2026/first-public-working-draft-verifiable-credentials-data-model-v2-1/).
- *Adoption:* the EU digital identity wallet, and AP2 mandates.
- *Where it stops:* VCs are attestations, not capabilities. A holder cannot narrow a credential and hand it on, and the model has no chaining rule saying a re-issued credential must be a subset of what the re-issuer held.

**OAuth 2.1 and OpenID Connect.** The baseline for delegated access: a resource owner authorizes a client at an authorization server, which mints a token bound to an audience.
- *Status:* OAuth 2.1 is still draft-ietf-oauth-v2-1 (MCP cites -13), but it is the de facto profile; OIDC adds user identity on top.
- *Where it stops:* three parties and one hop. Tokens are opaque to everyone but the AS and the resource, so a downstream party cannot inspect or narrow what it received without going back to the issuer.

**RFC 8693 Token Exchange and RFC 9396 Rich Authorization Requests.**
- *What they do:* 8693 (January 2020) lets a client trade one token for another, recording the delegation in `act` and `may_act` claims (https://www.rfc-editor.org/rfc/rfc8693). 9396 (May 2023) replaces flat scopes with structured `authorization_details` objects (https://www.rfc-editor.org/rfc/rfc9396). Together they can express "B acts for A with these details."
- *Where they stop:* every exchange is an online round trip to an AS that both hops trust, and exchange across domains needs the identity-chaining pattern, which is still an individual draft. Nothing is offline.

**RFC 9449 DPoP and RFC 9421 HTTP Message Signatures.**
- *What they do:* DPoP (September 2023) binds an access token to a client key (https://www.rfc-editor.org/rfc/rfc9449). 9421 (February 2024) signs selected HTTP components with any key (https://www.rfc-editor.org/rfc/rfc9421).
- *Adoption:* real for 9421, but slow; most of the fediverse still runs draft-cavage-12, and Fedify "double-knocks" both (https://socialhub.activitypub.rocks/t/rfc-9421-http-signatures-in-2026/8427, https://hackers.pub/@fedify/2026/why-activitypub-is-hard).
- *Where they stop:* they prove possession of a key on the wire, which is a good primitive at the message layer, but say nothing about what the key holder may do.

**RFC 9635 GNAP.** A ground-up successor to OAuth (October 2024), in which the client negotiates a grant, keys replace pre-registration, and access rights are structured objects (https://www.rfc-editor.org/rfc/rfc9635).
- *Adoption:* limited; no major vendor has shipped it as a primary flow (https://oauth.net/gnap/).
- *Where it stops:* still centered on the AS. Attenuation and delegation go through the grant server.

**SPIFFE/SPIRE and IETF WIMSE.** SPIFFE issues X.509 or JWT SVIDs to workloads after attestation.
- *Status:* SPIRE v1.15.3 shipped 2026-08-21 (https://github.com/spiffe/spire/releases). WIMSE's architecture draft is at -08 (2026-07-06, Informational), with token-profile drafts behind it (https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/).
- *Adoption:* Uber, Stripe, Netflix, and CNCF graduation.
- *Where it stops:* identity inside one trust domain, with federation between domains by exchanging bundles. There is no delegation object, and an SVID names a workload, not a task.

**Object capabilities and ZCAP-LD.** Authorization Capabilities for Linked Data encodes a capability as a JSON-LD document signed with a Data Integrity proof, delegated by chaining documents with caveats, and exercised by a signed invocation.
- *Status:* a CCG work item at v0.4.0-draft, with commits into September 2026 (https://w3c-ccg.github.io/zcap-spec/, https://github.com/w3c-ccg/zcap-spec).
- *Adoption:* Digital Bazaar products and some Solid experiments.
- *Where it stops:* the cost of JSON-LD canonicalization, a dependency on DIDs, no receipt for an invocation, and no standards-track status after six years.

**UCAN 1.0.** The UCAN Working Group spec is marked "Version 1.0.0", with sub-specs for Delegation, Invocation, Promise, and Revocation. Each delegation "MUST either directly restate or attenuate (diminish) its capabilities," subjects are DIDs, and all UCANs "MUST be canonically encoded with DAG-CBOR for signing" (https://github.com/ucan-wg/spec/blob/main/README.md).
- *Status:* I could not find a dated 1.0 release announcement, so treat the version as self-declared.
- *Adoption:* Storacha (formerly web3.storage), the Fission lineage, go-ucan.
- *Where it stops:* IPLD and CIDs everywhere, and principals that can only be DIDs. Its receipts sign one invocation's result and the tasks it enqueues; they do not embed the receipts of work delegated below, account for consumption across them, or give upstream issuers recovery and reversal. (Corrected 2026-09-29: this entry used to say UCAN had a Promise and no signed receipt. See section 9.)

**Biscuit.** An Eclipse Foundation token format with Datalog policies, offline attenuation by appending blocks, and third-party blocks signed by outside keys.
- *Status:* v3.3 shipped 2024-11-27 with a clearer version scheme (https://www.biscuitsec.org/blog/biscuit-3-3/, https://github.com/eclipse-biscuit/biscuit).
- *Where it stops:* verification needs the root public key, so only parties who know the issuer can check, and Datalog is a large surface for a minimal protocol. No receipts.

**Macaroons.** Google's 2014 bearer credential, whose HMAC chain lets any holder add caveats offline and lets third parties discharge caveats (https://www.researchgate.net/publication/269196979_Macaroons_Cookies_with_Contextual_Caveats_for_Decentralized_Authorization_in_the_Cloud).
- *Adoption:* Lightning's L402, and ports of libmacaroons.
- *Where it stops:* HMAC means only the holder of the root key can verify, so a downstream hop cannot check what it received and a third party cannot audit. The delegates never sign anything.

**CapTP and OCapN.** Spritely's and Agoric's capability transport protocol for distributed objects, with promise pipelining and object references across the network. OCapN is an explicit pre-standardization group with draft specs (https://ocapn.org/, https://github.com/ocapn/ocapn).
- *Where it stops:* it is a live-session protocol. Authority is a reference held in a connection, not a portable document that survives offline or can be shown to a third party.

**WebAuthn Level 3 and passkeys.** A W3C Recommendation since 2026-08-25, adding PRF key derivation, Related Origin Requests, the Signal API, and conditional create (https://www.w3.org/TR/webauthn-3/).
- *Where it stops:* it authenticates a human to an origin. It is the right root for "a person approved this", but it produces no reusable delegation artifact.

**Matrix.** Federated real-time messaging. Spec v1.19 landed in July 2026, and Matrix 2.0 is being cut (https://matrix.org/blog/2026/07/17/this-week-in-matrix-2026-07-17/). Servers sign events, and rooms have a DAG with power levels.
- *Where it stops:* authorization is based on room membership. There is no narrowed capability per task, and the transport assumes homeservers.

**ActivityPub.** W3C social federation. A new Social Web Working Group was chartered on 2026-01-15, through 2028-01-31, to maintain it (https://www.w3.org/2026/01/social-web-wg-charter.html).
- *Where it stops:* actors and inboxes are a fine model for discovery and addressing, but authorization is server-level HTTP signatures, and there is no delegation and no task semantics.

**IETF SCITT.** The architecture is now RFC 9943 (Proposed Standard, June 2026). An Issuer makes a COSE_Sign1 Signed Statement, a Transparency Service registers it and returns a Receipt, and the pair is a Transparent Statement that can be verified without contacting the service (https://www.rfc-editor.org/info/rfc9943/). The reference API (SCRAPI) is still a draft (https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/).
- *Where it stops:* SCITT says nothing about authority. It makes a statement non-repudiable and timestamped; it does not say the maker of the statement was allowed to act.

**in-toto attestations and SLSA.** in-toto defines a Statement (digests of the subject plus a typed predicate) inside a DSSE envelope, and SLSA v1.2 (2025-11-24) defines the Provenance predicate and build levels (https://github.com/in-toto/attestation, https://slsa.dev/blog).
- *Adoption:* GitHub artifact attestations, Sigstore.
- *Where it stops:* provenance about artifacts, not about actions under delegated authority. Nothing links a predicate to the capability that permitted the build.

**C2PA.** Content Credentials: a manifest of assertions, a claim, and a claim signature bound to a media asset, with an X.509 trust list. v2.4 was released in April 2026 and supports chained manifests across successive editors (https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html).
- *Where it stops:* shaped for media, X.509 only, and provenance without authorization.

**OpenID AuthZEN.** Authorization API 1.0 became a Final Specification in January 2026, standardizing the decision call from a PEP to a PDP (https://openid.net/notice-of-vote-to-approve-proposed-authorization-api-1-final-specification/). Working Group drafts add the Access Request and Approval Profile (flows for human approval) and COAZ, a binding for authorizing MCP tools (https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/).
- *Where it stops:* a PDP must be online for every decision, which is the opposite of offline verification.

**IETF agent-auth drafts.**
- draft-klrc-aiagent-auth-03 (2026-07-06, individual, with authors from Defakto, AWS, Zscaler, Ping, OpenAI, and Okta) composes WIMSE, token exchange, and transaction tokens into agent delegation chains (https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/).
- draft-oauth-transaction-tokens-for-agents (through -06, Informational) puts the agent in `act` and the principal in `sub` (https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/).
- draft-ietf-oauth-client-id-metadata-document-02 (2026-07-06) is the CIMD mechanism MCP already depends on (https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/).
- The OpenID AIIM Community Group and a proposed W3C Agent Identity Registry Protocol CG (2026-04-24) are where the discussion happens (https://openid.net/cg/artificial-intelligence-identity-management-community-group/, https://www.w3.org/community/blog/2026/04/24/proposed-group-agent-identity-registry-protocol-community-group/).
- *Where they all stop:* every design routes through an AS or a transaction-token service, online, and none defines what a result receipt looks like.

**AGNTCY.** Cisco's Outshift project, donated to the Linux Foundation on 2025-07-29: OASF (Open Agent Schema Framework) for describing capabilities, an agent directory, an identity service, SLIM messaging, and observability (https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-agntcy-project-to-standardize-open-multi-agent-system-infrastructure-and-break-down-ai-agent-silos).
- *Where it stops:* infrastructure and a directory, not a delegation model; verifying identity presumes the AGNTCY identity service.

**NANDA, Agora, LMOS.**
- NANDA (MIT Media Lab) proposes a hybrid registry index plus per-organization registries and an "AgentFacts" passport (https://projectnanda.org/).
- Agora (Oxford, arXiv 2410.11905) is a meta-protocol in which agents negotiate content-addressed Protocol Documents from natural language (https://www.alphaxiv.org/overview/2410.11905).
- Eclipse LMOS builds on W3C Web of Things Thing Descriptions and runs in production at Deutsche Telekom, with a progress review scheduled for 2026-09-23 (https://projects.eclipse.org/projects/technology.lmos/reviews/eclipse-lmos-2026.09-progress-review).
- *Where all three stop:* discovery and description, not authority or evidence.

## 2. Comparison matrix

Y = defined by the standard. partial = present, but incomplete for the multi-hop case across domains. N = absent. "Attenuation" means hop 2 can narrow what hop 1 got, offline, without the original issuer online.

| Standard | Identity | Discovery | Capability description | Authentication | Authorization | Delegation with attenuation | Task lifecycle | Receipts / provenance | Cancellation propagation | Idempotency | Compensation / rollback | Version negotiation | Central authority required? | Offline verifiable? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MCP 2026-07-28 | partial: CIMD URL, serverInfo | partial: server/discover, no registry | Y: tools/list JSON Schema | Y: OAuth 2.1 bearer | partial: scopes, one hop | N: tokens must not transit | partial: Tasks extension | N: unsigned JSON-RPC | partial: tasks/cancel, one hop | N: retry means new request id | N | Y: _meta protocolVersion | Y: AS per server | N |
| A2A 1.0.1 | partial: signed Agent Card | Y: .well-known card | Y: skills in card | Y: securitySchemes, mTLS | partial: opaque tenant | N: no delegation object | Y: eight states | N: artifacts unsigned | partial: CancelTask, one hop | partial: taskId continuation | N | Y: protocolVersion in card | partial: card issuer domain | partial: card only |
| ANP 1.1 | Y: did:wba | Y: .well-known | Y: JSON-LD description | Y: DID signatures | N | N | N | N | N | N | N | N | N: DNS only | Y: DID docs cached |
| AP2 0.2.0 | partial: DIDs via VC | N: rides A2A | N | partial: wallet signatures | Y: mandate chain | partial: user to agent to merchant only | partial: open/closed mandate | Y: signed mandates | N | partial: mandate id | N: refund out of band | partial | partial: payment network | Y |
| x402 v2 | partial: wallet key | N | N | Y: payment signature | N | N | N | partial: on-chain settlement | N | partial: nonce | N | partial: x402Version | partial: facilitator | partial |
| DID 1.1 / did:key / did:web | Y | partial: resolution | N | partial: keys only | N | N | N | N | N | N | N | partial | N for did:key; DNS for did:web | Y for did:key |
| VC DM 2.0 | partial: issuer/subject | N | N | N | partial: attestation, not capability | N: no subset rule | N | partial: signed claims | N | N | N | Y: context | N | Y |
| OAuth 2.1 / OIDC | partial: client_id, sub | Y: RFC 8414/9728 | N: flat scopes | Y | Y | N | N | N | N | N | N | partial | Y: AS | N: introspection or JWT keys |
| RFC 8693 + RFC 9396 | partial: act chain | N | Y: authorization_details | Y | Y | partial: AS narrows, online | N | N | N | N | N | N | Y: AS every hop | N |
| RFC 9449 DPoP / RFC 9421 | partial: key binding | N | N | Y: proof of possession | N | N | N | partial: signed request | N | partial: jti nonce | N | N | N | Y |
| GNAP RFC 9635 | Y: key-based client | partial | Y: access rights objects | Y | Y | partial: AS mediated | N | N | N | N | N | Y | Y: grant server | N |
| SPIFFE / WIMSE | Y: SVID | N | N | Y: mTLS or JWT | N | N | N | N | N | N | N | partial | Y: SPIRE server per domain | partial: bundle cached |
| ZCAP-LD 0.4 | Y: DID controller | N | partial: allowedAction | Y: invocation proof | Y | Y: caveat chain | N | N: no receipt | N | N | N | N | N | Y |
| UCAN 1.0 | Y: DID | N | Y: cmd and policy | Y: signed invocation | Y | Y: must attenuate | partial: Promise | Y: signed Receipt of an invocation, no embedded sub-receipts (corrected 2026-09-29) | partial: Revocation | Y: invocation CID | N | Y: version field | N | Y |
| Biscuit 3.3 | partial: keys only | N | partial: Datalog facts | partial: root key | Y | Y: appended blocks | N | N | N | N | N | Y: block version | N | Y if root key known |
| Macaroons | N | N | partial: caveats | N | Y | Y: caveats | N | N | N | N | N | N | N | partial: issuer only |
| CapTP / OCapN | partial: object refs | N | N: dynamic | Y: session | Y: reference is authority | Y: facets | partial: promises | N | partial: promise break | N | N | partial | N | N: live session |
| WebAuthn L3 | Y: human credential | N | N | Y | N | N | N | partial: signed assertion | N | N | N | N | N: origin | partial |
| Matrix 1.19 | Y: MXID plus server keys | Y: rooms, directory | N | Y | partial: power levels | N | N | partial: signed event DAG | N | Y: txn ids | N | Y | partial: homeserver | partial |
| ActivityPub | Y: actor URI | Y: inbox/outbox, webfinger | N | partial: HTTP signatures | N | N | N | N | partial: Undo | partial: activity id | N | N | partial: home server | N |
| SCITT RFC 9943 | partial: issuer key | N | N | N | N | N | N | Y: Receipts | N | N | N | Y: COSE | Y: Transparency Service to register | Y: to verify |
| in-toto / SLSA 1.2 | partial: signer key | N | N | N | N | N | N | Y: Statement in DSSE | N | N | N | Y: predicateType | N | Y |
| C2PA 2.4 | Y: X.509 | N | N | N | N | N | N | Y: manifest chain | N | N | N | Y | Y: trust list | Y |
| AuthZEN 1.0 | partial: subject | N | partial: action/resource | N | Y: decision API | N | N | N | N | N | N | Y | Y: PDP online | N |
| AGNTCY | partial: identity service | Y: directory | Y: OASF | partial | N | N | N | N | N | N | N | partial | partial: directory | N |
| AIP / IBCT (arXiv 2603.24775, 2026-03) | partial: issuer and delegator ids in the token | N | partial: scope strings, budget | Y: EdDSA JWT or Biscuit chain | Y | Y: subset per block, holder-appended, offline | N | partial: optional completion block with result hash, self-reported | N | N: short expiry only | N | partial | N | Y |
| AgentROA (draft-nivalto, -01, 2026-04) | partial: Agent Identity Registry | N | partial: capability ids in the ROA | Y: Ed25519 over JSON | Y: policy-engine-signed ROA | Y: ARA per hop references its parent, monotonic narrowing | partial: session | Y: AER execution receipts signed by the gateway | N | partial: (envelope_id, session_id) cache | N | N | partial: policy engine and registry | partial: cached registry data |
| WIMSE agent delegation chain (draft-asor, -01, 2026-09-03) | partial: iss, sub, cnf key | N | Y: authorization_details (RAR) | Y: JWS, DPoP holder binding | Y | Y: par_hash to the parent's JWS signing input, constraint subsumption, offline | N | N | N | partial: cnf and jti | N | partial: del_depth | N: optional status list | Y |
| OAuth agent delegation profile (draft-hamr, -01, 2026-09-02) | partial: keyid per link | N | partial: scope strings, eight floor axes | Y: RFC 9421 plus per-link signatures | Y | Y: subset, floor, expiry per adjacent pair, offline; no hash link between links | N | N: out of scope by design | N | partial: nonce echo, per-chain write budget | N | N | N: trust source for the root | Y |
| EP authorization receipts (draft-schrock, -12, 2026-08-16) | partial: approver keys in a directory | N | N | Y: JCS plus ES256 or EdDSA | Y: per-action approval bound to the action hash | N | N | Y: pre-execution receipt, later trust receipt with consumption proof | N | Y: one-time consumption | N | N | partial: shared consumption domain, log | Y: with a log checkpoint |
| Agentic tool-call binding (draft-das, -02, 2026-08-28) | N | N | partial: tool and function ids | N | Y: authority_id consumed before invoke | partial: delegation_depth field only | N | N: log entry, unsigned | N | Y: single-use authority, compare-and-swap | N | N | Y: the host's authority store | N |
| **Writ v0.1** | Y: did:key | N: cards or well-known | partial: `act` prefix plus typed bounds | Y: Ed25519 over canonical JSON | Y: delegator-signed writ | Y: `prv` hash link, five-type subset rule, offline | N: one call per task step | Y: tally per hop, sub-tree embedded, three-valued verdict | Y: revoke with forwarding and `canceled` tallies | Y: (leaf writ, `id`), byte-identical replay | Y: `sys/undo` by any issuer, `rev.until` | Y: `v`, `crit` | N | Y |

## 3. What is solved

These functions need no new standard: reuse them, and profile them where needed.

- **Authenticating one client to one server at the transport level:** OAuth 2.1 as profiled by MCP, with RFC 9728 and RFC 8414 discovery, and CIMD for client identity without registration.
- **Proof of possession on the wire:** RFC 9449 DPoP inside OAuth, and RFC 9421 for any HTTP message.
- **Workload identity inside one trust domain:** SPIFFE SVIDs, with WIMSE as the coming IETF framing.
- **Human approval as a root of trust:** WebAuthn Level 3 assertions.
- **Decentralized key identifiers:** did:key for short-lived agent keys, did:web for keys anchored to a domain. Do not invent a new identifier scheme.
- **An envelope for signed statements:** COSE_Sign1 (SCITT) or DSSE (in-toto). Either is fine; pick one and stop.
- **A grammar for structured permissions:** RFC 9396 `authorization_details` objects are a mature vocabulary for "what exactly," even outside OAuth.
- **Service discovery and capability description:** A2A Agent Cards for agents, and MCP `tools/list` plus `server/discover` for tools. OASF is a candidate schema layer if one is needed.
- **Task lifecycle states:** A2A's eight states and MCP's Tasks extension already agree on the shape (submitted, working, input required, completed, failed, canceled).
- **Version negotiation:** MCP's per-request `_meta` protocol version and `server/discover`, and A2A's `protocolVersion` in the card.
- **Append-only transparency and timestamping:** SCITT RFC 9943 Receipts, when a public log is wanted.
- **Artifact provenance:** in-toto Statements and SLSA Provenance for software, and C2PA for media.
- **Payment:** AP2 mandates over A2A, or x402 over HTTP. Do not couple the core protocol to either.
- **Online policy decisions:** AuthZEN, when a PDP is acceptable.
- **Trace context:** W3C `traceparent` in `_meta`, as MCP already documents.

## 4. The smallest important gap

**The scenario.** Agent A (vendor 1) gives Agent B (vendor 2) a narrow task: "summarize tickets 100 to 200 in project P, read only." B passes part of it to Agent C (vendor 3) with strictly less authority: "read tickets 150 to 200 in P." B and C return results carrying verifiable evidence of who did what under which authority. A can verify all of that offline, and can cancel the work in flight or compensate afterward.

**Where MCP breaks.**
- *Step 1 works:* A is an MCP client of B and obtains a token from B's authorization server, scoped to P.
- *Step 2 breaks:* B cannot hand C anything derived from A's grant, because "MCP servers MUST NOT accept or transit any other tokens" (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). B must go to C's authorization server as a fresh client and obtain a token whose scope is whatever C's AS will grant B, with no cryptographic tie to A's narrower grant.
- *Step 3 breaks:* MCP results are unsigned JSON-RPC `structuredContent`. C's result to B and B's result to A are bare data.
- *Step 4 breaks:* `tasks/cancel` reaches B, but nothing reaches C except through B's own code, and the extension states that cancellation "does not prove that remote work stopped" (https://modelcontextprotocol.io/extensions/tasks/overview). Compensation has no primitive at all.

**Where A2A breaks.**
- *Step 1 half works:* A verifies B's signed Agent Card, so it knows the endpoint belongs to vendor 2's domain, then opens a task with the OAuth or mTLS scheme B advertises.
- *Step 2 breaks:* B opens a second task with C. The only carrier for context is `tenant`, "an opaque routing identifier," so C never learns that it acts under A's authority, narrowed to tickets 150 to 200 (https://a2a-protocol.org/latest/specification/).
- *Step 3 breaks:* only the Agent Card is signed; "no signature mechanisms are defined for individual messages, parts, or artifacts," so A cannot tell "C produced this under B's sub-delegation" from "B made it up."
- *Step 4 breaks:* `CancelTask` from A stops B's task; passing it on to C is B's private behavior. A cannot verify offline, because there is nothing signed to verify.

**Where OAuth breaks.**
- *Step 1 works,* with RFC 9396 details describing the ticket range.
- *Step 2 half works,* and only if A's AS, B, and C all trust one AS or a federation. B performs RFC 8693 token exchange, and the AS narrows the scope and records `act`. That is online by construction, and across vendors it needs identity chaining, which is still an individual draft (https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/). The holder (B) cannot itself produce a strictly narrower credential; only the issuer can.
- *Step 3 breaks:* an access token is permission, not evidence. Nothing in the OAuth family is a signed statement by C that "I did X with token T."
- *Step 4 breaks:* revocation is a call to the AS, and the AS cannot reach C's work in flight. Verifying the chain offline is impossible, because A never sees C's token, and C's token was minted by an AS that A may not even know.

**The gap in one sentence, as found against MCP, A2A, and OAuth on 2026-09-03.** Those three give no object, owned by no vendor and checkable offline, that ties a chain of delegations scoped to a task (each hop narrowing what it passes on, without contacting any issuer) to a signed receipt from each hop saying what it did under exactly which link of that chain. Section 7 records that several 2026 drafts and papers outside those three now cover parts of this gap, and says what Writ still adds.

Everything else in the scenario (discovery, endpoint identity, transport authentication, task states, cancellation at one hop) is already standardized. The missing piece is small: one envelope for authority that can be narrowed, plus one receipt format that references it, with the rule that a receipt is valid only if its link of authority is valid.

## 5. Closest prior art to the gap, ranked

1. **UCAN 1.0.** The closest.
   - *Has:* delegation with a mandatory attenuation rule, a separate Invocation that names the delegation chain, Promise for awaiting results, and Revocation.
   - *Missing:* a receipt tree. UCAN does specify a signed Receipt from the executor (section 9 corrects the claim that it did not), but a Receipt's `fx` enqueues further tasks rather than embedding the receipts of delegated work, and nothing accounts for consumption across hops.
   - *Baggage:* DAG-CBOR and CIDs (IPLD), principals that can only be DIDs, and a policy language of its own.
2. **Biscuit 3.3.**
   - *Has:* offline attenuation by appended blocks, third-party blocks signed by outside keys (a natural place for C's contribution), and a clean versioning story.
   - *Missing:* receipts; and verification is tied to knowing the root public key, so a stranger cannot audit.
   - *Baggage:* Datalog as the policy language, and Protobuf encoding.
3. **ZCAP-LD.**
   - *Has:* an explicit capability chain with caveats and a signed invocation, DID controllers, and Data Integrity proofs.
   - *Missing:* any receipt, and any home on a standards track.
   - *Baggage:* JSON-LD canonicalization, DID resolution, and six years at v0.4-draft.
4. **Macaroons.**
   - *Has:* the simplest attenuation primitive there is, and third-party caveats map to "C must discharge."
   - *Missing:* verification by public key, so only the root issuer (A) can verify, and delegates never sign anything.
   - *Baggage:* minimal, but HMAC makes it useless as evidence to anyone but A.
5. **AP2 mandates.**
   - *Has:* the only shipped chain of signed objects from the agent era where each step references the previous one and the final object is the receipt.
   - *Missing:* hops from agent to sub-agent, and anything not shaped like a purchase.
   - *Baggage:* coupling to payments, VC and JSON-LD encoding, and FIDO working-group governance.
6. **in-toto attestations.**
   - *Has:* the right receipt shape: digests of the subject plus a typed predicate in a DSSE envelope, chainable by referencing earlier statements.
   - *Missing:* any authority model; a predicate cannot point at the capability that permitted the action.
   - *Baggage:* light, which is why it is the strongest candidate to borrow for the receipt half.
7. **SCITT RFC 9943.**
   - *Has:* Signed Statements that are non-repudiable and timestamped, with Receipts verifiable offline.
   - *Missing:* authority; and registration needs a Transparency Service online, which the scenario forbids for the verification step.
   - *Baggage:* COSE and CBOR (fine), and a transparency log operator (not fine as a requirement). Best used as an optional anchor for receipts, never as the core.

## 6. Names already taken

Avoid these, or expect collisions in search and in conversation.

- **ACP**: three live meanings. IBM's Agent Communication Protocol (merged into A2A), Zed's Agent Client Protocol (editor to agent, August 2025), and OpenAI/Stripe's Agentic Commerce Protocol (September 2025) (https://zed.dev/acp, https://github.com/agentic-commerce-protocol/agentic-commerce-protocol).
- **ANP**: Agent Network Protocol.
- **AP2** and **Mandate** (Intent Mandate, Cart Mandate, Payment Mandate, Checkout Mandate): Google's payments vocabulary.
- **UCP**: Google's Universal Commerce Protocol, January 2026 (https://developers.googleblog.com/under-the-hood-universal-commerce-protocol-ucp/).
- **Agent Card**: A2A. **Agent Passport** and **AgentFacts**: NANDA. **Agent Pay** and **Agentic Tokens**: Mastercard. **Trusted Agent Protocol / TAP**: Visa.
- **Agora**: the Oxford meta-protocol, plus a Web3 governance project of the same name.
- **Coral**: Coral Protocol (Internet of Agents) and a separate CORAL autoresearch project.
- **SLIM**, **OASF**: AGNTCY. **LMOS**: Eclipse. **goose**, **AGENTS.md**: AAIF projects.
- **WARP**: Cloudflare's client and tunnel product.
- **Transaction Token**: an IETF OAuth term. **Cross App Access / XAA**: Okta. **EMA**: MCP's Enterprise-Managed Authorization extension.
- **AIP**: an arXiv "Agent Identity Protocol." **AIMS**: an IETF agent identity draft. **AIIM**: OpenID's community group. **AARP**, **COAZ**: AuthZEN profiles.
- **Receipt**, **Signed Statement**, **Transparent Statement**: SCITT terms of art. **Statement**, **Predicate**: in-toto. **Content Credentials**: C2PA.
- **Capability**: overloaded between MCP's feature flags and the object-capability meaning. If the protocol uses the ocap sense, say so once, and never use the word for feature negotiation.
- **Task**: both A2A and MCP own it, with slightly different state machines. Reuse it only if the states match theirs.
- **Biscuit**, **Macaroon**, **Cookie**: the pastry lineage is taken.
- **Matrix**, **Passkey**, **SPIFFE**, **WIMSE**, **GNAP**: established.

## 7. The 2026 agent-delegation drafts, and where Writ stands (added 2026-09-04)

Section 8 re-checks this section on 2026-09-28 against newer revisions and five more sources, and supersedes 7.1 and 7.3 where they differ.

Six pieces of work published between March and September 2026 address the same gap as section 4, from different directions. Each was fetched from its primary source on 2026-09-04 and is summarized as it describes itself, and the comparison is against the v0.1 specification as revised the same day.

**AIP and Invocation-Bound Capability Tokens** (arXiv 2603.24775v1, Sunil Prakash, Indian School of Business, 2026-03-25, https://arxiv.org/html/2603.24775v1).
- *Two token formats:* a compact EdDSA-signed JWT carrying issuer, subject, scope, a budget in cents, a maximum delegation depth, and timestamps; and a chained Biscuit token whose Ed25519 append-only blocks carry narrowed scopes under Datalog evaluation, so that "each delegation block MUST be a subset of its parent's capabilities" and holders narrow "without contacting the issuer." Tokens are "verified offline without contacting an authorization server."
- *Evidence:* optional completion blocks appended after the work carry a result hash, a verification status, resource consumption, and cost. They are "self-reported by default", with escalation to counter-signed or third-party attested.
- *Bindings:* `X-AIP-Token` on every MCP tool call, and an `aip_token` field in A2A task metadata.
- *Revocation:* not provided; "AIP v1 relies on short-lived tokens."
- *So:* offline attenuation linked by hash, MCP and A2A bindings, and a form of completion evidence all exist here.

**AgentROA** (draft-nivalto-agentroa-route-authorization-01, Joseph Michalak, Nivalto, 2026-04-16, Informational, https://datatracker.ietf.org/doc/draft-nivalto-agentroa-route-authorization/).
- *Three objects:* an ROA envelope, signed by a Policy Engine with Ed25519, binding an agent session to a capability set; Agent Route Attestations, signed by each delegating agent and each referencing its parent, forming a hash chain with scope that only narrows; and Agent Execution Receipts, signed by a Border Gateway at enforcement time, before and after an invocation, carrying the policy digest, session, capability, and outcome.
- *Verification:* against locally cached Agent Identity Registry data. Revocation goes through that registry, and replay is caught by a cache of `(envelope_id, session_id)` scoped to the session.
- *Encoding and position:* JSON with EdDSA signatures and optional SCITT countersignatures, positioned above MCP's OAuth, and requiring an ARA in A2A delegation requests.
- *So:* attestation chained by hash at every hop, and signed execution receipts, exist here, with a policy engine and a registry as the roots.

**Verifiable Attenuated Delegation for AI Agent Chains** (draft-asor-wimse-agent-delegation-chain-01, Rafael Asor, Attenu, 2026-09-03, intended Standards Track, https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/).
- *Shape:* a profile of OAuth JWT access tokens. Each delegation token carries `authorization_details` (RFC 9396), a `cnf` holder key bound by DPoP, `del_depth` and `del_max_depth`, and, for every token but the root, `par_hash`, the SHA-256 of the parent's JWS Signing Input, so that "each DT_i (i > 0) is linked to DT_{i-1}" and re-parenting fails.
- *Verification:* "deterministic, requiring no server contact except optional status-list checks": signatures, hash linkage, depth, attenuation at each hop, expiry that only shrinks, holder binding, and status.
- *Constraints:* typed (`max`, `min`, `one_of`, `not_one_of`, string prefix, rank), with a subsumption rule per type; scopes are dot-separated with a trailing wildcard. Ed25519 is mandatory, with JCS for protected headers.
- *Revocation:* expiry plus an optional Token Status List. No receipt.
- *So:* the closest neighbor. Hash-linked, offline, typed attenuation in a JWT envelope.

**An Attenuated Delegation Profile for Automated Agents** (draft-hamr-oauth-agent-delegation-01, A. Hassan, 2026-09-02, intended Standards Track, https://www.ietf.org/archive/id/draft-hamr-oauth-agent-delegation-01.html).
- *Shape:* an `Agent-Delegation` HTTP header carries a Structured Field list of opaque links, root first, each signed by its delegator, with an RFC 9421 message signature over the request.
- *Three rules per adjacent pair:* scope containment by exact string equality (the draft forbids "wildcard or prefix matching; hierarchical or namespace containment"); floors that never relax, over eight registered axes, with `min`, `max`, `rank`, and `one_of` comparators, where "an unknown or misspelled axis name MUST be treated as a hard rejection"; and expiry that never extends. Verifiers must check every link, not only the last. Links are not linked to each other by hash.
- *Out of scope:* receipts ("layer (a)", who may act, with draft-schrock cited for layer (c)); and "this profile defines no revocation mechanism".
- *Other rules:* a write budget per verifier, keyed by the root link's signature, bounds writes per chain, and failures MUST be indistinguishable to the presenter.
- *So:* a closed comparator registry over attenuation exists here too, with a deliberately narrower scope rule and a different stance on reporting errors.

**Authorization Receipts for High-Risk Agent Actions** (draft-schrock-ep-authorization-receipts-12, Iman Schrock, EMILIA Protocol Inc., 2026-08-16, https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/).
- *Shape:* before the action runs, an approver key, held apart from the orchestrating operator, signs an Authorization Context over the SHA-256 of the canonical (JCS) action, a policy reference, a nonce, an audience, and a validity window. An Authorization Bundle carries the action, the contexts, WebAuthn assertion data where used, and directory inclusion proofs; a later Trust Receipt adds one-time consumption state and a Merkle inclusion proof.
- *What it is not:* the bundle "contains no consumption, log_proof, execution outcome, or success assertion". It is evidence that an action was approved, not that it happened.
- *So:* approval receipts per action, issued before execution, verifiable offline, and backed by formal models, exist here.

**Agentic tool-call binding** (draft-das-agentic-tool-binding-02, Sangam Das, 2026-08-28, https://datatracker.ietf.org/doc/draft-das-agentic-tool-binding/).
- *Shape:* a tool call generated by a model becomes a non-effective Candidate Act carrying an `arguments_digest` (SHA-256 of the JCS arguments), tool and function identifiers, a destination, and an `authority_id` that must be consumed by compare-and-swap before `invoke()` can be reached. A retry after consumption "is a new act or a fetch of the original tool_result, never a second invoke."
- *Limits:* enforcement is local to the host, against an authority store. There is a `delegation_depth` field, but no delegation token that crosses a boundary, no signed receipt, and no offline verification.
- *So:* binding to an argument digest, and single-use consumption at the MCP dispatcher, exist here.

### 7.1 Already present in neighboring work

Writ can no longer claim any of these as its own, and the README and specification do not:

- Delegation chains linked by hash, narrowed by their holders, and verifiable offline: draft-asor (`par_hash`), AgentROA (ARA parent references), AIP (Biscuit blocks).
- Typed attenuation compared mechanically, with a closed comparator set that rejects unknown types: draft-asor's constraint subsumption, draft-hamr's axis registry.
- Bindings to MCP and A2A: AIP (header and task metadata), AgentROA (above MCP OAuth, ARA in A2A delegation).
- Completion or execution evidence: AIP's completion blocks, AgentROA's execution receipts.
- Binding to a single action, and single-use consumption: draft-schrock, draft-das.
- Signed refusals, and mandatory verification of the whole chain: draft-hamr.

### 7.2 What Writ combines differently

- **One table, both directions.** The same five comparisons decide both whether a child narrows a parent and whether a call argument satisfies a bound. The neighbors compare token to token, and leave the check against a request's arguments to the resource.
- **A bare envelope.** Bounds are signed by the delegator in a bare JSON object, with no OAuth or JWT envelope, no algorithm member, and did:key as the only identity, so the whole envelope is four lines and a chain is readable in a log. draft-asor keeps the JWT and DPoP, draft-hamr keeps RFC 9421, and AgentROA keeps a policy engine.
- **`count` against every writ.** `count` is consumed against every writ in the chain at every executor, so a holder cannot reset it by re-delegating to itself. draft-hamr's write budget is per chain at one verifier, and AIP's budget is a ceiling in the token.
- **Receipts from the executor, carrying the tree.** The receipt names the exact link it was executed under and is signed by that link's holder, and it carries every child writ issued and every sub-receipt received, verbatim, so the root delegator verifies three hops with nothing but its own writ. AIP's completion block is appended to the token by the executor, and AgentROA's receipt is signed by a gateway, not the executor, and names a session.

### 7.3 What remains distinctive, as of 2026-09-04

Writ's specific contribution is a compact protocol you can run for offline delegation that narrows at every hop, with a closed set of bound types that compare mechanically, signed receipt trees returned after the work, and explicit rules for replay, failure, recovery, revocation, and reversal. Concretely, none of the six sources defines:

- **A post-execution receipt tree:** an executor's signed account that carries sub-receipts and the child writs they ran under, with consumption accounting (`used`) checked against the last writ and summed across siblings, and a verdict with three values (`valid`, `signed_unauthorized`, `unverifiable`) that turns a signer's own inconsistency into an admission.
- **Idempotency as a protocol rule:** at most one execution per `(leaf writ identity, call.id)`, a byte-identical stored tally on replay, and named states for the cases where the executor cannot know (`pending`, `unknown_outcome`, `undeliverable`).
- **Recovery:** `sys/tallies`, a standing call by any issuer on a chain that asks any executor what ran under a writ, honored after the writ has expired or been revoked.
- **Reversal as a standing operation:** `sys/undo`, by any issuer on the chain, bounded by the executor's own `rev.until` rather than by the writ's expiry, and safe to repeat per tally identity.
- **Revocation with in-flight semantics:** a revoke names the chain, is honored by position, cancels work not yet started, is forwarded down, and never withdraws the issuer's standing to recover or reverse.
- **A normative first-failure order** for every object, and a corpus that two implementations pass with the same reason code per vector, including the executor's stateful behavior in scenario tests.

### 7.4 Limitations that no design here removes

- **Hidden sub-delegation.** A holder can delegate to a key it controls and produce a perfect tally tree, or leave out a sub-delegation it made. `wrt` and `sub` make the omission a signed false statement, and `sys/tallies` lets a delegator ask any executor it learns of, but a delegator learns of an executor only if the evidence surfaces. The `hld` bound closes this when the delegator names its executors in advance. AIP, AgentROA, and the drafts have the same hole; AgentROA's registry and draft-schrock's approver directory narrow who can be a key, not what a key can hide.
- **Fan-out across executors.** `max` and `count` are enforced per executor, against that executor's store. A holder with `count` 1 can issue sibling writs to two executors, and each will accept one call. Enforcing a total across executors needs coordination the protocol does not define; the delegator splits the total across writs or names one executor, and audits `used` afterwards. draft-hamr's write budget has the same shape (per verifier).
- **Timestamps are claims.** `acc` is the executor's word. An honest executor will not accept a forward call after `exp`; a dishonest one can backdate, and the tally is then evidence of a false statement, not a stopped action.
- **Key rotation.** A did:key cannot rotate; the answer is a short `exp` and a key-wide revoke. draft-asor's status list and AgentROA's registry are the online alternatives.
- **Root acceptance is policy.** A chain proves attenuation from its root; whether the root matters is a decision each executor makes outside the protocol.

## 8. Re-check, 2026-09-28

Every source below was read from its primary page on 2026-09-28. Quotes are verbatim, with line breaks collapsed. The comparison is against the specification as revised that day.

**Agent Passport System** (draft-pidlisnyi-aps-03, 2026-07-18, https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt). Section 7 missed it, although it predates section 7.
- *A post-execution record:* "An action-result record has receipt_type "aps:action-result:v1". issuer is the enforcement boundary" (5.3.3). It names the delegation leaf, since "delegation_ref identifies the selected AuthorityDelegationV1 leaf" (5.1), and "status is succeeded, failed, or unknown" (5.3.3).
- *Revocation:* it "MUST initiate a cascade to all transitive descendants; a cascade is complete only when the cascade-completion record of Section 3.5.1 has been emitted" (3.5).
- *Spend:* "the boundary MUST atomically reserve the proposed amount against every bounded ancestor in the selected root-to-leaf chain" (4).
- *Retries:* approvals are single-use, and "An identical retry is idempotent; conflicting reuse is rejected" (3.4).
- *Not there:* no text cancels work already dispatched, and no replay returns a stored result.

**Action Evidence Boundary** (draft-schrock-action-evidence-boundary-07, 2026-09-25, https://www.ietf.org/archive/id/draft-schrock-action-evidence-boundary-07.txt), "an executor-side processing model".
- *Outcomes:* after invocation, "the boundary MUST classify the result as EXECUTED, FAILED, or INDETERMINATE" (5.13).
- *Repeats:* refused, not answered from storage: "the boundary MUST refuse a new attempt whose action key is occupied or closed" (5.10).
- *Reconciliation:* runs from the executor to the provider (5.14), not from an issuer to the executor.
- *No format:* it "defines no receipt or token format".

**draft-hamr-oauth-agent-delegation-02** (2026-09-19).
- *Budgets:* now come in classes, "rBudget, wBudget, and xBudget" (10.1), keyed to "the signature value of L(0), the root link" (10.3), and held "per verifier, not shared across verifiers" (10.4).
- *Still missing:* it "does not produce a receipt" (3) and "defines no revocation" (17).
- *Order:* its verification steps run "in the order given", but a failure at any step "MUST produce one uniform rejection outcome" (13), so the order cannot be observed.

**draft-asor-wimse-agent-delegation-chain** is still at -01. Its verifier denies "on the first failure" (6), without reason codes.

**attenu-guard** (https://github.com/attenu-io/attenu-guard).
- *Vectors:* 20 Delegation Token vectors that "pin the required bytes and rejection reasons", one fault each, run by outside implementers: Node.js 20 of 20; Kieran Sweeney's Cred 17 of 20, with 3 declared gaps; and Xuebin Ma's Rust verifier 19 of 19 on the observer-envelope vectors.
- *Several faults:* its bundle vectors score "the minimal set" of failures a verifier must report, and one envelope row pins which of two faults on one input takes precedence.
- *Revocation:* in-process: "revoke any node, every descendant denies immediately".
- *Interop:* the APS roadmap records that "attenu-guard (draft-asor-wimse-agent-delegation-chain-00) offered to run APS vectors through its verifier" (https://agent-passport.org/roadmap.html).

**decionis agent-safe.verifying-provider/1** (version 0.2, draft, https://github.com/decionis/agent-safe-pipeline/blob/master/docs/authority/verifying-provider.md).
- *Order:* a verification procedure for providers: "Normative, in this order. The first failing step names the refusal, and a refusal effects nothing." Its vectors are run by "five implementations that must agree", all in the author's repository.
- *Receipts:* the provider signs "what it effected, or refused", with `effect.status` `EFFECTED`, `REFUSED`, or `INDETERMINATE`, and "A signed refusal is evidence too."

**Also read:**
- draft-mcgraw-httpapi-agent-budget-04 makes credential acceptance at most once, but says it "does not guarantee exactly-once completion".
- draft-noa-scitt-ai-agent-receipt-01 has seven lifecycle verdicts, including ROLLED_BACK, and requires a verifier to report every failing condition, not the first.
- draft-abak-agent-control-delivery-evidence-01 models evidence that a revoke or cancel was delivered and applied, without defining the verbs.
- draft-watts-oauth-agent-revocation-closure-00 models cancelling a queued operation before its effect commits, and notes "Credential invalidation is not consequence reversal".
- draft-schrock-ep-authorization-receipts-13 and draft-das-agentic-tool-binding-03 add nothing on these points (das -03 adds a signed receipt of each enforcement decision, before any effect).

### 8.1 Where Writ stands now

| Claim | 2026-09-04 | 2026-09-28 |
|---|---|---|
| a receipt signed by the executor, naming the exact delegation link | distinctive | partly shared: APS-03 names the leaf, signed by the enforcement boundary rather than each hop's executor |
| a receipt tree: downstream receipts embedded verbatim, consumption summed and checked | distinctive | still distinctive; APS-03 sums spend in the boundary's ledger, not in receipts |
| named outcomes beyond ok and failed | distinctive | largely shared (APS-03, AEB-07, noa-01, decionis); a signed `undeliverable` for a sub-call that never answered is Writ's |
| at most one execution, with the stored receipt returned byte for byte on replay | distinctive | narrowly: at most once is shared (AEB-07, APS-03); none returns the stored receipt, AEB refuses the repeat |
| recovery and reversal by any upstream issuer after expiry or revocation, bounded by the executor's `rev.until` | distinctive | still distinctive; elsewhere reversal is a newly authorized compensating action or a recorded verdict |
| revoke that cancels in-flight work and is forwarded down | distinctive | partly shared and narrower: APS-03 cascades revocation, attenu denies later checks, watts-00 and abak-01 model cancelling before the effect without a wire mechanism |
| a normative first-failure order pinned by a cross-implementation corpus | distinctive | partly shared: decionis pins a normative order with named codes across five implementations by one author; attenu pins one two-fault precedence across three. Writ's remaining difference is a full order exercised by two-fault vectors and a differential fuzzer; its two implementations are also by one author |

## 9. Re-check, 2026-09-29

A review dated 2026-09-29 said the survey missed Tenuo and that "UCAN lacks signed execution receipts" was too sweeping. Both hold. Every source below was read from its primary page on 2026-09-29; quotes are verbatim.

**UCAN Receipt.** The UCAN Invocation specification, "Version 1.0.0", states in its abstract that it "defines a format for expressing the intention to execute delegated UCAN capabilities, and the attested receipts from an execution", and its life cycle has "Invocation ||--|| Receipt: returns" (https://github.com/ucan-wg/invocation/blob/main/README.md). The Receipt repository it links (https://github.com/ucan-wg/receipt/blob/main/README.md) still carries the older combined text, "UCAN Invocation Specification v0.1.1", which defines "A Receipt is a cryptographically signed description of the Invocation output and requested Effects" (link brackets dropped) with members `ran` ("Invocation this is a receipt for"), `out`, `fx`, `meta`, `iss`, `prf`, and `s`, commented "Signature from the 'iss'". `fx` is "a request to invoke enclosed set of tasks concurrently": tasks to run next, not receipts of work already delegated.
- *Implementation:* Storacha's ucanto signs `{ran, out, fx, meta, iss, prf}` in `packages/core/src/receipt.js` (https://github.com/storacha/ucanto/blob/main/packages/core/src/receipt.js), and the Invocation spec calls ucanto "a production system that uses UCAN as the basis for an RPC layer".
- *Correction:* sections 1, 2, and 5 of this note said UCAN had a Promise and no signed receipt, and README section 4 and adoption.md section 5 repeated it. All are amended.
- *Not there:* no receipt embeds the receipts of delegated sub-work, and nothing accounts for consumption across them; an executor's standing to be asked or to reverse after expiry is not defined.

**Tenuo** (https://github.com/tenuo-ai/tenuo), "Task-scoped authorization for AI agents", marked "v0.2 - Production/Stable".
- *Delegation:* "Delegation mints a child warrant signed by the parent's holder. The verifier walks the whole chain from a trusted root to the leaf. Each link may drop tools, tighten constraints, or shorten expiry. No delegated warrant can exceed its parent."
- *Holder binding and offline checks:* "Every call carries a signature from that key over the warrant, the tool, the exact arguments, and a short time window", and "Checking it needs no lookup and no network."
- *Receipts:* "Signed authorization receipts are opt-in when you need to show why a call was allowed or denied." These record the decision before the effect, not the outcome after it.
- *Integrations:* MCP middleware (`TenuoMiddleware`), Python, TypeScript (beta), and Rust SDKs, and "Tenuo Cloud: Early Access. Managed control plane with revocation".
- *Not there, from its README:* no receipt tree, no consumption accounting across hops, no stored-receipt replay, no issuer recovery or reversal after expiry.

### 9.1 Where Writ stands now

| Claim | 2026-09-28 | 2026-09-29 |
|---|---|---|
| a receipt signed by the executor, naming the exact delegation link | partly shared (APS-03) | more widely shared: a UCAN Receipt is signed by its issuer and names the invocation, whose proofs name the chain |
| a receipt tree: downstream receipts embedded verbatim, consumption checked across them | still distinctive | still distinctive, but its accounting was wrong until 2026-09-29: step 10 summed one level only, and a complete tree two levels deep could report twice the root's `max` and verify (spec revision note, vectors 210 to 213) |
| task-scoped narrowing checked at the tool boundary, with MCP integration | not listed | shared, and shipped: Tenuo |

Unchanged: recovery and reversal after expiry, the stored-receipt replay, and the in-flight revoke remain as section 8.1 left them. The practical reading is the review's: overlap in features does not establish demand, and Tenuo and UCAN are candidates for swapping test vectors, not rivals to outrun.

