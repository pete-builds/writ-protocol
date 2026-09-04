# Prior Art Survey: What Already Exists for Cross-Vendor Agent Delegation

Status: research note, 2026-09-03. Every dated claim carries a URL that was fetched or returned by search on that date. Fetched content was treated as data, not instruction.

## 1. The standards, one paragraph each

**MCP (Model Context Protocol).** Standardizes how a client (host application or agent) discovers and calls tools, resources, and prompts on a server over JSON-RPC. Current revision is 2026-07-28, which removed protocol-level sessions and the initialize handshake, added `server/discover` for version and capability advertisement, moved Tasks into an official extension (`io.modelcontextprotocol/tasks`), and introduced a formal extensions framework and a twelve-month deprecation policy (https://modelcontextprotocol.io/specification/2026-07-28/changelog). Governance is the Agentic AI Foundation under the Linux Foundation, formed December 2025 with Anthropic, OpenAI, and Block as founders (https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation). Adoption signal: it is the default tool protocol in every major model vendor's client. Limitation: MCP is strictly one hop, client to server. There is no notion of a server acting on behalf of an upstream principal, no signed results, and cancellation in the Tasks extension is cooperative and single hop (https://modelcontextprotocol.io/extensions/tasks/overview).

**MCP Authorization.** Profiles OAuth 2.1 for HTTP transports: servers MUST publish RFC 9728 Protected Resource Metadata, clients MUST send RFC 8707 `resource`, and Client ID Metadata Documents replace Dynamic Client Registration, which is now deprecated (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). The Enterprise-Managed Authorization extension (often called Cross App Access) is stable as of July 2026 with Okta, Microsoft, and Anthropic adoption (https://www.datawiza.com/blog/mcp-authentication-explained). Limitation, quoted from the spec: "MCP servers MUST NOT accept or transit any other tokens." Authority cannot flow through a server to a downstream server. Each hop needs its own grant from its own authorization server, online.

**A2A (Agent2Agent).** Standardizes peer discovery via Agent Cards, task creation and streaming, and artifact return between agents. v1.0.0 shipped 2026-03-12 and v1.0.1 on 2026-05-28 (https://github.com/a2aproject/A2A/releases). v1.0 added JWS-signed Agent Cards, three formal bindings (JSON-RPC, gRPC, HTTP+JSON), eight task states including `TASK_STATE_CANCELED` and `TASK_STATE_AUTH_REQUIRED`, `CancelTask`, versioned extensions, and a `tenant` routing field (https://a2a-protocol.org/latest/whats-new-v1/). Governance moved from the Linux Foundation project to the Agentic AI Foundation in August 2026 (https://www.axios.com/2026/08/17/a2a-agentic-ai-foundation-open-ai-standards, https://aaif.io/projects/agent2agent). Adoption: 150+ organizations and production use at Microsoft, AWS, and Google as of April 2026 (https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year). Limitation: only the Agent Card is signed. Messages, parts, and artifacts carry no signature, `tenant` is "an opaque routing identifier," and nothing in a task says under whose authority the callee acts (https://a2a-protocol.org/latest/specification/).

**ACP (IBM BeeAI Agent Communication Protocol).** Standardized REST-based agent invocation for the BeeAI platform, launched March 2025. It merged into A2A under the Linux Foundation on 2025-08-29; IBM took a seat on the A2A TSC and BeeAI now ships an A2A adapter (https://lfaidata.foundation/communityblog/2025/08/29/acp-joins-forces-with-a2a-under-the-linux-foundations-lf-ai-data/). Treat as historical. Its limitation is A2A's limitation.

**ANP (Agent Network Protocol).** A Chinese-origin open protocol with a three-layer design: `did:wba` identity (a did:web derivative, v0.2), agent description in JSON-LD, and discovery via `.well-known` files; the current line is ANP 1.1 (https://agent-network-protocol.com/specs/did-method.html, https://agentnetworkprotocol.com/en/specs/01-agentnetworkprotocol-technical-white-paper/). Governance is a small GitHub community, adoption is thin outside China. Limitation: authentication is per-request DID signatures, but authorization is out of scope; there is no delegation object and no receipts.

**AP2 (Agent Payments Protocol).** Google's open extension for A2A that represents a purchase as a chain of signed mandates, described at launch as Intent, Cart, and Payment Mandates backed by verifiable digital credentials (https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol). v0.1.0 shipped 2025-09-16 and v0.2.0 on 2026-04-28 "focused on providing Human Not Present flows" (https://github.com/google-agentic-commerce/AP2/releases); the v0.2 docs reorganize around Checkout and Payment Mandates, each with Open and Closed stages, and say standardization "will continue within the Agentic Authentication Technical and Payments Technical Working Groups in FIDO" (https://ap2-protocol.org/). Limitation: the mandate chain is the closest shipped analog of a task receipt chain, but every object is payment-shaped and the chain is user to agent to merchant, not agent to sub-agent.

**x402.** An HTTP 402 payment handshake: server returns `PAYMENT-REQUIRED`, client retries with `PAYMENT-SIGNATURE`, a facilitator verifies and settles. v1 launched 2025-05-06 and v2 on 2025-12-11 with CAIP-2 network ids and de-prefixed headers (https://x402.org/x402-v2-launch/). The x402 Foundation under the Linux Foundation became operational on 2026-07-14 with Visa, Mastercard, Stripe, AWS, Google, and Microsoft among members (https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications). Limitation: pure metering. No identity beyond a wallet key, no delegation, no task semantics.

**DIDs (did:key, did:web, DID Core 1.1).** Standardize a URI scheme that resolves to a document with verification keys. DID 1.1 reached Candidate Recommendation on 2026-03-05 (https://www.w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifiers-dids-v1-1/). did:key (https://w3c-ccg.github.io/did-key-spec/) and did:web (https://w3c-ccg.github.io/did-method-web/) remain Credentials Community Group drafts, not Recommendations, yet are what UCAN, ZCAP, ANP, and AP2 all actually use. Limitation: identity only. A DID says who signed, never what they were allowed to do.

**W3C Verifiable Credentials Data Model 2.0.** A JSON-LD envelope for signed claims by an issuer about a subject. Became a Recommendation on 2025-05-15; v2.1 has a First Public Working Draft in 2026 (https://www.w3.org/TR/vc-data-model-2.0/, https://www.w3.org/news/2026/first-public-working-draft-verifiable-credentials-data-model-v2-1/). Adoption: EU digital identity wallet, AP2 mandates. Limitation: VCs are attestations, not capabilities. A holder cannot narrow a credential and hand it on; the model has no chaining rule that says a re-issued credential must be a subset of what the re-issuer held.

**OAuth 2.1 and OpenID Connect.** The delegated-access baseline: a resource owner authorizes a client at an authorization server, which mints an audience-bound token. OAuth 2.1 is still draft-ietf-oauth-v2-1 (MCP cites -13) but is the de facto profile; OIDC supplies user identity on top. Limitation: three parties and one hop. Tokens are opaque to everyone except the AS and resource, so a downstream party cannot inspect or narrow what it received without going back to the issuer.

**RFC 8693 Token Exchange and RFC 9396 Rich Authorization Requests.** 8693 (January 2020) lets a client trade one token for another, recording delegation in `act` and `may_act` claims (https://www.rfc-editor.org/rfc/rfc8693). 9396 (May 2023) replaces flat scopes with structured `authorization_details` objects (https://www.rfc-editor.org/rfc/rfc9396). Together they can express "B acts for A with these details." Limitation: every exchange is an online round trip to an AS that both hops trust, and cross-domain exchange needs the identity-chaining pattern, still an individual draft. Nothing is offline.

**RFC 9449 DPoP and RFC 9421 HTTP Message Signatures.** DPoP (September 2023) binds an access token to a client key (https://www.rfc-editor.org/rfc/rfc9449). 9421 (February 2024) signs selected HTTP components with any key (https://www.rfc-editor.org/rfc/rfc9421). Adoption for 9421 is real but slow: most of the fediverse still runs draft-cavage-12 and Fedify "double-knocks" both (https://socialhub.activitypub.rocks/t/rfc-9421-http-signatures-in-2026/8427, https://hackers.pub/@fedify/2026/why-activitypub-is-hard). Limitation: they prove possession of a key on a wire, which is a good message-layer primitive, but say nothing about what the key holder may do.

**RFC 9635 GNAP.** A ground-up successor to OAuth (October 2024) where the client negotiates a grant, keys replace pre-registration, and access rights are structured objects (https://www.rfc-editor.org/rfc/rfc9635). Adoption is limited; no major vendor has shipped it as a primary flow (https://oauth.net/gnap/). Limitation: still AS-centric. Attenuation and delegation route through the grant server.

**SPIFFE/SPIRE and IETF WIMSE.** SPIFFE issues X.509 or JWT SVIDs to workloads after attestation; SPIRE v1.15.3 shipped 2026-08-21 (https://github.com/spiffe/spire/releases). WIMSE's architecture draft is at -08 (2026-07-06, Informational) with token-profile drafts behind it (https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/). Adoption: Uber, Stripe, Netflix, and CNCF graduation. Limitation: identity inside one trust domain, federation between domains via bundle exchange. There is no delegation object, and an SVID names a workload, not a task.

**Object capabilities and ZCAP-LD.** Authorization Capabilities for Linked Data is a CCG work item at v0.4.0-draft with commits into September 2026 (https://w3c-ccg.github.io/zcap-spec/, https://github.com/w3c-ccg/zcap-spec). It encodes a capability as a JSON-LD document signed with a Data Integrity proof, delegated by chaining documents with caveats, and exercised by a signed invocation. Adoption: Digital Bazaar products and some Solid experiments. Limitation: JSON-LD canonicalization cost, DID dependency, no invocation receipt, and no standards-track status after six years.

**UCAN 1.0.** The UCAN Working Group spec is marked "Version 1.0.0" with sub-specs for Delegation, Invocation, Promise, and Revocation; each delegation "MUST either directly restate or attenuate (diminish) its capabilities," subjects are DIDs, and all UCANs "MUST be canonically encoded with DAG-CBOR for signing" (https://github.com/ucan-wg/spec/blob/main/README.md). I could not locate a dated 1.0 release announcement, so treat the version as self-declared. Adoption: Storacha (formerly web3.storage), Fission lineage, go-ucan. Limitation: IPLD and CID everywhere, DID-only principals, and Promise covers awaiting a result but not a signed receipt of what an executor actually did.

**Biscuit.** An Eclipse Foundation token format with Datalog policies, offline attenuation by appending blocks, and third-party blocks signed by external keys; v3.3 shipped 2024-11-27 with a clearer version scheme (https://www.biscuitsec.org/blog/biscuit-3-3/, https://github.com/eclipse-biscuit/biscuit). Limitation: verification needs the root public key, so only parties who know the issuer can check, and Datalog is a large surface for a minimal protocol. No receipts.

**Macaroons.** Google's 2014 bearer credential whose HMAC chain lets any holder add caveats offline and lets third parties discharge caveats (https://www.researchgate.net/publication/269196979_Macaroons_Cookies_with_Contextual_Caveats_for_Decentralized_Authorization_in_the_Cloud). Adoption: Lightning's L402, libmacaroons ports. Limitation: HMAC means only the root-key holder can verify, so a downstream hop cannot check what it received and a third party cannot audit. No signatures from the delegates.

**CapTP and OCapN.** Spritely and Agoric's capability transport protocol for distributed objects, with promise pipelining and network-level object references; OCapN is an explicit pre-standardization group with draft specs (https://ocapn.org/, https://github.com/ocapn/ocapn). Limitation: a live-session protocol. Authority is a reference held in a connection, not a portable document that survives offline or can be shown to a third party.

**WebAuthn Level 3 / passkeys.** Became a W3C Recommendation on 2026-08-25, adding PRF key derivation, Related Origin Requests, the Signal API, and conditional create (https://www.w3.org/TR/webauthn-3/). Limitation: authenticates a human to an origin. It is the right root for "a person approved this," but produces no reusable delegation artifact.

**Matrix.** Federated real-time messaging; spec v1.19 landed July 2026 and Matrix 2.0 is being cut (https://matrix.org/blog/2026/07/17/this-week-in-matrix-2026-07-17/). Servers sign events, and rooms have a DAG with power levels. Limitation: authorization is room-membership based; there is no per-task attenuated capability, and the transport assumes homeservers.

**ActivityPub.** W3C social federation; a new Social Web Working Group was chartered 2026-01-15 through 2028-01-31 to maintain it (https://www.w3.org/2026/01/social-web-wg-charter.html). Limitation: actors and inboxes are a fine discovery and addressing model, but authorization is server-level HTTP signatures and there is no delegation or task semantics.

**IETF SCITT.** The architecture is now RFC 9943 (Proposed Standard, June 2026): an Issuer makes a COSE_Sign1 Signed Statement, a Transparency Service registers it and returns a Receipt, and the pair is a Transparent Statement verifiable without contacting the service (https://www.rfc-editor.org/info/rfc9943/). The reference API (SCRAPI) is still a draft (https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/). Limitation: SCITT says nothing about authority. It makes a statement non-repudiable and timestamped; it does not say the statement-maker was allowed to act.

**in-toto attestations and SLSA.** in-toto defines a Statement (subject digests plus a typed predicate) inside a DSSE envelope; SLSA v1.2 (2025-11-24) defines the Provenance predicate and build levels (https://github.com/in-toto/attestation, https://slsa.dev/blog). Adoption: GitHub artifact attestations, Sigstore. Limitation: provenance about artifacts, not about actions under delegated authority. There is no link from a predicate to the capability that permitted the build.

**C2PA.** Content Credentials: a manifest of assertions, a claim, and a claim signature bound to a media asset, with an X.509 trust list; v2.4 released April 2026 and supports chained manifests across successive editors (https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html). Limitation: media-shaped, X.509-only, and provenance without authorization.

**OpenID AuthZEN.** Authorization API 1.0 became a Final Specification in January 2026, standardizing the PEP-to-PDP decision call (https://openid.net/notice-of-vote-to-approve-proposed-authorization-api-1-final-specification/). Working Group drafts add the Access Request and Approval Profile (human approval flows) and COAZ, a binding for MCP tool authorization (https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/). Limitation: a PDP must be online for every decision. It is the opposite of offline verification.

**IETF agent-auth drafts.** draft-klrc-aiagent-auth-03 (2026-07-06, individual, authors from Defakto, AWS, Zscaler, Ping, OpenAI, Okta) composes WIMSE, token exchange, and transaction tokens into agent delegation chains (https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/). draft-oauth-transaction-tokens-for-agents (through -06, Informational) puts the agent in `act` with the principal in `sub` (https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/). draft-ietf-oauth-client-id-metadata-document-02 (2026-07-06) is the CIMD mechanism MCP already depends on (https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/). The OpenID AIIM Community Group and a proposed W3C Agent Identity Registry Protocol CG (2026-04-24) are the discussion venues (https://openid.net/cg/artificial-intelligence-identity-management-community-group/, https://www.w3.org/community/blog/2026/04/24/proposed-group-agent-identity-registry-protocol-community-group/). Limitation shared by all: every design routes through an AS or a transaction-token service, online, and none define what a result receipt looks like.

**AGNTCY.** Cisco's Outshift project, donated to the Linux Foundation on 2025-07-29: OASF (Open Agent Schema Framework) for capability description, an agent directory, an identity service, SLIM messaging, and observability (https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-agntcy-project-to-standardize-open-multi-agent-system-infrastructure-and-break-down-ai-agent-silos). Limitation: infrastructure and directory, not a delegation model; identity verification presumes the AGNTCY identity service.

**NANDA, Agora, LMOS.** NANDA (MIT Media Lab) proposes a hybrid registry index plus per-organization registries and an "AgentFacts" passport (https://projectnanda.org/). Agora (Oxford, arXiv 2410.11905) is a meta-protocol where agents negotiate content-addressed Protocol Documents from natural language (https://www.alphaxiv.org/overview/2410.11905). Eclipse LMOS builds on W3C Web of Things Thing Descriptions and runs in production at Deutsche Telekom, with a progress review scheduled 2026-09-23 (https://projects.eclipse.org/projects/technology.lmos/reviews/eclipse-lmos-2026.09-progress-review). Limitation common to all three: discovery and description, not authority or evidence.

## 2. Comparison matrix

Y = defined by the standard. partial = present but incomplete for the cross-domain multi-hop case. N = absent. "Attenuation" means hop 2 can narrow what hop 1 got, offline, without the original issuer online.

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
| UCAN 1.0 | Y: DID | N | Y: cmd and policy | Y: signed invocation | Y | Y: must attenuate | partial: Promise | partial: Promise, no signed receipt | partial: Revocation | Y: invocation CID | N | Y: version field | N | Y |
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

## 3. What is solved

These functions need no new standard. Reuse and profile.

- Transport-level authentication of one client to one server: OAuth 2.1 as profiled by MCP, with RFC 9728 and RFC 8414 discovery and CIMD for registration-free client identity.
- Proof of possession on the wire: RFC 9449 DPoP inside OAuth, RFC 9421 for any HTTP message.
- Workload identity inside one trust domain: SPIFFE SVIDs, with WIMSE as the coming IETF framing.
- Human approval as a root of trust: WebAuthn Level 3 assertions.
- Decentralized key identifiers: did:key for ephemeral agent keys, did:web for domain-anchored ones. Do not invent a new identifier scheme.
- Signed-statement envelope: COSE_Sign1 (SCITT) or DSSE (in-toto). Either is fine; pick one and stop.
- Structured permission grammar: RFC 9396 `authorization_details` objects are a mature vocabulary for "what exactly," even outside OAuth.
- Service discovery and capability description: A2A Agent Cards for agents, MCP `tools/list` plus `server/discover` for tools. OASF is a candidate schema layer if one is needed.
- Task lifecycle states: A2A's eight states and MCP's Tasks extension already agree on the shape (submitted, working, input required, completed, failed, canceled).
- Version negotiation: MCP's per-request `_meta` protocol version and `server/discover`; A2A's `protocolVersion` in the card.
- Append-only transparency and timestamping: SCITT RFC 9943 Receipts when a public log is wanted.
- Artifact provenance: in-toto Statements and SLSA Provenance for software, C2PA for media.
- Payment: AP2 mandates over A2A or x402 over HTTP. Do not couple the core protocol to either.
- Online policy decisions: AuthZEN when a PDP is acceptable.
- Trace context: W3C `traceparent` in `_meta`, as MCP already documents.

## 4. The smallest important gap

Scenario. Agent A (vendor 1) delegates to Agent B (vendor 2) a narrowly scoped task: "summarize tickets 100 to 200 in project P, read only." B sub-delegates part of it to Agent C (vendor 3) with strictly less authority: "read tickets 150 to 200 in P." B and C return results carrying verifiable evidence of who did what under which authority. A can verify all of that offline, and can cancel the work in flight or compensate afterward.

**Where MCP breaks.** Step 1 works: A is an MCP client of B and obtains a token from B's authorization server scoped to P. Step 2 breaks. B cannot hand C anything derived from A's grant, because "MCP servers MUST NOT accept or transit any other tokens" (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). B must go to C's authorization server as a fresh client and obtain a token whose scope is whatever C's AS is willing to grant to B, with no cryptographic tie to A's narrower grant. Step 3 breaks: MCP results are unsigned JSON-RPC `structuredContent`; C's result to B and B's result to A are bare data. Step 4 breaks: `tasks/cancel` reaches B, but nothing propagates to C except B's own code, and the extension states cancellation "does not prove that remote work stopped" (https://modelcontextprotocol.io/extensions/tasks/overview). Compensation has no primitive at all.

**Where A2A breaks.** Step 1 half-works: A verifies B's signed Agent Card, so it knows the endpoint belongs to vendor 2's domain, then opens a task with the OAuth or mTLS scheme B advertises. Step 2 breaks: B opens a second task with C. The only carrier for context is `tenant`, "an opaque routing identifier," so C never learns that it acts under A's authority narrowed to tickets 150 to 200 (https://a2a-protocol.org/latest/specification/). Step 3 breaks: only the Agent Card is signed; "no signature mechanisms are defined for individual messages, parts, or artifacts," so A cannot distinguish "C produced this under B's sub-delegation" from "B made it up." Step 4 breaks: `CancelTask` from A stops B's task; propagating to C is B's private behavior. A cannot verify offline because there is nothing signed to verify.

**Where OAuth breaks.** Step 1 works with RFC 9396 details describing the ticket range. Step 2 half-works only if A's AS, B, and C all trust one AS or a federation: B performs RFC 8693 token exchange, the AS narrows the scope and records `act`. That is online by construction, and cross-vendor it requires identity chaining that is still an individual draft (https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/). The holder (B) cannot itself produce a strictly narrower credential; only the issuer can. Step 3 breaks: an access token is permission, not evidence. Nothing in the OAuth family is a signed statement by C that "I did X with token T." Step 4 breaks: revocation is a call to the AS, and the AS cannot reach C's in-flight work. Offline verification of the chain is impossible because A never sees C's token, and C's token was minted by an AS A may not even know.

**The gap in one sentence.** There is no vendor-neutral, offline-verifiable object that binds a task-scoped delegation chain, which each hop can narrow without contacting any issuer, to a signed receipt from each hop stating what it did under exactly which link of that chain.

Everything else in the scenario (discovery, endpoint identity, transport auth, task states, cancellation at one hop) is already standardized. The missing piece is small: one attenuable authority envelope plus one receipt format that references it, with a rule that a receipt is valid only if its authority link is valid.

## 5. Closest prior art to the gap, ranked

1. **UCAN 1.0.** Closest. Delegation with a mandatory attenuation rule, a separate Invocation that names the delegation chain, Promise for awaiting results, and Revocation. Missing: a signed executor receipt; Promise awaits a value but does not sign "who did what." Baggage: DAG-CBOR and CIDs (IPLD), DID-only principals, and a policy language of its own.

2. **Biscuit 3.3.** Offline attenuation by appended blocks, third-party blocks signed by outside keys (a natural place for C's contribution), and a clean versioning story. Missing: receipts, and verification is bound to knowing the root public key, so a stranger cannot audit. Baggage: Datalog as the policy language, Protobuf encoding.

3. **ZCAP-LD.** Explicit capability chain with caveats and a signed invocation, DID controllers, and Data Integrity proofs. Missing: any receipt and any standards-track home. Baggage: JSON-LD canonicalization, DID resolution, six years at v0.4-draft.

4. **Macaroons.** The simplest attenuation primitive there is, and third-party caveats map to "C must discharge." Missing: public-key verification, so only the root issuer (A) can verify, and delegates never sign anything. Baggage: minimal, but HMAC makes it unusable as evidence to anyone but A.

5. **AP2 mandates.** The only shipped agent-era chain of signed objects where each step references the previous one and the final object is the receipt. Missing: agent-to-sub-agent hops and anything not shaped as a purchase. Baggage: payments coupling, VC and JSON-LD encoding, FIDO working-group governance.

6. **in-toto attestations.** The right receipt shape: subject digests plus a typed predicate in a DSSE envelope, chainable by referencing earlier statements. Missing: any authority model; a predicate cannot point at the capability that permitted the action. Baggage: light, which is why it is the strongest candidate to borrow for the receipt half.

7. **SCITT RFC 9943.** Non-repudiable, timestamped Signed Statements with offline-verifiable Receipts. Missing: authority, and registration needs a Transparency Service online, which the scenario forbids for the verification step. Baggage: COSE and CBOR (fine), a transparency log operator (not fine as a requirement). Best used as an optional anchor for receipts, never as the core.

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
- **Transaction Token**: IETF OAuth term. **Cross App Access / XAA**: Okta. **EMA**: MCP's Enterprise-Managed Authorization extension.
- **AIP**: an arXiv "Agent Identity Protocol." **AIMS**: an IETF agent identity draft. **AIIM**: OpenID's community group. **AARP**, **COAZ**: AuthZEN profiles.
- **Receipt**, **Signed Statement**, **Transparent Statement**: SCITT terms of art. **Statement**, **Predicate**: in-toto. **Content Credentials**: C2PA.
- **Capability**: overloaded between MCP's feature flags and the object-capability meaning. If the protocol uses the ocap sense, say so once and never use the word for feature negotiation.
- **Task**: both A2A and MCP own it with slightly different state machines. Reuse it only if the states match theirs.
- **Biscuit**, **Macaroon**, **Cookie**: the pastry lineage is taken.
- **Matrix**, **Passkey**, **SPIFFE**, **WIMSE**, **GNAP**: established.
