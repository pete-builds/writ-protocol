# 01. What durable infrastructure has in common

Before designing a protocol for agents, this report looks at nine protocols that lasted, pulls out the principles they share, and records five earlier attempts at "universal agent" protocols that died, and why. Claims that could not be confirmed are marked (verify).

- Part 1 looks at each of the nine protocols.
- Part 2 turns what they share into ten principles, each with a test a new design must pass.
- Part 3 lists what to copy and what to refuse.
- Part 4 is the hazards: the agent protocols that failed.

## Part 1: nine protocols

### TCP/IP

- **What it does:** moves packets between networks of different kinds.
- **Core:** IP delivers a datagram, best effort, to an address. TCP layers ordered, reliable byte streams on top, with sequence numbers, acknowledgments, and retransmission.
- **Left out:** reliability at the IP layer, quality of service, sessions, security, accounting.
- **When things fail:** routers drop packets without apology; endpoints notice by timeout and retransmit; routing converges around dead links.
- **Why it won:** it shipped. The ARPANET cut over on 1 January 1983, 4.2BSD carried a free implementation that year, and when the US government mandated OSI through GOSIP in 1990, every university already ran TCP/IP. OSI was specified by committee before it was built; Clark's 1992 "rough consensus and running code" was the IETF's answer.
- **Losers:** OSI/CLNP, X.25, SNA, DECnet.

### DNS

- **What it does:** maps names to records across zones that are run independently.
- **Core:** a hierarchical namespace, delegation by NS record, caching bounded by a TTL, and a small UDP query and response.
- **Left out:** consistency (eventual by design), security (DNSSEC came a decade later and is still patchy), transactions, and any notion of ownership beyond delegation.
- **When things fail:** several authoritative servers, resolvers that retry the next one, negative caching, and stale answers served while the authority is down.
- **Why it won:** HOSTS.TXT at SRI-NIC had to be re-downloaded by every host, and X.500, the OSI directory, needed ASN.1, a global schema, and licensed software. Mockapetris's RFC 882 (1983) was small enough that new record types (SRV, TXT, CAA) were still being added forty years later without breaking a resolver.

### HTTP

- **What it does:** fetches or changes a resource named by a URL.
- **Core:** a request line (method, path, version), headers, and a body; a response with a status code, headers, and a body; no state between requests.
- **Left out:** sessions (cookies were a 1994 Netscape add-on), reliability, security (handed to TLS), push, and any content model beyond a media type.
- **When things fail:** status classes, idempotent methods so a client can safely retry, and Retry-After.
- **Why it won:** HTTP/0.9 was one line, `GET /path`, and a server fit in a few dozen lines. Gopher had a rigid menu model and no inline links, and in 1993 the University of Minnesota announced licensing fees, at which point the web absorbed it. WAIS lost the same way. Unknown headers are ignored, which is how HTTP has been extended for thirty years.

### SMTP

- **What it does:** relays a text message from one mail domain to another.
- **Core:** five verbs (HELO, MAIL FROM, RCPT TO, DATA, QUIT), plain ASCII, store-and-forward, and MX records to find the next hop.
- **Left out:** sender authentication, rich content (MIME arrived in 1992 as an extension), receipts, and any guarantee beyond "I accepted responsibility for this message."
- **When things fail:** queue and retry with backoff for days, then a bounce to the sender.
- **Why it won:** X.400 (CCITT, 1984) needed addresses like `C=US;ADMD=;PRMD=;O=;S=` and depended on the X.500 directory, licensed software, and a telco billing model. Postel's RFC 821 (1982) could be spoken by hand over telnet. The cost of leaving out authentication was spam, and SPF, DKIM, and DMARC are the thirty-year patch.
- **Losers:** X.400, UUCP, proprietary LAN mail.

### TLS

- **What it does:** sets up a confidential, authenticated channel over a transport nobody trusts.
- **Core:** a handshake that negotiates a cipher suite, authenticates the server with a certificate, and agrees a key; then a record layer that encrypts the application's bytes.
- **Left out:** identity beyond "this key is bound to this name by a CA", authorization, and application meaning.
- **When things fail:** fatal alerts and abort, and version negotiation with downgrade protection. TLS 1.3 removed renegotiation and most of the options that had produced a decade of attacks.
- **Why it won:** it sits under an application that does not change. SSL 2 was broken, Microsoft's PCT never left Windows, S-HTTP needed changes to applications, and IPsec needed the network administrator. TLS needed only the server operator. Its structural weakness is the CA trust list; Certificate Transparency and Let's Encrypt (2015) made that survivable, not fixed.

### Git

- **What it does:** tracks a history of a file tree, addressed by content, where every clone is a complete copy.
- **Core:** four object types (blob, tree, commit, tag), each named by the hash of its content, plus refs.
- **Left out:** a central server, access control, locking, code review, identity verification (signing is optional), and any merge policy beyond "here is the conflict."
- **When things fail:** every object is immutable and verifies itself, the reflog means almost nothing is lost, and there is no network state to recover.
- **Why it won:** CVS and Subversion needed a server for every commit and made branching a slow copy. BitKeeper's free license was revoked in April 2005, so Torvalds wrote Git in weeks and the kernel adopted it at once. Mercurial had a comparable design and lost to GitHub's network effect; Darcs had a more elegant theory of patches and merges that could take exponential time. An ugly command line, but the right data model.

### OAuth

- **What it does:** lets a user give a third-party application scoped access to a resource without sharing a password.
- **Core (2.0):** an authorization server issues an access token; the client presents it as a bearer credential; the resource server honors it; scopes name what it covers.
- **Left out, compared with 1.0a:** request signing (which implementers got wrong constantly), a defined token format, and identity (OpenID Connect added that in 2014).
- **When things fail:** short expiry, refresh tokens, a revocation endpoint, and a fixed error vocabulary.
- **Why it won:** a client needs no cryptography, no key storage, and no clock discipline, only the ability to put a string in a header. SAML was XML and leaned on browser POSTs, OpenID 2 asked users to manage URL identifiers, and WS-Trust needed a SOAP stack. Eran Hammer resigned as editor in 2012, calling 2.0 a framework rather than a protocol. He was right, and it won anyway.

### Unix pipes

- **What it does:** connects the output of one process to the input of another.
- **Core:** a byte stream, three file descriptors, and one shell character.
- **Left out:** types, structure, schemas, two-way traffic, and any error channel richer than stderr and an exit status.
- **When things fail:** SIGPIPE kills a writer whose reader has gone, and exit codes carry the verdict; `pipefail` came decades later.
- **Why it won:** McIlroy proposed pipes in 1964, and Thompson implemented them in 1973 in a single day, by McIlroy's account, after which every existing tool could be combined with every other, unchanged. Typed successors (CMS Pipelines, PowerShell objects) are useful inside one vendor and never became an interface between vendors. Text won because every party can already read it.

### Bitcoin

- **What it does:** keeps a shared, append-only ledger among parties who trust neither each other nor any operator.
- **Core:** transactions signed by keys, blocks chained by hash, proof of work, and the rule that the heaviest valid chain wins.
- **Left out:** identity, reversibility, a governing body, throughput, privacy, and general computation (Script has no loops, on purpose).
- **When things fail:** every node validates every block and rejects invalid ones whoever mined them, forks resolve by chain weight, and upgrades that tighten the rules (soft forks) stay compatible with old nodes.
- **Why it won:** DigiCash had a central issuer and went bankrupt in 1998; e-gold had a central operator and was shut down; b-money and bit gold were designs without code. Bitcoin was a nine-page paper plus running software that solved double spending with no trusted party, and it needed nobody's permission to start.

## Part 2: ten principles

Each principle comes with an example, a counter-example that died by violating it, and a test the design must pass.

**1. A minimal mandatory core, shipped as running code, extended at the edges.**
- *Example:* the IP header, HTTP/0.9, Git, and Bitcoin each shipped small and grew for decades without a flag day.
- *Counter-example:* OSI, X.400, and WS-* specified session layers and optional services that nothing needed, before anyone built them.
- *Test:* one engineer can implement the mandatory subset in a week, and no feature becomes mandatory until two independent implementations interoperate on it.

**2. Verification end to end, and offline.**
- *Example:* TCP puts reliability at the endpoints. A Git commit, a Bitcoin transaction, and a signed certificate can each be checked by a stranger holding public keys, with no network call.
- *Counter-example:* X.25 did reliability hop by hop and could not keep up; opaque OAuth bearer tokens need introspection at the issuer; Kerberos needs the KDC up, which is fine inside one domain and fatal across many.
- *Test:* a third party can verify that A authorized B to do X from the message and public keys alone, without contacting A or trusting anyone in between.

**3. A narrow waist.**
- *Example:* IP is the neck of the hourglass, and the pipe is a byte stream; everything above and below varies freely.
- *Counter-example:* NetBIOS, IPX, and AppleTalk tied applications to their transports and died with them; X.400 could not run without the OSI stack beneath it.
- *Test:* the same messages work over HTTP, over a message queue, and over files dropped in a directory.

**4. A strict core with tolerant edges (Postel, corrected).**
- *Example:* browsers that accepted sloppy HTML drove adoption.
- *Where it went wrong:* quirks modes, SMTP address parsers that disagreed, X.509 parsers that disagreed, and version intolerance so bad that TLS 1.3 disguises itself as 1.2 on the wire. RFC 9413 (2023) formally retires "liberal in what you accept" as a design goal.
- *Test:* mandatory fields have one specified parse, so any two implementations reject the same inputs; only unknown extensions are tolerated.

**5. Value with two parties (N=2).**
- *Example:* Git is useful with one repository, a pipe with two programs, and HTTP was useful with one server and one browser at CERN.
- *Counter-example:* UDDI was worthless until thousands of businesses registered, so none did; FIPA agents needed a platform, a directory, and an ontology before two of them could speak.
- *Test:* two agents from two vendors, with no registry, no CA, and no third party, can complete a delegated task and verify its result.

**6. State is explicit, or absent.**
- *Example:* HTTP has no session, TCP's state machine is fully written down, and DNS gives every cached fact a TTL.
- *Counter-example:* FTP's hidden second connection broke behind NAT; CORBA object references silently dangled when the server restarted.
- *Test:* either party can crash and resume from the wire, and every piece of state is in the message or explicitly named with a lifetime.

**7. A readable wire format first, binary later.**
- *Example:* HTTP/1.1, SMTP, and DNS zone files can be debugged with telnet and a text editor.
- *Counter-example:* ASN.1 in X.400, X.500, and SNMP kept implementations scarce and buggy.
- The exceptions prove the order: HTTP/2 and Bitcoin are binary and succeeded, but only after a readable predecessor had settled the semantics.
- *Test:* a developer can read a full delegation exchange in a log file without a decoder.

**8. No mandatory central authority.**
- *Example:* DNS delegates, SMTP relays peer to peer, Git needs no server, and Bitcoin has no operator.
- *Counter-example:* HOSTS.TXT, UDDI, DigiCash, and BitKeeper; TLS's weakest point is its central CA list.
- *Test:* the list of parties whose downtime or refusal can stop two agents from working is empty.

**9. Versioning that never needs a flag day.**
- *Example:* unknown HTTP headers are ignored, RFC 3597 lets resolvers carry record types they do not understand, EHLO falls back to HELO, and Bitcoin upgrades by soft fork.
- *Counter-example:* IPv6 was not backward compatible with IPv4, and thirty years later it carries under half of traffic (verify current share).
- *Test:* a v1 agent that receives a v3 message does something safe, under the rule "ignore unknown fields, reject unknown fields marked critical."

**10. Failure is a defined message, not an absence.**
- *Example:* TCP timeouts, SMTP bounces, HTTP status codes, Git conflicts: each failure has a name and a next action.
- *Counter-example:* CORBA exceptions did not map across languages; early UDP services retried without backoff and melted networks.
- *Test:* every message has a written answer to "what if no reply arrives?" and "what if the reply is malformed?"

## Part 3: copy this, refuse that

**Copy:**

- IP's discipline about addresses: an agent is a name plus a key, and nothing else is needed to reach it.
- Discovery the way DNS does it: a well-known document at a URL, delegated by domain, cached with a TTL. Registries are optional overlays, never prerequisites.
- HTTP's request and response shape, its idempotent operations, and its fixed status vocabulary, so retries are safe and errors compare across vendors.
- SMTP's store-and-forward with bounces: a delegated task completes, fails with a named reason, or bounces after a stated retry budget.
- Git's content addressing: every task, result, and authorization is hashed, immutable, and referable by its hash.
- The pipe's byte stream: results are text or JSON the receiver can read without the sender's runtime.
- Bitcoin's rule: every party validates on its own, and upgrades only tighten.

**Refuse:**

- Any mandatory registry, directory, broker, or ORB.
- Any semantic model that needs agreement on an ontology before the first message.
- Any token whose meaning only its issuer knows.
- Any state that lives in a session rather than in the messages.
- Any binary wire format before the semantics have survived a year in a readable one.
- Any matrix of optional features large enough that two conforming implementations can fail to share a working subset.

**On OAuth's bearer model.** OAuth's secret to adoption is that authority equals possession of a string, and only the issuer needs to know what the string means. That took cryptography, clocks, and key management away from the client, which is why every mobile app and SaaS integration adopted it.

The same property is its ceiling. A bearer token cannot say "B may act for A, on task T, until time X, and may hand subtask T' to C but nothing more" in a way that C's counterparty can check without asking the issuer. Each hop in a delegation chain has two choices, both bad:

- forward the original token, so the last hop holds the first principal's full authority (the classic confused deputy); or
- go back to the authorization server for a fresh token (RFC 8693 token exchange), which makes the issuer a mandatory online authority at every hop and breaks principles 2 and 8.

Bearer tokens can also be replayed by anyone who reads them; DPoP (RFC 9449) and mTLS binding are patches that have been slow to spread.

An agent protocol needs what OAuth cannot express: signed capability chains, narrowable and verifiable offline, in the lineage of SPKI/SDSI, macaroons, and UCAN. And it should keep OAuth's one great lesson: the first hop must be as easy as putting a string in a header.

## Part 4: hazards

Five earlier attempts at protocols for software agents, what killed each, and the trap to avoid.

**CORBA (OMG, 1991).**
- *The promise:* language-neutral distributed objects. Define an interface in IDL, and any client could call it as if it were local.
- *What happened:* vendors' ORBs did not interoperate until IIOP arrived in CORBA 2.0 (1996). Object references were tied to a host and port and dangled whenever a server restarted. The wire format was hostile to firewalls, and the specification grew to thousands of pages of optional services. Michi Henning's 2006 ACM Queue post-mortem blames features added by vote without implementations.
- *The trap:* pretending a remote agent is a local function call. Latency, partial failure, and the chance that the other side has changed must be visible in the message model, not hidden behind a stub.

**SOAP and WS-\* (1999 to roughly 2008).**
- *The promise:* an XML envelope over HTTP, with WS-Security, WS-Trust, WS-Addressing, WS-ReliableMessaging, WS-Policy, and dozens more layered on top, each optional and, in theory, composable.
- *What happened:* no two vendors' stacks supported the same subset, and WSDL tools generated code that only round-tripped with itself. Developers fled to plain HTTP and JSON, which offered less and worked.
- *The trap:* a menu of optional specifications instead of one mandatory profile. The first version must define exactly one conformance level, with every listed feature required, so "implements the protocol" has one meaning.

**Semantic Web agents (2001 onward).**
- *The promise:* Berners-Lee, Hendler, and Lassila's 2001 Scientific American article described agents that read RDF and OWL markup to negotiate appointments and purchases on a user's behalf.
- *What happened:* the data never appeared. Publishing markup cost the producers, while the benefit went to consumers, and OWL needed global agreement on meaning before anything useful happened. The agents were never built. The schema.org subset that survived is a thin vocabulary that search engines paid publishers to adopt.
- *The trap:* requiring a shared ontology before the first interaction. Capabilities must be describable in plain text and JSON Schema between two parties, with shared vocabularies emerging from use.

**KQML and FIPA-ACL (1993 to roughly 2005).**
- *The promise:* the DARPA Knowledge Sharing Effort produced KQML, and FIPA standardized FIPA-ACL, messages as speech acts (inform, request, propose, agree) with meaning defined by the sender's beliefs, desires, and intentions.
- *What happened:* a receiver could verify none of it; the "sincerity condition" simply assumed the sender believed what it said. The reference platform, JADE, was a heavyweight Java framework with a mandatory directory facilitator, and the ecosystem never left academic labs.
- *The trap:* defining what a message means by the sender's internal states, which nobody can check. Meaning must come from observable commitments (what was asked, promised, delivered, and signed) that the receiver and a third party can check.

**UDDI (2000 to 2006).**
- *The promise:* IBM, Microsoft, and Ariba launched UDDI as the registry where businesses would publish web services for discovery at runtime.
- *What happened:* the public Universal Business Registry was shut down by its own sponsors in 2006 (verify exact date), having collected mostly test entries. Real discovery happened through documentation pages and search engines. A registry is worth nothing until it is nearly complete, and nothing made it complete.
- *The trap:* a global registry as a prerequisite for discovery. Agents must be discoverable the way web servers are, by a name that resolves to a well-known document, with any index built afterward by whoever finds it worth building.
