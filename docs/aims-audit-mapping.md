# Writ and the WIMSE AIMS audit requirements

`draft-ietf-wimse-aims-00`, adopted by the WIMSE working group on 2026-09-15, describes how existing standards apply to AI agents. Its section 11 sets audit requirements, and this page maps a Writ receipt tree onto each one, including the ones Writ does not meet. It is meant for the WIMSE and proposed AUDIT discussions. Writ is offered there as one concrete mechanism for an audit record that crosses organizations, not as a new framework.

## The requirement that matters most

> Implementations SHOULD provide operators the ability to reconstruct a complete execution chain of an agent task, including delegated authority, intermediate calls, and resulting actions across service boundaries.
> (AIMS section 11)

A Writ tally is a receipt signed by the executor that did the work. A tally from an agent that delegated part of the job carries, unchanged, the writs it issued (`wrt`) and the tallies it received back (`sub`). The root delegator can therefore check the whole tree offline, with nothing but its own writ, its own call, and the keys inside the objects. For each hop, the tree says who acted, under exactly which link of the delegation chain, what it consumed, and how it ended. Spec section 6.2 defines the check; the `verify_tally` vectors in `conformance/vectors/` pin it, including trees two levels deep.

What the tree cannot show is a hop that was left out. A holder can delegate to a key it controls, or leave a delegation out of `wrt`. A transparency log registration (spec section 13) narrows that gap. Nothing removes it.

## The seven minimum audit fields

AIMS section 11: "At a minimum, audit events MUST record:"

| AIMS field | Where a Writ receipt carries it | Gap |
|---|---|---|
| authenticated agent identifier | `from` on the call, the key that signed it; the tally's signer is the executor. Spec 7.6 binds a transport-authenticated peer (mTLS, SPIFFE ID, OAuth client) to `from` before the executor answers. | A did:key is a key, not a name. Binding it to an organization is the directory's job (docs/directories.md). |
| delegated subject (user or system), when present | `iss` of the chain's root writ, and every `iss` to `hld` hop after it, all signed and hash-linked | The root is a key; who holds it is outside the protocol. |
| resource or tool being accessed | `op` on the call and tally (for MCP, `mcp/tools/<tool>`), and the executor's key | `op` names are a convention between the parties. |
| action requested and authorization decision | requested: `op` and `args` on the signed call. Decision: the tally's `st`, with a refusal's reason from a closed set of codes (spec section 11) in `err.code`; consumption in `used` | A refusal at the first two checks of section 7 is unsigned; the executor's audit record (spec 9.3) still logs it. |
| timestamp and transaction or request correlation identifier | `acc` on the tally; `tally.call` is the hash of the call, and `tally.writ` the hash of the leaf writ, so every receipt correlates to exactly one request and one link | `acc` is the signer's word. A timestamp authority's countersignature over `sig` (RFC 3161) would bound it, and is planned as an extension. |
| posture assessment or risk state influencing the decision | not carried | No member carries it. It could be added as a `crit` extension if the AUDIT work wants it in the signed record. |
| remediation or revocation events and their cause | a revoke is a signed object, forwarded down the chain; a reversal is a `sys/undo` call answered with its own tally, which names the tally it reversed | The revoke says who withdrew what, not why. |

AIMS also requires that "Audit records MUST be tamper-evident". Every Writ object is signed over its canonical form, and a tally commits to its result body by hash (`out`), so a changed receipt fails verification. Retention is deployment policy (spec 9.3).

## Running code

- The Go reference and the Python implementation, in this repository, check each other in CI on every change. Both come from one author's tooling.
- writ-ts (https://github.com/griffinwork40/writ-ts) is a TypeScript verifier and executor that its author's AI agent built from the specification and corpus alone.
- Corpus: `conformance/vectors/` (one JSON file per case, with the answer and the reason a verifier must give) and `conformance/scenarios/` (executor behavior that needs state), with JSON schemas in `conformance/schema/`.
- The specification in Internet-Draft form, not submitted: `docs/ietf/draft-stergion-writ-00.md`.

## Where this fits

The proposed AUDIT BoF covers records across the whole action chain. Its proponent placed delegation-chain composition out of scope there, so on that reading the receipt tree belongs to AUDIT and the delegation semantics to WIMSE. `draft-gilda-wimse-agent-audit-record` carries the same seven fields as an in-toto predicate. A Writ tally could travel as one such record's evidence, rather than compete with it.
