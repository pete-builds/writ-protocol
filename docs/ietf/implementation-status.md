
# Implementation Status

Note to the RFC Editor: please remove this section before publication.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs. Please note that the listing of any individual implementation here does not imply endorsement by the IETF. Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features. Readers are advised to note that other implementations may exist.

According to {{RFC7942}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature. It is up to the individual working groups to use this information as they see fit".

{{RFC7942}} asks for this section just before the Security Considerations. It is placed here instead so that every section number matches the repository text this document is generated from.

The conformance corpus is in the repository: 241 vectors of section 14 and 24 executor scenarios of section 14.1, with JSON schemas for both.

## Go reference implementation

- Organization: none; Pete Stergion.
- Location: https://github.com/pete-builds/writ-protocol, directory impl/go.
- Description: verifier and executor, the HTTP binding of section 10, MCP and A2A bindings, a file transport, a command-line tool, and a three-agent demonstration. It generates the conformance corpus from fixed seeds.
- Maturity: prototype.
- Coverage: the whole of this document, including Appendix D.
- Version compatibility: this version (-00), which is version 0.1 of the repository text.
- Licensing: Apache License 2.0.
- Implementation experience: every executor bug found so far was in executor state (atomic admission, revocation against in-flight work, durable claims), not in the stateless verifier, whose first-failure order has been fuzzed against the Python implementation with no disagreements.
- Contact: issues at https://github.com/pete-builds/writ-protocol.
- Last updated: 2026-10-01.

## Python implementation

- Organization: none; Pete Stergion.
- Location: https://github.com/pete-builds/writ-protocol, directory impl/python.
- Description: verifier and executor, written from the specification text without consulting the Go code; the executor by an AI coding agent kept away from it.
- Maturity: prototype.
- Coverage: sections 1 to 11, the ack of section 9.4 included, and the conformance harness of section 14. It passes every vector and every scenario, and serves the HTTP binding well enough to stand in for the Go executor in the three-agent demonstration.
- Version compatibility: this version (-00).
- Licensing: Apache License 2.0.
- Implementation experience: writing the executor found ten places where the text was unclear, each since answered in the specification. It comes from the same author's tooling as the Go implementation, so agreement between the two shows that the text can be read the same way twice, not that a stranger can build from it.
- Contact: issues at https://github.com/pete-builds/writ-protocol.
- Last updated: 2026-10-01.

## writ-ts

- Organization: none; Griffin Long.
- Location: https://github.com/griffinwork40/writ-ts.
- Description: a TypeScript verifier and executor written from the specification and the conformance corpus alone, without reading either implementation above, by an AI coding agent directed by its author, who discloses that it counts "as an independent reading of the text, not as a human stranger".
- Maturity: prototype.
- Coverage: the verifier passes all 213 vectors of the corpus at that commit, which were available while it was built. The executor was built with every scenario's expected answers removed, and its first run passed 19 of 22 scenarios (136 of 140 steps); the three failures had one cause in the implementation, which was then fixed.
- Version compatibility: the repository text at commit 6552968 (2026-09-30), before the ack of section 9.4 was added. It does not yet sign acks, so its executor's answer to a revoke lacks the members section 10 now requires.
- Licensing: Apache License 2.0.
- Implementation experience: it reported two places where the text was unclear, both confirmed: a `canceled` tally for a call not yet accepted names no error code (section 9.1), and "outermost value" in the nesting limit of section 1.1 is ambiguous.
- Contact: https://github.com/pete-builds/writ-protocol/issues/22.
- Last updated: 2026-09-30.
