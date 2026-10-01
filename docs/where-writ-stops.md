# Where Writ stops

Writ bounds what an agent may do, and returns a signed record of what it did. It does not decide whether the agent should want to. This page says plainly what that leaves open, where Writ sits next to the defenses that address it, and the two ways of deploying Writ that get the most out of its bounds. The README's section of the same name is the short version.

## Bounds are not a prompt-injection defense

Writ's own threat model concedes the central point: "An injected B that delegates to a permitted party, within bounds, for the attacker, is lawful as far as the protocol can see" (docs/design/05-threat-model.md). The same holds for an injected agent that spends, sends, or deletes inside its writ. A signature proves which key asked; it cannot prove that the model behind the key was following its principal rather than a string it read in an email.

So the right assumption is that the model will be hijacked, and the question is how much a hijacked model can do. NIST's agent-hijacking evaluations saw attack success rise "from 11% for the strongest baseline attack to 81% for the strongest new attack", and repeated attempts raised the average "from 57% to 80%" ([NIST, 2025](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)). Writ's job is to make the answer small and checkable: `max` and `set` limit what one call can do, `count` caps how many times an attacker gets to try at each executor, short `exp` limits how long, and the receipt tree says afterwards exactly what ran.

Least privilege alone is not enough, and the literature says so. The design-patterns paper states the principle as "once an LLM agent has ingested untrusted input, it must be constrained so that it is impossible for that input to trigger any consequential actions", and judges a least-privilege booking assistant one that "remains vulnerable to prompt injection attacks located in the calendar description of events" ([Beurer-Kellner et al., 2025](https://arxiv.org/abs/2506.08837)). The two deployment patterns below are how Writ helps meet that principle rather than only shrink the blast radius.

## Writ and CaMeL compose; neither replaces the other

CaMeL uses the word "capability" for a different thing. In CaMeL, "Capabilities are metadata assigned to each value passed to a tool that track the sources and allowed recipients of each value," so that "the untrusted data retrieved by the LLM can never impact the program flow" ([Debenedetti et al., 2025](https://arxiv.org/abs/2503.18813)). That is data-flow control: where did this argument come from, and may it go there?

Writ checks something else: who may perform which operation, within which limits, under whose authority, and it returns signed evidence of what happened. It never asks whether an argument came from untrusted data.

The two fit together in one direction. A CaMeL-style interpreter decides whether a value may flow into a tool call; Writ is the enforcement and receipt layer that the call then passes through, at an executor that may belong to another organization and has never seen the interpreter. The interpreter's guarantee ends at its own process boundary. Writ's starts there.

## OWASP Top 10 for Agentic Applications

OWASP published its Top 10 for Agentic Applications on 2025-12-09 ([OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)). The names below are taken from [Auth0's summary](https://auth0.com/blog/owasp-top-10-agentic-applications-lessons/), because OWASP's own document did not extract for this review; the mapping should be re-checked against the primary text.

| Risk | Writ | Why |
|---|---|---|
| ASI01 Agent Goal Hijack | no | A hijacked agent acting inside its bounds is lawful to the protocol. Writ limits and records the damage; it does not stop the hijack. |
| ASI02 Tool Misuse & Exploitation | partly | Only where an argument carries the meaning: a `set` of recipients or a `max` amount binds the tool's effect, and a free-text argument or a shell command does not. `writ-mcp-proxy -closed` refuses arguments the grant never names. |
| ASI03 Identity & Privilege Abuse | yes | Authority is a signed, expiring, narrowing chain checked at the executor, never a borrowed session or a cached credential. A child writ cannot exceed its parent. |
| ASI04 Agentic Supply Chain Vulnerabilities | no, except tool descriptions | A malicious dependency is out of scope. For MCP tool descriptions, `writ-mcp-proxy -pins` lists and calls only definitions a person approved (docs/bindings.md). |
| ASI05 Unexpected Code Execution (RCE) | no | Code an agent runs can do anything its process can. docs/claude-code.md says the same of its own adapter: a grant "cannot say what a shell command will do". |
| ASI06 Memory & Context Poisoning | no | Writ does not see what an agent remembers or reads. |
| ASI07 Insecure Inter-Agent Communication | yes | Every call, receipt, and revoke is signed and verifiable offline; replays are named and answered from the replay store; the peer binding (spec 7.6) ties a transport identity to the signing key. |
| ASI08 Cascading Failures | partly | Per-executor limits, revocation that reaches the whole subtree, and `sys/undo` within a promised window bound how far one failure spreads and what can be reversed. They do not prevent it. |
| ASI09 Human-Agent Trust Exploitation | no | The spec has no rule for showing bounds to a person, so a person can still approve something they did not understand. |
| ASI10 Rogue Agents | partly | The same as ASI08: short expiry, revocation, and receipts bound and expose a rogue agent's work. Nothing in a signature detects one. |

## Pattern 1: commit before ingest

The design-patterns paper's plan-then-execute pattern fixes the list of actions before the agent reads anything untrusted. Writ makes the plan binding and the result checkable. The profile:

1. **Plan from trusted input only.** The planner sees the principal's request and nothing an attacker could have written: no inbox, no web page, no tool output.
2. **Mint the writs from the plan.** Issue one writ per planned action, as narrow as the plan allows: `set` rather than `prefix` for recipients and hosts, the plan's amount as `max`, `count` 1 where the plan does a thing once, and an `exp` measured in minutes.
3. **Only then ingest.** The executing agent reads the untrusted content and does the work, holding writs that were signed before it read a word of it.
4. **Anything off-plan is refused, with a reason.** A call the plan did not mint a writ for fails at the executor as `forbidden_op`, `out_of_bounds`, or `count_exhausted`, whatever the injected text asked for.
5. **Check the receipt tree against the plan.** The tallies say what ran under each writ, so a principal can compare outcome to plan without trusting the agent's account.

What this does not do: injected content can still choose among the actions and values the plan allowed. If the plan says "send one email to someone in this set of three", an injection can pick which of the three. Narrow bounds shrink that choice; they do not remove it.

## Pattern 2: cut the exfiltration leg with a `set` of recipients or hosts

Simon Willison's lethal trifecta is private data, untrusted content, and a way to communicate externally, together: "If a tool can make an HTTP request... that tool can be used to pass stolen information back to an attacker" ([Willison, 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). An agent that must have the first two can still lose the third, for attacker-chosen destinations, with a `set` bound on the argument that names where data goes:

```json
{"act":  {"t": "prefix", "v": "mcp/tools/send_email"},
 "to":   {"t": "set",    "v": ["travel@example.com", "me@example.com"]},
 "uses": {"t": "count",  "v": 1}}
```

The bound holds only if every channel is a bounded argument. Three ways it fails, and what to do about each:

- **An argument the writ does not name.** Spec 7.2 leaves unbounded arguments unconstrained, so a `cc` or `bcc` argument the writ never mentions is a second, open channel. Run `writ-mcp-proxy -closed`, which refuses any argument the grant has no bound for.
- **A tool that is a channel by nature.** A shell, a generic HTTP fetch, or a code interpreter can reach anywhere whatever its arguments say. Do not grant one to an agent that also reads untrusted content and holds private data.
- **An allowed destination the attacker can write to.** Binding `host` to `github.com` still lets data leave in an issue on the attacker's repository. Bind to a destination the principal controls, and bind the path as well as the host where the tool allows it.

## A proposed extension: Rule of Two labels

*A proposal, not part of v0.1 and not implemented.*

Meta's Agents Rule of Two says an agent "must satisfy no more than two" of three properties within a session: "[A] An agent can process untrustworthy inputs", "[B] An agent can have access to sensitive systems or private data", and "[C] An agent can change state or communicate externally". It allows a change of configuration mid-session as "a one-way switch to [B] by disabling communication", and it suggests "declaring an Agents Rule of Two configuration in supporting tool calls" ([Meta](https://ai.meta.com/blog/practical-ai-agent-security/)).

Writ's narrowing already has the shape of a one-way switch: a child writ can only drop authority. A label would make the configuration mechanical:

- A writ carries an optional member, say `r2`, listed in `crit` so that a verifier that does not understand it rejects the writ instead of ignoring it (spec 1.7). Its value is a set of at most two of `"A"`, `"B"`, `"C"`.
- A child narrows its parent when its `r2` is a subset of the parent's, so a holder can switch from `[A, C]` to `[C]` but never add `B`.
- A tool or executor declares which properties a call exercises, and the executor refuses a call whose properties are not all in the leaf's `r2`.

It is not a writ bound, because a bound is compared against the call's arguments (spec 7.2). The open questions are who declares a tool's properties, and whether an executor can be trusted to declare its own.

## What Writ does answer on MCP, and what it does not

The MCP specification's security guidance describes an audit-trail risk: "The MCP Server will be unable to identify or distinguish between MCP Clients" ([MCP security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)). Writ answers that one: every tool call names its signer and its chain, and every result carries a receipt.

The same document's confused-deputy section is about OAuth static client IDs and consent cookies at an MCP proxy server. Writ does not address it, and nothing here should be read as claiming it does.

MCP tool poisoning, where "a malicious server can change the tool description after the client has already approved it" ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)), bypasses argument bounds, because the description steers the model before any argument exists. `writ-mcp-proxy -pins` lists and calls only the tool definitions a person approved, and refuses a tool whose definition has changed since (docs/bindings.md).
