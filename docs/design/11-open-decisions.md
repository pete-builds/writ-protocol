# Open decisions

Questions the specification or the adapters leave open, each with the options, a recommendation, and what it costs. None is decided here: each needs the author's call, and a decision becomes spec text, vectors, and a decision record entry in one change.

## 1. A stolen key keeps its standing after a key-wide revoke

**Today.** Section 7 skips expiry and revocation for standing calls (steps 4 and 7), so an issuer can still list (`sys/tallies`) and reverse (`sys/undo`) work done under a chain after withdrawing it. That is what lets the rightful owner clean up. It also lets whoever stole the key do the same: read what ran under that issuer's writs, and reverse any effect still inside its `rev.until`, even after the owner's key-wide revoke.

**Options.**

- **A. Keep it.** Reversal is bounded by `rev.until`, which the executor chose, and listing reveals only what ran. The owner keeps cleanup.
- **B. A key-wide revoke also ends the key's standing.** The thief loses it; so does the owner through that key. Anyone higher on the chain keeps standing, so only a compromised *root* key strands cleanup.
- **C. The revoker chooses.** A key-wide revoke gains an optional member, `std`, and `"std": false` ends standing too. Revokes accumulate and a thief cannot remove one, so once any revoke of the key ends standing, it stays ended. Retiring a key keeps standing; reporting a compromise ends it.

**Recommendation: C.** It separates the two situations the current rule conflates, at the cost of one optional member, a `crit` entry for verifiers that must understand it, new `verify_revoke` vectors and executor scenarios, and both implementations.

## 2. `max` and `count` are per executor, not totals

**Today.** Section 7.3: a holder given `count` 1 can delegate to two executors and get two operations. Totals across executors are detected afterwards from `used` in the tally tree, never enforced at request time.

**Options.** Keep it; or define coordination between executors (a shared ledger, reservations against an ancestor), which is what the spec avoided to stay offline and serverless.

**Recommendation: keep it,** and keep saying so plainly. A delegator that needs a total splits it across the writs it issues or names one executor in `hld`. A future *budget* extension could define a ledger for deployments that have one, outside the core.

## 3. The audit record is a SHOULD

**Today.** Section 9.3 asks executors to keep an audit record, and both implementations and every adapter do, but a conforming executor may not.

**Recommendation: keep SHOULD in the core,** and make it a MUST in a named deployment profile (for example, one for regulated use) if and when someone needs to claim it. Conformance tests cannot check a log the protocol never reads.

## 4. Where Pete's own Claude Code gate runs

**Today.** `writ-hook` works in place, or as its own process behind `writ-hook serve`. docs/claude-code.md lists three placements: a second OS user, the same user under Claude Code's sandbox, or another machine.

**Recommendation:** try it first on one project, in place, with a grant that has no Bash. Before relying on it with a shell in the grant, move the gate to a second OS user on the Mac. The nix1 placement is the strongest and the slowest, and needs an mTLS front for the gate that is not built.

## 5. The MCP client side

**Today.** `mcpbind` and `writ-mcp` enforce Writ on the server side, and Claude Code, as an MCP client, reached `writ-mcp` and got refused, because no MCP client attaches Writ calls.

**Options.** Build a client adapter that signs a call for each MCP tool use an agent makes, such as a `writ-hook` mode that adds `_meta` to MCP tool calls (which needs Claude Code to let a hook change a tool's input), or a proxy MCP server that fronts another and adds the call. Or wait for demand.

**Recommendation: the proxy MCP server,** because it needs nothing from any client: point the client at the proxy, and the proxy signs under a grant and forwards to the real server. It is the MCP counterpart of `writ-gate`. *Built 2026-09-30 as `cmd/writ-mcp-proxy` and run with Claude Code (docs/bindings.md), so this one is decided.*
