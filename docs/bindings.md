# MCP and A2A bindings

Writ does not replace the protocols agents already speak. It rides inside them: the call goes out with the request, and the signed tally comes back with the result. docs/adoption.md sections 2a and 2b are the design; this page is what is built.

## MCP: `impl/go/mcpbind` and `cmd/writ-mcp`

A client puts the Writ call in `params._meta["io.writ/call"]` on `tools/call`, with `op` set to `mcp/tools/<tool name>` and `args` equal to the tool's `arguments`. The server checks the call with the executor, runs the tool only if it passes, and returns the tally in `result._meta["io.writ/tally"]`, with the tool's `structuredContent` as the result body the tally commits to. A server advertises the extension as `io.writ/delegation`.

- **Server:** `mcpbind.NewServer(executor, tools, require)` and `CallTool(ctx, params)`. It refuses, as `malformed`, a call whose `arguments` differ from the signed `args` or whose `op` names another tool, so what was signed and what runs are the same bytes. With `require`, a tool call carrying no Writ call is refused (`missing_call`); without it, the call runs unenforced and its result carries no tally.
- **Client:** `mcpbind.Params(tool, call)` builds the request. `mcpbind.Ready(call, advertised)` refuses to send a chain with `max` or `count` bounds to a server that does not advertise the extension (`unenforced_server`). `mcpbind.Check(call, result)` verifies the tally, and treats a result with no tally as `missing_tally`: the work does not count as done.
- **`writ-mcp`** is a minimal MCP server over stdio with one tool, `echo`, that runs only under a Writ call.

Tested: the binding end to end in `mcpbind_test.go` (an enforced call, a count running out, arguments differing from what was signed, a failing tool, both client rules, a result body changed after signing), a scripted stdio session in `cmd/writ-mcp`, and Claude Code itself as the MCP client on 2026-09-30: it connected, listed `echo`, called it, and received the `missing_call` refusal, because no MCP client attaches Writ calls yet. That last point is the gap: a client adapter that signs calls for an agent's MCP tool use is the next piece.

## A2A: `impl/go/a2abind`

Message-level helpers for any A2A server or client:

- `CallFrom(message)` reads the call from a data part of `application/writ-call+json` (preferred) or from `message.metadata["io.writ/call"]`, and says which form it came in, so the server answers in the same shape.
- `TallyArtifact(id, tally)` wraps the tally as the task's last artifact, `StatusMetadata(tally)` gives the terminal status message its `io.writ/tally` identity, and `TallyFrom(artifacts)` reads it back.
- `RevokeFrom(message)` reads a revoke from a `CancelTask` message's `metadata["io.writ/revoke"]`.
- `CardExtension(did, bounds, maxChain)` is the Agent Card's `capabilities.extensions` entry, which, because the card is JWS-signed under the vendor's domain, binds the key to the vendor.

Tested at the message level in `a2abind_test.go`, through JSON, in both call forms, with the tally verified offline. It has not been run against an A2A SDK or a live A2A server; the part and artifact field names follow docs/adoption.md section 2b and should be checked against the A2A version a deployment uses.
