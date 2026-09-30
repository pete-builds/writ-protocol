# Writ for Claude Code

`writ-hook` puts a Claude Code session's tool calls under a Writ grant. You grant the session a bounded piece of authority, such as "Read and Edit, only files under this project, at most 200 calls, for the next 8 hours". Before each tool runs, the gate checks the call against the grant with the reference executor and blocks it, with the reason, when the grant does not cover it. After each tool runs, it signs a receipt. Every call and every refusal lands in an audit record, and one command verifies every receipt offline.

The model never holds a key and never writes a receipt. The checks run in this program, outside the model, which is the enforcement point spec section 12 requires.

## How it maps onto Writ

| Writ | Here |
|---|---|
| root issuer | your grantor key, `~/.writ/root.seed` |
| a grant | a writ from you to the session's agent key, `~/.writ/claude/grants/<name>.json`; you can hold several |
| a call | one tool call: `op` is `claude/<tool name>`, `args` is the tool input plus `tool`, the tool's name |
| the executor | the gate key, which enforces the grant and signs every receipt |
| a tally | the receipt for one tool call, committing to the tool's response by SHA-256 |

The agent key passes the grant to the gate unchanged, so the chain is root, agent, gate, and every bound in the grant is enforced on every call. String inputs longer than 1024 bytes, such as file contents, are carried as their SHA-256, so the receipt commits to exactly what the tool was given without storing it.

## Set up

Build it (Go 1.25 or newer):

```
cd impl/go && go build -o ~/bin/writ-hook ./cmd/writ-hook
```

Create the keys once, then grant a session. Each grant has a name, and a tool call is checked under the grant that lists its tool, so file tools can be held to one folder while search tools are not:

```
writ-hook init
writ-hook grant -name files  -tools Read,Edit,Write -under /Users/you/project -uses 200 -ttl 8h
writ-hook grant -name search -tools Grep,Glob -uses 200 -ttl 8h
```

A tool no grant lists is checked under the first grant without a `-tools` list, or failing that the first grant by name, which refuses it with its reason.

| Flag | Bound it signs | Meaning |
|---|---|---|
| `-name` | none | the grant's name, lowercase letters, digits, and dashes; granting the same name again replaces it |
| `-tools` | `tool`, a `set` | the tools the session may call; empty for any |
| `-under` | `file_path`, a `prefix` | every call must carry a `file_path` under this folder |
| `-uses` | `uses`, a `count` | the most tool calls the grant allows |
| `-ttl` | the writ's `exp` | how long it lasts, at most 24 hours |

Register the hooks in the project's `.claude/settings.json`. The empty matcher covers every tool, MCP tools included:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "writ-hook recover"}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook pre"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook post"}]}]
  }
}
```

Set `WRIT_HOME` in the command to keep keys and state somewhere other than `~/.writ`.

## Check the receipts

```
writ-hook receipts
```

It verifies every receipt against the chain it names, with the keys inside the objects and nothing else, and exits non-zero if any fails. The audit record is `~/.writ/claude/audit.jsonl`, one JSON line per call, refusals included.

## What Claude sees when a call is blocked

The tool does not run, and Claude gets the reason with what the grant allows, for example:

```
Writ: missing_arg: this grant requires file_path on every call and a Bash call has none; the grant allows only Read
```

This was run against Claude Code on 2026-09-30: an allowed Read ran and was receipted, a Read outside the granted folder and a Bash call were both blocked, and a Read of a missing file produced a verified `failed` receipt through `PostToolUseFailure`.

## What it does not do

- **A bound applies to every call under its grant.** `-under` adds a `file_path` bound, so a tool whose input has no `file_path` is refused under that grant: Bash, Grep and Glob (which use `path`), and NotebookEdit (which uses `notebook_path`). Give those tools their own named grant.
- **Bash defeats it.** The gate refuses any input that names `~/.writ`, so an allowed tool cannot read the keys or rewrite the grant, but that is a text match, and a shell command can build the path at run time. A grant that must hold does not include Bash.
- **The keys live on the same machine as the tools.** A receipt proves what the gate admitted and what Claude Code reported back, signed by a key the model cannot reach through an allowed tool. It does not prove the tool's effect in the world, and anyone with access to `~/.writ` can do anything.
- **Paths are checked as text.** Inputs with `.` or `..` segments are refused, but a symlink inside the granted folder can still point outside it.
- **A revoke does not stop a tool already running**; it refuses every later call.
- **A call Claude Code never reports back**, because you rejected it at the permission prompt or the session ended mid-tool, stays unfinished until the next `writ-hook recover`, which resolves it to `unknown_outcome`. Run one session per `WRIT_HOME` at a time, because `recover` resolves every unfinished call in it.
- **It fails closed before the tool, not after.** If the gate cannot check a call, the call is blocked. If signing a receipt fails after the tool ran, the call stays unfinished and `recover` resolves it.
- **macOS and Linux only**, because it serializes hook processes with `flock`.
