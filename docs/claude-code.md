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

When a call is refused for its arguments or its operation and a writ above the one that refused it would allow it, the reason names that writ's signer, usually you, and tells the model to ask rather than retry. When the signer is you, the refusal also names an ID, the call's `tool_use_id`, and you approve exactly that call, once ([approval.md](approval.md)):

```
writ-hook approve toolu_01AbC          # shows the refused call; signs nothing
writ-hook approve -yes toolu_01AbC     # signs a one-use approval, 30 minutes by default (-ttl)
```

The approval is a writ from your grantor key for that tool and those arguments, every one pinned, with a single use. The gate tries approvals before the grants, uses one only for the call it names, and removes it once the call is admitted, so a second identical call is refused again and every other call is still checked under your grants. Its receipt carries the approval in its chain, signed by you. Like `grant`, `approve` is a local command for the grantor, never answered over the gate's socket.

| Flag | Bound it signs | Meaning |
|---|---|---|
| `-name` | none | the grant's name, lowercase letters, digits, and dashes; granting the same name again replaces it |
| `-tools` | `tool`, a `set` | the tools the session may call; empty for any |
| `-under` | `file_path`, a `prefix` | every call must carry a `file_path` under this folder |
| `-uses` | `uses`, a `count` | the most tool calls the grant allows |
| `-ttl` | the writ's `exp` | how long it lasts, at most 24 hours |
| `-renew-before` | none | keep the grant already saved under this name, rather than sign a new one, while it has the same bounds and more than this left to run |

Register the hooks in the project's `.claude/settings.json`. The empty matcher covers every tool, MCP tools included:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "writ-hook recover"}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook post"}]}]
  }
}
```

Set `WRIT_HOME` in the command to keep keys and state somewhere other than `~/.writ`.

### A standing grant for every session

A grant lasts at most a day, so a setup meant to stay on renews its own: run the same `grant` with `-renew-before` at every session start, every prompt, and after every tool call. It keeps the saved grant while more than that much of it is left, and signs a fresh one when not, so with `-ttl 24h -renew-before 22h` a new grant starts about every two hours of use and none runs out while you work:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [
      {"type": "command", "command": "writ-hook grant -name session -uses 10000 -ttl 24h -renew-before 22h >/dev/null"},
      {"type": "command", "command": "writ-hook recover >/dev/null"}]}],
    "UserPromptSubmit": [{"hooks": [
      {"type": "command", "command": "writ-hook grant -name session -uses 10000 -ttl 24h -renew-before 22h >/dev/null"}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [
      {"type": "command", "command": "writ-hook post"},
      {"type": "command", "command": "writ-hook grant -name session -uses 10000 -ttl 24h -renew-before 22h >/dev/null"}]}],
    "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "writ-hook post"}]}]
  }
}
```

The output goes to `/dev/null` because Claude Code adds what a `SessionStart` or `UserPromptSubmit` hook prints to the model's context. Renewing this way means the grantor's key signs without you at the keyboard, which is the trade a standing setup makes: the grant is a policy you wrote once, not a decision made each time.

Each grant keeps its own store, `claude/stores/<grant identity>.json`, because a store is read and written whole on every call: a renewed grant starts a fresh file, so the one a hook rewrites holds a couple of hours of calls rather than every call ever made. `receipts` reads them all.

Several sessions can share one `WRIT_HOME`. `recover`, given the `SessionStart` input on stdin as above, resolves only the starting session's own unfinished calls, which cannot still be running, and any call older than 24 hours; another session's call in flight is left to finish. Run by hand with no input, it resolves every unfinished call, so run it that way only when no session is live.

## Keep the keys out of Claude's reach

Run as above, the gate opens its keys and state in the hook process, as your user, which is the user Claude Code's tools run as. A grant without a shell cannot reach them, because the gate refuses any input that names its `WRIT_HOME`, written out, or with `~`, `$HOME`, or `${HOME}`. A grant with a shell can: a command that builds the path at run time gets past a text check. So for a grant that must hold, run the gate as its own process where your user cannot read its files, and let the hooks only carry each event to it:

```
writ-hook serve -socket /run/writ/gate.sock
```

The hook commands find it through `WRIT_HOOK_SOCKET`:

```json
{"type": "command", "command": "WRIT_HOOK_SOCKET=/run/writ/gate.sock writ-hook pre || exit 2"}
```

Over the socket the gate answers `pre`, `post`, `recover`, and `receipts`, and nothing else. It never grants: granting is a local command run as the gate's own user, so a model with a shell and the socket still cannot grant itself. If the gate cannot be reached, `pre` blocks the call.

Where the gate runs is the choice that matters. The code is the same in each case:

| Where the gate runs | What keeps Claude out | Tested here |
|---|---|---|
| **A second OS user on the same machine** | the operating system: your user cannot read the gate user's files, and granting needs `sudo -u` | no; the socket and the gate are tested, but under one user |
| **The same user, with Claude Code's own sandbox denying its tools the gate's directory** | the sandbox | no |
| **Another machine**, reached over the network | the keys are never on the machine the tools run on | yes, on loopback: `serve -listen` with mutual TLS, run with Claude Code on 2026-10-02 ([central-gate.md](central-gate.md)) |

On Linux or NixOS, the second-user setup is:

```
sudo useradd --system --create-home --home-dir /var/lib/writ writ     # NixOS: users.users.writ = { isSystemUser = true; group = "writ"; home = "/var/lib/writ"; createHome = true; };
sudo install -d -o writ -m 0755 /run/writ
sudo -u writ writ-hook init
sudo -u writ writ-hook grant -name files -tools Read,Edit,Write -under /home/you/project -ttl 8h
sudo -u writ writ-hook serve -socket /run/writ/gate.sock               # or as a systemd service with User=writ
```

On macOS, [scripts/writ-gate-macos.sh](../scripts/writ-gate-macos.sh) does the same with a hidden account, `_writ`, that has no shell and no password. It installs the binary root-owned at `/usr/local/bin/writ-hook`, so your user cannot swap the program the gate runs, makes fresh keys and a grant as `_writ` under `/var/db/writ/home` (mode 700), and starts two LaunchDaemons as `_writ`: the gate on `/var/db/writ/run/gate.sock`, and a renewal that runs the standing `grant` every 15 minutes, since over the socket nobody else can:

```
sudo bash scripts/writ-gate-macos.sh install ./writ-hook
```

The hooks then carry each event to the socket, and the grant hooks go away:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/bin/writ-hook recover >/dev/null"}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/bin/writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/bin/writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/bin/writ-hook post"}]}]
  }
}
```

Moving from a gate that ran in place, `retire` moves the old `WRIT_HOME`'s three seed files into a root-only folder once the hooks point at the socket. Its receipts still verify, because `receipts` needs only `root.did`, but its keys can no longer sign. `uninstall` removes the daemons, the account, and the binary, and leaves the state.

What the socket still allows: any local process can send `pre` and `post` events, so a model with a shell could report a false outcome for one of its own calls in flight, or spend its own grant's `uses`. It cannot widen a grant, read a key, or sign a receipt for work the gate did not admit.

## Check the receipts

```
writ-hook receipts
```

It verifies every receipt against the chain it names, with the keys inside the objects and nothing else, and exits non-zero if any fails. The audit record is `~/.writ/claude/audit.jsonl`, one JSON line per call, refusals included. Each line carries the hash of the line before it, so `receipts` also reports whether every link is intact: an entry edited, removed, or reordered since it was written makes it fail. `writ audit <file>` checks any record the same way.

## What Claude sees when a call is blocked

The tool does not run, and Claude gets the reason with what the grant allows, for example:

```
Writ: missing_arg: this grant requires file_path on every call and a Bash call has none; the grant allows only Read
```

Refusals the hook makes before the executor sees a call, such as an input naming `~/.writ` or a path with `..`, are in the audit record too, with a `claude/` reason code.

This was run against Claude Code on 2026-09-30: an allowed Read ran and was receipted, a Read outside the granted folder and a Bash call were both blocked, and a Read of a missing file produced a verified `failed` receipt through `PostToolUseFailure`. The same was run again with the gate as its own process behind `writ-hook serve`: the Read was receipted through the socket, and a `cat` of the grantor's key was blocked.

On 2026-10-01 the standing setup above was run with two headless Claude Code sessions (2.1.287) sharing one `WRIT_HOME`: the first ran a 25-second foreground Bash command, and the second started and finished while it ran. The first call's pending record survived the second session's `recover` and was receipted `ok`. The same run with the binary from before this change (5203cf5) deleted the running call's pending record at the second session's start and receipted a command that printed its output as `failed`, `unknown_outcome`; it also reported `-1 refusal(s)`, because the executor's own recovery signed the tally without an audit entry. A `head` of the grantor's seed was blocked and an `echo` of text mentioning `~/.writ` ran, with `WRIT_HOME` elsewhere. A hook pair, `pre` and `post`, took about 40 ms.

## What it does not do

- **A bound applies to every call under its grant.** `-under` adds a `file_path` bound, so a tool whose input has no `file_path` is refused under that grant: Bash, Grep and Glob (which use `path`), and NotebookEdit (which uses `notebook_path`). Give those tools their own named grant.
- **Bash defeats it unless the gate runs apart.** Run in place, the gate protects its keys with a text match, which a shell command can get past. Run as its own user (above), the operating system protects them. Either way, a grant cannot say what a shell command will do: `rm -rf` and `ls` are both one Bash call. Bounding that is a sandbox's job, not a grant's.
- **The keys live on the same machine as the tools.** A receipt proves what the gate admitted and what Claude Code reported back, signed by a key the model cannot reach through an allowed tool. It does not prove the tool's effect in the world, and anyone with access to `~/.writ` can do anything.
- **Paths are checked as text.** Inputs with `.` or `..` segments are refused, but a symlink inside the granted folder can still point outside it.
- **A revoke does not stop a tool already running**; it refuses every later call.
- **A call Claude Code never reports back**, because you rejected it at the permission prompt or the session ended mid-tool, stays unfinished until that session starts again, or for 24 hours, and is then resolved to `unknown_outcome`. A call you declined at the permission prompt reads the same as one cut off mid-run: the gate admitted it, and Claude Code never said what happened.
- **It fails closed before the tool, not after, given `|| exit 2`.** Claude Code runs the tool when a `PreToolUse` hook exits with any code but 2 and prints no decision, or times out. `writ-hook pre` turns every error it can catch, an unreachable gate included, into a deny, but a missing binary exits 127 and unreadable input exits 1, and either would let the call through; `|| exit 2` blocks those too. Tested on 2026-10-02: with the hook pointing at a missing binary, a Bash `touch` ran; with `|| exit 2`, it was blocked. A hook still running at its timeout (600 seconds unless set) lets the call through, which the gate's 30-second socket deadline keeps from happening. If signing a receipt fails after the tool ran, the call stays unfinished and `recover` resolves it.
- **macOS and Linux only**, because it serializes hook processes with `flock`.
