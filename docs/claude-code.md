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
| **A second OS user on the same machine** | the operating system: your user cannot read the gate user's files, and granting needs `sudo -u` | yes on macOS, on every CI run: the `macos-gate` job in `.github/workflows/ci.yml` runs `scripts/writ-gate-macos.sh` with sudo on a GitHub-hosted Mac (below); the Linux steps have not been run |
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

On macOS, [scripts/writ-gate-macos.sh](../scripts/writ-gate-macos.sh) does the same with a hidden account, `_writ`, that has no shell and no password. It copies the program to `/usr/local/libexec/writ/writ-hook`, in a folder it makes root-owned, and refuses to install if that folder or any folder above it is a symbolic link, is not owned by root, or can be written by its group or by everyone, since whoever can write a folder can rename the program in it and put their own in its place. (On an Intel Mac with Homebrew, `/usr/local/bin` belongs to your user, which is why the program does not go there.) It makes keys and a grant as `_writ` under `/var/db/writ/home` (mode 700), and starts two LaunchDaemons as `_writ`: the gate on `/var/db/writ/run/gate.sock`, and a renewal, since over the socket nobody else can grant. Their logs are in `/var/db/writ/log`, which stays root's.

**Before you run it.** The agent runs as you, so anything you can write, it can: the clone, the build, even the script while it runs. So quit every agent session (Claude Code and anything else that runs as you) before you clone, review, and install. Right before `sudo`, confirm that `git rev-parse HEAD` prints the commit you reviewed and `git status --porcelain` prints nothing. If any agent has ever run as this user, take the program and its SHA-256 from the Releases page rather than building it, since a build uses a toolchain and caches your user can write. Run `sudo` as `/usr/bin/sudo` from `/bin/bash --noprofile --norc`, so no shell startup file of yours runs first. And know the limit: if the account was compromised before the install, something the agent left running or installed as you can outlast it, and the install cannot make that safe.

The checksum is required; `install --no-checksum BINARY` skips it on purpose. The script checks the hash of its own root-owned copy, not of the file you named, so the file cannot change between the check and the copy.

```
/bin/bash --noprofile --norc
cd /path/to/fresh/writ-protocol && git rev-parse HEAD && git status --porcelain
/usr/bin/sudo /bin/bash scripts/writ-gate-macos.sh install /path/to/writ-hook <sha256 from the Releases page>
```

**First run on a real Mac**, in order:

1. Check the folders above the program: `stat -f '%N %Su:%Sg %Lp' / /usr /usr/local /usr/local/libexec` should show each owned by root with no group or world write (the script refuses otherwise; a missing `/usr/local/libexec` is fine).
2. Check nothing is called `_writ` or has uid 350: `dscl . -read /Users/_writ`, `dscl . -read /Groups/_writ`, and `dscl . -search /Users UniqueID 350` should all find nothing.
3. Quit every agent session, make a fresh clone, review it, and confirm the commit and a clean status as above.
4. Install, with the command above.
5. Check the result: `ls -ld /usr/local/libexec/writ /usr/local/libexec/writ/writ-hook /var/db/writ/log` all root:wheel; `sudo ls -l /var/db/writ/home` shows `root.seed` mode 600, owned by `_writ`; `ps -axo user,command | grep '[w]rit-hook serve'` shows `_writ`.
6. Install the managed settings file below, root:wheel 644.
7. Run `sudo -l` and confirm no rule for your user says `NOPASSWD`.
8. Start one Claude Code session, have it Read a file, then run `WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/libexec/writ/writ-hook receipts` and see one verified receipt.
9. Delete any old `~/.writ` from a gate that ran as you, by hand, as your normal user.
10. To back out: `sudo rm "/Library/Application Support/ClaudeCode/managed-settings.json"`, then `sudo /bin/bash scripts/writ-gate-macos.sh uninstall`. The keys and receipts stay in `/var/db/writ`, root's; `sudo rm -rf /var/db/writ` once you no longer need them.

**Hold the hooks in place with managed settings.** On one Mac your own Claude Code settings are files the agent, running as you, can edit: it could switch the gate off or point the hooks at a fake one. A managed settings file is root's, and with `allowManagedHooksOnly` only its hooks run. Save this as `/Library/Application Support/ClaudeCode/managed-settings.json`, owned by root:wheel, mode 644:

```json
{
  "allowManagedHooksOnly": true,
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/libexec/writ/writ-hook recover >/dev/null"}]}],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/libexec/writ/writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/libexec/writ/writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "WRIT_HOOK_SOCKET=/var/db/writ/run/gate.sock /usr/local/libexec/writ/writ-hook post"}]}]
  },
  "permissions": {"disableBypassPermissionsMode": "disable"}
}
```

```
sudo install -d -o root -g wheel -m 0755 "/Library/Application Support/ClaudeCode"
sudo install -o root -g wheel -m 0644 managed-settings.json "/Library/Application Support/ClaudeCode/managed-settings.json"
```

The same hooks work in your own `.claude/settings.json`, but there the agent can remove them. The grant hooks of the in-place setup go away either way: over the socket nobody but the renewal grants.

**The standing grant is broad.** By default the install signs `grant -name session -uses 10000 -ttl 24h -renew-before 22h`: any tool, any path, up to 10,000 calls a day. The renewal checks it every 15 minutes and signs a fresh one once less than 22 hours are left, so about every two hours. To narrow it, set `WRIT_GATE_GRANT` when installing; the install prints it before signing, and the renewal uses it too. Keep `-name session`: installing again with the same name and new bounds replaces the old grant at once, while a grant under another name would leave the old any-tool `session` grant in force for up to 24 hours, so the script refuses any other name. It also refuses a grant without `-uses` or with `-uses 0`, which mean no limit.

```
sudo env WRIT_GATE_GRANT='grant -name session -tools Read,Edit,Write,Grep,Glob -uses 2000 -ttl 24h -renew-before 22h' /bin/bash scripts/writ-gate-macos.sh install /path/to/writ-hook <sha256>
```

**What the separate account does and does not do.** It keeps the keys, and so the integrity of every receipt, out of your user's reach. It does not make receipts exist: that takes the managed settings above. And it assumes your user cannot become root or `_writ` without you: give it no `NOPASSWD` sudo rule, and never approve a Touch ID or password prompt for sudo that you did not start yourself.

**Coming from a gate that ran in place**, as your user: its keys were readable by the agent, so treat them as exposed. The install makes new ones. Once the hooks point at the socket, delete the old `~/.writ` by hand, as your normal user, after copying anything you want to keep.

`uninstall` stops the daemons, kills anything still running as uid 350, and removes the account and the program. It leaves `/var/db/writ`, which holds the keys and receipts: it removes every name there that is not a folder, a socket, or a file with a single name, which never touches the file such a link points to, and makes the rest root's, so an account later given uid 350 cannot read them. Installing again over that state hands it back to `_writ` only from an account the install has just made, with nothing running as uid 350, and refuses if the state holds any link or special file, so a root `chown` can never be led to another file. It reuses the kept keys rather than making fresh ones, so earlier receipts still verify. If you installed with `WRIT_GATE_LIBEXEC` set, uninstall needs the same value. If a step of `install` fails, or it is interrupted with Ctrl-C or a signal, it undoes what that run created, so a first install either completes or leaves nothing behind, and state it found goes back to root. A failed reinstall keeps the account, keys, and receipts it found, but not the program and daemon definitions it had already replaced; run the install again.

The `macos-gate` CI job runs the script for real, with sudo, on a GitHub-hosted macOS runner (green on macOS 26.7.2, arm64), whose own user plays the user Claude Code's tools run as. It requires:

- an install with no checksum, or a wrong one, to be refused and leave no account, daemon, program, folder, or state;
- an install whose program folder sits under a runner-owned folder, or under a root-owned folder its group can write, to be refused, and so too a program folder inside `/var/db/writ` or with a `..` segment, a grant with `-uses 0`, without `-uses`, or under another name, and a stray `_writ` group with no account;
- an install of a program that cannot run to fail after creating the account, then undo all of it;
- after a real install, the log folder to be root:wheel 755 with each log `_writ` 640; the runner user's `cat` of each of the three seeds and `ls` of `/var/db/writ/home` to fail with `Permission denied`, while root reads the same files and finds each one mode 600, owned by `_writ`;
- the runner user's rename or overwrite of the program, and any write into its folder, to fail with `Permission denied`, while the same rename as root succeeds;
- a Read call's `pre` and `post` events sent through the socket to be admitted and receipted, a call naming the gate's keys refused, `receipts` to report one verified receipt and an intact audit record, and that receipt, copied out as root, to verify with `writ verify` against the response sent, while a different response must not;
- a reinstall over the running gate to keep its receipts, and a reinstall over an account whose shell was changed to be refused;
- `_writ` to succeed in hard-linking `/private/etc/hosts` into its home, and then a reinstall, an uninstall (which must remove the link), an install refused because a link was left in the kept state, and a clean install to each leave `/private/etc/hosts` root:wheel;
- `uninstall` to leave no `_writ` account, daemon, process, or program, `pre` to block the next call, and every file left under `/var/db/writ` to be root's;
- a reinstall over that kept state, with a grant narrowed to Read, to give every file back to `_writ`, verify both receipts, admit a Read, and refuse a Bash call.

The events are written by the job, not sent by a Claude Code session; the managed settings file and an interrupted install are not exercised.

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
