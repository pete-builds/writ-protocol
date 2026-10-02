# Writ across an organization

This is one way to run Writ for every Claude Code user in an organization, so that each tool call is checked against a grant the organization signed and leaves a receipt the organization holds. It is a single recommended path, not a menu. Each part says whether it is built and tested here, built but not run at scale, or designed only.

## The path

1. **One central gate.** The gate that checks calls and signs receipts runs on a server the organization controls, not on the laptops. Each laptop's hooks reach it over mutual TLS.
2. **Keys in Vault.** The grantor key and the gate key sign through HashiCorp Vault's transit engine. The private keys never leave Vault, so not even the gate server holds them.
3. **Grants from directory groups.** A grantor job turns group membership into grants: a group is a template of tools, paths, and limits, and membership decides who gets it.
4. **Device certificates from Jamf or Intune.** The MDM already enrolls every laptop. It issues each one a client certificate naming the device, and the gate admits only certificates from that CA.
5. **Managed settings lock the hooks on.** Claude Code's managed settings deploy the hooks and refuse every other hook source, so a user cannot turn the gate off from their own settings.
6. **Receipts to a SIEM and write-once storage.** The gate ships its audit record to the SIEM as it is written and archives receipts where they cannot be changed.

## What is built

| Part | State |
|---|---|
| Gate as its own OS user on one Mac, hooks over a Unix socket | **Tested** on macOS: see [claude-code.md](claude-code.md) and `scripts/writ-gate-macos.sh` |
| Central gate over mutual TLS | **Tested**: `writ-hook serve -listen`, over real TLS handshakes and with Claude Code itself on loopback ([central-gate.md](central-gate.md)); not yet run across machines |
| Gate and grantor keys in Vault transit | **Tested** against a real Vault server, locally and in CI ([vault.md](vault.md)); not deployed |
| Grants from directory groups | Designed only |
| Device certificates from Jamf or Intune | Designed only. Both can put a URI in a SCEP certificate, which is what the gate needs; neither has been tried here |
| Managed settings that lock the hooks on | Key names checked against Claude Code's documentation on 2026-10-02; not deployed through an MDM here |
| Receipts to a SIEM and write-once storage | Designed only. The audit record is hash-linked and `writ audit` verifies it; nothing ships it yet |

## 1. One central gate

On one machine the gate runs as its own OS user, so the user Claude Code's tools run as cannot read its keys ([claude-code.md](claude-code.md), "Keep the keys out of Claude's reach"). That holds against a model with a shell, but not against the person who owns the laptop, who has the administrator password. A central gate holds against both: the keys and the record are on a machine the laptop's owner does not administer.

`writ-hook serve -listen` answers the same four requests it answers on a socket (`pre`, `post`, `recover`, `receipts`) over TLS 1.3 with client certificates, and never grants ([central-gate.md](central-gate.md)). The peer rules are the ones every Writ executor already follows (spec 7.6, [directories.md](directories.md)): the client certificate's one URI that is not a `did:key` names the device, a bindings file says which keys each device may speak for, and a certificate that names no device, or two, is refused before anything runs. Every audit entry names the device, and only the device that began a call can report how it ended. A hook that cannot reach the gate blocks the call.

## 2. Keys in Vault

A seed file on the gate server is still a file an administrator of that server can copy. With Vault transit ([vault.md](vault.md)), the gate asks Vault to sign and gets back a signature; the private key stays inside Vault, which can record every use in its audit log. Writ signs only with Ed25519 (spec 1.4), and Vault transit supports `ed25519` keys, so nothing in the protocol changes: a signature made through Vault verifies with the same verifier as one made from a seed.

The gate then holds a Vault token instead of a key, whose policy allows reading and signing with its two keys and nothing else; the token is the secret to protect, and it cannot export either key. A KMS that signs with Ed25519 fits the same place. One that offers only ECDSA or RSA does not, because Writ does not accept those keys.

## 3. Grants from directory groups

A grant is policy written once: which tools, under which paths, how many calls, for how long. Each group in the directory (Entra ID, Okta, or Active Directory) maps to one such template, kept in version control. A grantor job, running beside Vault, reads group membership and signs each member's grant through Vault, renewing it before it runs out as `grant -renew-before` does on one machine today. Leaving the group stops the renewal, and the grant lapses within its time to live; a revoke ends it at once.

A call the grant refuses names the grant's signer and tells the model to ask. An approval is a one-time delegation for exactly that call ([approval.md](approval.md)), so an approver in the group's owning team can allow it without widening the grant.

## 4. Device certificates from Jamf or Intune

The MDM issues each enrolled laptop a client certificate through SCEP with one URI subject alternative name that identifies the device, such as `urn:writ:device:<serial>`. Apple's SCEP payload (which Jamf delivers) and Intune's SCEP profile both accept a URI there. The gate trusts only the issuing CA. The bindings file is exported from the MDM's inventory: each device's URI and the key it speaks for. A laptop retired in the MDM drops out of the next export and is refused on its next call.

Holding the certificate's private key where only the hook can use it, such as a non-exportable key in the System keychain or the TPM, needs a platform signer in the client, which is not built: the client reads a certificate and key from files.

## 5. Managed settings lock the hooks on

Deliver one managed settings document through the MDM: a configuration profile in the `com.anthropic.claudecode` domain from Jamf, or the `Settings` value under `HKLM\SOFTWARE\Policies\ClaudeCode` from Intune. Use one channel only. By default Claude Code takes its policy from the highest-ranked managed source that has one (server-managed settings, then the MDM policy, then the file in `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, or `C:\Program Files\ClaudeCode\`) and skips the rest, so a second source does not add to the first.

```json
{
  "allowManagedHooksOnly": true,
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem /usr/local/bin/writ-hook recover >/dev/null"}]}],
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem /usr/local/bin/writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem /usr/local/bin/writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem /usr/local/bin/writ-hook post"}]}]
  },
  "permissions": {"disableBypassPermissionsMode": "disable"},
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.org:4317",
    "OTEL_LOG_TOOL_DETAILS": "1"
  }
}
```

The gate's address and the device certificate's paths are written into the hook commands rather than the `env` block: a managed hook command is locked, while a launch environment that the Claude Desktop app or a self-hosted runner builds takes precedence over `env`.

What each key does, from Claude Code's settings reference:

- `allowManagedHooksOnly`: only managed hooks run, plus Agent SDK hooks and hooks from plugins the managed settings force-enable. User, project, and local hooks are blocked. A user's `disableAllHooks` turns off only non-managed hooks; only managed settings can turn off managed ones.
- `hooks`, with matcher `"*"`: every tool call, MCP tools included. A hook process inherits Claude Code's environment, so these run wherever the session does.
- `|| exit 2` on `pre`: Claude Code runs the tool when a `PreToolUse` hook exits with any code but 2 without printing a decision, or times out. The gate turns its own errors into a deny; `|| exit 2` covers a missing or broken binary. Tested on 2026-10-02: without it, a hook pointing at a missing binary let a Bash call run.
- `permissions.disableBypassPermissionsMode` (the string `"disable"`): no one can enter bypass-permissions mode.
- `env`: Claude Code's own telemetry, for the cross-check in step 6. The exporter selectors are set here because a developer's own setting could otherwise switch them off.

Two consequences to plan for. `/goal` does not run while `allowManagedHooksOnly` is set, because it depends on hooks. And a developer with administrator rights can edit the managed source itself; the MDM redeploys it on its schedule, so the gate's protection on such a laptop is detection between redeploys, not prevention.

## 6. Receipts to a SIEM and write-once storage

The gate writes one audit line per call, refusals included, each carrying the hash of the line before it, so an edit, a deletion, or a reordering breaks the chain and `writ audit` reports it. Ship it in two directions:

- **The SIEM**, as each line is written, by whatever log shipper the SIEM already uses tailing the file. Refusals become alerts the security team already knows how to route.
- **Write-once storage**, such as S3 Object Lock in compliance mode, for the receipts and the audit record together. A receipt verifies offline with the keys inside it, so an auditor years later needs the archive and the verifier, nothing else.

The cross-check that makes this more than a log: Claude Code's own `claude_code.tool_result` event carries the call's `tool_use_id`, and so does the result body each receipt signs. In the SIEM, join the two. A tool result with no receipt is a call that ran without the gate, whether from a disabled hook, an edited managed source, or a gap in Writ. Nothing here runs that join yet.

## What this does not give you

- **The tool's effect in the world.** A receipt proves what the gate admitted and what Claude Code reported back. It does not prove what a shell command did.
- **A bound on what a shell command does.** `rm -rf` and `ls` are one Bash call each. A grant can refuse Bash; it cannot read a command. That is a sandbox's job.
- **Protection from the laptop's administrator.** Managed settings and the MDM make tampering visible and short-lived. A central gate keeps the keys and the record out of reach. Neither stops an administrator from running Claude Code without the hooks until the next redeploy; the cross-check in step 6 is what notices.
