# One gate for many machines

`writ-hook serve` can listen on TCP with mutual TLS, so one gate on a server checks the tool calls of many machines and signs their receipts. Its keys, grants, and audit record are on the server, not on any laptop, so the person at the laptop, administrator password and all, cannot read them or rewrite the record. The hooks on each machine only carry each event to the gate and relay its answer, as they do over the Unix socket ([claude-code.md](claude-code.md)).

## How a machine is known

The rules are the ones every Writ executor follows when a transport authenticates the caller (spec 7.6, [directories.md](directories.md)):

- TLS 1.3 with a client certificate required and verified against the CA you give the gate. A client with no certificate, or one from any other CA, fails the handshake, and nothing reaches the gate.
- The certificate's one URI subject alternative name that is not a `did:key` names the machine, such as `urn:writ:device:laptop-1`. A certificate that names none, or two, is refused `peer_mismatch` before anything runs.
- The machine must speak for the key that signed the call: a `did:key` URI in the same certificate, or an entry in the bindings file, which maps each machine to the keys it speaks for and is reread when it changes. Removing a machine from the file refuses its next call.
- Every audit entry names the machine, and a call one machine began only that machine can report the outcome of, or recover. Over mTLS, `recover` must name its session, since `recover` with no session resolves every unfinished call.

The gate signs calls with one agent key for every machine, so each machine's entry in the bindings file names that key.

## Run it

On the server, as the gate's own user:

```
writ-hook init
writ-hook grant -name session -uses 10000 -ttl 24h -renew-before 22h
writ-hook serve -listen :8443 -tls-cert gate.pem -tls-key gate-key.pem \
  -client-ca devices-ca.pem -bindings bindings.json
```

`-socket` can run beside `-listen`, for hooks on the server itself. `bindings.json`:

```json
{"urn:writ:device:laptop-1": ["did:key:z6Mk...the agent key init printed"]}
```

On each machine, the hooks name the gate, the machine's certificate and key, and the CA that signed the gate's certificate:

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem writ-hook recover >/dev/null"}]}],
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem writ-hook pre || exit 2"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem writ-hook post"}]}],
    "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "WRIT_HOOK_GATE=https://gate.example.org:8443 WRIT_HOOK_CERT=/etc/writ/device.pem WRIT_HOOK_KEY=/etc/writ/device-key.pem WRIT_HOOK_CA=/etc/writ/gate-ca.pem writ-hook post"}]}]
  }
}
```

If the gate cannot be reached, the TLS handshake fails, or the certificate cannot be loaded, `pre` blocks the call. Each request has a 30-second deadline, well inside Claude Code's hook timeout, after which Claude Code would run the tool anyway.

## Tested

In `cmd/writ-hook/mtls_test.go`, each over a real TLS handshake on loopback with generated CAs:

- An allowed `Read` from a bound machine is admitted and receipted, one outside the grant is refused, `receipts` verifies, and every audit entry names the machine.
- A client with no certificate, and one presenting a certificate from another CA that names a bound machine, are blocked by TLS, and the audit record does not grow.
- A certificate from the trusted CA that names an unbound machine, no machine, only a `did:key`, or two machines is refused `peer_mismatch`.
- With nothing listening, or with the machine's certificate missing, `pre` blocks.
- One machine cannot report the outcome of another's call or recover it, and `recover` without a session is refused.

Twelve mutants were each caught by a failing test: the handler dropping the gate's answer; the client certificate made optional, accepted unverified, or not asked for; every peer bound; an unidentified peer passed through; the peer dropped before admission or before the receipt; `pre` failing open; another machine finishing or recovering a call; and `recover` answered without a session.

On 2026-10-02 it was run with Claude Code itself: a gate on loopback with `-listen`, and a headless session whose hooks reached it with a machine certificate. A `Read` and a Bash call ran and were receipted, and the audit entry named the machine. With the gate stopped, a Bash call was blocked and its file was never written.

## What it does not do

- **It does not keep a machine's own certificate from the model.** The key the hooks present is readable by the user Claude Code's tools run as, so a model with a shell can send events as that machine: report a false outcome for its own call in flight, or spend its grant. It cannot widen a grant, read the gate's keys, or get a receipt for a call the gate did not admit. Holding the key where only the hook can use it, such as the System keychain or a TPM, needs a platform signer, which is not built.
- **One agent key and one grant set for every machine.** Grants per machine or per group need an agent key per machine, which is designed in [enterprise.md](enterprise.md) and not built.
- **No certificate revocation lists.** A machine is cut off by removing it from the bindings file, or by the certificate expiring.
- **`receipts` answers any machine** with the totals for all of them; it shows counts, not the calls.
