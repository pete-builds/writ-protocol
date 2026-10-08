# Signing through Vault

A seed file is a private key on disk: anyone who can read it can sign as its owner. The reference implementation can instead sign through the transit engine of [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/secrets/transit), so the private key is made inside Vault, marked not exportable, and never leaves it. The signer sends Vault the bytes to sign and gets back a signature, and checks that signature against the key's public half before using it, so a signature that would not verify never reaches the wire.

Nothing in the protocol changes. Writ signs only with Ed25519 (spec 1.4), transit makes `ed25519` keys, and a signature made through Vault verifies with the same verifier as one made from a seed.

## In Go

`keys.Signer` is anything that names an Ed25519 key by its did:key and signs with it. `*keys.Identity`, a key in memory, is one. `vault.Signer`, in `keys/vault`, is another:

```go
s, err := vault.New(ctx, vault.Config{Addr: "https://vault.example.org:8200", Token: token, Key: "writ-gate"})
w, err := writ.Issue(s, holder, bounds, exp, nil)   // or exec.New(s, store) for an executor
```

It refuses a transit key that is not `ed25519`, and a derived key, whose public half depends on a context Writ does not carry. It is pinned to one version of its key, the latest when `New` runs unless `Version` names another, so rotating the key in Vault does not change what a running signer signs with. It uses only the standard library.

## With writ-hook

The grantor and the gate can each sign through Vault; the agent key stays a seed, since it only signs calls the gate then checks. Make the keys, and a policy that lets a token read them and sign with them, and nothing else:

```
vault secrets enable transit
vault write -f transit/keys/writ-root type=ed25519
vault write -f transit/keys/writ-gate type=ed25519
vault policy write writ-signer - <<'EOF'
path "transit/keys/writ-root" { capabilities = ["read"] }
path "transit/sign/writ-root" { capabilities = ["update"] }
path "transit/keys/writ-gate" { capabilities = ["read"] }
path "transit/sign/writ-gate" { capabilities = ["update"] }
EOF
vault token create -policy=writ-signer -field=token > token && chmod 600 token
```

Then run `writ-hook` with:

| Variable | Meaning |
|---|---|
| `WRIT_VAULT_ROOT_KEY` | the grantor's transit key; unset, the grantor is `root.seed` |
| `WRIT_VAULT_GATE_KEY` | the gate's transit key; unset, the gate is `claude/gate.seed` |
| `VAULT_ADDR`, `VAULT_NAMESPACE` | where Vault is |
| `WRIT_VAULT_TOKEN_FILE`, or `VAULT_TOKEN` | the token; the file wins when both are set |
| `WRIT_VAULT_MOUNT` | the transit mount, `transit` unless set |

`writ-hook init` then writes no seed for either key, and `root.did` records the transit key's did:key, so `receipts` checks the chain as before.

**The token is now the key.** It cannot export the private key, but it can sign as the grantor and the gate for as long as it is valid. Keep it where the seed would have been: readable only by the gate's own user ([claude-code.md](claude-code.md)). Run in place, the gate refuses any tool input that names `WRIT_VAULT_TOKEN_FILE`, as it does for `WRIT_HOME`, and with the same limit: a shell command that builds the path at run time gets past a text check.

If Vault cannot be reached, the gate cannot load its key, so `pre` blocks every call, and `grant` fails, so a standing grant is not renewed.

## Tested

On 2026-10-02, against `vault server -dev` from the official Vault 2.1.1 binary (its SHA-256 checked against HashiCorp's PGP-signed checksum file, and its Apple notarization checked), and on every pull request in the `vault` CI job against the `hashicorp/vault` 2.1.1 image pinned by digest:

- A grant signed by one transit key and a receipt signed by another verify with `writ.VerifyChain` and `writ.VerifyTally`; the same objects with one signature byte flipped fail (`keys/vault`, `TestRealVault`).
- `writ-hook` with both keys in Vault runs `init`, `grant`, an allowed `Read` and a refused one, and `receipts` verifies; neither seed file exists; with Vault unreachable, `pre` denies (`cmd/writ-hook`, `TestGateSignsThroughVault`).
- With the policy above, the token signed, and was refused when it tried to export the gate key or create another key. The root token was refused the export as well: the key is not exportable.
- A `pre` and `post` pair through Vault took about 60 ms on one machine with Vault on loopback.

Tests that need no server cover the signer's own checks against a fake transit mount: a signature over other bytes and one from a rotated key version are refused before they reach a caller, an `ecdsa-p256` key, a derived key, and a missing version are refused, and Vault's own error reaches the caller. Eight mutants of the signer and of `writ-hook`'s use of it were each caught by a failing test. A ninth, dropping the check that a signature names the pinned key version, is not: any signature from another version is from another key, and the signature check behind it refuses it.

## What it does not do

- **A KMS that cannot sign Ed25519 does not fit.** Writ accepts no other key type.
- **It does not hide the token.** Vault's audit device can record every signature, and a token can be short-lived and renewed by Vault Agent, which writes the file `WRIT_VAULT_TOKEN_FILE` names; neither is built into `writ-hook`.
- **It costs a round trip per signature**, and one more when the gate starts a call, so a Vault far from the gate adds that latency to every tool call.
