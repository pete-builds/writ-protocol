# Connecting a directory

Spec section 7.6 says that when the transport authenticates who is calling, the executor must know that caller is allowed to use the key that signed the call. The reference implementation ships two ways to know it. Both feed the same check, and both fail closed.

## 1. The certificate says so

Serve the executor over mTLS. The client certificate's first URI subject alternative name that is not a `did:key` is the peer, and every `did:key:` URI in the same certificate is a key the certificate authority vouches the peer speaks for. No lookup is needed: the CA's signature is the binding.

This works with a private CA you run, such as step-ca or Vault PKI, that can put both URIs in one certificate. It does not work with SPIRE as is: a SPIFFE X.509-SVID carries exactly one URI, its SPIFFE ID, so an SVID identifies the peer and a bindings file supplies its keys.

## 2. A bindings file exported from the directory

A JSON object mapping each peer to the keys it speaks for:

```json
{
  "spiffe://example.org/booking": ["did:key:z6Mk..."],
  "spiffe://example.org/payment": ["did:key:z6Mk...", "did:key:z6Mk..."]
}
```

Whatever owns your workloads writes this file: a script over SPIRE registration entries, an Entra or Okta export, or a hand-kept list. The executor rereads it when it changes, so revoking a workload in the directory takes effect on the next call once the export runs. A file that is missing or cannot be parsed binds nothing.

## Running it

```
writ-agent -role payment -seed <hex> -accept <root did> \
  -tls-cert server.pem -tls-key server-key.pem \
  -client-ca clients-ca.pem \
  -bindings bindings.json
```

With `-client-ca`, the agent serves TLS 1.3 and requires a verified client certificate on every connection. In Go, the same is `httpbind.NewHandler(e, wk, httpbind.Options{MTLS: true})` behind a `tls.Config` that requires and verifies client certificates, with `e.PeerBinds = bindings.Binds` from `exec.LoadBindings`.

A call whose signer the certificate names passes. A call whose signer the bindings file lists for that peer passes. Anything else is refused with `peer_mismatch`, and the audit record (section 9.3) names the peer either way. `httpbind/peer_test.go` runs all of this through a real TLS handshake with a generated CA.
