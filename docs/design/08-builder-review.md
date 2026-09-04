# 08. Builder review: can one developer ship Writ v0.1 in weeks?

Status: build review, 2026-09-03. Role: Independent Builder. Inputs: `04-architectures.md` (six candidates, architect chose Writ with the Behalf HTTP binding), `05-threat-model.md` (45 requirements, 20 adversarial seeds), and the code already in `impl/go/` (a JCS canonicalizer restricted to safe integers, and a did:key Ed25519 package; `go test ./...` passes on Go 1.26.0). My standard: v0.1 is buildable by one strong developer with agentic coding tools in weeks, with no governments, consortiums, blockchains, new hardware, or global adoption anywhere in the dependency list. Everything below was checked against the local toolchain: Go 1.26.0, Node 26.5.0, Python 3.14.7 with cryptography 46.0.5.

## 1. Feasibility verdicts

**Writ. BUILD.** Twenty-six developer-days as the architect specified it, sixteen with the cuts in section 4. The hardest component is not the cryptography, which is four stdlib calls, but the executor's replay and idempotency stores and the reversal lookup, because they are the only stateful parts and the only parts where a crash changes the answer. No dependency touches the rejection list: Ed25519, SHA-256, base64url, JCS, did:key, all offline. Two packages already exist and are tested. The one thing the architect underweights is the strict parser: `encoding/json` in Go does not reject duplicate keys or lone surrogates, and I confirmed the current `jcs` package passes both through (a duplicate key resolves to the last value, a lone surrogate becomes U+FFFD), which fails MUST 8 in the threat model and needs a token-stream pre-scan before anything is signed or verified.

**Voucher. Feasible, wrong target.** Two weeks for the voucher object itself, but the demo needs two OAuth 2.1 authorization servers that both support RFC 9396 Rich Authorization Requests and federate for hop two. Mocking them proves nothing; running real ones is a week of configuration. Nothing on the rejection list is required, but "AS1 and AS3 federate" is a bilateral contract, which is adoption in disguise. The hardest component is the subset check applied to RAR objects whose field names each AS invents. Keep it as the fallback; do not build it first.

**Tether. Feasible, six weeks, and a transport.** X25519, HKDF, and HMAC are all in Go's stdlib (`crypto/ecdh`, `crypto/hkdf`, `crypto/hmac`), so nothing is blocked. The hardest component is the resume path and the cancel race inside a state machine that must be written down completely before it is coded, which is the two weeks the architect counted and which I believe. Not rejected on the list; rejected on the calendar.

**Docket. REJECT.** A transparency service with signed tree heads is an operator, and "register on the parent's log" makes vendor 1's operator load-bearing for vendors 2 and 3, which is a consortium in the making. COSE and CBOR have no Go stdlib support, so the zero-dependency rule falls too. A local toy log is buildable in five weeks and proves nothing about the trust model. Steal the freshness window and the index-ordered cancel rule as an appendix and stop there.

**Behalf. Feasible as a binding, three weeks alone, not the protocol.** No rejection-list dependency. The hardest component is RFC 9421 message signatures with `;req` response components on top of an RFC 9651 Structured Fields parser, neither of which is in Go's stdlib, so zero-dependency means writing both. That is where the three weeks go, and where interoperability bugs will live. The plain-header form of the binding (one header carrying the JSON call) costs half a day and gives ninety percent of the developer experience, which is why section 4 cuts the RFC 9421 form from v0.1.

**Pouch. Feasible, five weeks, defer to v0.2.** It is Writ plus an envelope, stamps, retry budget, and an inbox per agent. The hardest component is the stamp chain with `prev` hashes across hops and the bounce semantics on exhausted budget. No rejection-list dependency. Its value is for hours-long asynchronous work, which the demo does not exercise, and its envelope can wrap an unchanged Writ chain later.

## 2. Build plan for Writ v0.1

**Language.** Go for the reference implementation, because everything the protocol needs is in the standard library: `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64` (`RawURLEncoding` is exactly base64url without padding), `net/http`, and `math/big` for base58. The result is one static binary that runs the same on macOS and NixOS, which matters because the three-agent demo is three processes and a shell script.

**Second implementation.** A Python verifier, and only a verifier: no signing, no HTTP, no stores. It reads a conformance vector and prints accept or reject plus the reason. Python's stdlib has `hashlib`, `json` (with `object_pairs_hook` for duplicate-key detection), and `base64`; Ed25519 comes from `cryptography`, which is installed. The rule for whoever writes it: work from the spec text and the vector corpus, never from the Go source. If both implementations reject the same 40 vectors for the same reason, the spec is implementable from text. That is a better conformance control than any amount of Go test coverage, because it proves the spec rather than the code.

**Repo layout.**

```
impl/go/
  go.mod                      module agentproto (exists)
  jcs/                        exists; add strict pre-scan (dup keys, lone surrogates)
  keys/                       exists; did:key Ed25519
  hash/hash.go                SHA-256 of canonical bytes, 43-char base64url, Parse/Format
  wire/types.go               Writ, Call, Tally, Recall structs
  wire/parse.go               strict decode: unknown fields, round-trip byte check, size cap
  wire/sign.go                Sign(obj, id) and Verify(obj) with sig as sibling field
  wire/reason.go              the fixed rejection vocabulary, one constant per reason
  bounds/registry.go          five types, value syntax validation
  bounds/narrows.go           Narrows(child, parent) per type
  bounds/satisfies.go         Satisfies(leaf bound, call arg) per type
  chain/verify.go             executor-side ordered procedure, root to leaf
  chain/audit.go              delegator-side tally tree audit (steps 1 to 8)
  exec/executor.go            Handle(call) -> tally
  exec/replay.go              ReplayStore interface, JSONL file implementation
  exec/idem.go                IdempotencyStore, stores tally bytes verbatim
  exec/reversal.go            tally store lookup for chain-less reversal calls
  httpbind/server.go          POST /writ/call, POST /writ/recall
  httpbind/client.go          Call(url, call) with retry on same id
  httpbind/header.go          Writ-Call header form (plain header adapter)
  adapters/mcp/meta.go        writ in request _meta, tally in result _meta
  adapters/a2a/parts.go       writ and tally as DataPart
  cmd/writ/main.go            keygen, issue, narrow, call, verify, recall, serve
  demo/{a,b,c}.go demo/run.sh three processes on localhost, end to end
conformance/
  keys.json                   fixed 32-byte seeds for A, B, C, D
  vectors/accept/*.json
  vectors/reject/*.json
  gen/main.go                 regenerates every vector from seeds; diff must be empty
impl/py/writ_verify/
  jcs.py didkey.py bounds.py chain.py run_vectors.py
```

**Order.** Types, strict parser, hashing, and signing first, because every later component consumes them. Then the bound registry, then chain verification, then the vector generator and the first thirty vectors, because at that point the verifier is complete and the Python port can start in parallel with the executor. Executor and stores next, then the HTTP binding, then the CLI (which is a thin wrapper), then the demo, then adversarial runtime tests, then adapters last because they are formatting.

**Estimate, developer-days, as the architect specified it.**

| Component | Days |
|---|---|
| writ/call/tally/recall types, strict parse, canonical hashing, sign and verify | 2 |
| bound registry, five comparisons in both directions, value syntax checks | 1.5 |
| chain verification (executor side) and tally tree audit (delegator side) | 3 |
| executor with replay store, idempotency store, reversal lookup, file persistence | 4 |
| HTTP binding: POST endpoint plus Behalf header form (RFC 9421 and 9651 from scratch) | 3 |
| CLI: keygen, writ issue, writ narrow, call, verify, recall, serve | 1.5 |
| conformance vectors: generator, corpus, runner | 2.5 |
| Python verifier from spec text | 2 |
| adversarial runtime tests (the ones a static vector cannot express) | 2 |
| three-agent demo with compensation | 2 |
| MCP adapter | 1 |
| A2A adapter | 1 |
| plain HTTP header adapter | 0.5 |
| **Total** | **26** |

Twenty-six developer-days is five working weeks solo. Agentic tooling compresses the mechanical parts but not the stores or the vectors, where the work is deciding what correct means.

## 3. Things that look small and are not

**Canonicalization of nested bound values.** `bnd` is a map of maps holding arrays whose element type varies by bound type. JCS sorts keys by UTF-16 code units at every depth, which the existing package handles, but the comparisons have their own traps: a `set` of `[1]` and a `set` of `["1"]` must not be equal, a `set` with duplicate elements must be rejected at parse rather than deduplicated, and set element order is irrelevant to the comparison but relevant to the hash, so two writs with the same meaning can have different hashes; document it so nobody "fixes" it. An empty `set` narrows validly to nothing. A `window` with `v[0] > v[1]` is an empty interval and should be rejected at parse.

**did:key edge cases.** `z6Mk` is necessary, not sufficient. Base58 is case-sensitive and has no canonical-encoding check by default: a leading `1` prepends a zero byte, which the 34-byte length check catches, but only if the length check runs before the multicodec check. A decoded key can be off-curve or a small-order point; Go's `ed25519.Verify` returns false, Python's `cryptography` raises at key load time, so the two implementations reach the same rejection by different paths and the reason vocabulary must map both to `did_invalid`. Whether the two libraries agree on non-canonical point encodings is something to settle with a vector, not by assumption. `iss` of a child must byte-equal `hld` of the parent; never compare decoded keys, because two encodings of one key would otherwise pass.

**Replay store persistence across restarts.** `count` is the only bound whose enforcement lives in state. If the store is in memory, a restart re-arms every writ, and the second charge goes through. The store must be written before the operation executes, not after, which produces a "reserved, outcome unknown" record on a crash mid-operation, and that record needs a defined resolution (the architect's tally with `st: failed` and `err.code: "undeliverable"` is the right shape). Entries are keyed by writ hash and expire at that writ's `exp`. The idempotency store must hold the tally bytes verbatim rather than re-sign a reconstruction.

**The reversal call authority lookup.** A refund call carries `chain: []` and names a tally hash. The tally does not carry the root issuer; it carries the leaf writ hash. So C's tally store must persist the full chain, or at least the root `iss`, beside every tally it signs, or the lookup has nothing to check `from` against. The threat model's MUST 32 and MUST 42 are also in tension with the architect's design here: a forward writ must not authorize a reversal, and a chain-less call must be refused, unless the reversal class is defined as its own thing. The clean answer for v0.1: `rev.op` names are a reversal class, accepted only with `chain: []` and `args.tally`, authorized by store lookup, root issuer only, idempotent on tally hash. Attempting `travel/refund` under a forward writ is `op_not_granted`.

**Unknown-field policy.** The architect is strict about unknown bound types and silent about unknown top-level fields. The threat model (MUST 11) wants unrecognized critical fields rejected. A field the verifier ignores is still inside the signed bytes, so the signature holds; the danger is semantic, a field that changes meaning for a newer verifier and is invisible to an older one. v0.1 should reject any unknown top-level key in the four signed objects and treat `args` and `res` as opaque.

**Time handling.** Only the verifier's clock counts. `ts` is checked for skew (at most 120 seconds in the future) and never used as "now". `nbf` and `exp` are strict integer comparisons. The `dates` window holds integers shaped like `20261015`, which are not timestamps and must never be parsed as dates; they compare as integers and nothing else. At audit time A checks the tally `ts` against the writ window, which means B's clock and C's clock both matter to A, and a tally signed one second after `exp` is invalid evidence even if the operation was fine.

**base64url padding.** Measured on this machine: Go's `RawURLEncoding` rejects padded input, Python's `urlsafe_b64decode` raises on unpadded 43-character input, Node's `base64url` accepts unpadded. A Python implementer's first fix is to append `=` before decoding, which silently accepts both forms and creates two encodings of one hash. The rule: check length (43 for hashes, 86 for signatures) and alphabet before decoding, reject `=`, `+`, and `/`.

**Hash-of-signed-object versus hash-of-payload.** Every signed object is canonicalized twice: once without `sig` to produce the bytes that are signed, once with `sig` to produce the hash that `prv`, `tally.writ`, and `tally.call` reference. `tally.in` is a third case, the hash of `args` alone, which has no `sig`. Mixing these up produces vectors that verify in the implementation that made them and nowhere else, which is precisely what the Python port exists to catch. One note on the architect's claim that a re-signed writ is a different authority: Ed25519 is deterministic, so re-signing identical fields with the same key produces the same signature and the same hash. Uniqueness comes from `nnc`, not from the signature.

## 4. Cut list to ship in three weeks

Three weeks is fifteen developer-days. The table above says twenty-six. Ten days come out as follows.

| Cut | Saves | Cost |
|---|---|---|
| RFC 9421 and RFC 9651 Behalf header form; keep the plain `Writ-Call` header carrying the JSON call | 2.5 | The "add headers, never parse a writ" adoption story waits for v0.2; no interoperability with existing 9421 libraries is claimed |
| A2A adapter | 1 | Demo shows MCP and plain HTTP only |
| Recall forwarding by intermediaries and the freshness window; recall is honored on direct delivery only | 1 | MUST 36 unmet; A must deliver recalls to every hop itself, which the tally tree lets it do |
| Stolen appendices: SCITT anchor, `ttl` and `budget` on calls, bounce tally | 1 | Silence after retry exhaustion is a client timeout, not a signed object |
| Adversarial runtime tests reduced to five: replay across restart, duplicate delivery, cancel racing completion, reversal idempotency, depth limit before any signature check | 1 | Everything else in the threat model's seed list is expressed as a static vector instead, which covers 15 of the 20 seeds |
| Store garbage collection by `exp`; stores grow until the process exits | 0.5 | Fine for a demo, unacceptable for a service, and one line to add later |
| Reversal as a store-lookup only, no reversal-class writ | 0.5 | MUST 32 is met by op-class rule, but a delegated reversal (A lets D refund) is not expressible |
| Task binding (MUST 17) via root `nnc` rather than a task id field | 0.5 | A writ cannot be reused across tasks anyway, but the audit cannot name a task |
| Chain depth fixed at 4, object size capped at 64 KB, no configuration | 0.5 | Ten-hop chains are out; nobody needs them in v0.1 |
| Second vector runner in Python trimmed to chain and call vectors; tally tree audit vectors run in Go only | 1 | The audit procedure is proven by one implementation, not two, until v0.2 |

Sixteen days remain, which is three weeks with a day of slack. One cheap addition I would make rather than cut: a reserved bound key `dlg` of type `set` listing the did:keys a holder may narrow to, with an empty set meaning no further delegation. It satisfies MUST 38 with zero new comparison logic and costs half a day, mostly vectors.

## 5. Test vectors first

Every vector is one JSON file: `{name, kind, now, trusted_root, input, expect, reason}`, where `kind` is one of `object`, `chain`, `call`, `tally`, `recall`, `reversal`, and stateful vectors add a `sequence` array processed in order against a fresh store. Keys derive from fixed seeds in `keys.json`; because Ed25519 is deterministic, regenerating the corpus must produce byte-identical files, and `conformance/gen` diffing clean is itself a test. Reasons are the fixed vocabulary in `wire/reason.go`; both implementations must print the same string.

**Accept.**

| File | Asserts |
|---|---|
| `A01-writ-root-minimal` | root writ with only `act` verifies |
| `A02-writ-root-scenario` | writ_1 with all seven bounds verifies |
| `A03-narrow-max` | 50000 under 60000 |
| `A04-narrow-count` | 1 under 2 |
| `A05-narrow-prefix` | `travel/charge` under `travel/` |
| `A06-narrow-set` | `["USD"]` under `["USD","EUR"]` |
| `A07-narrow-window` | `[20261016,20261018]` inside `[20261015,20261019]` |
| `A08-narrow-equal` | child identical to parent on every bound (comparisons are inclusive) |
| `A09-narrow-adds-key` | child adds `pnr` bound the parent lacks |
| `A10-chain-depth-3` | four links A to D verify, depth limit 4 |
| `A11-call-scenario` | B to C call with args inside every leaf bound |
| `A12-call-unbound-args` | `pnr` in args with no matching bound is ignored |
| `A13-canonical-variants` | same call with shuffled keys and `é` escaped as `é` in one file and literal in the other: both verify, same hash |
| `A14-tally-single` | tally_C verifies against call and writ_2 |
| `A15-tally-tree` | tally_B with `sub` and `wrt`: all eight audit steps pass |
| `A16-tally-failed` | `st: failed` with `err` is a valid receipt |
| `A17-recall-by-root` | A recalls writ_2 (ancestor, not issuer) |
| `A18-recall-by-issuer` | B recalls writ_2 |
| `A19-reversal-by-root` | `chain: []`, `args.tally`, `from` equals root iss, before `until`; store seeded |
| `A20-call-skew-ok` | `ts` is `now + 100` |
| `A21-duplicate-call-same-tally` | sequence: same call twice, second response is byte-identical to the first |
| `A22-count-two-distinct-ids` | sequence under `count: 2`, two calls with distinct ids both accepted |

**Reject.**

| File | Reason |
|---|---|
| `R01-version-2` | `version_unsupported` |
| `R02-typ-unknown` | `type_unknown` |
| `R03-typ-tally-as-writ` | `type_mismatch` |
| `R04-sig-bit-flipped` | `sig_invalid` |
| `R05-sig-wrong-key` | `sig_invalid` (signed by B, `iss` says A) |
| `R06-sig-padded` | `encoding_invalid` |
| `R07-hash-padded` | `encoding_invalid` (`prv` ends in `=`) |
| `R08-did-truncated` | `did_invalid` |
| `R09-did-web` | `did_invalid` |
| `R10-did-offcurve` | `did_invalid` (34 bytes, not a point) |
| `R11-json-duplicate-key` | `non_canonical` |
| `R12-json-float` | `non_canonical` (`60000.0`) |
| `R13-json-lone-surrogate` | `non_canonical` |
| `R14-json-over-2p53` | `non_canonical` |
| `R15-unknown-top-field` | `field_unknown` |
| `R16-writ-missing-act` | `bound_missing_act` |
| `R17-act-wrong-type` | `bound_type_mismatch` |
| `R18-bound-type-unknown` | `bound_type_unknown` (`x-vendor-limit`) |
| `R19-widen-max` | `bound_widened` (65000 under 60000) |
| `R20-widen-count` | `bound_widened` |
| `R21-widen-prefix` | `bound_widened` (`trip/` under `travel/`) |
| `R22-widen-set` | `bound_widened` (adds `EUR`) |
| `R23-widen-window` | `bound_widened` (starts one day early) |
| `R24-set-type-confusion` | `bound_widened` (`["1"]` under `[1]`) |
| `R25-omit-parent-key` | `bound_missing` (child drops `count`) |
| `R26-type-changed` | `bound_type_mismatch` (`amount` becomes `count`) |
| `R27-iss-not-parent-hld` | `issuer_mismatch` |
| `R28-prv-wrong-hash` | `parent_mismatch` |
| `R29-root-has-prv` | `parent_mismatch` |
| `R30-exp-exceeds-parent` | `window_not_nested` |
| `R31-nbf-before-parent` | `window_not_nested` |
| `R32-depth-5` | `depth_exceeded`, with `sig_checks: 0` asserted |
| `R33-untrusted-root` | `untrusted_root` |
| `R34-call-from-not-hld` | `holder_mismatch` |
| `R35-call-op-outside-prefix` | `op_not_granted` |
| `R36-call-arg-over-max` | `bound_violated` |
| `R37-call-arg-not-in-set` | `bound_violated` |
| `R38-call-arg-outside-window` | `bound_violated` |
| `R39-call-expired` | `expired` |
| `R40-call-not-yet-valid` | `not_yet_valid` |
| `R41-call-skew` | `ts_skew` (`now + 121`) |
| `R42-nonce-short` | `nonce_invalid` (8 bytes) |
| `R43-count-exhausted` | sequence: second distinct id under `count: 1` is `count_exhausted` |
| `R44-tally-writ-mismatch` | `tally_writ_mismatch` |
| `R45-tally-call-mismatch` | `tally_call_mismatch` |
| `R46-tally-exe-not-hld` | `executor_mismatch` |
| `R47-tally-in-mismatch` | `input_mismatch` |
| `R48-sub-without-wrt` | `sub_writ_missing` |
| `R49-wrt-widened` | `bound_widened` (audit catches B over-delegating) |
| `R50-used-exceeds-bound` | `used_exceeds_bound` |
| `R51-tally-after-exp` | `receipt_outside_window` |
| `R52-recall-non-ancestor` | `recall_unauthorized` |
| `R53-reversal-not-root` | `reversal_unauthorized` |
| `R54-reversal-unknown-tally` | `tally_unknown` |
| `R55-reversal-after-until` | `reversal_expired` |
| `R56-reversal-under-forward-writ` | `op_not_granted` |

Seventy-eight vectors, fifty-six of them rejections. The reject list is the spec's rejection vocabulary made executable; if the spec adds a reason without a vector, the vector suite should fail a count check.

## 6. What a three-week v0.1 will not prove

It will prove that four signed JSON objects, five comparisons, and one ordered verification procedure can be implemented twice from text and agree on seventy-eight vectors, and that three processes on one machine can delegate, narrow, execute, receipt, and refund with every step verifiable offline. It will not prove that the bound registry is expressive enough for any real vendor's operation, because every bound in the corpus was chosen by the people who chose the registry. It will not prove that the replay store survives anything worse than a kill signal, because there is no concurrent load and no partitioned network. It will not prove that a did:key maps to a vendor anyone can sue, because that binding is OUT and untouched. It will not prove interoperability with a single existing A2A or MCP deployment, because the adapters carry the objects and nothing on the other end reads them yet. And it will not prove that two implementations written by two people disagree less than two people reading the same spec paragraph, because the Python verifier will be written by the same person who wrote the Go, with the same misreadings, unless someone else writes it.
