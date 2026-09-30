# writ-gate: Writ in front of an API that has never heard of it

`writ-gate` is a reverse proxy. A caller sends its ordinary request to the gate with a Writ call in a `Writ-Call` header. The gate checks that the request carries exactly the values the call signs and nothing else, checks the call, and only if it passes sends the API a request rebuilt from the signed values. It returns the API's response unchanged, with its own signed tally in a `Writ-Tally` header.

## The mapping file

```json
{
  "upstream": "http://127.0.0.1:9000",
  "routes": {
    "create_order": {
      "method": "POST",
      "path": "/v1/orders",
      "act": "orders/create",
      "bind": {"amount": "$.total_cents", "currency": "$.currency"},
      "used": {"amount": "$.total_cents"},
      "reverse": {"method": "POST", "path": "/v1/orders/{id}/cancel", "id": "$.id", "ttl": 86400}
    }
  }
}
```

- `act` is the op the call must name.
- `bind` maps each call argument to where the request carries it: a member of the JSON request body (`"$.total_cents"`, or `"$.payment.cents"` inside an object), or a path parameter (`"{id}"` for a `{id}` segment of `path`). The call's `args` must equal exactly these values.
- `used` names the bound body member whose integer each `max` bound consumes, reported in the tally.
- `reverse` is the request that undoes the effect. An identifier is taken from the API's response at `id`, and a `sys/undo` to the gate calls it within `ttl` seconds.
- A `{name}` path segment matches any one segment. A request that matches no route is refused with 404 and never reaches the API.

## The request contract

Each route is a contract for the request it matches. The gate enforces it before the executor runs, and the API never sees a request that breaks it:

- **The body is one strict JSON object.** No duplicate member at any depth, no unpaired surrogate escape, no invalid UTF-8, nothing after the object but whitespace, nesting no deeper than 64 (`noncanonical`, `too_large`). A body that is not an object is `malformed`.
- **No two member names fold together.** In any object of the body, two names that are equal under Unicode simple case folding (`total_cents` and `TOTAL_CENTS`, or `total_centſ` with a long s) are refused as `gate/ambiguous_member`, because a case-insensitive decoder such as Go's `encoding/json` reads them as one field and keeps the last.
- **The body holds exactly the bound members.** A member no `bind` entry names is refused as `gate/unbound_member`, at any depth. A bound member that is missing, or where an object was expected something else, is `malformed`. A route that binds no body member takes an empty body.
- **Every path parameter is bound.** A `{name}` segment the route does not bind would let a caller send a call signed for one resource to another, so the gate refuses to start with such a mapping. A path parameter of `.` or `..` is `malformed`.
- **No query string.** Routes bind nothing from the query, and many frameworks let a query parameter override the body, so any query string is `gate/unbound_query`.
- **The values equal the signed args.** Anything else is `malformed`, as before.

The gate also refuses to start with a mapping that is ambiguous in itself: two bound members of one object whose names fold together, one bound member inside another, a member or path parameter bound twice, a `used` entry that reads a member no `bind` entry signs, or a path that is not `$.` followed by member names.

**What the API receives** is rebuilt from the signed args alone, never the caller's bytes: the route's method, the route's path with each parameter filled in from its signed value (percent-encoded), and a body holding each bound member once, in canonical form (spec section 1.2) with `Content-Type: application/json`. Other request headers are forwarded, except `Writ-Call`, `Host`, the body headers (`Content-Type`, `Content-Length`, `Content-Encoding`, `Transfer-Encoding`), and the method override headers `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override`. The tally's `used` is read from the signed args, so it reports what the API was actually asked to do.

What the contract cannot see: a header the API reads as an operation parameter. Headers other than those above are forwarded unchecked and unsigned, so an API that takes, say, an amount from a header cannot be put behind the gate safely.

## Running it

```
writ-gate -config gate.json -seed-file gate.seed -accept <root did> -store gate-store.json -audit audit.jsonl -listen 127.0.0.1:8090
```

A caller sends `Writ-Call: <base64url of the call's JSON>` with its ordinary request. The answers are:

| Case | Answer |
|---|---|
| the call passes | the API's own status, headers, and body, plus `Writ-Tally: <base64url of the tally>` |
| the call is refused after its signature verified | 200 with `{"tally": ...}`, a signed refusal; the API is not called |
| a replay of the same call | 200 with the stored tally; the API is not called again |
| no call, or a request that breaks the route's contract | 400 with `{"error": <reason>}`: `missing_call`, `malformed`, `noncanonical`, `too_large`, `gate/ambiguous_member`, `gate/unbound_member`, or `gate/unbound_query` |

The tally's result body is `{"status", "body_sha256", "reverse_id"}`, so a caller can rebuild it from the response it received and verify the tally, which proves the response was not altered after the gate. Standing calls (`sys/undo`, `sys/tallies`) and revokes go to the gate's own section 10 endpoint, `POST /writ`, and `/.well-known/writ` publishes its key.

## Where it departs from docs/adoption.md section 2c

- The mapping is JSON, not YAML, and the replay store is the reference executor's file store, not SQLite, because the reference implementation has no dependencies.
- The call rides only in the `Writ-Call` header, base64url-encoded; the body form would collide with the API's own body.
- It is a standalone proxy, not an Envoy `ext_authz` service.

## Compatibility

The request contract was added on 2026-09-30, after a review found that the gate checked the fields it extracted but forwarded the caller's bytes: a body of `{"total_cents":1200,"TOTAL_CENTS":9999}` signed for 1200 was charged 9999 by an API that decodes into a Go struct, and the gate signed a valid tally reporting 1200. The changes a deployment notices:

- A request with any body member the route does not bind is refused. Before, unbound members passed through unsigned. Bind every member the API reads; a member with no bound in the writ is still an argument the call signs.
- A request with a query string is refused.
- A mapping with an unbound path parameter no longer starts.
- The API receives a canonical body (members sorted, no whitespace) and the route's method in upper case, not the caller's bytes.

## Tested

`cmd/writ-gate/contract_test.go` puts the gate in front of a ledger API that decodes the way most Go services do, into a tagged struct with `encoding/json`, and also lets a query parameter override the body, multiplies by a `quantity`, reads every JSON value of a batch body, and honors `X-HTTP-Method-Override`. Every request is signed for 1200 under a `max` of 5000. A case alias, a Unicode folding alias, a duplicate member, trailing JSON, an unbound member, a query string, a path parameter other than the signed one, and a dot segment are each refused before the API sees anything; before the fix, the first two were charged 9999 under a valid tally reporting 1200, the batch was charged twice, the unbound `quantity` was charged 12000, and the query string was charged 9999. An accepted charge reaches the API as the canonical body and the signed path, with the method override and a form content type removed, and its tally's `used` equals what the API charged. Mappings that leave a path parameter unbound, bind folding names, or read `used` from an unsigned member are refused at start. With each check removed in turn, a test fails.

`cmd/writ-gate/main_test.go` runs a fake orders API behind the gate: an order inside the grant is created and its tally verifies against the rebuilt response, the API never sees the `Writ-Call` header, an order over the `max`, a body that differs from the signed args, and a request with no call are all refused without reaching the API, a replay is answered from the store, the count runs out, an undo cancels the order through the API, and an unrouted path is refused. With the check that the signed args equal the body switched off, the test fails: an order signed for 1200 and sent as 9999 is created.
