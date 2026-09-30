# writ-gate: Writ in front of an API that has never heard of it

`writ-gate` is a reverse proxy. A caller sends its ordinary request to the gate with a Writ call in a `Writ-Call` header. The gate checks the call, forwards the request only if the call passes, and returns the API's response unchanged, with its own signed tally in a `Writ-Tally` header. The API sees exactly the request it saw before Writ existed.

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
- `bind` maps each call argument to a field of the JSON request body. The call's `args` must equal exactly these fields, so what the caller signed and what the API receives are the same values. A request whose body differs from the signed args is refused as `malformed` before the API sees it.
- `used` names the integer each `max` bound consumes, reported in the tally.
- `reverse` is the request that undoes the effect. An identifier is taken from the API's response at `id`, and a `sys/undo` to the gate calls it within `ttl` seconds.
- A `{name}` path segment matches any one segment. A request that matches no route is refused with 404 and never reaches the API.

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
| no call, or one that does not match the route or body | 400 with `{"error": <reason>}` |

The tally's result body is `{"status", "body_sha256", "reverse_id"}`, so a caller can rebuild it from the response it received and verify the tally, which proves the response was not altered after the gate. Standing calls (`sys/undo`, `sys/tallies`) and revokes go to the gate's own section 10 endpoint, `POST /writ`, and `/.well-known/writ` publishes its key.

## Where it departs from docs/adoption.md section 2c

- The mapping is JSON, not YAML, and the replay store is the reference executor's file store, not SQLite, because the reference implementation has no dependencies.
- The call rides only in the `Writ-Call` header, base64url-encoded; the body form would collide with the API's own body.
- It is a standalone proxy, not an Envoy `ext_authz` service.

## Tested

`cmd/writ-gate/main_test.go` runs a fake orders API behind the gate: an order inside the grant is created and its tally verifies against the rebuilt response, the API never sees the `Writ-Call` header, an order over the `max`, a body that differs from the signed args, and a request with no call are all refused without reaching the API, a replay is answered from the store, the count runs out, an undo cancels the order through the API, and an unrouted path is refused. With the check that the signed args equal the body switched off, the test fails: an order signed for 1200 and sent as 9999 is created.
