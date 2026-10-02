# Approval: a payment above the line waits for a person

An agent should spend small amounts on its own and ask a person before a large one. Products that gate agent payments build this as a third answer beside yes and no: x402Shield calls it `REQUIRE_APPROVAL`, parks the request, and mints no permit until an approver decides.

Writ needs no third answer, no new object, and no new reason code for it, because a chain already carries the approval line and the authority above it.

## How it works

The agent's own writ is its line. Every writ above it in the chain is wider, because each child narrows its parent (spec section 4). So when an executor refuses a call as `out_of_bounds`, `forbidden_op`, or `missing_arg`, the caller can find, in the chain it already holds, the first writ that does not admit the call. Every writ above that one admits it. The issuer of that writ holds the wider authority, so that issuer is the approver.

The approver approves by issuing a writ in place of the one that refused, for exactly this call:

- `act` is the call's operation;
- every bound the writ above carries is pinned to the call's value;
- every other argument is pinned too, with a one-element `set`, so the approval names one action and not a family of them;
- it may be used once, by its own `count` of 1;
- it ends at the approver's chosen time, and never after the writ above it.

The holder then re-issues, the same way, each writ that stood below the one replaced. In the usual chain of a person, their agent, and an executor, that is the agent's one writ to the executor. The agent calls again under the new chain, and the executor runs it like any other: it does not know approval exists.

## What this gives

- **No one approves more than they hold.** The approval is a child of the approver's own writ, so `writ.Issue` refuses one that widens it, and so would every executor. A manager with a 10000 limit cannot approve 20000; the person above the manager can.
- **The approval is evidence.** It is in the chain of the tally for the work done under it, signed by the approver. Who allowed the large payment is not a log line; it is a signature the verifier checks.
- **Once means once, everywhere.** The approval's `count` is consumed at every executor like any other.
- **Nothing waits inside the protocol.** "Parked" is just the time between the refusal and the approval. The agent holds a refused call and a signed refusal; nothing is reserved, and nothing runs, until a writ that allows it exists.

## Two places an approval is looser than the call

A child keeps its parent's bound types (spec section 4 step 4), and two types cannot express "exactly":

- **A `max` or `total` pinned to an amount is a ceiling.** Approving a payment of 500 lets the agent pay up to 500 once, to the pinned recipient, with the pinned memo. It cannot pay more, or pay twice.
- **`act` is a prefix.** Approving `pay` also admits `pay/extra` (spec section 3.1). Name operations so that nothing riskier sits below one a person might approve.

`TestApprovalCeilings` in `impl/go/writ/approval_test.go` records both, so a change to either rule is a deliberate one.

## Using it

```
writ approve -chain w1.json,w2.json -op pay -args '{"amount":500,"pay_to":"v1"}'
```

prints the approver's key: the issuer of the first writ in the chain that refuses the call. The approver then signs:

```
writ approve -seed <approver seed> -chain w1.json,w2.json -op pay -args '{"amount":500,"pay_to":"v1"}' -exp <unix> > a1.json
```

and the holder below re-issues its writ under the approval, naming the approval and its own old writ, with `-at 1`:

```
writ approve -seed <holder seed> -chain a1.json,w2.json -at 1 -op pay -args '{"amount":500,"pay_to":"v1"}' -exp <unix> > a2.json
```

The call under `a1.json,a2.json` runs once. In Go, `writ.ApprovalPoint` finds the approver and `writ.Approve` issues the writ. Under Claude Code, `writ-hook` names the grant's signer when it refuses a call that signer could approve, and tells the model to ask the person rather than retry (docs/claude-code.md).

## What it does not do

It does not show the person what they are approving; a front end does that, and the approval writ is a small, complete statement of one action for it to show. It does not stop a person approving something they did not understand (OWASP ASI09). It does not decide which payments need approval: the line is whatever the agent's writ says, and it is set when that writ is issued.
