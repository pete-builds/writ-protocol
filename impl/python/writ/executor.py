"""The executor: sections 7, 7.1 to 7.5, 8, 9, 9.1 and 9.2.

An Executor holds one Ed25519 key, the root issuers it accepts (section
7.1), a clock that can be set, the durable stores of section 9 (stores.py),
and an application callback that performs operations.

Answers are the section 14.1 shapes, which are also the section 10 HTTP
bodies:

- ``{"error": <reason>}``: an unsigned rejection at section 7 steps 1 and 2,
  or an invalid revoke.
- ``{"tally": <tally>}`` or ``{"tally": <tally>, "res": <body>}``: a signed
  reply, final or pending.
- ``{"inflight": True}``: the call was accepted and its operation has not
  returned; its final tally comes from ``complete()``.
- ``{"tallies": [...]}``: the answer to a valid revoke.

The application
---------------

``app(op)`` is called with an Operation at section 7 step 11, for a forward
call (``op.kind == "forward"``) and for a sys/undo reversal (``"undo"``).
It returns an Outcome, or HELD to say the operation is still running; the
application then reports later with ``executor.complete(op.call_id,
outcome)``. ``op.stop_requested()`` turns true when a revoke tells the
operation to stop (section 9.1). sys/tallies never calls the application.
An application that raises has an unknown outcome: the call's tally is
``failed`` with ``unknown_outcome``.

Delegating onward (sections 7.5 and 9.2)
----------------------------------------

A forward operation may delegate part of its work. ``op.issue(holder,
bnd=..., exp=...)`` narrows the leaf writ this executor holds into a child
(issue.narrow, never a writ received as data) and durably adds it to the
call's ``wrt`` before returning it. ``op.make_call(child, op, args)`` signs
a forward call under the extended chain. ``op.receive_tally(call, tally,
res)`` verifies a sub-tally under section 6.2 and durably adds it to the
call's ``sub`` before returning the verdict, so the application acts on it
only after it is persisted. The final tally carries every issued writ and
every received sub-tally, whatever its own ``st``, including a ``failed``
tally with ``undeliverable`` for a sub-call that never answered, and so
does the tally a pending record resolves to after a restart. Either
tally's ``used`` is raised, where the outcome reports less, to cover its
sub-tallies' (section 6: ``used`` is inclusive of the subtree).

``forward_revoke(revoke, holder)``, when given, is called after a valid
revoke for the holder of every writ this executor issued under the revoked
writ (section 9.1, SHOULD).

Concurrency
-----------

One lock covers admission (steps 1 to 10 and the pending record of step
11), completion, revocation, and restart, so steps 9 and 10 are atomic with
respect to every other call and a revoke can never slip between a call's
revocation check and its admission. The application runs outside the lock.
"""

import threading
import time

from . import bounds as B
from . import chain as C
from . import issue as I
from . import objects as O
from . import verify as V
from .canon import loads_lenient as canon_loads
from .errors import WritError
from .keys import Key
from .stores import BEGAN, DONE, FINAL, PENDING, UNKNOWN, Stores

HELD = object()
"""Returned by an application whose operation has not finished yet."""

STORE_WRITE_FAILED = "writ-py/store_write_failed"
"""Implementation code (section 11) for a call refused because the call or
count store could not be written at section 7 steps 9 and 10 (section 9)."""

OUTCOME_STATES = ("ok", "failed", "canceled")


def _max_names(writ):
    """Names of the writ's max bounds, in canonical order."""
    bnd = writ["bnd"]
    return [n for n in sorted(bnd, key=lambda k: k.encode("utf-16-be", "surrogatepass")) if bnd[n]["t"] == "max"]


def _cover_subs(used, max_names, sub):
    """Section 6: used is inclusive of the subtree. Returns used raised, for
    every max bound of the leaf, to the sum over the sub-tallies: an
    operation cannot have consumed less than the work it delegated reports,
    and a record resolved after a restart, whose own outcome is unknown,
    reports at least that much."""
    out = dict(used)
    for name in max_names:
        total = sum(S["used"].get(name, 0) for S in sub)
        if total > out.get(name, 0):
            out[name] = total
    return out


class Outcome:
    """What an operation returned: the application's side of a tally.

    ``st`` is ok, failed, or canceled; ``code`` the err.code, required
    exactly when st is not ok; ``res`` the result body or None; ``used``
    the tally's used object; ``rev`` the rev.until time or None.
    """

    def __init__(self, st, code=None, res=None, used=None, rev=None):
        if st not in OUTCOME_STATES:
            raise ValueError(f"outcome st must be one of {OUTCOME_STATES}, not {st!r}")
        if (st == "ok") != (code is None):
            raise ValueError("an outcome has a code exactly when st is not ok")
        self.st = st
        self.code = code
        self.res = res
        self.used = dict(used or {})
        self.rev = rev

    @classmethod
    def from_json(cls, d):
        """Build an Outcome from a section 14.1 ``app`` object."""
        return cls(d["st"], code=d.get("code"), res=d.get("res"), used=d.get("used"), rev=d.get("rev"))

    def __repr__(self):
        return f"Outcome({self.st}, code={self.code!r})"


class Operation:
    """One operation the executor asks its application to perform."""

    def __init__(self, kind, call, call_id, leaf_id, acc, target=None, target_id=None, executor=None):
        self.kind = kind            # "forward", "undo", or "tallies"
        self.call = call            # the parsed call; its chain is parsed writs
        self.call_id = call_id      # identity of the call
        self.leaf_id = leaf_id
        self.acc = acc
        self.target = target        # sys/undo: the tally being reversed
        self.target_id = target_id
        self._stop = threading.Event()
        self._ex = executor
        self._subcalls = {}         # identity of a sub-call -> the sub-call
        self.peer = None            # the transport-authenticated peer that delivered the call
        self.deferred = False       # answered inflight; audited when it finishes (section 9.3)

    def issue(self, holder, bnd=None, exp=None, nnc=None):
        """Section 7.5: issue a child of the leaf writ to ``holder``,
        narrowed by ``bnd`` and ``exp``, recorded in this call's wrt before
        it is returned."""
        return self._ex._issue_child(self, holder, bnd, exp, nnc)

    def make_call(self, child, op, args, call_id=None):
        """Sign a forward call under this call's chain extended by
        ``child``, which must be a writ this operation issued."""
        return self._ex._make_subcall(self, child, op, args, call_id)

    def receive_tally(self, call, tally, res=None):
        """Verify a sub-tally for ``call`` (section 6.2), persist it in this
        call's sub, then return the verify.Verdict."""
        return self._ex._receive_subtally(self, call, tally, res)

    @property
    def op(self):
        return self.call["op"]

    @property
    def args(self):
        return self.call["args"]

    def stop_requested(self):
        """True once a revoke has told this operation to stop (section 9.1)."""
        return self._stop.is_set()

    def _signal(self):
        self._stop.set()


class Executor:
    """A Writ executor over durable stores in ``store_dir``.

    ``key`` is a keys.Key or a 32-byte seed (bytes or hex). ``accept`` is
    the iterable of root issuer keys this executor acts under (section 7.1).
    ``clock`` is a callable returning integer Unix seconds; ``set_time()``
    fixes the clock instead. ``resolver(record)`` may return an Outcome for a
    pending record found after a restart, when the application can tell
    what happened; otherwise the record resolves to ``unknown_outcome``.
    ``peers`` maps each transport identity the executor holds a binding for
    to the keys that peer speaks for (section 7.6). ``audit(entry)``, when
    given, receives one dict for every call and revoke the executor answers,
    refusals included (section 9.3); ``writ.audit.AuditLog.record`` fits.

    Opening an executor over a directory that holds pending records is a
    restart: they are resolved at once, and ``resolved_at_open`` says how
    many were.
    """

    def __init__(self, key, accept, store_dir, app=None, clock=None, resolver=None,
                 forward_revoke=None, peers=None, audit=None):
        self.key = key if isinstance(key, Key) else Key.from_seed(key)
        self.did = self.key.did
        self.accept = frozenset(accept)
        self.peers = {p: frozenset(ks) for p, ks in (peers or {}).items()}
        self.audit = audit
        self.store_dir = store_dir
        self.app = app
        self.resolver = resolver
        self.forward_revoke = forward_revoke
        self._clock = clock or (lambda: int(time.time()))
        self._fixed = None
        self._lock = threading.RLock()
        self._running = {}      # call identity -> Operation
        self._waiting = {}      # target tally identity -> [Operation], queued undos
        self._revoked_mem = []  # revokes the revoke store could not persist
        self.stores = Stores(store_dir)
        self.resolved_at_open = self._recover()

    # ------------------------------------------------------------ clock

    def set_time(self, t):
        """Fix the executor's clock at t (integer Unix seconds)."""
        self._fixed = t

    def now(self):
        return self._fixed if self._fixed is not None else self._clock()

    # ------------------------------------------------------------ calls

    def receive_call(self, data, peer=None):
        """Section 7 for one call (bytes, text, or a parsed object). ``peer``
        is the identity the transport authenticated for the party that
        delivered it, or None when the transport authenticated none."""
        with self._lock:
            answer, op = self._admit(data, peer)
        if op is None:
            self._audit_received(data, peer, answer)
            return answer
        op.peer = peer
        answer = self._perform(op)
        if answer.get("inflight"):
            op.deferred = True  # audited when its final tally is signed
        else:
            self._audit_received(data, peer, answer)
        return answer

    # ------------------------------------------------------------- audit

    def _audit(self, entry):
        if self.audit is not None:
            self.audit({k: v for k, v in entry.items() if k == "peer" or v not in (None, "")})

    def _audit_received(self, data, peer, answer):
        """Section 9.3 for an answer given as the call arrived."""
        if self.audit is None:
            return
        entry = {"at": self.now(), "kind": "call", "peer": peer}
        try:
            entry["id"] = O.identity(data if isinstance(data, dict) else canon_loads(data))
        except Exception:  # noqa: BLE001, an unreadable object has no identity
            pass
        if "error" in answer:
            entry.update(outcome="rejected", reason=answer["error"])
            self._audit(entry)
            return
        call = O.check_structure(data, "call")  # its signature verified, so from is known
        self._audit_tally(entry, call["from"], call["chain"][0]["iss"], answer["tally"])

    def _audit_tally(self, entry, frm, root, tally):
        entry.update(
            id=tally["call"], **{"from": frm}, root=root, leaf=tally["writ"], op=tally["op"],
            outcome=tally["st"], reason=(tally["err"] or {}).get("code"), tally=O.identity(tally),
        )
        self._audit(entry)

    def _admit(self, data, peer=None):
        """Steps 1 to 10 and the pending record of step 11.

        Returns (answer, None) when the call is answered without performing
        anything, or (None, Operation) when the application must run.
        """
        try:                                                        # step 1
            call = O.check_structure(data, "call")
        except WritError as e:
            return {"error": e.reason}, None
        try:                                                        # step 2
            writs = [O.verify_object(w, "writ") for w in call["chain"]]
            O.check_signature(call, call["from"])
        except WritError as e:
            return {"error": e.reason}, None
        call_id = O.identity(call)
        leaf_id = O.identity(writs[-1])
        now = self.now()
        standing = call["op"].startswith("sys/")
        try:
            ids = C.check_chain(writs)                              # step 3
            if not standing:                                        # step 4
                for w in writs:
                    if now >= w["exp"]:
                        raise WritError("expired", f"a writ expired at {w['exp']}")
            if writs[0]["iss"] not in self.accept:                  # step 5
                raise WritError("root_not_accepted", "root issuer is not accepted")
            if writs[-1]["hld"] != self.did:                        # step 6
                raise WritError("wrong_executor", "this executor is not the leaf hld")
            if not standing:                                        # step 7
                for i, w in zip(ids, writs):
                    if self._is_revoked(i, w["iss"]):
                        raise WritError("revoked", f"writ {i} is revoked")
            if peer is not None and call["from"] not in self.peers.get(peer, ()):  # step 8
                raise WritError("peer_mismatch", "the authenticated peer is not bound to from")
            if standing:
                self._check_standing(call, writs)
            else:
                self._check_forward(call, writs[-1])
        except WritError as e:
            return self._refusal(call_id, leaf_id, call["op"], now, e.reason), None

        rec = self.stores.calls.lookup(leaf_id, call["id"])        # step 9
        if rec is not None:
            if rec["state"] == FINAL:
                return self._stored_answer(rec), None
            return {"tally": self._pending_tally(rec)}, None

        counted = []
        if not standing:                                            # step 10
            for i, w in zip(ids, writs):
                limits = [b["v"] for b in w["bnd"].values() if b["t"] == "count"]
                if not limits:
                    continue
                used = self.stores.counts.used(i)
                if used >= min(limits):
                    return self._refusal(call_id, leaf_id, call["op"], now, "count_exhausted"), None
                counted.append((i, used, w["exp"]))

        rec = {                                                     # step 11
            "state": PENDING, "leaf": leaf_id, "id": call["id"], "call": call_id,
            "op": call["op"], "acc": now, "chain": ids, "iss": [w["iss"] for w in writs],
            "exp": writs[-1]["exp"], "standing": standing, "max": _max_names(writs[-1]),
        }
        if not self._write_admission(rec, counted):
            return self._refusal(call_id, leaf_id, call["op"], now, STORE_WRITE_FAILED), None

        call = dict(call, chain=writs)  # never mutate the caller's object
        kind = "forward" if not standing else call["op"][len("sys/"):]
        op = Operation(kind, call, call_id, leaf_id, now, executor=self)
        return None, op

    def _check_forward(self, call, leaf):
        """Step 8 for a forward call."""
        if call["from"] != leaf["iss"]:
            raise WritError("no_standing", "from is not the leaf iss")
        if not B.prefix_matches(leaf["bnd"]["act"]["v"], call["op"]):
            raise WritError("forbidden_op", "op is not matched by the leaf act")
        V.check_forward_args(leaf, call["args"])

    def _check_standing(self, call, writs):
        """Step 8 for a standing call: standing, then a defined operation.
        The operation's own checks (sections 8.1 and 8.2) run when it is
        performed, after replay (see _operation_checks)."""
        if call["from"] not in {w["iss"] for w in writs}:
            raise WritError("no_standing", "from is not the iss of any writ in the chain")
        if call["op"] not in V.STANDING_OPS:
            raise WritError("forbidden_op", f"{call['op']!r} is not a standing operation")

    def _operation_checks(self, op):
        """Sections 8.1 and 8.2, at step 11: a standing operation's own
        checks. A failure is the operation's outcome, a final tally stored
        like any other, so a retry of the call is answered from the call
        store. For sys/undo, sets op.target and records its identity on the
        call record before any reversal begins."""
        writs = op.call["chain"]
        ids = [O.identity(w) for w in writs]
        target = V.check_standing_args(op.op, op.args, writs, ids, self.now(), op.call["from"])
        if target is None:
            return
        target_id = O.identity(target)
        if not self.stores.tallies.holds(target_id):                # section 8.1, last check
            raise WritError("not_reversible", "the target tally is not in this executor's tally store")
        op.target, op.target_id = target, target_id
        self.stores.calls.record(dict(self._record_of(op), target=target_id))

    def _is_revoked(self, writ_id, writ_iss):
        if self.stores.revokes.revokes_writ(writ_id, writ_iss):
            return True
        for r in self._revoked_mem:
            if r["writ"] == writ_id or (r["writ"] == "*" and r["iss"] == writ_iss):
                return True
        return False

    def _write_admission(self, rec, counted):
        """Persist steps 10 and 11: every count increment, then the pending
        record. On a write failure undo what was written and return False,
        so that a refused call records nothing (section 9). Count entries
        are written first so that a crash between the two writes leaves a
        use consumed, never an operation performed without one."""
        written = []
        try:
            for i, used, exp in counted:
                self.stores.counts.set_used(i, used + 1, exp)
                written.append((i, used, exp))
            self.stores.calls.record(rec)
        except OSError:
            for i, used, exp in written:
                try:
                    if used:
                        self.stores.counts.set_used(i, used, exp)
                    else:
                        self.stores.counts.delete(i)
                except OSError:
                    pass
            return False
        return True

    # ------------------------------------------------------- performing

    def _perform(self, op):
        """Step 11 outside the lock: run the operation, or answer at once."""
        if op.kind in ("tallies", "undo"):
            with self._lock:
                try:
                    self._operation_checks(op)
                except WritError as e:
                    return self._finish(op, Outcome("failed", e.reason), reversal=False)
                except OSError:
                    # Nothing was performed; the pending record resolves.
                    return {"tally": self._pending_tally(self._record_of(op))}
        if op.kind == "tallies":
            with self._lock:
                return self._finish_tallies(op)
        if op.kind == "undo":
            with self._lock:
                state = self.stores.reversals.state(op.target_id)
                if state is not None and state["state"] == DONE:
                    return self._finish(op, Outcome("ok", res=state.get("res")), reversal=False)
                if state is not None and state["state"] == UNKNOWN:
                    return self._finish(op, Outcome("failed", "unknown_outcome"), reversal=False)
                if state is not None and state["state"] == BEGAN:
                    # Section 8.1: reversals of one tally never run at once.
                    # This call waits for the running one (see DIVERGENCES.md).
                    self._waiting.setdefault(op.target_id, []).append(op)
                    return {"inflight": True}
                try:
                    self.stores.reversals.begin(op.target_id, op.call_id)
                except OSError:
                    # Nothing was performed; the pending record resolves.
                    return {"tally": self._pending_tally(self._record_of(op))}
                self._running[op.call_id] = op
        else:
            with self._lock:
                self._running[op.call_id] = op
        return self._invoke(op)

    def _invoke(self, op):
        """Call the application for op and complete it if it returned."""
        unknown = False
        try:
            outcome = self.app(op) if self.app is not None else None
            if outcome is None:
                raise RuntimeError("no application is configured")
            if outcome is not HELD and not isinstance(outcome, Outcome):
                raise TypeError(f"application returned {type(outcome).__name__}, not an Outcome")
        except Exception:  # noqa: BLE001, an application failure has an unknown outcome
            outcome, unknown = Outcome("failed", "unknown_outcome"), True
        with self._lock:
            if op.call_id not in self._running:
                # Already completed through complete(), or lost to a restart
                # that resolved its record: answer from the call store.
                rec = self._record_of(op)
                if rec["state"] == FINAL:
                    return self._stored_answer(rec)
                return {"tally": self._pending_tally(rec)}
            if outcome is HELD:
                return {"inflight": True}
            return self._complete_locked(op, outcome, unknown=unknown)

    def complete(self, call_id, outcome):
        """The operation of call ``call_id`` returned ``outcome``.

        Signs and persists the final tally (step 12) and returns the answer
        the caller would have received. Raises KeyError when no such
        operation is running (after a restart it is lost, and its record has
        been resolved).
        """
        if isinstance(outcome, dict):
            outcome = Outcome.from_json(outcome)
        with self._lock:
            op = self._running.get(call_id)
            if op is None:
                raise KeyError(f"no running operation for call {call_id}")
            answer = self._complete_locked(op, outcome)
        return answer

    def signaled(self, call_id):
        """True when the running operation of call_id was told to stop."""
        op = self._running.get(call_id)
        return op is not None and op.stop_requested()

    def running(self):
        """Identities of calls whose operation is running now."""
        return sorted(self._running)

    def _complete_locked(self, op, outcome, unknown=False):
        self._running.pop(op.call_id, None)
        answer = self._finish(op, outcome, reversal=op.kind == "undo", unknown=unknown)
        if op.kind == "undo":
            self._release_waiters(op.target_id)
        return answer

    def _release_waiters(self, target_id):
        """Run the undos that queued behind a reversal of target_id."""
        queue = self._waiting.pop(target_id, [])
        while queue:
            nxt = queue.pop(0)
            state = self.stores.reversals.state(target_id)
            if state is not None and state["state"] == DONE:
                self._finish(nxt, Outcome("ok", res=state.get("res")), reversal=False)
                continue
            if state is not None and state["state"] == UNKNOWN:
                self._finish(nxt, Outcome("failed", "unknown_outcome"), reversal=False)
                continue
            if queue:
                self._waiting[target_id] = queue
            try:
                self.stores.reversals.begin(target_id, nxt.call_id)
            except OSError:
                return
            self._running[nxt.call_id] = nxt
            # Started from inside the lock; an application that must not
            # block should return HELD and report with complete().
            self._invoke(nxt)
            return

    def _finish(self, op, outcome, reversal, unknown=False):
        """Step 12: sign and persist the final tally, update the reversal
        state when op performed a reversal, return the answer."""
        if reversal:
            try:
                if unknown:
                    self.stores.reversals.put(op.target_id, {"state": UNKNOWN, "call": op.call_id})
                elif outcome.st == "ok":
                    self.stores.reversals.done(op.target_id, op.call_id, outcome.res)
                else:
                    # Only a reversal that succeeded counts (section 8.1).
                    self.stores.reversals.clear(op.target_id)
            except OSError:
                pass  # the began record stays, and resolves to unknown after a restart
        rev = None
        if op.kind == "forward" and outcome.rev is not None:
            rev = {"until": outcome.rev}
        rec = self._record_of(op)
        tally = self._sign_tally(
            op.call_id, op.leaf_id, op.op, op.acc, outcome.st,
            None if outcome.st == "ok" else {"code": outcome.code},
            None if outcome.res is None else O.hash_body(outcome.res),
            _cover_subs(outcome.used, _max_names(op.call["chain"][-1]), rec.get("sub", [])),
            rev, sub=rec.get("sub", []), wrt=rec.get("wrt", []),
        )
        answer = self._persist_final(rec, tally, outcome.res)
        if op.deferred and self.audit is not None:
            entry = {"at": self.now(), "kind": "call", "peer": op.peer}
            self._audit_tally(entry, op.call["from"], op.call["chain"][0]["iss"], answer["tally"])
        return answer

    def _finish_tallies(self, op):
        """Section 8.2: the list is computed before this call's own tally
        is signed, so it never contains it."""
        body = {"tallies": self.stores.tallies.under(op.args["writ"])}
        tally = self._sign_tally(op.call_id, op.leaf_id, op.op, op.acc, "ok", None,
                                 O.hash_body(body), {}, None)
        return self._persist_final(self._record_of(op), tally, body)

    def _record_of(self, op):
        rec = self.stores.calls.lookup(op.leaf_id, op.call["id"])
        if rec is None:
            writs = op.call["chain"]
            rec = {"state": PENDING, "leaf": op.leaf_id, "id": op.call["id"], "call": op.call_id,
                   "op": op.op, "acc": op.acc, "chain": [O.identity(w) for w in writs],
                   "iss": [w["iss"] for w in writs], "exp": writs[-1]["exp"],
                   "standing": op.kind != "forward"}
        return rec

    def _persist_final(self, rec, tally, res):
        """Persist a final tally in the call store, then the tally store.

        If the call store cannot be written the executor must not answer as
        if it had (section 9): it answers pending, which is what the durable
        record resolves to after a restart. A crash between the two writes
        is repaired when the stores are reopened (_recover)."""
        final = dict(rec, state=FINAL, tally=tally)
        if res is not None:
            final["res"] = res
        try:
            self.stores.calls.record(final)
        except OSError:
            return {"tally": self._pending_tally(rec)}
        try:
            self.stores.tallies.add(O.identity(tally), tally, rec["chain"])
        except OSError:
            pass  # re-added from the call store at the next open
        return self._stored_answer(final)

    # ----------------------------------------------------------- tallies

    def _sign_tally(self, call_id, leaf_id, op, acc, st, err, out, used, rev, sub=(), wrt=()):
        body = {
            "v": 1, "typ": "tally", "call": call_id, "writ": leaf_id, "op": op,
            "acc": acc, "st": st, "err": err, "out": out, "used": dict(used),
            "rev": rev, "sub": [t for t in sub], "wrt": [w for w in wrt],
        }
        body["sig"] = self.key.sign(O.signing_input(body))
        return body

    def _refusal(self, call_id, leaf_id, op, now, reason):
        """A failure at steps 3 to 10: signed, returned, recorded nowhere."""
        return {"tally": self._sign_tally(call_id, leaf_id, op, now, "failed", {"code": reason},
                                          None, {}, None)}

    def _pending_tally(self, rec):
        """Section 6: the pending tally for a record, at the record's acc."""
        return self._sign_tally(rec["call"], rec["leaf"], rec["op"], rec["acc"], "pending",
                                {"code": "pending"}, None, {}, None)

    @staticmethod
    def _stored_answer(rec):
        answer = {"tally": rec["tally"]}
        if "res" in rec:
            answer["res"] = rec["res"]
        return answer

    # --------------------------------------------------- delegating onward

    def _issue_child(self, op, holder, bnd, exp, nnc):
        """Section 7.5: narrow the leaf this executor holds. The child is
        persisted in the call's wrt before anyone can see it."""
        if op.kind != "forward":
            raise ValueError("only a forward operation delegates under its chain")
        chain = op.call["chain"]
        child = I.narrow(chain[-1], self.key, holder, exp=exp, bnd=bnd, nnc=nnc)
        C.check_depth(chain + [child])
        with self._lock:
            rec = self._record_of(op)
            if rec["state"] != PENDING:
                raise ValueError("the call is already final")
            self.stores.calls.record(dict(rec, wrt=rec.get("wrt", []) + [child]))
        return child

    def _make_subcall(self, op, child, name, args, call_id):
        child_id = O.identity(child)
        rec = self._record_of(op)
        if child_id not in [O.identity(w) for w in rec.get("wrt", [])]:
            raise ValueError("a sub-call must run under a writ this operation issued")
        call = I.make_call(self.key, op.call["chain"] + [child], name, args, call_id=call_id)
        op._subcalls[O.identity(call)] = call
        return call

    def _receive_subtally(self, op, call, tally, res):
        """Section 7.5: verify, then persist before the application acts.

        A tally that fails section 6.1 (unverifiable) is not added to sub:
        nothing proves who produced it. A later tally for the same sub-call
        replaces an earlier one in place, as a final tally supersedes a
        pending one (section 6). See DIVERGENCES.md."""
        call_id = O.identity(call)
        sub_call = op._subcalls.get(call_id)
        if sub_call is None:
            raise ValueError("not a sub-call this operation made")
        verdict = V.verify_tally(sub_call["chain"][-1], sub_call, tally, res=res)
        if verdict.status == V.UNVERIFIABLE:
            return verdict
        with self._lock:
            rec = self._record_of(op)
            if rec["state"] != PENDING:
                raise ValueError("the call is already final")
            old = rec.get("sub", [])
            if any(t.get("call") == call_id for t in old):
                sub = [tally if t.get("call") == call_id else t for t in old]
            else:
                sub = old + [tally]
            self.stores.calls.record(dict(rec, sub=sub))
        return verdict

    # ----------------------------------------------------------- revokes

    def receive_revoke(self, data, peer=None):
        """Section 9.1: verify, record, and answer with the tallies of every
        forward call under the revoked writ that is not yet final. ``peer``
        is recorded in the audit record only; any key may revoke its own
        writs (section 7.6)."""
        answer = self._receive_revoke(data)
        if self.audit is not None:
            entry = {"at": self.now(), "kind": "revoke", "peer": peer, "outcome": "recorded"}
            try:
                entry["id"] = O.identity(data if isinstance(data, dict) else canon_loads(data))
            except Exception:  # noqa: BLE001, an unreadable object has no identity
                pass
            if "error" in answer:
                entry.update(outcome="rejected", reason=answer["error"])
            if "error" not in answer or answer["error"] == STORE_WRITE_FAILED:
                r = V.verify_revoke(data)  # verified, so its signer is known
                entry.update(**{"from": r["iss"]}, leaf=r["writ"],
                             root=r["chain"][0]["iss"] if r["chain"] else None)
            self._audit(entry)
        return answer

    def _receive_revoke(self, data):
        with self._lock:
            try:
                r = V.verify_revoke(data)
            except WritError as e:
                return {"error": e.reason}
            exp = None if r["writ"] == "*" else r["chain"][-1]["exp"]
            unsaved = False
            try:
                self.stores.revokes.add(r, exp)
            except OSError:
                # Honored in memory either way. A writ's revoke is SHOULD-durable;
                # a key-wide one MUST survive restart, so it is answered as an
                # error and the sender retries (section 9).
                self._revoked_mem.append(r)
                unsaved = r["writ"] == "*"
            hit = []
            for rec in self.stores.calls.pending():
                if rec["standing"]:
                    continue  # a revoke ends forward authority, not standing
                if r["writ"] == "*":
                    under = r["iss"] in rec["iss"]
                else:
                    under = r["writ"] in rec["chain"]
                if under:
                    hit.append(rec)
            hit.sort(key=lambda rec: rec["call"].encode("ascii"))
            tallies = []
            for rec in hit:
                # Every pending forward record here belongs to an operation
                # that is running, so it is answered pending and told to stop.
                op = self._running.get(rec["call"])
                if op is not None:
                    op._signal()
                tallies.append(self._pending_tally(rec))
            holders = self._issued_under(r) if self.forward_revoke is not None else []
        for holder in holders:
            try:
                self.forward_revoke(data, holder)
            except Exception:  # noqa: BLE001, forwarding is a SHOULD and never fails the revoke
                pass
        if unsaved:
            return {"error": STORE_WRITE_FAILED}
        return {"tallies": tallies}

    def _issued_under(self, r):
        """Holders of every writ this executor issued under the revoked writ,
        from forward call records, pending or final, in the order issued."""
        holders = []
        for _, rec in sorted(self.stores.calls.items()):
            if rec["standing"] or not rec.get("wrt"):
                continue
            if r["writ"] == "*":
                under = r["iss"] in rec["iss"]
            else:
                under = r["writ"] in rec["chain"]
            if under:
                for w in rec["wrt"]:
                    if w["hld"] not in holders:
                        holders.append(w["hld"])
        return holders

    # ----------------------------------------------------------- restart

    def restart(self):
        """Lose everything not in a durable store, as in a crash, reopen the
        stores, and resolve pending records (section 9). Returns how many
        pending records were resolved."""
        with self._lock:
            for op in self._running.values():
                op._signal()
            self._running.clear()
            self._waiting.clear()
            self._revoked_mem = []
            self.stores = Stores(self.store_dir)
            return self._recover()

    def _recover(self):
        """Resolve every pending record, after repairing the tally store."""
        calls, tallies = self.stores.calls, self.stores.tallies
        for _, rec in calls.items():
            if rec["state"] == FINAL:
                tid = O.identity(rec["tally"])
                if not tallies.holds(tid):
                    tallies.add(tid, rec["tally"], rec["chain"])
        # A reversal that began and never reported has an unknown outcome.
        self.stores.reversals.mark_unknown()
        n = 0
        for rec in calls.pending():
            outcome = self.resolver(rec) if self.resolver is not None else None
            if outcome is None:
                outcome = Outcome("failed", "unknown_outcome")
            target = rec.get("target")
            if target is not None:
                # Only the call that began the reversal speaks for it; a call
                # queued behind it performed nothing and stays unknown.
                state = self.stores.reversals.state(target)
                if state is not None and state.get("call") == rec["call"]:
                    if outcome.st == "ok":
                        self.stores.reversals.done(target, rec["call"], outcome.res)
                    elif outcome.code != "unknown_outcome":
                        self.stores.reversals.clear(target)
            rev = None
            if not rec["standing"] and outcome.rev is not None:
                rev = {"until": outcome.rev}
            # Section 9.2: wrt and sub complete for everything it did learn,
            # and used covering the sub-tallies (sections 6 and 9).
            tally = self._sign_tally(
                rec["call"], rec["leaf"], rec["op"], rec["acc"], outcome.st,
                None if outcome.st == "ok" else {"code": outcome.code},
                None if outcome.res is None else O.hash_body(outcome.res),
                _cover_subs(outcome.used, rec.get("max", []), rec.get("sub", [])),
                rev, sub=rec.get("sub", []), wrt=rec.get("wrt", []),
            )
            self._persist_final(rec, tally, outcome.res)
            n += 1
        return n
