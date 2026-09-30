"""Durable executor state (section 9), one directory of files per store.

Section 9 names four stores an executor holds. Each is a FileStore here: a
directory with one JSON file per record, named by the SHA-256 of the
record's key so that no key, however long or however it is cased, becomes
an unsafe or colliding file name (base64url keys differ only by case on a
case-insensitive file system). Every write goes to a temporary file that is
flushed and fsynced, then renamed over the record, so a crash leaves either
the old record or the new one and never a torn one.

| Store | Key | Holds |
|---|---|---|
| CallStore | (leaf writ identity, call id) | pending record or final tally and body |
| CountStore | writ identity | uses consumed, and the writ's exp |
| TallyStore | tally identity | every final tally, indexed by each writ in its chain |
| RevokeStore | writ identity, or "*" plus a key | recorded revokes |
| ReversalStore | target tally identity | the sys/undo reversal state (section 8.1) |

ReversalStore is not in the section 9 table. Section 8.1 requires the
executor to "durably record that a reversal of the tally has begun" and to
answer later undos with the successful reversal's body, so the state has
to live somewhere durable; see DIVERGENCES.md.

Stores hold data only. Every rule about when to read or write them lives in
executor.py.
"""

import hashlib
import json
import os
import tempfile

from .canon import canonicalize


def _utf8(s):
    return s.encode("utf-8", "surrogatepass")


class FileStore:
    """A durable map from string keys to JSON values, one file per key."""

    SUFFIX = ".json"

    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _file(self, key):
        return os.path.join(self.path, hashlib.sha256(_utf8(key)).hexdigest() + self.SUFFIX)

    def get(self, key):
        """The value stored under key, or None."""
        try:
            with open(self._file(key), "rb") as f:
                rec = json.loads(f.read().decode("utf-8"))
        except FileNotFoundError:
            return None
        return rec["value"] if rec.get("key") == key else None

    def put(self, key, value):
        """Store value under key durably. Raises OSError when it cannot."""
        data = canonicalize({"key": key, "value": value})
        fd, tmp = tempfile.mkstemp(dir=self.path, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._file(key))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._sync_dir()

    def delete(self, key):
        try:
            os.unlink(self._file(key))
        except FileNotFoundError:
            return
        self._sync_dir()

    def items(self):
        """Every (key, value) pair, in no particular order."""
        out = []
        for name in os.listdir(self.path):
            if not name.endswith(self.SUFFIX) or name.startswith("."):
                continue
            try:
                with open(os.path.join(self.path, name), "rb") as f:
                    rec = json.loads(f.read().decode("utf-8"))
            except FileNotFoundError:
                continue
            out.append((rec["key"], rec["value"]))
        return out

    def __len__(self):
        return sum(1 for n in os.listdir(self.path) if n.endswith(self.SUFFIX) and not n.startswith("."))

    def _sync_dir(self):
        # Make the rename itself durable. Some file systems refuse fsync on
        # a directory; the rename has then already reached the kernel.
        try:
            fd = os.open(self.path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)


# ------------------------------------------------------------ call store

PENDING = "pending"
FINAL = "final"


class CallStore(FileStore):
    """Section 9 call store: (leaf writ identity, call id) to a record.

    A record is a dict with ``state`` pending or final, and the facts the
    executor needs to answer a replay, resolve the record after a restart,
    or list it in a revoke's answer without the call in hand: ``leaf``,
    ``id``, ``call`` (the call's identity), ``op``, ``acc``, ``chain`` (the
    writ identities, root first), ``iss`` (their issuers), ``exp`` (the
    leaf's exp), ``standing``, and for a sys/undo ``target`` (the identity
    of the tally being reversed). A final record adds ``tally`` and, when
    there is one, ``res``.
    """

    @staticmethod
    def key(leaf_id, call_id):
        return leaf_id + " " + call_id

    def lookup(self, leaf_id, call_id):
        return self.get(self.key(leaf_id, call_id))

    def record(self, rec):
        self.put(self.key(rec["leaf"], rec["id"]), rec)

    def remove(self, leaf_id, call_id):
        self.delete(self.key(leaf_id, call_id))

    def pending(self):
        return [rec for _, rec in self.items() if rec["state"] == PENDING]

    def prune(self, now):
        """Drop final forward records whose leaf has expired (section 9:
        "forward call: until leaf exp"). A retry after exp is refused at
        section 7 step 4 before the call store is read, so nothing is lost.
        Standing records are kept, as the tally store keeps their tallies.
        """
        n = 0
        for key, rec in self.items():
            if rec["state"] == FINAL and not rec["standing"] and now >= rec["exp"]:
                self.delete(key)
                n += 1
        return n


# ----------------------------------------------------------- count store

class CountStore(FileStore):
    """Section 9 count store: writ identity to the uses consumed."""

    def used(self, writ_id):
        rec = self.get(writ_id)
        return 0 if rec is None else rec["n"]

    def set_used(self, writ_id, n, exp):
        self.put(writ_id, {"n": n, "exp": exp})

    def prune(self, now):
        """Drop entries whose writ has expired: a forward call under it is
        refused at section 7 step 4, before count."""
        n = 0
        for key, rec in self.items():
            if now >= rec["exp"]:
                self.delete(key)
                n += 1
        return n


# ----------------------------------------------------------- tally store

def tally_order(identity, tally):
    """Section 8.2 order: ascending acc, ties by tally identity compared as
    byte strings (the bytes of the base64url identity; see DIVERGENCES.md)."""
    return (tally["acc"], _utf8(identity))


class TallyStore(FileStore):
    """Section 9 tally store: tally identity to the tally, indexed by every
    writ identity in the chain of the call it answers.

    The index is rebuilt from the files when the store is opened and kept
    in memory after that; the files are the durable truth.
    """

    def __init__(self, path):
        super().__init__(path)
        self._index = {}
        self._ids = set()
        for tid, rec in self.items():
            self._add_index(tid, rec["chain"])

    def _add_index(self, tid, chain):
        self._ids.add(tid)
        for w in chain:
            self._index.setdefault(w, set()).add(tid)

    def add(self, tally_id, tally, chain, iss=None):
        """``iss`` is the issuer of each writ in ``chain``, so an ack of a
        key-wide revoke can list the tallies under that key (section 9.4)."""
        rec = {"tally": tally, "chain": list(chain)}
        if iss is not None:
            rec["iss"] = list(iss)
        self.put(tally_id, rec)
        self._add_index(tally_id, chain)

    def held_under(self, writ_id, key=None):
        """Section 9.4 held: {tally identity: call identity} for every tally
        under writ_id or, when writ_id is "*", under a writ ``key`` issued.
        A record written before issuers were kept is listed under every
        key-wide revoke: an extra entry accounts only for a tally that
        exists, so it can hide nothing."""
        if writ_id != "*":
            return {tid: self.tally(tid)["call"] for tid in self._index.get(writ_id, ())
                    if self.tally(tid) is not None}
        held = {}
        for tid, rec in self.items():
            if "iss" not in rec or key in rec["iss"]:
                held[tid] = rec["tally"]["call"]
        return held

    def holds(self, tally_id):
        return tally_id in self._ids

    def tally(self, tally_id):
        rec = self.get(tally_id)
        return None if rec is None else rec["tally"]

    def under(self, writ_id):
        """Every tally indexed under writ_id, in section 8.2 order."""
        found = []
        for tid in self._index.get(writ_id, ()):
            t = self.tally(tid)
            if t is not None:
                found.append((tally_order(tid, t), t))
        found.sort(key=lambda p: p[0])
        return [t for _, t in found]


# ---------------------------------------------------------- revoke store

class RevokeStore(FileStore):
    """Section 9 revoke store.

    A revoke of one writ is keyed by that writ's identity and kept until
    the writ's exp. A key-wide revoke is keyed by "*" and the revoking key;
    it has no writ and so no exp, and is kept for good (see DIVERGENCES.md).
    """

    @staticmethod
    def _key_wide(iss):
        return "* " + iss

    def add(self, revoke, exp=None):
        if revoke["writ"] == "*":
            self.put(self._key_wide(revoke["iss"]), {"revoke": revoke, "exp": None})
        else:
            self.put(revoke["writ"], {"revoke": revoke, "exp": exp})

    def revokes_writ(self, writ_id, writ_iss):
        """True when writ_id is revoked by identity or its issuer key-wide."""
        return self.get(writ_id) is not None or self.get(self._key_wide(writ_iss)) is not None

    def prune(self, now):
        n = 0
        for key, rec in self.items():
            if rec["exp"] is not None and now >= rec["exp"]:
                self.delete(key)
                n += 1
        return n


# -------------------------------------------------------- reversal store

BEGAN = "began"
DONE = "done"
UNKNOWN = "unknown"


class ReversalStore(FileStore):
    """Section 8.1 reversal state, keyed by the identity of the target tally.

    ``began``: a reversal is running (written before it is performed).
    ``done``: one succeeded; ``res`` holds its result body when it had one.
    ``unknown``: a reversal began and never reported before a restart.
    No record: nothing has been reversed, or every attempt failed.
    """

    def state(self, tally_id):
        return self.get(tally_id)

    def begin(self, tally_id, call_id):
        self.put(tally_id, {"state": BEGAN, "call": call_id})

    def done(self, tally_id, call_id, res=None):
        rec = {"state": DONE, "call": call_id}
        if res is not None:
            rec["res"] = res
        self.put(tally_id, rec)

    def clear(self, tally_id):
        self.delete(tally_id)

    def mark_unknown(self):
        """After a restart: every reversal that began and never reported has
        an unknown outcome. Returns how many were marked."""
        n = 0
        for key, rec in self.items():
            if rec["state"] == BEGAN:
                self.put(key, {"state": UNKNOWN, "call": rec["call"]})
                n += 1
        return n


# ------------------------------------------------------------- the bundle

class Stores:
    """Every store an executor holds, under one directory."""

    def __init__(self, path):
        self.path = path
        self.calls = CallStore(os.path.join(path, "calls"))
        self.counts = CountStore(os.path.join(path, "counts"))
        self.tallies = TallyStore(os.path.join(path, "tallies"))
        self.revokes = RevokeStore(os.path.join(path, "revokes"))
        self.reversals = ReversalStore(os.path.join(path, "reversals"))

    def prune(self, now):
        """Apply the section 9 lifetimes. Returns how many records went."""
        return self.calls.prune(now) + self.counts.prune(now) + self.revokes.prune(now)
