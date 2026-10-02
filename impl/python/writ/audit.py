"""Section 9.3 audit record: an append-only file, one JSON object per line.

Entries are built by the executor (``Executor(audit=...)``); this module only
stores them. Each line is flushed and synced before ``record`` returns, and
carries ``prev``, the hash of the line before it as its bytes stand in the
file (null for the first), so editing, removing, or reordering an entry
breaks every later link. ``writ audit`` in the Go command-line tool walks the
links. Several processes may share one record: ``record`` holds an exclusive
``flock`` on the file from reading the last line to syncing its own, where
the platform has one.
"""

import base64
import hashlib
import json
import os
import threading

try:
    import fcntl
except ImportError:  # no flock here: one process per record
    fcntl = None


def line_hash(line):
    """The section 1 hash of one line of the record, without its newline."""
    return base64.urlsafe_b64encode(hashlib.sha256(line).digest()).rstrip(b"=").decode("ascii")


def _last_line(f):
    """The file's last line without its newline (None when empty), and
    whether a crash left that line without one."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return None, False
    chunk = 4096
    while True:
        chunk = min(chunk, size)
        f.seek(size - chunk)
        buf = f.read(chunk)
        torn = not buf.endswith(b"\n")
        body = buf if torn else buf[:-1]
        i = body.rfind(b"\n")
        if i >= 0:
            return body[i + 1:], torn
        if chunk == size:
            return body, torn
        chunk *= 2


class AuditLog:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._f = open(path, "a+b")

    def record(self, entry):
        with self._lock:
            if fcntl:
                fcntl.flock(self._f.fileno(), fcntl.LOCK_EX)
            try:
                last, torn = _last_line(self._f)
                entry = dict(entry, prev=None if last is None else line_hash(last))
                line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
                if torn:
                    # A crash cut the last line short. It stays, as an entry
                    # whose bytes this one links to, and is ended here.
                    line = b"\n" + line
                self._f.write(line)
                self._f.flush()
                os.fsync(self._f.fileno())
            finally:
                if fcntl:
                    fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)

    def close(self):
        self._f.close()
