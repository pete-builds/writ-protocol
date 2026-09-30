"""Section 9.3 audit record: an append-only file, one JSON object per line.

Entries are built by the executor (``Executor(audit=...)``); this module only
stores them. Each line is flushed and synced before ``record`` returns.
"""

import json
import os
import threading


class AuditLog:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._f = open(path, "a", encoding="utf-8")

    def record(self, entry):
        line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            self._f.write(line)
            self._f.flush()
            os.fsync(self._f.fileno())

    def close(self):
        self._f.close()
