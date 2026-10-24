"""In-memory log of every request the service has answered, so a judge can later submit the answer key and be scored right away (see scoring.py).

Only the strict schema response and the (truncated) code are kept, in memory; nothing is written to disk.  CODEGUARD_LOG=0 turns the log off.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import deque

MAX_ENTRIES = 50_000
MAX_CODE_CHARS = 30_000
_STRICT = ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")
_lock = threading.Lock()
_log: deque = deque(maxlen=MAX_ENTRIES)
_seq = 0


def enabled() -> bool:
    return os.environ.get("CODEGUARD_LOG", "1") != "0"


def code_hash(code: str) -> str:
    """Hash of the code with trailing whitespace on each line and at the ends removed, so a key that was copied through a form or a PDF still matches."""
    norm = "\n".join(l.rstrip() for l in (code or "").replace("\r\n", "\n").strip().split("\n"))
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:20]


def record(ident, code: str, response: dict, source: str = "api", ms: float = 0.0) -> None:
    global _seq
    if not enabled():
        return
    entry = {"id": None if ident is None else str(ident), "hash": code_hash(code), "code": (code or "")[:MAX_CODE_CHARS], "response": {k: response.get(k) for k in _STRICT},
             "source": source, "ms": round(ms, 2), "t": time.time()}
    with _lock:
        _seq += 1
        entry["seq"] = _seq
        _log.append(entry)


def snapshot() -> list:
    with _lock:
        return list(_log)


def clear() -> int:
    with _lock:
        n = len(_log)
        _log.clear()
        return n


def stats() -> dict:
    with _lock:
        items = list(_log)
    by_source: dict = {}
    for e in items:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1
    return {"enabled": enabled(), "entries": len(items), "with_id": sum(1 for e in items if e["id"] is not None), "by_source": by_source,
            "first_at": items[0]["t"] if items else None, "last_at": items[-1]["t"] if items else None, "capacity": MAX_ENTRIES}
