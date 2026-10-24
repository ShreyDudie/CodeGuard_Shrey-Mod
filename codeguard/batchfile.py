"""Batch scanning of a file of code snippets.

Accepted input files
  .jsonl / .json / .txt : {"code": "..."} objects - one per line, in a list, or several concatenated back to back; tolerates raw quotes
                          inside the code (extra fields such as id/language/label are ignored)
  .csv             : a header row with a "code" column
  anything else    : the whole file is ONE snippet (e.g. a .py / .sh / .sql / .md file)
  a directory      : every file inside is scanned as one snippet

Output: the fixed schema per snippet plus idx (1-based position) and latency_ms, in input order (JSON Lines by default, or a JSON array).
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
from typing import Iterable, Iterator

from . import pipeline

SCHEMA_KEYS = ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")


def _code_of(obj) -> str:
    if isinstance(obj, dict):
        for k in ("code", "snippet", "source", "text", "content", "input"):
            if k in obj:
                v = obj[k]
                return v if isinstance(v, str) else ("" if v is None else json.dumps(v))
        return ""
    return obj if isinstance(obj, str) else ("" if obj is None else str(obj))


def read_items(path: str) -> list:
    """-> list of (id_or_None, code)"""
    if os.path.isdir(path):
        out = []
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                fp = os.path.join(root, fn)
                with open(fp, "rb") as f:
                    out.append((os.path.relpath(fp, path), f.read().decode("utf-8", "replace")))
        return out
    from .snippets import extract_from_bytes
    with open(path, "rb") as f:
        return extract_from_bytes(f.read(), path)


def scan_items(items: list, keep_id: bool = False, verbose: bool = False) -> Iterator[dict]:
    for n, (ident, code) in enumerate(items, start=1):
        t0 = time.perf_counter()
        res = pipeline.scan(code, verbose=verbose)
        out = {"idx": n, **{k: res[k] for k in SCHEMA_KEYS}, "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2)}
        if verbose:
            out["explanation"] = res.get("explanation")
        if keep_id and ident is not None:
            out = {"id": ident, **out}
        yield out


def run(path: str, out_path: str | None = None, as_array: bool = False, keep_id: bool = False, verbose: bool = False, quiet: bool = False) -> int:
    pipeline.warmup()
    items = read_items(path)
    results = list(scan_items(items, keep_id=keep_id, verbose=verbose))
    if out_path is None:
        base = path.rstrip("\\/") if not os.path.isdir(path) else path.rstrip("\\/") + "_results"
        out_path = os.path.splitext(base)[0] + ("_results.json" if as_array else "_results.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        if as_array:
            json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if not quiet:
        blocked = sum(1 for r in results if r["verdict"] == "block")
        print(f"scanned {len(results)} snippet(s): {blocked} blocked, {len(results) - blocked} allowed", file=sys.stderr)
        print(f"results written to {out_path}", file=sys.stderr)
    return 0
