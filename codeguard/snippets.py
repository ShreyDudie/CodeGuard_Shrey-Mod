"""Tolerant extraction of code snippets from a test file.

Handles, in this order:
  1. valid JSON in any layout: one object, a list, JSON Lines, or several objects concatenated back to back
     ( {"code": "..."} {"code": "..."} {"code": "..."} )
  2. almost-JSON where the code contains raw, unescaped double quotes
     ( {"code": "x = f"SELECT '{a}'""} ) - recovered by splitting on the {"code": markers
  3. anything else: the whole text is a single snippet (e.g. a .py / .sh / .sql / .md file)
"""
from __future__ import annotations

import json
import re

# an object may carry other simple fields before the code ({"id": "x", "code": "..."}) and after it ("language": "python")
_FIELD = r'"[A-Za-z_][\w\-]{0,30}"\s*:\s*(?:"[^"\n]{0,120}"|-?\d+(?:\.\d+)?|true|false|null)'
_START = re.compile(r'\{\s*(?:' + _FIELD + r'\s*,\s*)*"(?:code|snippet|source)"\s*:\s*"')
_TAIL = re.compile(r'"\s*(?:,\s*' + _FIELD + r'\s*)*\}\s*[,\]]*\s*$')
_ID = re.compile(r'"id"\s*:\s*"([^"\n]{0,120})"')
_KEYS = ("code", "snippet", "source", "text", "content", "input")


def _flatten(obj) -> list:
    out = []
    if isinstance(obj, dict):
        for k in _KEYS:
            if k in obj:
                v = obj[k]
                out.append((obj.get("id"), v if isinstance(v, str) else ("" if v is None else json.dumps(v))))
                return out
        for k in ("items", "snippets", "samples", "data", "codes", "batch", "inputs"):
            if isinstance(obj.get(k), list):
                for o in obj[k]:
                    out.extend(_flatten(o))
                return out
    elif isinstance(obj, list):
        for o in obj:
            out.extend(_flatten(o))
    elif isinstance(obj, str):
        out.append((None, obj))
    return out


def _lenient_unescape(body: str) -> str:
    """JSON-style unescape that keeps bare quotes and unknown escapes as they are."""
    out = []
    i = 0
    n = len(body)
    simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            d = body[i + 1]
            if d in simple:
                out.append(simple[d])
                i += 2
                continue
            if d == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", body[i + 2:i + 6] or ""):
                out.append(chr(int(body[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strict(raw: str) -> list | None:
    dec = json.JSONDecoder()
    pos, n = 0, len(raw)
    items: list = []
    while pos < n:
        while pos < n and raw[pos] in " \t\r\n,":
            pos += 1
        if pos >= n:
            break
        try:
            obj, end = dec.raw_decode(raw, pos)
        except ValueError:
            return None
        if not isinstance(obj, (dict, list, str)):
            return None
        items.extend(_flatten(obj))
        pos = end
    return items or None


def _tolerant(raw: str) -> list | None:
    starts = list(_START.finditer(raw))
    if not starts:
        return None
    items = []
    width = max((len(l) for l in raw.split("\n")), default=0)        # wrapped text breaks lines at about this width
    for i, m in enumerate(starts):
        end_limit = starts[i + 1].start() if i + 1 < len(starts) else len(raw)
        seg = raw[m.end():end_limit]
        t = _TAIL.search(seg)
        body = seg[:t.start()] if t else seg.rstrip().rstrip(",").rstrip()
        if not t and body.endswith("}"):
            body = body[:-1].rstrip()
            if body.endswith('"'):
                body = body[:-1]
        if "\\n" in body:
            # the text uses \n escapes for newlines, so any real line break inside it is an artefact of wrapping (PDF / editor)
            body = _rejoin_wrapped(body, width, m.end() - (raw.rfind("\n", 0, m.end()) + 1))
        ident = _ID.search(raw[m.start():m.end()])
        items.append((ident.group(1) if ident else None, _lenient_unescape(body)))
    return items


def _rejoin_wrapped(body: str, width: int, first_extra: int = 0) -> str:
    """Undo hard line wrapping.  A break at a space is turned back into one space; a line that runs all the way to the wrap width (a long token that had no
    space to break at, such as `b64decode(p).dec` + `ode()`) is joined with nothing."""
    rows = re.split(r"[ \t]*\r?\n[ \t]*", body)
    if len(rows) == 1:
        return body
    out = rows[0]
    prev_len = len(rows[0]) + first_extra          # the first line also holds the {"id": ..., "code": " prefix that was cut off
    for r in rows[1:]:
        out += ("" if _break_inside_token(out, r, prev_len, width) else " ") + r
        prev_len = len(r)
    return out


_VOCAB: set = set()


def _vocab() -> set:
    """Identifiers that code is made of: keywords, builtins, methods of the common types and public names of the commonly used standard-library modules."""
    if _VOCAB:
        return _VOCAB
    import builtins
    import importlib
    import keyword
    names = set(keyword.kwlist) | set(dir(builtins))
    for t in (str, bytes, list, dict, set, tuple, int, float):
        names |= set(dir(t))
    for mod in ("os", "os.path", "sys", "subprocess", "base64", "binascii", "shutil", "json", "re", "socket", "threading", "urllib.request", "urllib.parse", "pathlib",
                "sqlite3", "pickle", "zlib", "codecs", "time", "math", "hashlib", "requests", "http.client", "tempfile", "glob", "ctypes", "logging", "random"):
        try:
            names |= {n for n in dir(importlib.import_module(mod)) if not n.startswith("_")}
        except Exception:
            continue
    _VOCAB.update(n for n in names if len(n) >= 3)
    return _VOCAB


_WORDLIKE = {"True", "False", "None", "in", "as", "is", "not", "and", "or", "if", "else", "elif", "for", "while", "with", "def", "class", "return", "import", "from", "try",
             "except", "finally", "lambda", "pass", "raise", "yield", "del", "global", "async", "await", "print"}


def _break_inside_token(out: str, nxt: str, prev_len: int, width: int) -> bool:
    """Was this hard line break in the middle of a token (so the two pieces must be glued), as opposed to at a space?"""
    a = re.search(r"[A-Za-z0-9_]+$", out)
    b = re.match(r"[A-Za-z0-9_]+", nxt)
    if not a or not b:
        return out[-1:] in "._(/-" and nxt[:1].isalnum() and prev_len >= width - 3 and width >= 40
    ta, tb = a.group(0), b.group(0)
    if ta in _WORDLIKE or tb in _WORDLIKE:
        return False                                  # `while` + `True:`  ->  a space
    if (ta + tb) in _vocab() and ta not in _vocab():
        return True                                   # `dec` + `ode`  ->  decode
    if ta.endswith("_") and width >= 40:
        return True
    return width >= 40 and prev_len >= width - 1 and ta not in _vocab() and tb not in _vocab() and len(ta) + len(tb) >= 6 and (ta + tb) not in _WORDLIKE


def _pdf_text(data: bytes) -> str:
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return ""


def _csv_snippets(raw: str) -> list:
    import csv
    import io
    import sys
    csv.field_size_limit(sys.maxsize)
    rows = list(csv.DictReader(io.StringIO(raw)))
    return [(r.get("id"), r.get("code") or r.get("snippet") or "") for r in rows]


def extract_from_bytes(data: bytes, filename: str = "") -> list:
    """Raw uploaded file -> snippets.  Handles PDF (text layer), CSV, JSON / JSON-ish and plain code files."""
    if data[:5] == b"%PDF-" or filename.lower().endswith(".pdf"):
        text = _pdf_text(data)
        if not text.strip():
            return [(None, "")]
        return extract_snippets(text, filename)
    raw = data.decode("utf-8-sig", "replace")
    if filename.lower().endswith(".csv"):
        rows = _csv_snippets(raw)
        if rows:
            return rows
    return extract_snippets(raw, filename)


def extract_snippets(raw: str, filename: str = "") -> list:
    """-> list of (id_or_None, code)"""
    if raw.startswith("﻿"):
        raw = raw[1:]
    head = raw.lstrip()[:1]
    looks_structured = head in ("{", "[", '"')
    if looks_structured:
        strict = _strict(raw)
        if strict:
            return strict
        tol = _tolerant(raw)
        if tol:
            return tol
    return [(None, raw)]
