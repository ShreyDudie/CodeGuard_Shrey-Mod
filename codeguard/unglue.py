"""Recover Python statements from text whose line breaks were lost (copy/paste, PDF or chat extraction).

    import tarfilewith tarfile.open('a') as t:    t.extractall('b')

Lost newlines leave three kinds of traces, and each is a *structural* cue, not a pattern for a specific program:
  * a run of spaces (the old indentation) between statements,
  * a closing bracket, quote or digit directly followed by the next statement,
  * an imported name glued to the next statement (`import tarfilewith`, `import Pathuser_path`); the imported name is
    resolved against the standard library's module names / the module's own top-level definitions (read as text,
    never imported or executed).
The result is only used if it parses as Python; otherwise nothing changes.
"""
from __future__ import annotations

import ast
import importlib.util
import re
import sys
from functools import lru_cache
from typing import Optional

_STMT_KW = ("import", "from", "with", "for", "while", "if", "elif", "else", "try", "except", "finally", "def", "class", "return", "raise", "print",
            "assert", "del", "pass", "break", "continue", "async", "await", "yield", "global", "nonlocal", "lambda")
_GLUE_KW = ("import", "from", "with", "def", "class", "while", "try", "return", "raise", "print", "assert", "for", "if", "else", "pass")
_ID = re.compile(r"[A-Za-z_]\w*")


@lru_cache(maxsize=256)
def _exports(mod: str) -> tuple:
    """Top-level names defined by a module, read from its source text (no import)."""
    try:
        spec = importlib.util.find_spec(mod) if "." not in mod else None
        origin = getattr(spec, "origin", None)
        if not origin or not str(origin).endswith(".py"):
            return ()
        with open(origin, encoding="utf-8", errors="replace") as f:
            txt = f.read(400_000)
    except Exception:
        return ()
    names = set(re.findall(r"^(?:class|def|async def)\s+([A-Za-z_]\w*)", txt, re.M))
    names |= set(re.findall(r"^([A-Za-z_]\w*)\s*(?::[^=\n]+)?=", txt, re.M))
    for m in re.finditer(r"__all__\s*=\s*[\[(]([^\])]*)[\])]", txt, re.S):
        names |= set(re.findall(r"['\"](\w+)['\"]", m.group(1)))
    return tuple(sorted(names, key=len, reverse=True))


@lru_cache(maxsize=1)
def _popular_modules() -> frozenset:
    """Import names of widely used third-party packages (from the typosquat knowledge list) so `import requestssecret` splits right."""
    try:
        from . import knowledge as K
        return frozenset(n.replace("-", "_").lower() for n in K._pop("pypi") if len(n) >= 3)
    except Exception:
        return frozenset({"requests", "numpy", "pandas", "flask", "django", "yaml", "boto3", "urllib3", "paramiko", "psutil", "jwt", "redis"})


def _split_glued_name(word: str, candidates) -> Optional[tuple]:
    """word = known_name + rest  ->  (known_name, rest); longest known name wins."""
    for c in sorted(candidates, key=len, reverse=True):
        if len(c) >= 2 and word.startswith(c) and len(word) > len(c):
            return c, word[len(c):]
    return None


def _scan(text: str):
    """Yield (index, char, in_string, depth) over the text."""
    i, n = 0, len(text)
    depth = 0
    q = None
    while i < n:
        ch = text[i]
        if q:
            if ch == "\\":
                yield i, ch, True, depth
                i += 1
                if i < n:
                    yield i, text[i], True, depth
                    i += 1
                continue
            if text.startswith(q, i):
                for k in range(len(q)):
                    yield i + k, text[i + k], True, depth
                i += len(q)
                q = None
                continue
            yield i, ch, True, depth
            i += 1
            continue
        if ch in "'\"":
            q = ch * 3 if text.startswith(ch * 3, i) else ch
            for k in range(len(q)):
                yield i + k, text[i + k], True, depth
            i += len(q)
            continue
        if ch == "#":
            return
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(depth - 1, 0)
        yield i, ch, False, depth
        i += 1


def _insert_breaks(text: str) -> str:
    """Put a newline at every place where a statement visibly ended."""
    info = {i: (ins, d) for i, _c, ins, d in _scan(text)}
    n = len(text)
    cuts = set()
    i = 0
    while i < n:
        ins, d = info.get(i, (True, 0))
        ch = text[i]
        if not ins and d == 0 and ch == " ":
            j = i
            while j < n and text[j] == " ":
                j += 1
            before = text[:i].rstrip(" ")
            # a run of spaces was the indentation of a line whose newline got lost
            if j - i >= 2 and j < n and before and not before.endswith((",", "(", "[", "{", "\\", ":=")):
                cuts.add(i)
            i = j
            continue
        if i + 1 < n:
            nxt_ins = info.get(i + 1, (True, 0))[0]
            nxt = text[i + 1]
            # a closing bracket directly followed by a name, or a string that ends right before a name
            if not ins and d == 0 and ch in ")]}" and (nxt.isalpha() or nxt == "_"):
                cuts.add(i + 1)
            elif ins and ch in "'\"" and not nxt_ins and (nxt.isalpha() or nxt == "_") and info.get(i + 1, (False, 0))[1] == 0:
                cuts.add(i + 1)
        i += 1
    # `...returncodedef install(name):` - a definition header is a very specific shape (def NAME( ... ) :), so a glued one is safe to split
    for m in re.finditer(r"(?<=[A-Za-z0-9_])(def\s+[A-Za-z_]\w*\s*\()|(?<=[A-Za-z0-9_])(class\s+[A-Z_a-z]\w*\s*[(:])", text):
        pos = m.start()
        if not info.get(pos, (True, 0))[0] and info.get(pos, (True, 0))[1] == 0:
            cuts.add(pos)
    out = []
    last = 0
    for pos in sorted(cuts):
        out.append(text[last:pos].rstrip(" "))
        out.append(chr(10))
        last = pos
    out.append(text[last:])
    return "".join(out)


def _fix_import_glue(text: str) -> str:
    """`import tarfilewith ...` / `from pathlib import Pathuser_path = ...`: separate the glued next statement."""
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | _popular_modules()

    def imp(text: str) -> str:
        for m in re.finditer(r"(\bimport\s+)([A-Za-z_]\w*)", text):
            word = m.group(2)
            if word in stdlib:
                continue
            sp = _split_glued_name(word, stdlib)
            if not sp:
                continue
            rest = sp[1] + text[m.end():]
            if re.match(r"(" + "|".join(_GLUE_KW) + r")\b", rest) or re.match(r"[A-Za-z_]\w*\s*([=.(]|\+=|-=)", rest):
                return text[:m.start(2)] + sp[0] + chr(10) + rest
        return text

    for _ in range(8):
        new_text = imp(text)
        if new_text == text:
            break
        text = new_text

    def frm(m):
        mod, word, tail = m.group(1), m.group(2), m.group(3)
        names = _exports(mod.split(".")[0]) if "." not in mod else ()
        if not names:
            return m.group(0)
        if word in names:
            return m.group(0)
        sp = _split_glued_name(word, names)
        if sp:
            return f"from {mod} import {sp[0]}\n{sp[1]}{tail}"
        return m.group(0)

    text = re.sub(r"\bfrom\s+([\w.]+)\s+import\s+([A-Za-z_]\w*)([^\n]*)", frm, text)
    return text


def unglue(code: str) -> Optional[str]:
    """Return repaired multi-line Python, or None if the text is not recoverable (or already fine)."""
    if "\n" in code.strip() or len(code) < 20 or len(code) > 20000:
        return None
    if not re.search(r"\b(import|def|class|with|while|for|print|open|subprocess|os\.)\b", code):
        return None
    try:
        ast.parse(code)
        return None                                   # already valid one-liner
    except (SyntaxError, ValueError):
        pass
    try:
        t = _fix_import_glue(code)
        t = _insert_breaks(t)
        t = "\n".join(l.rstrip() for l in t.split("\n"))
        # a space run became a newline *and* kept its spaces as indentation (they follow the break)
        for cand in (t, _reindent(t)):
            try:
                ast.parse(cand)
                return cand
            except (SyntaxError, ValueError):
                pass
    except Exception:
        return None
    return None


def _reindent(t: str) -> str:
    try:
        from .pyfe import repair_flat_indent
        return repair_flat_indent(t) or t
    except Exception:
        return t


_GAP1 = re.compile(r"(?<=\S) (?=\S)")
_GAP2 = re.compile(r"(?<=\S)  (?=\S)")


def undouble_spaces(code: str) -> Optional[str]:
    """Text copied from a PDF often has every space doubled ('import  os', and two spaces per indent level).
    Real code always has some single gaps between words; if there are none and many doubles, halve every run of spaces."""
    if len(code) < 20 or len(code) > 200_000:
        return None
    body = "\n".join(l.lstrip(" ") for l in code.split("\n"))
    if _GAP1.search(body) or len(_GAP2.findall(body)) < 3:
        return None
    out = []
    for line in code.split("\n"):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        out.append(" " * (indent // 2) + re.sub(r" {2}", " ", stripped))
    return "\n".join(out)
