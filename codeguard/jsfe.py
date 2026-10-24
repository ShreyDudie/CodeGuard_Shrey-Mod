"""JavaScript / TypeScript front-end: parse to a Python AST (jsparse) and run the shared abstract interpreter."""
from __future__ import annotations

import ast
import re

from . import textscan
from .ctx import Ctx
from .events import EMPTY, HOLE


def _looks_ts(text: str) -> bool:
    return bool(re.search(r"(:\s*(string|number|boolean|any|void|unknown|never)\b|\binterface\s+\w+\s*\{|\bimplements\s+\w+|\benum\s+\w+\s*\{|\btype\s+\w+\s*=|\bas\s+(string|number|any|unknown)\b|<\w+(\[\])?>)", text))


def analyze_js_text(text: str, ctx: Ctx, hole_labels: frozenset = EMPTY, nested: bool = False) -> bool:
    from .jsparse import JSParseError, parse_js
    from . import pyfe
    ts = _looks_ts(text)
    tree = None
    comments: list = []
    for attempt_ts in ([ts, not ts] if ts else [False, True]):
        try:
            tree, comments = parse_js(text, attempt_ts)
            break
        except (JSParseError, RecursionError, IndexError, ValueError, AttributeError, TypeError) as e:
            ctx.notes.append(f"js parse failed (ts={attempt_ts}): {type(e).__name__}: {e}")
            tree = None
    if tree is None:
        for ln, body in textscan.extract_c_comments(text):
            ctx.text(ln, body, "comment", "javascript")
        from . import genericfe
        genericfe.analyze_generic_text(text, ctx, "javascript")
        return False
    for ln, body in comments:
        ctx.text(ln, body, "comment", "javascript")
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 24 and " " in node.value:
            ctx.text(getattr(node, "lineno", 1), node.value, "string", "javascript")
        elif isinstance(node, ast.JoinedStr):
            lit = "".join(p.value for p in node.values if isinstance(p, ast.Constant) and isinstance(p.value, str))
            if len(lit) >= 24 and " " in lit:
                ctx.text(getattr(node, "lineno", 1), lit, "string", "javascript")
    pyfe.analyze_tree(tree, ctx, text, js=True, hole_labels=hole_labels)
    return True
