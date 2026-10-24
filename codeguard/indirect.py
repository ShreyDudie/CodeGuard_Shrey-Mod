"""Indirect access to dangerous callables (structural, no execution).

A dangerous function that is reached any way other than being called by its own name is a way of hiding the call from readers and
simple scanners: kept in a variable, a tuple, a dict or a list, handed to map(), looked up through globals()/sys.modules/importlib/
getattr, or spelled with look-alike Unicode letters.  Intent-neutral code almost never does this.  The idea (looking at how a
callable is *reached*, not only what it is) is shared with public malware-audit tools such as hexora; the implementation is ours.
"""
from __future__ import annotations

import ast

from .astutil import walk_all
import unicodedata

from .ctx import Ctx
from .events import Event

# plain builtins that execute text / load code
_BUILTIN_EXEC = {"eval", "exec", "compile", "execfile", "__import__"}
# module attributes that run commands or processes
_MODULE_EXEC = {
    "os": {"system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe", "spawnv", "spawnve", "spawnvp",
           "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "posix_spawn", "posix_spawnp", "startfile"},
    "subprocess": {"Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"},
    "commands": {"getoutput", "getstatusoutput"},
    "pty": {"spawn"},
    "builtins": _BUILTIN_EXEC,
    "__builtins__": _BUILTIN_EXEC,
    "importlib": {"import_module"},
    "runpy": {"run_path", "run_module"},
}
_ALL_ATTRS = set().union(*_MODULE_EXEC.values())
_NAMESPACE_CALLS = {"globals", "locals", "vars"}


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_namespace_lookup(node) -> bool:
    """globals()[...], vars()[...], sys.modules[...], __builtins__[...], and attribute reads on __builtins__/builtins."""
    if isinstance(node, ast.Subscript):
        v = node.value
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in _NAMESPACE_CALLS:
            return True
        d = _dotted(v)
        return d in ("sys.modules", "__builtins__", "builtins.__dict__", "__builtins__.__dict__")
    return False


def _module_ref(node) -> bool:
    """An expression that evaluates to a module obtained dynamically: import_module(..), __import__(..), sys.modules[..], globals()[..]."""
    if _is_namespace_lookup(node):
        return True
    if isinstance(node, ast.Call):
        d = _dotted(node.func)
        if d in ("importlib.import_module", "import_module", "__import__", "importlib.__import__"):
            return True
    return False


def scan_indirect(tree: ast.AST, ctx: Ctx, source: str = "") -> None:
    defined = {n.name for n in walk_all(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for n in walk_all(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            defined.add(n.id)
        elif isinstance(n, ast.arg):
            defined.add(n.arg)
    parent: dict = {}
    for n in walk_all(tree):
        for ch in ast.iter_child_nodes(n):
            parent[id(ch)] = n
    seen = set()

    def report(line: int, kind: str, what: str) -> None:
        if (line, kind) in seen:
            return
        seen.add((line, kind))
        ctx.emit(Event(cap="INDIRECT_CALL", line=line, name=what, target=what, flags={"indirect_" + kind}, lines={line}))

    for n in walk_all(tree):
        par = parent.get(id(n))
        called = isinstance(par, ast.Call) and par.func is n
        if isinstance(par, (ast.ClassDef, ast.arguments, ast.Compare)):
            continue                          # base class, default argument, identity test: not a hidden call
        # 1. a dangerous callable used as a plain value (alias, container member, callback)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in _BUILTIN_EXEC and n.id not in defined and not called:
            if not (isinstance(par, ast.Attribute)):
                report(n.lineno, "value", n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and not called:
            base = n.value
            if isinstance(base, ast.Name) and base.id in _MODULE_EXEC and n.attr in _MODULE_EXEC[base.id] and not isinstance(par, ast.Attribute):
                if not (isinstance(par, ast.Call) and n in par.args and False):
                    report(n.lineno, "value", f"{base.id}.{n.attr}")
        # 2. called through a namespace / module looked up at run time
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr in _ALL_ATTRS and _module_ref(f.value):
                report(n.lineno, "lookup", f.attr)
            elif _is_namespace_lookup(f):
                report(n.lineno, "lookup", "namespace lookup")
            elif isinstance(f, ast.Attribute) and f.attr in _BUILTIN_EXEC and isinstance(f.value, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                d = _dotted(f.value)
                if d in ("builtins", "__builtins__") or _is_namespace_lookup(f.value):
                    report(n.lineno, "lookup", f.attr)
            elif isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr" and f.args:
                # getattr(<module-ish>, <name>)(...): the called function is chosen at run time
                target = f.args[0]
                tname = _dotted(target)
                if _module_ref(target) or tname in _MODULE_EXEC or tname in ("sys.modules", "__builtins__", "builtins"):
                    report(n.lineno, "getattr", "getattr")
            elif isinstance(f, (ast.Subscript, ast.Call)) and not _is_namespace_lookup(f):
                # dispatch["run"](...) / [os.system][0](...) where the container holds a dangerous callable
                for sub in ast.walk(f):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id in _MODULE_EXEC and sub.attr in _MODULE_EXEC[sub.value.id]:
                        report(n.lineno, "value", f"{sub.value.id}.{sub.attr}")
                        break
    # 3. look-alike Unicode spelling of a dangerous builtin
    for n in walk_all(tree):
        nm = getattr(n, "id", None) if isinstance(n, ast.Name) else None
        if nm and not nm.isascii():
            norm = unicodedata.normalize("NFKC", nm)
            if norm in _BUILTIN_EXEC or norm in _ALL_ATTRS:
                report(n.lineno, "unicode", norm)
    if source and not source.isascii():
        for i, line in enumerate(source.split("\n"), 1):
            if line.isascii():
                continue
            for tok in _non_ascii_words(line):
                norm = unicodedata.normalize("NFKC", tok)
                if norm != tok and (norm in _BUILTIN_EXEC or norm in _ALL_ATTRS):
                    report(i, "unicode", norm)


def _non_ascii_words(line: str) -> list:
    out, cur = [], []
    for ch in line:
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        else:
            if cur:
                w = "".join(cur)
                if not w.isascii():
                    out.append(w)
            cur = []
    if cur:
        w = "".join(cur)
        if not w.isascii():
            out.append(w)
    return out
