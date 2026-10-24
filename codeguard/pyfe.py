"""Python front-end: an abstract interpreter over the `ast`.

It tracks constants (as string skeletons with holes), provenance labels (taint), qualified names (through
aliases and dynamic imports) and call graphs across helper functions.  Library calls are not executed: they
are routed to semantic stubs (pylib.py) that emit behaviour events.  Nothing here ever touches the real OS.
"""
from __future__ import annotations

import ast
import re
import textwrap
from typing import Any, Optional

from . import knowledge as K
from .ctx import Ctx, Stop
from .events import (TRAVERSAL, ARBITRARY_FILE, BUILT, COMPILED, DB, DECODED, DYNCODE, EMPTY, ENV, ENV_DUMP, FILE, HOLE, NET, QUOTED, SAFE_NUM, SECRET, SENS_SYS,
                     UNK, USER, VALIDATED, Event, V, U, join_values, mk)
from .pylib import LibMixin, DANGEROUS_ALIAS_MODULES, CONVENTIONAL_ALIASES
from .jslib import JSLibMixin, JS_SPECIAL, JS_GLOBALS

HANDLE_NAMES = {"res", "reply", "next", "done", "cb", "callback", "ws", "stream", "conn", "connection", "con", "cursor", "cur", "db", "database", "session", "client", "logger", "log", "app", "ctx", "context",
                "engine", "pool", "executor", "loop", "sock", "socket", "lock", "queue", "q", "parser", "args_parser", "response", "resp", "req_obj"}
SAFE_TYPES = {"int", "float", "bool", "complex", "Decimal", "UUID", "datetime", "date"}
TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)
KNOWN_ENV_VALUES = {"HOME": "~", "USERPROFILE": "~", "HOMEPATH": "~", "TMPDIR": "/tmp", "TEMP": "/tmp", "TMP": "/tmp", "PWD": ".", "SHELL": "/bin/bash"}



_SRC_VERBS = frozenset({"fetch", "download", "recv", "receive", "scrape"})
_SRC_GENERIC = frozenset({"get", "read", "load", "pull", "query", "retrieve", "poll"})
_SRC_NOUNS = frozenset({"db", "database", "network", "remote", "url", "http", "https", "socket", "api", "server", "web", "cloud", "upload", "stdin", "request",
                        "external", "untrusted", "form", "queue", "message", "internet", "client", "user"})


def _remote_source_name(name: str) -> bool:
    """Identifier -> capability: does a helper's name say it returns data from outside the program?  (fetch_*, get_*_from_db, read_remote_*, ...)"""
    toks = [t for t in re.split(r"[_\W]+|(?<=[a-z])(?=[A-Z])", name) if t]
    low = {t.lower() for t in toks}
    if low & _SRC_VERBS:
        return True
    return bool(low & _SRC_GENERIC) and bool(low & _SRC_NOUNS)


_IMPLICIT_MODULES = frozenset({"os", "sys", "subprocess", "socket", "shutil", "pickle", "base64", "urllib", "ctypes", "glob", "pathlib", "tempfile", "threading", "multiprocessing", "importlib", "marshal", "zlib", "codecs", "binascii"})


class Env:
    __slots__ = ("vars", "parent")

    def __init__(self, parent: "Optional[Env]" = None):
        self.vars: dict = {}
        self.parent = parent

    def get(self, name: str):
        e = self
        while e is not None:
            if name in e.vars:
                return e.vars[name]
            e = e.parent
        return None

    def set(self, name: str, v: V) -> None:
        self.vars[name] = v

    def fork(self) -> "Env":
        n = Env(self.parent)
        n.vars = dict(self.vars)
        return n


class FuncInfo:
    __slots__ = ("node", "name", "cls", "env", "kind", "qual", "is_lambda")

    def __init__(self, node, name, cls, env, kind="function", is_lambda=False):
        self.node = node
        self.name = name
        self.cls = cls
        self.env = env
        self.kind = kind          # function | property | staticmethod | classmethod
        self.qual = f"{cls}.{name}" if cls else name
        self.is_lambda = is_lambda


class ClassInfo:
    __slots__ = ("node", "name", "env", "methods", "bases", "attrs")

    def __init__(self, node, name, env):
        self.node = node
        self.name = name
        self.env = env
        self.methods: dict = {}
        self.bases: list = []
        self.attrs: dict = {}


class Flow:
    NONE = None
    RET = "ret"
    BRK = "brk"
    CNT = "cnt"
    RAISE = "raise"


def _terminates(stmts: list) -> bool:
    for s in stmts:
        if isinstance(s, TERMINATORS):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
            f = s.value.func
            nm = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            if nm in ("exit", "_exit", "abort", "quit"):
                return True
        if isinstance(s, ast.If) and s.orelse and _terminates(s.body) and _terminates(s.orelse):
            return True
    return False


def _names_in(node) -> list:
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


_VALIDATOR_FN = re.compile(r"(valid|check|allow|safe|sanit|verify|whitelist|allowlist|permitted|is_trusted|trusted)", re.I)


def _looks_like_validation(test) -> bool:
    for n in ast.walk(test):
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
            return True
        if isinstance(n, ast.Call):
            f = n.func
            nm = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            if nm in ("startswith", "endswith", "isalnum", "isdigit", "isalpha", "fullmatch", "match", "isidentifier", "isnumeric", "is_relative_to", "commonpath", "samefile"):
                return True
            if _VALIDATOR_FN.search(nm or ""):
                return True
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
            if any(isinstance(c, ast.Constant) for c in n.comparators + [n.left]):
                return True
    return False


class Interp(LibMixin, JSLibMixin):
    SPECIAL = {**LibMixin.SPECIAL, **JS_SPECIAL}

    def __init__(self, tree: ast.AST, ctx: Ctx, hole_labels: frozenset = EMPTY, hole_src: frozenset = EMPTY, source: str = "", js: bool = False):
        self.tree = tree
        self.origins: dict = {}
        self.alias_lines: set = set()
        self.cred_vars: set = set()
        self.ctx = ctx
        self.source = source
        self.hole_labels = hole_labels
        self.hole_src = hole_src
        self.genv = Env()
        self.funcs: dict = {}          # name / Class.name -> FuncInfo
        self.classes: dict = {}
        self.called: set = set()       # function quals executed at least once
        self.pending_lambdas: list = []
        self.ran_lambdas: set = set()
        self.referenced: set = set()   # names referenced anywhere (call-graph for entry detection)
        self.stack: list = []          # function call stack (quals)
        self.mult = 1
        self.loops: list = []          # active loop descriptors
        self.ret_stack: list = []
        self.depth = 0
        self.thread_ctx = 0
        self.symbolic_entry = False
        self.unconditional_rec: set = set()
        self.gen_marks: set = set()
        self.js = js
        self.cb_done: set = set()
        self.try_exit = 0

    # ------------------------------------------------------------------------ top level
    NAME_HINTS = [
        (re.compile(r"exfil|steal|stealer|siphon|harvest|keylog|\bspy", re.I), "data_exfiltration"),
        (re.compile(r"wipe|wiper|destroy|ransom|encrypt_all|nuke|erase_all|format_disk|shred_all", re.I), "destructive_command"),
        (re.compile(r"fork_?bomb|cpu_?burn|memory_?hog|exhaust|dos_attack|flood", re.I), "resource_exhaustion"),
        (re.compile(r"backdoor|persist|autorun|install_startup|add_startup", re.I), "persistence_or_privesc"),
        (re.compile(r"obfuscat|packer|stager|decode_and_run|run_payload", re.I), "obfuscated_execution"),
        (re.compile(r"dump_cred|steal_cred|grab_pass|harvest_cred|dump_secret", re.I), "secret_access"),
        (re.compile(r"reverse_?shell|bind_?shell|port_?scan|portscan", re.I), "ssrf_network_exfil"),
        (re.compile(r"typosquat|malicious_package", re.I), "dependency_risk"),
    ]

    def emit_name_hints(self) -> None:
        seen = set()
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for rx, cat in self.NAME_HINTS:
                    if rx.search(node.name) and (node.name, cat) not in seen:
                        seen.add((node.name, cat))
                        self.emit("NAME_HINT", node.lineno, "name", target=node.name, extra={"hint_cat": cat})

    def run(self) -> None:
        tree = self.tree
        try:
            self.emit_name_hints()
        except Exception:
            pass
        self._collect_references(tree)
        self.install_builtins()
        try:
            self.exec_block(tree.body, self.genv)
        except Stop:
            raise
        except RecursionError:
            self.ctx.notes.append("recursion limit (module)")
        self.run_entry_points()

    def _collect_references(self, tree) -> None:
        """Static call-graph approximation: any name/attribute mentioned outside its own def counts as a reference."""
        defs: dict = {}

        class V1(ast.NodeVisitor):
            def __init__(s):
                s.cur = None

            def visit_FunctionDef(s, n):
                prev = s.cur
                s.cur = n.name
                for d in n.decorator_list:
                    s.visit(d)
                for a in n.args.defaults + n.args.kw_defaults:
                    if a is not None:
                        s.visit(a)
                for st in n.body:
                    s.visit(st)
                s.cur = prev

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Name(s, n):
                if isinstance(n.ctx, ast.Load) and n.id != s.cur:
                    self.referenced.add(n.id)

            def visit_Attribute(s, n):
                if isinstance(n.ctx, ast.Load) and n.attr != s.cur:
                    self.referenced.add(n.attr)
                s.generic_visit(n)
        V1().visit(tree)

    # ------------------------------------------------------------------------ defining things
    def predefine(self, body: list, env: Env, cls: Optional[ClassInfo] = None) -> None:
        pass

    def define_function(self, node, env: Env, cls: Optional[str] = None) -> FuncInfo:
        kind = "function"
        for d in node.decorator_list:
            dn = d.id if isinstance(d, ast.Name) else (d.attr if isinstance(d, ast.Attribute) else "")
            if dn in ("property", "cached_property"):
                kind = "property"
            elif dn == "staticmethod":
                kind = "staticmethod"
            elif dn == "classmethod":
                kind = "classmethod"
        fi = FuncInfo(node, node.name, cls, env, kind)
        self.funcs[fi.qual] = fi
        if node.name not in self.funcs or cls is None:
            self.funcs.setdefault(node.name, fi)
        if _unconditional_recursion(node):
            self.unconditional_rec.add(fi.qual)
        return fi

    # ------------------------------------------------------------------------ statements
    def exec_block(self, stmts: list, env: Env) -> Optional[str]:
        for st in stmts:
            self.ctx.tick()
            r = self.exec_stmt(st, env)
            if r is not None:
                return r
        return None

    def exec_stmt(self, st, env: Env) -> Optional[str]:
        m = getattr(self, "s_" + type(st).__name__, None)
        if m is None:
            # unknown statement: evaluate any expressions inside for side effects
            return None
        return m(st, env)

    def s_Expr(self, st, env):
        self.ev(st.value, env)

    def s_Pass(self, st, env):
        return None

    def s_Import(self, st, env):
        for a in st.names:
            name = a.name
            if a.asname:
                v = V(q=name, kind="module", lines=frozenset({st.lineno}))
                if name.split(".")[0] in DANGEROUS_ALIAS_MODULES and a.asname not in CONVENTIONAL_ALIASES and a.asname != name.split(".")[-1]:
                    v.alias = a.asname
                    self.alias_lines.add(st.lineno)
                env.set(a.asname, v)
            else:
                top = name.split(".")[0]
                env.set(top, V(q=top, kind="module", lines=frozenset({st.lineno})))

    def s_ImportFrom(self, st, env):
        mod = ("." * (st.level or 0)) + (st.module or "")
        for a in st.names:
            if a.name == "*":
                continue
            q = f"{mod}.{a.name}" if mod and not mod.startswith(".") else a.name
            v = self.v_for_q(q, [st.lineno])
            nm = a.asname or a.name
            if a.asname and mod.split(".")[0] in DANGEROUS_ALIAS_MODULES and a.asname != a.name and a.asname not in CONVENTIONAL_ALIASES:
                v.alias = a.asname
                self.alias_lines.add(st.lineno)
            env.set(nm, v)

    def s_FunctionDef(self, st, env):
        fi = self.define_function(st, env, None)
        env.set(st.name, V(kind="func", fn=fi, lines=frozenset({st.lineno})))

    s_AsyncFunctionDef = s_FunctionDef

    def s_ClassDef(self, st, env):
        ci = ClassInfo(st, st.name, env)
        for b in st.bases:
            if isinstance(b, ast.Name):
                ci.bases.append(b.id)
            elif isinstance(b, ast.Attribute):
                ci.bases.append(self.dotted(b) or b.attr)
        self.classes[st.name] = ci
        cenv = Env(env)
        for s2 in st.body:
            if isinstance(s2, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fi = self.define_function(s2, env, st.name)
                ci.methods[s2.name] = fi
            elif isinstance(s2, (ast.Assign, ast.AnnAssign)):
                try:
                    self.exec_stmt(s2, cenv)
                except Stop:
                    raise
                except Exception:
                    pass
        ci.attrs = {k: v for k, v in cenv.vars.items()}
        env.set(st.name, V(kind="class", fn=ci, cls=st.name, lines=frozenset({st.lineno})))

    def dotted(self, node) -> Optional[str]:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    def s_Assign(self, st, env):
        v = self.ev(st.value, env)
        for t in st.targets:
            self.assign(t, v, env, st.value)
            if isinstance(t, ast.Name):       # remember what a value was derived from, so checking the parsed form checks the original
                self.origins[t.id] = set(_names_in(st.value))

    def s_AnnAssign(self, st, env):
        if st.value is not None:
            v = self.ev(st.value, env)
            self.assign(st.target, v, env, st.value)

    def s_AugAssign(self, st, env):
        cur = self.ev_target_load(st.target, env)
        rhs = self.ev(st.value, env)
        res = self.binop(st.op, cur, rhs, st)
        self.assign(st.target, res, env, st.value)
        # accumulation inside loops (memory growth)
        if self.loops and isinstance(st.op, (ast.Add, ast.Mult, ast.LShift)):
            self.loops[-1]["growth"] = True

    def ev_target_load(self, t, env) -> V:
        if isinstance(t, ast.Name):
            v = env.get(t.id)
            return v if v is not None else V()
        if isinstance(t, (ast.Attribute, ast.Subscript)):
            return self.ev(t, env)
        return V()

    def assign(self, t, v: V, env: Env, value_node=None) -> None:
        if isinstance(t, ast.Name):
            env.set(t.id, v)
            return
        if isinstance(t, (ast.Tuple, ast.List)):
            elems = t.elts
            items = v.items if isinstance(v.items, list) else None
            if items is not None and len(items) == len(elems) and not any(isinstance(e, ast.Starred) for e in elems):
                for e, x in zip(elems, items):
                    self.assign(e, x, env)
            else:
                for e in elems:
                    tgt = e.value if isinstance(e, ast.Starred) else e
                    self.assign(tgt, V(c=UNK, labels=v.all_labels(), src=v.all_src(), lines=v.lines), env)
            return
        if isinstance(t, ast.Attribute):
            base = self.ev(t.value, env)
            if base.attrs is not None:
                base.attrs[t.attr] = v
            base.labels = U(base.labels, v.all_labels()) if v.all_labels() else base.labels
            return
        if isinstance(t, ast.Subscript):
            base = self.ev(t.value, env)
            key = self.ev(t.slice, env) if not isinstance(t.slice, ast.Slice) else V()
            if base.q == "os.environ":
                return
            if isinstance(base.items, dict) and key.c is not UNK and not isinstance(key.c, (list, dict)):
                base.items[key.c if not isinstance(key.c, str) or HOLE not in key.c else HOLE] = v
            elif isinstance(base.items, list):
                base.items.append(v)
                base.n = None
            elif base.items is None and base.kind in ("dict", "list"):
                base.items = {} if base.kind == "dict" else []
            base.labels = U(base.labels, v.all_labels())
            base.src = U(base.src, v.all_src())
            return
        if isinstance(t, ast.Starred):
            self.assign(t.value, v, env)

    def s_Return(self, st, env):
        v = self.ev(st.value, env) if st.value is not None else V(c=None)
        if self.ret_stack:
            cur = self.ret_stack[-1]
            cur.append(v)
        return Flow.RET

    def s_Raise(self, st, env):
        if st.exc is not None:
            try:
                self.ev(st.exc, env)
            except Stop:
                raise
        return Flow.RAISE

    def s_Assert(self, st, env):
        self.ev(st.test, env)

    def s_Delete(self, st, env):
        return None

    def s_Global(self, st, env):
        return None

    s_Nonlocal = s_Global

    def s_Break(self, st, env):
        return Flow.BRK

    def s_Continue(self, st, env):
        return Flow.CNT

    # -- control flow ----------------------------------------------------------------------
    def merge_env(self, base: Env, branches: list) -> None:
        """Merge branch environments (those that fall through) into `base`."""
        if not branches:
            return
        keys = set()
        for b in branches:
            keys |= set(b.vars)
        for k in keys:
            vals = [b.vars[k] for b in branches if k in b.vars]
            if len(vals) < len(branches) and k in base.vars:
                vals.append(base.vars[k])
            if not vals:
                continue
            out = vals[0]
            for x in vals[1:]:
                out = join_values(out, x)
            base.vars[k] = out

    def const_truth(self, v: V) -> Optional[bool]:
        c = v.c
        if c is UNK:
            return None
        if isinstance(c, str) and HOLE in c:
            return None
        if isinstance(c, (bool, int, float, type(None))):
            return bool(c)
        if isinstance(c, str):
            return bool(c)
        return None

    def s_If(self, st, env):
        tv = self.ev(st.test, env)
        truth = self.const_truth(tv) if tv.kind in (None, "num", "bool", "str") else None
        if truth is True:
            return self.exec_block(st.body, env)
        if truth is False:
            return self.exec_block(st.orelse, env)
        names = _names_in(st.test)
        validation = _looks_like_validation(st.test)
        if validation:
            seen = set(names)
            todo = list(names)
            for _ in range(4):
                nxt = []
                for n in todo:
                    for o in self.origins.get(n, ()):
                        if o not in seen:
                            seen.add(o)
                            nxt.append(o)
                todo = nxt
            names = list(seen)
        negated = isinstance(st.test, ast.UnaryOp) and isinstance(st.test.op, ast.Not)
        # branch 1
        e1 = env.fork()
        if validation and not negated:
            self.mark_validated(names, e1)
        r1 = self.exec_block(st.body, e1)
        e2 = env.fork()
        if validation and negated:
            self.mark_validated(names, e2)
        r2 = self.exec_block(st.orelse, e2) if st.orelse else None
        live = []
        if r1 not in (Flow.RET, Flow.RAISE, Flow.BRK, Flow.CNT):
            live.append(e1)
        if r2 not in (Flow.RET, Flow.RAISE, Flow.BRK, Flow.CNT):
            live.append(e2)
        # guard pattern: `if bad: raise/return` validates names for the continuation
        if not live:
            pass
        elif len(live) == 1 and validation:
            if live[0] is e2 and r1 in (Flow.RET, Flow.RAISE, Flow.CNT, Flow.BRK) and not negated:
                self.mark_validated(names, e2)
            if live[0] is e1 and r2 in (Flow.RET, Flow.RAISE, Flow.CNT, Flow.BRK) and negated:
                self.mark_validated(names, e1)
        if not live:
            # both branches terminate
            self.merge_env(env, [e1, e2])
            return r1 if r1 == r2 else Flow.RET
        if len(live) == 1 and st.orelse == [] and r1 in (Flow.RET, Flow.RAISE, Flow.CNT, Flow.BRK):
            # `if cond: return` - continuation is the (forked) else path
            env.vars = e2.vars
            return None
        self.merge_env(env, live)
        return None

    def mark_validated(self, names: list, env: Env) -> None:
        for n in names:
            v = env.vars.get(n)
            if v is None:
                v2 = env.get(n)
                if v2 is None:
                    continue
                v = v2
            if v.labels & {USER}:
                nv = v.with_labels(VALIDATED)
                env.vars[n] = nv

    def iter_values(self, it: V) -> tuple:
        """-> (list_of_element_V or None, element_template V, count_or_None)"""
        if isinstance(it.items, list) and it.n is not None and it.n > len(it.items) and it.n > 64:
            tmpl = it.items[0] if it.items else V()
            for x in it.items[1:]:
                tmpl = join_values(tmpl, x)
            return None, tmpl, it.n
        if isinstance(it.items, list) and len(it.items) <= 64:
            return list(it.items), None, len(it.items)
        if isinstance(it.items, dict) and len(it.items) <= 64:
            return [V(c=k, labels=EMPTY) if not isinstance(k, V) else k for k in it.items.keys()], None, len(it.items)
        if it.kind == "range" and it.meta and it.meta.get("stop") is not None:
            r = it.meta
            start, stop, step = r.get("start", 0), r["stop"], r.get("step", 1) or 1
            try:
                n = max(0, (stop - start + (step - (1 if step > 0 else -1))) // step)
            except Exception:
                n = None
            if n is not None and n <= 64:
                return [V(c=start + i * step, kind="num") for i in range(n)], None, n
            return None, V(c=UNK, kind="num", labels=EMPTY), n
        if isinstance(it.c, str) and HOLE not in it.c and len(it.c) <= 64 and it.kind != "file":
            return [V(c=ch, kind="str") for ch in it.c], None, len(it.c)
        lab = it.all_labels()
        el = V(c=HOLE if (it.kind in (None, "str", "file") or isinstance(it.c, str)) else UNK, labels=lab, src=it.all_src(), lines=it.lines)
        if it.kind == "environ" or it.q == "os.environ" or ENV_DUMP in lab:
            el = V(c=HOLE, labels=U(lab, {ENV, ENV_DUMP}), src=it.all_src())
        return None, el, it.n

    def s_For(self, st, env):
        it = self.ev(st.iter, env)
        elems, tmpl, count = self.iter_values(it)
        desc = {"kind": "for", "unbounded": False, "line": st.lineno, "growth": False}
        # unbounded iterators
        if isinstance(st.iter, ast.Call):
            nm = self.dotted(st.iter.func) if isinstance(st.iter.func, (ast.Attribute, ast.Name)) else ""
            if nm in ("itertools.count", "count", "itertools.cycle", "cycle", "itertools.repeat", "repeat") and not (nm.endswith("repeat") and len(st.iter.args) > 1):
                desc["unbounded"] = True
        if desc["unbounded"] and not self._has_exit(st.body):
            return self._run_unbounded_loop(st, env, desc, tmpl or V())
        if elems is not None:
            for ev_ in elems:
                self.ctx.tick()
                self.assign(st.target, ev_, env)
                self.loops.append(desc)
                r = self.exec_block(st.body, env)
                self.loops.pop()
                if r == Flow.BRK:
                    break
                if r in (Flow.RET, Flow.RAISE):
                    return None if r == Flow.RAISE else r
            return None
        old = self.mult
        if count is not None:
            self.mult = min(old * max(count, 1), 10 ** 12)
        elif it.n is not None:
            self.mult = min(old * max(it.n, 1), 10 ** 12)
        huge = count is not None and count >= 10 ** 8
        self.assign(st.target, tmpl if tmpl is not None else V(), env)
        e1 = env.fork()
        self.loops.append(desc)
        r = self.exec_block(st.body, e1)
        # second pass picks up taint accumulated in the first one
        if r not in (Flow.RET, Flow.RAISE):
            self.exec_block(st.body, e1)
        self.loops.pop()
        self.mult = old
        if huge:
            info = self._scan_loop_body(st.body)
            fl = {"huge_iter"}
            if not info["blocking"]:
                fl.add("busy")
            if info["spawn"]:
                fl.add("spawn")
            if info["growth"]:
                fl.add("mem_growth")
            self.emit("LOOP", st.lineno, "for", flags=fl, extra={"count": count})
        self.merge_env(env, [env, e1]) if False else self._merge_loop(env, e1)
        return None

    def _merge_loop(self, env: Env, e1: Env) -> None:
        for k, v in e1.vars.items():
            if k in env.vars and env.vars[k] is not v:
                env.vars[k] = join_values(env.vars[k], v)
            elif k not in env.vars:
                env.vars[k] = v

    s_AsyncFor = s_For

    def _has_exit(self, body: list) -> bool:
        if self.try_exit:
            return True
        for n in body:
            for sub in ast.walk(n):
                if isinstance(sub, (ast.Return, ast.Raise)):
                    return True
                if isinstance(sub, ast.Call):
                    nm = sub.func.attr if isinstance(sub.func, ast.Attribute) else (sub.func.id if isinstance(sub.func, ast.Name) else "")
                    if nm in ("exit", "_exit", "quit", "abort", "kill"):
                        return True
        # break only counts if not inside a nested loop
        return _has_own_break(body)

    def _scan_loop_body(self, body: list) -> dict:
        info = {"blocking": False, "spawn": False, "growth": False, "io": False}
        BLOCK = {"sleep", "wait", "recv", "recvfrom", "accept", "select", "poll", "join", "acquire", "communicate", "input", "readline", "read", "readlines",
                 "serve_forever", "run_forever", "run_until_complete", "get", "recv_into", "result", "wait_for", "sleep_ms", "urlopen", "request", "post", "put",
                 "fetch", "send", "sendall", "write", "flush", "print", "run", "call", "check_output", "check_call", "Popen", "execute", "commit", "upload"}
        SPAWN = {"Thread", "Process", "fork", "Popen", "spawn", "start", "submit", "system", "popen", "create_task", "apply_async", "run", "call", "forkpty", "startfile"}
        for n in body:
            for sub in ast.walk(n):
                if isinstance(sub, (ast.Await, ast.Yield, ast.YieldFrom)):
                    info["blocking"] = True
                if isinstance(sub, ast.Call):
                    nm = sub.func.attr if isinstance(sub.func, ast.Attribute) else (sub.func.id if isinstance(sub.func, ast.Name) else "")
                    if nm in BLOCK and not (nm == "get" and isinstance(sub.func, ast.Attribute) and sub.args):
                        info["blocking"] = True
                    if nm in ("append", "extend", "add", "update", "insert", "write", "appendleft"):
                        info["growth"] = True
                    if nm in SPAWN and nm not in ("run", "call", "start") or (nm in ("start", "system", "run", "call") and True):
                        if nm in ("Thread", "Process", "fork", "Popen", "spawn", "forkpty", "system", "popen", "start", "submit", "create_task", "apply_async", "startfile"):
                            info["spawn"] = True
                if isinstance(sub, ast.AugAssign) and isinstance(sub.op, (ast.Add, ast.Mult)):
                    info["growth"] = True
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mult) and any(isinstance(x, (ast.List, ast.Constant)) for x in (sub.left, sub.right)):
                    info["growth"] = True
        # spawn & blocking: a server loop that handles each request by spawning is not exhaustion; only treat spawn as heavy when nothing blocks
        return info

    def s_While(self, st, env):
        tv = self.ev(st.test, env)
        truth = self.const_truth(tv) if tv.kind in (None, "num", "bool") or tv.c is not UNK else None
        always = False
        if isinstance(st.test, ast.Constant) and bool(st.test.value) and not isinstance(st.test.value, str):
            always = True
        elif isinstance(st.test, ast.Constant) and isinstance(st.test.value, str) and st.test.value:
            always = True
        elif isinstance(st.test, ast.UnaryOp) and isinstance(st.test.op, ast.Not) and isinstance(st.test.operand, ast.Constant) and not st.test.operand.value:
            always = True
        elif truth is True and isinstance(st.test, ast.Name) and not any(isinstance(x, ast.Name) and x.id == st.test.id and isinstance(x.ctx, ast.Store) for b in st.body for x in ast.walk(b)):
            always = True
        desc = {"kind": "while", "unbounded": always, "line": st.lineno, "growth": False}
        if always and not self._has_exit(st.body):
            return self._run_unbounded_loop(st, env, desc, V())
        e1 = env.fork()
        self.loops.append(desc)
        r = self.exec_block(st.body, e1)
        if r not in (Flow.RET, Flow.RAISE):
            self.exec_block(st.body, e1)
        self.loops.pop()
        self._merge_loop(env, e1)
        if st.orelse:
            self.exec_block(st.orelse, env)
        return None

    def _run_unbounded_loop(self, st, env, desc, elem: V):
        info = self._scan_loop_body(st.body)
        fl = {"unbounded"}
        if not info["blocking"]:
            fl.add("busy")
        if info["spawn"]:
            fl.add("spawn")
        if info["growth"] and not info["blocking"]:
            fl.add("mem_growth")
        self.emit("LOOP", st.lineno, st.__class__.__name__.lower(), flags=fl, lines={s.lineno for s in st.body[:3]})   # the loop and what it repeats
        desc["unbounded"] = True
        if isinstance(st, ast.For):
            self.assign(st.target, elem, env)
        e1 = env.fork()
        self.loops.append(desc)
        self.exec_block(st.body, e1)
        self.loops.pop()
        self._merge_loop(env, e1)
        return None

    def s_Try(self, st, env):
        e0 = env.fork()
        exits = any(isinstance(x, (ast.Return, ast.Raise, ast.Break)) for h in st.handlers for x in ast.walk(h))
        if exits:
            self.try_exit += 1
        try:
            r = self.exec_block(st.body, e0)
        finally:
            if exits:
                self.try_exit -= 1
        branches = []
        if r not in (Flow.RET, Flow.RAISE, Flow.BRK, Flow.CNT):
            if st.orelse:
                r = self.exec_block(st.orelse, e0)
            if r not in (Flow.RET, Flow.RAISE, Flow.BRK, Flow.CNT):
                branches.append(e0)
        for h in st.handlers:
            eh = env.fork()
            if h.name:
                eh.set(h.name, V(c=UNK, labels=EMPTY))
            rh = self.exec_block(h.body, eh)
            if rh not in (Flow.RET, Flow.RAISE, Flow.BRK, Flow.CNT):
                branches.append(eh)
        if branches:
            self.merge_env(env, branches)
        if st.finalbody:
            rf = self.exec_block(st.finalbody, env)
            if rf is not None:
                return rf
        if not branches and (r in (Flow.RET, Flow.RAISE)):
            return r
        return None

    s_TryStar = s_Try

    def s_With(self, st, env):
        for item in st.items:
            cv = self.ev(item.context_expr, env)
            if item.optional_vars is not None:
                self.assign(item.optional_vars, cv, env)
        return self.exec_block(st.body, env)

    s_AsyncWith = s_With

    def s_Match(self, st, env):
        self.ev(st.subject, env)
        branches = []
        for c in st.cases:
            e = env.fork()
            r = self.exec_block(c.body, e)
            if r not in (Flow.RET, Flow.RAISE):
                branches.append(e)
        if branches:
            self.merge_env(env, branches)

    # ------------------------------------------------------------------------ expressions
    def ev(self, node, env: Env) -> V:
        self.ctx.tick()
        m = getattr(self, "e_" + type(node).__name__, None)
        if m is None:
            return V()
        return m(node, env)

    def e_Constant(self, n, env):
        c = n.value
        if isinstance(c, str):
            return V(c=c, kind="str", lines=frozenset({n.lineno}))
        if isinstance(c, bytes):
            try:
                return V(c=c.decode("latin-1"), kind="bytes", lines=frozenset({n.lineno}))
            except Exception:
                return V(c=UNK, kind="bytes")
        if isinstance(c, bool) or c is None:
            return V(c=c, kind="num" if c is not None else None)
        if isinstance(c, (int, float, complex)):
            return V(c=c, kind="num")
        return V(c=UNK)

    def e_JoinedStr(self, n, env):
        parts = []
        labels = set()
        src = set()
        lines = {n.lineno}
        all_known = True
        for p in n.values:
            if isinstance(p, ast.Constant):
                parts.append(str(p.value))
            elif isinstance(p, ast.FormattedValue):
                v = self.ev(p.value, env)
                if parts and parts[-1].endswith(("/", "\\")) and USER in v.all_labels() and not (v.all_labels() & {QUOTED, VALIDATED}):
                    labels.add(TRAVERSAL)          # fixed directory prefix + caller-supplied part
                labels |= v.all_labels()
                src |= v.all_src()
                lines |= v.all_lines()
                s = self.to_str(v)
                if p.format_spec is not None and s is not None and HOLE not in s:
                    # format spec may change width/precision; keep hole to stay conservative
                    spec = self.ev(p.format_spec, env)
                    sp = spec.exact()
                    if sp and re.fullmatch(r"[<>^]?\d*", sp or ""):
                        pass
                    else:
                        s = HOLE
                parts.append(s if s is not None else HOLE)
        return V(c="".join(parts), kind="str", labels=U(labels), src=U(src), lines=frozenset(lines))

    def to_str(self, v: V) -> Optional[str]:
        c = v.c
        if isinstance(c, str):
            return c
        if isinstance(c, bool):
            return str(c)
        if isinstance(c, (int, float)):
            return str(c)
        if c is None and v.kind is None and v.fn is None and v.q is None and v.items is None:
            return "None" if v.c is None else None
        if v.q and not v.labels and v.kind == "module":
            return v.q
        return None

    def e_Name(self, n, env):
        v = env.get(n.id)
        if v is not None:
            return v
        if n.id == "__name__":
            return V(c="__main__", kind="str")
        if n.id in self.genv.vars:
            return self.genv.vars[n.id]
        if self.js and n.id in JS_GLOBALS:
            return self.v_for_q("js." + n.id, [n.lineno])
        if n.id in ("__require__", "__unknown__", "property", "staticmethod", "classmethod"):
            return V(q="builtins." + n.id, kind="func")
        if n.id in self.BUILTIN_NAMES and not (self.js and n.id in ("input", "open", "exec", "compile", "print", "id", "type", "dir", "format", "hash", "vars", "iter", "next")):
            return V(q="builtins." + n.id, kind="func")
        if n.id == "request" and not self.js:       # web handlers use the framework's global request object
            return self.v_for_q("flask.request", [n.lineno])
        if not self.js and n.id in _IMPLICIT_MODULES:         # snippets are often fragments: a bare `os` that nothing else defines is the standard library module
            return V(q=n.id, kind="module", lines=frozenset({n.lineno}))
        if n.id in ("__file__",):
            return V(c="script.py", kind="str")
        if n.id in ("__builtins__",):
            return V(q="builtins", kind="module")
        return V(c=UNK, lines=frozenset({n.lineno}))

    def e_Attribute(self, n, env):
        base = self.ev(n.value, env)
        return self.get_attr(base, n.attr, n, env)

    def e_Subscript(self, n, env):
        base = self.ev(n.value, env)
        if isinstance(n.slice, ast.Slice):
            lo = self.ev(n.slice.lower, env) if n.slice.lower else None
            hi = self.ev(n.slice.upper, env) if n.slice.upper else None
            st = self.ev(n.slice.step, env) if n.slice.step else None
            return self.do_slice(base, lo, hi, st, n)
        key = self.ev(n.slice, env)
        if base.q and base.kind in ("module", "func", "class") and key.exact() is not None and base.q not in ("os.environ", "js.process.env", "sys.argv"):
            return self.get_attr(base, key.exact(), n, env)
        if base.q == "os.environ" or base.kind == "environ":
            kn = key.exact()
            lab = {ENV}
            src = {"the environment variable " + (kn if kn else "(unknown)")}
            if kn is None or K.secret_like_env(kn):
                lab.add(SECRET)
            self.emit("ENV_READ", n.lineno, "os.environ[]", target=kn or HOLE, flags={"secret_name"} if K.secret_like_env(kn or "") else set())
            return V(c=KNOWN_ENV_VALUES.get(kn, HOLE) if kn is not None else HOLE, kind="str", labels=U(lab), src=U(src), lines=frozenset({n.lineno}))
        if base.q in ("sys.argv",):
            return V(c=HOLE, kind="str", labels=U({USER}), src=frozenset({"command-line arguments"}), lines=frozenset({n.lineno}))
        if isinstance(base.items, dict):
            k = key.c
            if k is not UNK and k in base.items:
                return base.items[k]
            if isinstance(k, str) and HOLE in k:
                pass
        elif isinstance(base.items, list) and isinstance(key.c, int) and not isinstance(key.c, bool):
            try:
                return base.items[key.c]
            except IndexError:
                pass
        lab = base.all_labels()
        if base.kind == "str" or isinstance(base.c, str):
            return V(c=HOLE, kind="str", labels=U(lab, key.labels & {USER}), src=base.all_src(), lines=base.all_lines() | {n.lineno})
        return V(c=UNK, labels=lab, src=base.all_src(), lines=base.all_lines() | {n.lineno}, q=(base.q + "[]") if base.q else None)

    def do_slice(self, base: V, lo, hi, st, node) -> V:
        def num(x):
            return x.c if x is not None and isinstance(x.c, int) and not isinstance(x.c, bool) else (None if x is None else UNK)
        l, h, s = num(lo), num(hi), num(st)
        if UNK in (l, h, s):
            return V(c=HOLE if isinstance(base.c, str) else UNK, kind=base.kind, labels=base.all_labels(), src=base.all_src(), lines=base.all_lines())
        if isinstance(base.c, str) and HOLE not in base.c:
            try:
                return V(c=base.c[l:h:s], kind=base.kind, labels=base.labels, src=base.src, lines=base.lines)
            except Exception:
                pass
        if isinstance(base.items, list):
            try:
                its = base.items[l:h:s]
                return V(c=UNK, kind=base.kind, items=its, n=len(its), labels=base.labels, src=base.src, lines=base.lines)
            except Exception:
                pass
        n = None
        if h is not None and (l is None or l == 0) and s is None and h >= 0:
            n = h
        return V(c=HOLE if isinstance(base.c, str) else UNK, kind=base.kind, labels=base.all_labels(), src=base.all_src(), lines=base.all_lines(), n=n)

    def e_Tuple(self, n, env):
        its = [self.ev(x, env) if not isinstance(x, ast.Starred) else self.ev(x.value, env) for x in n.elts]
        return V(c=UNK, kind="tuple", items=its, n=len(its), labels=EMPTY, lines=frozenset({n.lineno}))

    def e_List(self, n, env):
        its = []
        for x in n.elts:
            if isinstance(x, ast.Starred):
                sv = self.ev(x.value, env)
                if isinstance(sv.items, list):
                    its.extend(sv.items)
                else:
                    its.append(V(c=UNK, labels=sv.all_labels(), src=sv.all_src()))
            else:
                its.append(self.ev(x, env))
        return V(c=UNK, kind="list", items=its, n=len(its), labels=EMPTY, lines=frozenset({n.lineno}))

    def e_Set(self, n, env):
        v = self.e_List(n, env)
        v.kind = "set"
        return v

    def e_Dict(self, n, env):
        d = {}
        labels = set()
        for k, vnode in zip(n.keys, n.values):
            vv = self.ev(vnode, env)
            if k is None:
                if isinstance(vv.items, dict):
                    d.update(vv.items)
                labels |= vv.all_labels()
                continue
            kv = self.ev(k, env)
            key = kv.c if kv.c is not UNK and not (isinstance(kv.c, str) and HOLE in kv.c) else HOLE
            d[key] = vv
        return V(c=UNK, kind="dict", items=d, n=len(d), labels=U(labels), lines=frozenset({n.lineno}))

    def e_Starred(self, n, env):
        return self.ev(n.value, env)

    def e_IfExp(self, n, env):
        t = self.ev(n.test, env)
        truth = self.const_truth(t) if t.c is not UNK else None
        if truth is True:
            return self.ev(n.body, env)
        if truth is False:
            return self.ev(n.orelse, env)
        a = self.ev(n.body, env)
        b = self.ev(n.orelse, env)
        return join_values(a, b)

    def e_BoolOp(self, n, env):
        vals = [self.ev(x, env) for x in n.values]
        out = vals[0]
        if isinstance(n.op, ast.Or):
            for i, v in enumerate(vals):
                t = self.const_truth(v) if v.c is not UNK else None
                if t is True and i == 0 and not v.labels:
                    return v
            for v in vals[1:]:
                out = join_values(out, v)
            return out
        for v in vals[1:]:
            out = join_values(out, v)
        return out

    def e_Compare(self, n, env):
        left = self.ev(n.left, env)
        res = None
        cur = left
        known = True
        for op, comp in zip(n.ops, n.comparators):
            right = self.ev(comp, env)
            r = self.compare_vals(op, cur, right)
            if r is None:
                known = False
            else:
                res = r if res is None else (res and r)
                if not r:
                    res = False
            cur = right
        if known and res is not None:
            return V(c=bool(res), kind="bool")
        return V(c=UNK, kind="bool")

    def compare_vals(self, op, a: V, b: V) -> Optional[bool]:
        if a.c is UNK or b.c is UNK:
            return None
        if isinstance(a.c, str) and HOLE in a.c or isinstance(b.c, str) and HOLE in b.c:
            return None
        try:
            if isinstance(op, ast.Eq):
                return a.c == b.c
            if isinstance(op, ast.NotEq):
                return a.c != b.c
            if isinstance(op, ast.Lt):
                return a.c < b.c
            if isinstance(op, ast.LtE):
                return a.c <= b.c
            if isinstance(op, ast.Gt):
                return a.c > b.c
            if isinstance(op, ast.GtE):
                return a.c >= b.c
            if isinstance(op, ast.In) and isinstance(b.c, str) and isinstance(a.c, str):
                return a.c in b.c
            if isinstance(op, ast.NotIn) and isinstance(b.c, str) and isinstance(a.c, str):
                return a.c not in b.c
        except Exception:
            return None
        return None

    def e_UnaryOp(self, n, env):
        v = self.ev(n.operand, env)
        if isinstance(n.op, ast.Not):
            t = self.const_truth(v) if v.c is not UNK else None
            return V(c=(not t) if t is not None else UNK, kind="bool")
        if isinstance(v.c, (int, float)) and not isinstance(v.c, bool):
            try:
                if isinstance(n.op, ast.USub):
                    return V(c=-v.c, kind="num")
                if isinstance(n.op, ast.UAdd):
                    return V(c=+v.c, kind="num")
                if isinstance(n.op, ast.Invert) and isinstance(v.c, int):
                    return V(c=~v.c, kind="num")
            except Exception:
                pass
        return V(c=UNK, labels=v.labels, kind="num" if v.kind == "num" else None)

    def e_BinOp(self, n, env):
        a = self.ev(n.left, env)
        b = self.ev(n.right, env)
        return self.binop(n.op, a, b, n)

    def num_guard(self, x) -> bool:
        return isinstance(x, (int, float)) and not isinstance(x, bool)

    def binop(self, op, a: V, b: V, node) -> V:
        lines = a.all_lines() | b.all_lines() | {getattr(node, "lineno", 0)}
        labels = U(a.all_labels(), b.all_labels())
        src = U(a.all_src(), b.all_src())
        # numbers
        if self.num_guard(a.c) and self.num_guard(b.c):
            try:
                x, y = a.c, b.c
                if isinstance(op, ast.Add):
                    return V(c=x + y, kind="num")
                if isinstance(op, ast.Sub):
                    return V(c=x - y, kind="num")
                if isinstance(op, ast.Mult):
                    if isinstance(x, int) and isinstance(y, int) and abs(x) > 10 ** 400 // max(abs(y), 1):
                        return V(c=10 ** 30, kind="num")
                    return V(c=x * y, kind="num")
                if isinstance(op, ast.Pow):
                    if isinstance(x, int) and isinstance(y, int) and (y > 200 or abs(x) > 10 ** 6 and y > 20):
                        return V(c=10 ** 30, kind="num")
                    return V(c=x ** y, kind="num")
                if isinstance(op, ast.LShift) and isinstance(x, int) and isinstance(y, int):
                    return V(c=x << min(y, 200), kind="num")
                if isinstance(op, ast.RShift) and isinstance(x, int) and isinstance(y, int):
                    return V(c=x >> y, kind="num")
                if isinstance(op, ast.FloorDiv):
                    return V(c=x // y, kind="num")
                if isinstance(op, ast.Div):
                    return V(c=x / y, kind="num")
                if isinstance(op, ast.Mod):
                    return V(c=x % y, kind="num")
                if isinstance(op, ast.BitOr) and isinstance(x, int) and isinstance(y, int):
                    return V(c=x | y, kind="num")
                if isinstance(op, ast.BitAnd) and isinstance(x, int) and isinstance(y, int):
                    return V(c=x & y, kind="num")
                if isinstance(op, ast.BitXor) and isinstance(x, int) and isinstance(y, int):
                    return V(c=x ^ y, kind="num")
            except Exception:
                return V(c=UNK, kind="num")
        # strings
        sa = a.c if isinstance(a.c, str) else None
        sb = b.c if isinstance(b.c, str) else None
        if isinstance(op, ast.Add):
            if isinstance(a.items, list) and isinstance(b.items, list):
                its = list(a.items) + list(b.items)
                return V(c=UNK, kind=a.kind, items=its, n=len(its), labels=EMPTY, lines=frozenset(lines))
            if (sa is not None or sb is not None) or a.kind == "str" or b.kind == "str":
                s1 = sa if sa is not None else (self.to_str(a) if self.to_str(a) is not None else HOLE)
                s2 = sb if sb is not None else (self.to_str(b) if self.to_str(b) is not None else HOLE)
                lab = set(labels)
                if sa is not None and sa.endswith(("/", "\\")) and USER in b.all_labels() and not (b.all_labels() & {QUOTED, VALIDATED}):
                    lab.add(TRAVERSAL)
                if HOLE not in (s1 + s2) and (sa is not None and sb is not None) and len(sa) and len(sb):
                    lab.add(BUILT)
                kind = "bytes" if (a.kind == "bytes" or b.kind == "bytes") else "str"
                return V(c=s1 + s2, kind=kind, labels=U(lab), src=src, lines=frozenset(lines))
        if isinstance(op, ast.Mod) and (sa is not None):
            return self.percent_format(sa, b, labels, src, lines)
        if isinstance(op, ast.Mult):
            if sa is not None and self.num_guard(b.c) and b.c >= 0:
                n_ = int(b.c)
                if len(sa) * n_ > 10 ** 6:
                    self.emit("ALLOC", getattr(node, "lineno", 0), "str*int", flags={"huge"} if len(sa) * n_ >= 10 ** 9 else {"large"},
                              extra={"size": len(sa) * n_}, mult_override=True)
                    return V(c=HOLE, kind="str", labels=labels, lines=frozenset(lines), n=len(sa) * n_)
                return V(c=sa * n_, kind="str", labels=labels, lines=frozenset(lines))
            if self.num_guard(a.c) and sb is not None and a.c >= 0:
                return self.binop(op, b, a, node)
            # list * n
            for lst, num in ((a, b), (b, a)):
                if (lst.kind in ("list", "tuple", "bytes") or isinstance(lst.items, list)) and self.num_guard(num.c) and num.c >= 0:
                    base_n = len(lst.items) if isinstance(lst.items, list) else 1
                    total = base_n * int(num.c)
                    if total >= 10 ** 7:
                        self.emit("ALLOC", getattr(node, "lineno", 0), "seq*int", flags={"huge"} if total >= 10 ** 9 else {"large"}, extra={"size": total}, mult_override=True)
                        return V(c=UNK, kind=lst.kind, labels=lst.labels, n=total, lines=frozenset(lines))
                    if isinstance(lst.items, list) and total <= 256:
                        return V(c=UNK, kind=lst.kind, items=list(lst.items) * int(num.c), n=total, lines=frozenset(lines))
                    return V(c=UNK, kind=lst.kind, labels=lst.labels, n=total, lines=frozenset(lines))
        if isinstance(op, ast.Div) and isinstance(a.q, str) is False and a.cls == "pathlib.Path" and sb is not None:
            pass
        # pathlib: Path / "x"
        if isinstance(op, ast.Div) and (a.cls == "pathlib.Path" or (sa is not None and a.kind == "path")):
            s1 = sa if sa is not None else HOLE
            s2 = sb if sb is not None else (self.to_str(b) or HOLE)
            plab = set(labels)
            if USER in b.all_labels() and not (b.all_labels() & {QUOTED, VALIDATED}) and a.exact() is not None:
                plab.add(TRAVERSAL)
            return V(c=(s1.rstrip("/") + "/" + s2.lstrip("/")) if s2 else s1, kind="path", cls="pathlib.Path", labels=U(plab), src=src, lines=frozenset(lines))
        if isinstance(op, ast.Div) and sa is not None:
            pass
        return V(c=HOLE if (sa is not None or sb is not None) else UNK, kind="str" if (sa is not None or sb is not None) else None, labels=labels, src=src, lines=frozenset(lines))

    def percent_format(self, tmpl: str, arg: V, labels, src, lines) -> V:
        if HOLE in tmpl and False:
            pass
        if isinstance(arg.items, dict):
            def rep(m):
                key = m.group(1)
                v = arg.items.get(key)
                s = self.to_str(v) if v is not None else None
                return s if s is not None else HOLE
            out = re.sub(r"%\(([^)]+)\)[#0\- +]*\d*(?:\.\d+)?[sdifrxXeEgGc]", rep, tmpl)
            out = out.replace("%%", "%")
            return V(c=out, kind="str", labels=labels, src=src, lines=frozenset(lines))
        vals = arg.items if isinstance(arg.items, list) and arg.kind == "tuple" else [arg]
        it = iter(vals)

        def rep2(m):
            if m.group(0) == "%%":
                return "%"
            try:
                v = next(it)
            except StopIteration:
                return HOLE
            s = self.to_str(v)
            if s is None:
                return HOLE
            if m.group(0)[-1] in "d i".split() or m.group(0)[-1] == "d":
                if not isinstance(v.c, (int, float)):
                    return HOLE
            return s
        out = re.sub(r"%%|%[#0\- +]*\d*(?:\.\d+)?[sdifrxXeEgGca]", rep2, tmpl)
        return V(c=out, kind="str", labels=labels, src=src, lines=frozenset(lines))

    def e_Call(self, n, env):
        return self.do_call(n, env)

    def e_Lambda(self, n, env):
        fi = FuncInfo(n, "<lambda>", None, env, "function", is_lambda=True)
        if any(isinstance(x, ast.Call) for x in ast.walk(n.body)):
            self.pending_lambdas.append(fi)         # run later if nothing ever calls it
        return V(kind="func", fn=fi, lines=frozenset({n.lineno}))

    def e_Await(self, n, env):
        return self.ev(n.value, env)

    def e_Yield(self, n, env):
        if n.value is not None:
            v = self.ev(n.value, env)
            if self.ret_stack:
                self.ret_stack[-1].append(v)
                self.gen_marks.add(len(self.ret_stack))
            return V(c=UNK, labels=v.all_labels(), src=v.all_src())
        return V()

    e_YieldFrom = e_Yield

    def e_NamedExpr(self, n, env):
        v = self.ev(n.value, env)
        self.assign(n.target, v, env)
        return v

    def e_FormattedValue(self, n, env):
        return self.ev(n.value, env)

    def comprehension(self, n, env, kind: str) -> V:
        e = env.fork()
        results: list = []
        labels = set()
        mult_before = self.mult

        def rec(gi: int):
            if gi >= len(n.generators):
                if kind == "dict":
                    k = self.ev(n.key, e)
                    v = self.ev(n.value, e)
                    results.append((k, v))
                else:
                    results.append(self.ev(n.elt, e))
                return
            g = n.generators[gi]
            it = self.ev(g.iter, e)
            elems, tmpl, count = self.iter_values(it)
            if elems is not None and len(results) < 128:
                for x in elems:
                    self.ctx.tick()
                    self.assign(g.target, x, e)
                    ok = True
                    for cond in g.ifs:
                        cv = self.ev(cond, e)
                        t = self.const_truth(cv) if cv.c is not UNK else None
                        if t is False:
                            ok = False
                    if ok:
                        rec(gi + 1)
            else:
                old = self.mult
                cnt = count if count is not None else it.n
                if cnt is not None:
                    self.mult = min(old * max(cnt, 1), 10 ** 12)
                self.assign(g.target, tmpl if tmpl is not None else V(), e)
                for cond in g.ifs:
                    self.ev(cond, e)
                rec(gi + 1)
                self.mult = old
                self._last_comp_count = cnt
        self._last_comp_count = None
        rec(0)
        self.mult = mult_before
        total = None
        g0 = n.generators[0]
        it0 = self.ev(g0.iter, env) if False else None
        if kind == "dict":
            d = {}
            for k, v in results:
                key = k.c if k.c is not UNK and not (isinstance(k.c, str) and HOLE in k.c) else HOLE
                d[key] = v
                labels |= v.all_labels()
            return V(c=UNK, kind="dict", items=d, n=len(d), labels=U(labels), lines=frozenset({n.lineno}))
        n_total = len(results) if results and self._last_comp_count is None else self._last_comp_count
        its = results[:128]
        res = V(c=UNK, kind="list" if kind != "set" else "set", items=its, n=n_total, labels=EMPTY, lines=frozenset({n.lineno}))
        if self._last_comp_count is not None and len(its) <= 2:
            res.n = self._last_comp_count
        return res

    def e_ListComp(self, n, env):
        return self.comprehension(n, env, "list")

    def e_SetComp(self, n, env):
        return self.comprehension(n, env, "set")

    def e_GeneratorExp(self, n, env):
        return self.comprehension(n, env, "list")

    def e_DictComp(self, n, env):
        return self.comprehension(n, env, "dict")

    def e_Slice(self, n, env):
        return V()

    # ------------------------------------------------------------------------ calls
    def do_call(self, n: ast.Call, env: Env) -> V:
        args: list = []
        kws: dict = {}
        star_labels = set()
        for a in n.args:
            if isinstance(a, ast.Starred):
                sv = self.ev(a.value, env)
                if isinstance(sv.items, list):
                    args.extend(sv.items)
                else:
                    star_labels |= sv.all_labels()
                    args.append(V(c=UNK, labels=sv.all_labels(), src=sv.all_src()))
            else:
                args.append(self.ev(a, env))
        for k in n.keywords:
            vv = self.ev(k.value, env)
            if k.arg is None:
                if isinstance(vv.items, dict):
                    for kk, x in vv.items.items():
                        if isinstance(kk, str):
                            kws[kk] = x
                else:
                    kws["**"] = vv
            else:
                kws[k.arg] = vv
        f = n.func
        try:
            self.note_credential_use(f, args, kws)
        except Exception:
            pass
        try:
            self.check_disabled_verification(f, args, kws, n)
        except Stop:
            raise
        except Exception:
            pass
        if isinstance(f, ast.Attribute):
            recv = self.ev(f.value, env)
            res = self.call_attr(recv, f.attr, args, kws, n, env)
            if self.js:
                self.run_callbacks(args, kws, res, recv)
            return res
        callee = self.ev(f, env)
        res = self.call_value(callee, args, kws, n, env, name_hint=f.id if isinstance(f, ast.Name) else "")
        if self.js:
            self.run_callbacks(args, kws, res, None)
        return res

    _CRED_KW = re.compile(r"^(password|passwd|pwd|secret|token|api[_-]?key|apikey|key|auth|authorization|credentials?|access[_-]?key|secret[_-]?key|client[_-]?secret|bearer|private[_-]?key|aws_\w*key\w*)$", re.I)
    _CRED_HEADER = re.compile(r"(authorization|api[-_]?key|x-auth|auth[-_]?token|x-token)", re.I)
    _CRED_CALLEE = re.compile(r"(client|session|connect|login|authenticate|auth|credential)", re.I)

    @staticmethod
    def _env_vars_of(v) -> set:
        return set(re.findall(r"the environment variable ([\w.\-]+)", " | ".join(v.all_src()))) if v is not None else set()

    def note_credential_use(self, f, args: list, kws: dict) -> None:
        """A secret that is handed over AS A CREDENTIAL (an Authorization header, password=/token= argument, a client constructor)
        is being used for its purpose. Exposure (printing, posting it in a body, sending it to an attacker host) is judged by the sinks."""
        def header_items(d) -> None:
            if isinstance(d.items, dict):
                for hk, hv in d.items.items():
                    if isinstance(hk, str) and self._CRED_HEADER.search(hk):
                        self.cred_vars |= self._env_vars_of(hv)
        for k, v in kws.items():
            if k == "**" or v is None:
                continue
            if self._CRED_KW.match(str(k)):
                self.cred_vars |= self._env_vars_of(v)
            header_items(v)
        for a in args:
            header_items(a)
        fname = self.dotted(f) if isinstance(f, (ast.Attribute, ast.Name)) else ""
        if fname and self._CRED_CALLEE.search(fname.split(".")[-1]):
            for a in args:
                if SECRET in a.all_labels():
                    self.cred_vars |= self._env_vars_of(a)

    def mark_credential_reads(self) -> None:
        for ev in self.ctx.events:
            if ev.cap == "ENV_READ" and ev.target in self.cred_vars:
                ev.flags.add("used_as_credential")

    _VERIFY_KW = re.compile(r"^(verify|verify_?signature|verify_?(exp|aud|iss|nbf|iat)|verify_?ssl|ssl_?verify|verify_?certs?|check_?hostname|validate_?(cert|signature|token)s?|require_?signature)$", re.I)

    def check_disabled_verification(self, f, args: list, kws: dict, n: ast.Call) -> None:
        """A verification / validation switch handed to any call as False (or an 'none' algorithm) means a safety check is turned off.
        Generic: it keys on the *meaning of the parameter name*, not on a particular library."""
        fname = self.dotted(f) if isinstance(f, (ast.Attribute, ast.Name)) else ""
        off: list = []

        def scan(d: dict) -> None:
            for k, v in d.items():
                if self._VERIFY_KW.match(str(k)) and v.c is False:
                    off.append(str(k))
                if str(k).lower() in ("algorithms", "algorithm", "alg") and v is not None:
                    vals = v.items if isinstance(v.items, list) else [v]
                    if any(isinstance(x.c, str) and x.c.lower() == "none" for x in vals):
                        off.append("algorithm=none")
        scan(kws)
        for a in args:
            if isinstance(a.items, dict):
                scan(a.items)
        for k, v in list(kws.items()):
            if isinstance(v.items, dict):          # options={"verify_signature": False}
                scan(v.items)
        if fname and re.search(r"unverified|_create_default_https_context|insecure", fname.split(".")[-1], re.I):
            off.append(fname.split(".")[-1])
        if not off:
            return
        auth = bool(re.search(r"jwt|token|jws|jwe|saml|oauth|paseto|auth|signature", (fname + " " + " ".join(off)), re.I))
        claim_only = all(re.match(r"verify_?(exp|aud|iss|nbf|iat)$", o, re.I) for o in off)
        fl = {"verification_off"} | (({"auth_claim_off"} if claim_only else {"auth_check_off"}) if auth else {"transport_check_off"})
        self.emit("SEC_DISABLE", n.lineno, fname or "call", target=", ".join(sorted(set(off))), flags=fl)

    def call_value(self, callee: V, args: list, kws: dict, n: ast.Call, env: Env, name_hint: str = "") -> V:
        if callee.kind == "func" and isinstance(callee.fn, FuncInfo):
            bound = callee.meta.get("self") if callee.meta else None
            return self.call_user(callee.fn, args, kws, n, bound_self=bound)
        if callee.kind == "class" and isinstance(callee.fn, ClassInfo):
            return self.instantiate(callee.fn, args, kws, n)
        if callee.q:
            return self.call_lib(callee.q, callee, args, kws, n)
        # unknown callee: propagate taint
        lab = set()
        src = set()
        for a in args:
            lab |= a.all_labels()
            src |= a.all_src()
        for a in kws.values():
            lab |= a.all_labels()
            src |= a.all_src()
        lab |= callee.labels
        if name_hint and _remote_source_name(name_hint):         # `fetch_data()`, `get_code_from_db()`: a helper whose name says it brings data in from outside
            lab.add(NET)
            src.add("data returned by " + name_hint + "()")
        return V(c=UNK, labels=U(lab), src=U(src), lines=frozenset({n.lineno}))

    def call_attr(self, recv: V, name: str, args: list, kws: dict, n: ast.Call, env: Env) -> V:
        # user object methods
        if recv.attrs is not None and recv.cls in self.classes:
            fi = self.find_method(recv.cls, name)
            if fi is not None:
                return self.call_user(fi, args, kws, n, bound_self=recv)
            av = recv.attrs.get(name)
            if av is not None and av.kind == "func" and isinstance(av.fn, FuncInfo):
                return self.call_user(av.fn, args, kws, n, bound_self=av.meta.get("self") if av.meta else None)
        if recv.kind == "class" and isinstance(recv.fn, ClassInfo):
            fi = recv.fn.methods.get(name)
            if fi is not None:
                return self.call_user(fi, args, kws, n, bound_self=None)
        if recv.q and recv.kind in ("module", "func", "class", None) and recv.q not in ("os.environ",) and not recv.cls:
            return self.call_lib(recv.q + "." + name, V(q=recv.q + "." + name, kind="func", alias=recv.alias, lines=recv.lines), args, kws, n, recv=recv)
        return self.call_method(recv, name, args, kws, n, env)

    def find_method(self, cls: str, name: str, _depth: int = 0) -> Optional[FuncInfo]:
        ci = self.classes.get(cls)
        if ci is None or _depth > 6:
            return None
        if name in ci.methods:
            return ci.methods[name]
        for b in ci.bases:
            fi = self.find_method(b, name, _depth + 1)
            if fi is not None:
                return fi
        return None

    def instantiate(self, ci: ClassInfo, args: list, kws: dict, n) -> V:
        obj = V(c=UNK, kind="obj", cls=ci.name, attrs=dict(ci.attrs), lines=frozenset({getattr(n, "lineno", 0)}))
        init = self.find_method(ci.name, "__init__")
        if init is not None:
            self.call_user(init, args, kws, n, bound_self=obj)
        # library base classes (threading.Thread subclass ...)
        for b in self._lib_bases(ci.name):
            obj.meta = obj.meta or {}
            obj.meta["libbase"] = b
        return obj

    def _lib_bases(self, cls: str, _d: int = 0) -> list:
        ci = self.classes.get(cls)
        out = []
        if ci is None or _d > 5:
            return out
        for b in ci.bases:
            if b in self.classes:
                out.extend(self._lib_bases(b, _d + 1))
            else:
                out.append(b)
        return out

    def param_value(self, arg: ast.arg, default: Optional[ast.expr], env: Env) -> V:
        nm = arg.arg
        ann = arg.annotation
        ann_name = ""
        if isinstance(ann, ast.Name):
            ann_name = ann.id
        elif isinstance(ann, ast.Attribute):
            ann_name = ann.attr
        elif isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
            ann_name = ann.value.id
        if nm in HANDLE_NAMES and not ann_name:
            return V(c=UNK, kind="obj", cls="db.Connection" if nm in ("conn", "connection", "con", "cursor", "cur", "db", "database", "engine") else None, lines=frozenset({arg.lineno}))
        if ann_name in SAFE_TYPES:
            return V(c=UNK, kind="num", labels=U({SAFE_NUM}), lines=frozenset({arg.lineno}))
        if ann_name in ("Connection", "Cursor", "Session", "Logger", "Engine", "Flask", "Request", "Response"):
            return V(c=UNK, kind="obj", lines=frozenset({arg.lineno}))
        src = frozenset({f"the function parameter '{nm}' (caller-controlled)"})
        if re.fullmatch(r"(request|req|http_request|event|payload|body|data|params|form|kwargs|args)", nm) and ann_name != "str":
            return V(c=UNK, kind=None, labels=U({USER}), src=frozenset({f"the request/input '{nm}'"}), lines=frozenset({arg.lineno}))
        is_str = ann_name in ("str", "") or ann_name in ("Path", "PathLike", "bytes")
        return V(c=HOLE if is_str else UNK, kind="str" if ann_name == "str" else None, labels=U({USER}), src=src, lines=frozenset({arg.lineno}))

    def call_user(self, fi: FuncInfo, args: list, kws: dict, n, bound_self: Optional[V] = None, symbolic: bool = False) -> V:
        if self.depth > 14:
            return V(c=UNK, labels=U(*[a.all_labels() for a in args]))
        recursion = self.stack.count(fi.qual)
        if recursion >= 2:
            lab = set()
            for a in args:
                lab |= a.all_labels()
            return V(c=UNK, labels=U(lab))
        node = fi.node
        self.called.add(fi.qual)
        fenv = Env(fi.env)
        a = node.args
        params = list(a.posonlyargs) + list(a.args)
        defaults = [None] * (len(params) - len(a.defaults)) + list(a.defaults)
        pos = list(args)
        use_self = fi.cls is not None and fi.kind in ("function", "property") and not (params and params[0].arg not in ("self", "cls") and bound_self is None)
        bind_self = bound_self
        if fi.cls is not None and fi.kind == "classmethod" and bound_self is None:
            bind_self = V(kind="class", fn=self.classes.get(fi.cls), cls=fi.cls)
        if fi.cls is not None and fi.kind != "staticmethod" and params:
            first = params[0]
            if bind_self is not None:
                fenv.set(first.arg, bind_self)
                params_rest = params[1:]
                defaults_rest = defaults[1:]
            else:
                # unbound access (e.g. Class.method(x)): treat first positional as self
                if pos:
                    fenv.set(first.arg, pos.pop(0))
                else:
                    fenv.set(first.arg, V(kind="obj", cls=fi.cls, attrs={}))
                params_rest = params[1:]
                defaults_rest = defaults[1:]
        else:
            params_rest, defaults_rest = params, defaults
        for i, p in enumerate(params_rest):
            if i < len(pos):
                fenv.set(p.arg, pos[i])
            elif p.arg in kws:
                fenv.set(p.arg, kws[p.arg])
            elif symbolic:
                fenv.set(p.arg, self.param_value(p, defaults_rest[i], fenv))
            elif defaults_rest[i] is not None:
                fenv.set(p.arg, self.ev(defaults_rest[i], fi.env))
            else:
                fenv.set(p.arg, V(c=UNK))
        if a.vararg:
            rest = pos[len(params_rest):]
            fenv.set(a.vararg.arg, V(c=UNK, kind="tuple", items=rest, n=len(rest), labels=U(*[x.all_labels() for x in rest])))
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if p.arg in kws:
                fenv.set(p.arg, kws[p.arg])
            elif symbolic:
                fenv.set(p.arg, self.param_value(p, d, fenv))
            elif d is not None:
                fenv.set(p.arg, self.ev(d, fi.env))
            else:
                fenv.set(p.arg, V(c=UNK))
        if a.kwarg:
            extra = {k: v for k, v in kws.items() if k not in [p.arg for p in params_rest] and k != "**"}
            fenv.set(a.kwarg.arg, V(c=UNK, kind="dict", items=extra, n=len(extra), labels=U(*[x.all_labels() for x in extra.values()])))
        self.stack.append(fi.qual)
        self.depth += 1
        pushed_loop = False
        if fi.qual in self.unconditional_rec:
            self.loops.append({"kind": "recursion", "unbounded": True, "line": node.lineno, "growth": False})
            pushed_loop = True
            self.emit("LOOP", node.lineno, "recursion", flags={"unbounded", "recursion", "busy"})
        self.ret_stack.append([])
        try:
            if fi.is_lambda:
                res = self.ev(node.body, fenv)
                rets = [res]
            else:
                self.exec_block(node.body, fenv)
                rets = self.ret_stack[-1]
        finally:
            self.ret_stack.pop()
            self.depth -= 1
            self.stack.pop()
            if pushed_loop:
                self.loops.pop()
        if fi.is_lambda:
            return rets[0]
        if not rets:
            return V(c=None, lines=frozenset({getattr(n, "lineno", 0)}))
        is_gen = any(isinstance(x, (ast.Yield, ast.YieldFrom)) for x in ast.walk(node) if x is not node)
        if is_gen:
            lab = U(*[r.all_labels() for r in rets])
            srcs = U(*[r.all_src() for r in rets])
            return V(c=UNK, kind="list", items=None, n=None, labels=lab, src=srcs, lines=frozenset({getattr(n, "lineno", 0)}))
        out = rets[0]
        for r in rets[1:]:
            out = join_values(out, r)
        return out

    # ------------------------------------------------------------------------ attributes
    def get_attr(self, base: V, name: str, node, env) -> V:
        line = getattr(node, "lineno", 0)
        if base.attrs is not None and base.cls in self.classes:
            if name in base.attrs:
                return base.attrs[name]
            fi = self.find_method(base.cls, name)
            if fi is not None:
                if fi.kind == "property":
                    return self.call_user(fi, [], {}, node, bound_self=base)
                return V(kind="func", fn=fi, meta={"self": base}, lines=frozenset({line}))
            # attribute not found on instance: unknown
            return V(c=UNK, labels=base.labels, src=base.src, lines=frozenset({line}))
        if base.kind == "class" and isinstance(base.fn, ClassInfo):
            ci = base.fn
            if name in ci.attrs:
                return ci.attrs[name]
            fi = self.find_method(ci.name, name)
            if fi is not None:
                return V(kind="func", fn=fi, meta={"self": None}, lines=frozenset({line}))
        if base.kind == "environ" or base.q in ("os.environ", "js.process.env"):
            lab = {ENV}
            if K.secret_like_env(name):
                lab.add(SECRET)
            self.emit("ENV_READ", line, "process.env." + name, target=name, flags={"secret_name"} if K.secret_like_env(name) else set())
            return V(c=KNOWN_ENV_VALUES.get(name, HOLE), kind="str", labels=U(lab), src=frozenset({"the environment variable " + name}), lines=frozenset({line}))
        if base.q:
            q = base.q + "." + name
            return self.module_attr(base, q, name, line)
        # attributes of unknown objects
        if base.cls == "subprocess.CompletedProcess" or base.cls == "subprocess.Popen":
            if name in ("stdout", "stderr"):
                return V(c=HOLE, kind="str", labels=U(base.labels, {"CMDSUB"}), src=base.src, lines=frozenset({line}), cls="stream")
            return V(c=UNK, lines=frozenset({line}))
        if base.cls == "requests.Response" or (base.labels & {NET} and name in ("text", "content", "json", "body", "data", "headers", "raw")):
            return V(c=HOLE, kind="str", labels=U(base.labels, {NET}), src=U(base.src, {"a network response"}), lines=frozenset({line}))
        if base.kind == "file" and name in ("name", "mode", "closed"):
            return V(c=UNK)
        if base.kind == "dict" and isinstance(base.items, dict) and name in base.items:
            return base.items[name]
        return V(c=HOLE if (base.labels and base.kind is None) else UNK, labels=base.all_labels(), src=base.all_src(), lines=base.lines | {line},
                 kind=None, cls=None, q=None)

    # ------------------------------------------------------------------------ events
    def emit(self, cap: str, line: int, name: str = "", target: Optional[str] = None, tl=EMPTY, pl=EMPTY, flags=(), hostc=None, pathc=None,
             extra=None, lines=None, mult_override: bool = False, **kw) -> Event:
        fl = set(flags)
        if self.loops:
            fl.add("in_loop")
            if any(d.get("unbounded") for d in self.loops):
                fl.add("in_unbounded_loop")
        if self.thread_ctx:
            fl.add("in_thread")
        extra_lines = set(self.alias_lines) if "aliased_import" in fl else set()      # the import that hid the module is part of the evidence
        ev = Event(cap=cap, line=line, name=name, target=target, tlabels=U(tl), plabels=U(pl), flags=fl, hostc=hostc, pathc=set(pathc or ()),
                   mult=self.mult, extra=extra or {}, lines={x for x in (lines or ()) if x} | extra_lines)
        return self.ctx.emit(ev)

    # ------------------------------------------------------------------------ entry points
    def run_entry_points(self) -> None:
        # functions / methods not referenced anywhere are analysed with symbolic parameters
        entries: list = []
        for ci in list(self.classes.values()):
            if ci.name not in self.referenced:
                entries.append(("class", ci))
        for qual, fi in list(self.funcs.items()):
            if fi.cls is not None:
                continue
            if fi.name in self.referenced or fi.qual in self.called:
                continue
            if "." in qual:
                continue
            entries.append(("func", fi))
        seen_func = set()
        for kind, obj in entries:
            self.ctx.tick(5)
            try:
                if kind == "func":
                    if obj.qual in seen_func or obj.qual in self.called:
                        continue
                    seen_func.add(obj.qual)
                    self.call_user(obj, [], {}, obj.node, symbolic=True)
                else:
                    self.run_class_entry(obj)
            except Stop:
                raise
            except RecursionError:
                self.ctx.notes.append("recursion limit (entry)")
            except Exception as e:  # keep analysing the remaining entries
                self.ctx.notes.append(f"entry {getattr(obj, 'name', '?')} failed: {type(e).__name__}")
        # classes that are referenced but whose methods were never executed (instantiated, methods unused)
        for ci in list(self.classes.values()):
            for mname, fi in ci.methods.items():
                if fi.qual in self.called or mname in self.referenced or mname == "__init__":
                    continue
                if ci.name in self.referenced and not self._class_instantiated(ci.name):
                    continue
                if ci.name in [c.name for c in self.classes.values() if c.name not in self.referenced]:
                    continue
                try:
                    obj = self._symbolic_instance(ci)
                    self.call_user(fi, [], {}, fi.node, bound_self=obj, symbolic=True)
                except Stop:
                    raise
                except Exception:
                    pass
        self._run_unexecuted_closures(seen_func)

    def _run_unexecuted_closures(self, seen_func: set) -> None:
        """Closures, decorator wrappers and lambdas that were defined but never executed (a decorator's inner function, a callback handed to something unknown) still
        hold behaviour.  Run each once with unknown (not user-controlled) arguments; running a wrapper can define further inner functions, so repeat a few rounds."""
        for _ in range(3):
            todo = [fi for qual, fi in list(self.funcs.items()) if fi.cls is None and qual not in self.called and qual not in seen_func]
            lam = [fi for fi in getattr(self, "pending_lambdas", []) if id(fi.node) not in self.ran_lambdas]
            if not todo and not lam:
                return
            for fi in todo + lam:
                self.ctx.tick(5)
                try:
                    seen_func.add(fi.qual)
                    if fi.is_lambda:
                        self.ran_lambdas.add(id(fi.node))
                    self.call_user(fi, [], {}, fi.node, symbolic=False)
                except Stop:
                    raise
                except RecursionError:
                    self.ctx.notes.append("recursion limit (closure)")
                except Exception as e:
                    self.ctx.notes.append(f"closure {getattr(fi, 'name', '?')} failed: {type(e).__name__}")

    def _class_instantiated(self, name: str) -> bool:
        return (name + ".__init__") in self.called

    def _symbolic_instance(self, ci: ClassInfo) -> V:
        obj = V(c=UNK, kind="obj", cls=ci.name, attrs=dict(ci.attrs), lines=frozenset({ci.node.lineno}))
        init = self.find_method(ci.name, "__init__")
        if init is not None:
            self.call_user(init, [], {}, init.node, bound_self=obj, symbolic=True)
        return obj

    def run_class_entry(self, ci: ClassInfo) -> None:
        obj = self._symbolic_instance(ci)
        for mname, fi in ci.methods.items():
            if mname == "__init__":
                continue
            if fi.qual in self.called and mname in self.referenced:
                continue
            if fi.kind == "property" and mname in self.referenced:
                continue
            self.call_user(fi, [], {}, fi.node, bound_self=obj, symbolic=True)


# ====================================================================================================
def _has_own_break(body: list) -> bool:
    for n in body:
        if isinstance(n, ast.Break):
            return True
        if isinstance(n, (ast.For, ast.While, ast.AsyncFor)):
            if _has_own_break(n.orelse):
                return True
            continue
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        for fld in ("body", "orelse", "finalbody"):
            sub = getattr(n, fld, None)
            if isinstance(sub, list) and _has_own_break(sub):
                return True
        if isinstance(n, ast.Try):
            for h in n.handlers:
                if _has_own_break(h.body):
                    return True
        if isinstance(n, (ast.With, ast.AsyncWith)) and _has_own_break(n.body):
            return True
    return False


def _unconditional_recursion(fn) -> bool:
    name = fn.name
    if any(isinstance(x, (ast.Import, ast.ImportFrom)) for x in ast.walk(fn)):
        return False
    params = {a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)}

    def passthrough(call) -> bool:
        return all(isinstance(a, ast.Name) and a.id in params for a in call.args) and all(isinstance(k.value, ast.Name) and k.value.id in params for k in call.keywords)
    def unguarded_self_call(expr) -> bool:
        """A call to the function itself that is not under a conditional expression, boolean short-circuit, lambda or comprehension."""
        def walk(node, guarded):
            if isinstance(node, (ast.IfExp, ast.BoolOp, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                guarded = True
            if isinstance(node, ast.Call) and not guarded:
                f = node.func
                if isinstance(f, ast.Name) and f.id == name:
                    return True
                if isinstance(f, ast.Attribute) and f.attr == name and isinstance(f.value, ast.Name) and f.value.id in ("self", "cls"):
                    return True
            return any(walk(ch, guarded) for ch in ast.iter_child_nodes(node))
        return walk(expr, False)

    for st in fn.body:
        if isinstance(st, (ast.If, ast.Try, ast.For, ast.While, ast.With, ast.Match)):
            return False
        if isinstance(st, (ast.Return, ast.Raise)):
            if isinstance(st, ast.Return) and st.value is not None and unguarded_self_call(st.value):
                return True
            return False
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
            if unguarded_self_call(st.value):
                return True
    return False


# ====================================================================================================
_OPENERS = ("def ", "class ", "async def ", "if ", "elif ", "else", "for ", "while ", "with ", "try", "except", "finally", "async for ", "async with ", "match ", "case ")
_DEDENT_KW = ("else", "elif ", "except", "finally")
_TERMINAL = ("return", "raise", "break", "continue")


def repair_flat_indent(text: str) -> Optional[str]:
    """Rebuild block structure for code whose indentation was flattened (every line at 0-1 spaces).
    Heuristic: a line ending in ':' opens a block; return/raise/break/continue end the block; else/except/finally
    close back to their opener; def/class at statement start return to the enclosing class (or top level)."""
    lines = text.replace("\t", " ").split("\n")
    if not any(l.strip().endswith(":") for l in lines):
        return None
    if max((len(l) - len(l.lstrip(" ")) for l in lines if l.strip()), default=0) > 1:
        return None                              # genuinely indented code: do not touch
    out: list = []
    openers: list = []                           # (keyword, level)
    has_one = any(l.startswith(" ") and l.strip() for l in lines)
    level = 0
    prev_open = False
    prev_term = False
    prev_blank = True
    prev_deco = False
    deco_level = 0
    defined: set = set()
    for raw in lines:
        s = raw.strip()
        if not s:
            out.append("")
            prev_blank = True
            continue
        first = s.split("(")[0].split(":")[0].split(" ")[0]
        m_def = re.match(r"(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)", s)
        calls_defined = bool(defined and not prev_open and re.match(r"(?:" + "|".join(map(re.escape, defined)) + r")\s*[(.]", s))     # `main()` / `Runner().run(x)`: a module-level call of something defined above
        if m_def:
            defined.add(m_def.group(1))
        if prev_open:
            level = level + 1
        elif prev_term:
            level = max(level - 1, 0)
        if has_one and not raw.startswith(" ") and not prev_open:
            level = 0                    # flush-left among 1-space lines: the original had this at top level
            openers = []
        if calls_defined:
            level = 0
            openers = []
        if s.startswith(_DEDENT_KW) or first in ("else", "try", "except", "finally"):
            if s.startswith(_DEDENT_KW):
                for k in range(len(openers) - 1, -1, -1):
                    if openers[k][0] in ("if", "elif", "try", "except", "for", "while") and openers[k][1] <= level:
                        level = openers[k][1]
                        del openers[k + 1:]
                        break
        elif s.startswith(("def ", "class ", "async def ", "@")):
            if prev_deco and not prev_open:
                level = deco_level                 # the def under a decorator stays at the decorator's level
            elif not prev_open:
                cls_levels = [lv for kw, lv in openers if kw == "class"]
                level = (cls_levels[-1] + 1) if cls_levels and not prev_blank and False else (cls_levels[-1] + 1 if cls_levels else 0)
        elif prev_blank and s.startswith(("import ", "from ")) and not prev_open:
            level = 0
        elif s.startswith("if __name__"):
            level = 0
        out.append("    " * level + s)
        prev_deco = s.startswith("@")
        deco_level = level
        kw = s.split(" ")[0].split(":")[0].split("(")[0]
        is_open = s.endswith(":") and not s.startswith("#")
        if is_open:
            openers.append((kw, level))
        prev_open = is_open
        prev_term = kw in _TERMINAL and not is_open
        prev_blank = False
    return "\n".join(out)


_BLOCK_KW_FOR_ELSE = ("if", "elif", "try", "except", "for", "while", "with", "else")


def _reindent(text: str, *, blank_ends: bool, terminal_ends: bool, single: bool, nest_all: bool, call_top: bool = False) -> Optional[str]:
    """One reading of flattened code.  Flat code is ambiguous (where does a body end?), so several policies exist:
    blank_ends    a blank line ends every open body (back to class level / top level);
    terminal_ends return / raise / break / continue end the body they are in;
    single        every block body is exactly one statement;
    nest_all      bodies run to the end of the text (only else/elif/except/finally and top-level markers dedent);
    call_top      a line that starts with the name of a function or class defined earlier (`main()`, `Runner().run(x)`) is a module-level call.
    A decorator keeps the next def at its own level; else/elif/except/finally return to their opener."""
    lines = text.replace("\t", " ").split("\n")
    if not any(l.strip().endswith(":") for l in lines):
        return None
    if max((len(l) - len(l.lstrip(" ")) for l in lines if l.strip()), default=0) > 1:
        return None
    out: list = []
    defined: set = set()
    openers: list = []                       # (keyword, level of the opener line)
    prev_level, prev_open, prev_term, prev_blank, prev_deco = 0, False, False, True, False
    body_first = False                       # the previous line was the first statement of a body (for `single`)
    for raw in lines:
        s = raw.strip()
        if not s:
            out.append("")
            prev_blank = True
            continue
        kw = s.split(" ")[0].split(":")[0].split("(")[0]
        is_def = s.startswith(("def ", "class ", "async def ", "@"))
        m_def = re.match(r"(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)", s)
        calls_defined = bool(call_top and defined and not prev_open and not prev_deco and re.match(r"(?:" + "|".join(map(re.escape, defined)) + r")\s*[(.]", s))
        if m_def:
            defined.add(m_def.group(1))
        if prev_open:
            level = prev_level + 1
        elif prev_deco:
            level = prev_level
        else:
            level = prev_level
            if single and body_first:
                level = max(prev_level - 1, 0)
            elif prev_term and terminal_ends:
                level = max(prev_level - 1, 0)
            if blank_ends and prev_blank and openers:
                cls = [lv for k, lv in openers if k == "class"]
                level = (cls[-1] + 1) if (cls and is_def) else 0
        if kw in ("else", "elif", "except", "finally"):
            for k in range(len(openers) - 1, -1, -1):
                if openers[k][0] in _BLOCK_KW_FOR_ELSE and openers[k][1] <= level:
                    level = openers[k][1]
                    break
        elif is_def and not prev_open and not prev_deco and not nest_all:
            cls = [lv for k, lv in openers if k == "class"]
            level = (cls[-1] + 1) if cls else 0
        elif s.startswith("if __name__") or calls_defined:
            level = 0
        while openers and openers[-1][1] >= level and not (kw in ("else", "elif", "except", "finally") and openers[-1][1] == level and False):
            openers.pop()
        out.append("    " * level + s)
        is_open = s.endswith(":") and not s.startswith("#")
        body_first = bool(prev_open) and not is_open
        if is_open:
            openers.append((kw, level))
        prev_open, prev_term = is_open, (kw in _TERMINAL and not is_open)
        prev_deco = s.startswith("@")
        prev_level, prev_blank = level, False
    return "\n".join(out)


def flat_indent_candidates(text: str) -> list:
    """Alternative readings of flattened code that parse as Python (the analyser keeps the union of what they find)."""
    seen: set = set()
    res: list = []
    for kw in (dict(blank_ends=True, terminal_ends=True, single=False, nest_all=False, call_top=True),
               dict(blank_ends=False, terminal_ends=False, single=False, nest_all=True),
               dict(blank_ends=False, terminal_ends=True, single=False, nest_all=False, call_top=True),
               dict(blank_ends=False, terminal_ends=False, single=True, nest_all=False, call_top=True),
               dict(blank_ends=False, terminal_ends=False, single=False, nest_all=True, call_top=True)):
        try:
            cand = _reindent(text, **kw)
            if cand and cand not in seen:
                seen.add(cand)
                ast.parse(cand)
                res.append(cand)
        except (SyntaxError, ValueError, RecursionError):
            continue
    return res


def parse_python(text: str):
    """Parse with a few salvage strategies.  Returns (tree, source) or (None, None)."""
    for candidate in (text, textwrap.dedent(text)):
        try:
            return ast.parse(candidate), candidate
        except SyntaxError:
            pass
        except (ValueError, RecursionError, MemoryError):
            return None, None
    # flattened indentation (e.g. text copied through JSON / PDF): rebuild the blocks
    fixed = repair_flat_indent(text)
    if fixed is not None:
        try:
            return ast.parse(fixed), fixed
        except SyntaxError:
            pass
    for cand in flat_indent_candidates(text):
        try:
            return ast.parse(cand), cand
        except (SyntaxError, ValueError, RecursionError):
            continue
    # strip shell prompt markers / markdown fences
    cleaned = re.sub(r"^\s*(>>>|\.\.\.) ?", "", text, flags=re.M)
    try:
        return ast.parse(cleaned), cleaned
    except Exception:
        pass
    # last resort: drop trailing lines until it parses (truncated snippets)
    lines = text.splitlines()
    for cut in range(1, min(6, len(lines))):
        try:
            return ast.parse("\n".join(lines[:-cut])), "\n".join(lines[:-cut])
        except Exception:
            continue
    return None, None


_NET_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "fetch", "urlretrieve", "create_connection"}


def _names_in(node) -> set:
    return {x.id for x in ast.walk(node) if isinstance(x, ast.Name)}


def check_decoy_validation(tree, ctx: Ctx) -> None:
    """A function checks one value (startswith / allowlist / hostname test) but its network call uses a different one:
    the check protects nothing.  Purely structural: it compares which names reach the check and which reach the request."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self", "cls"}
        if not params:
            continue
        guarded: dict = {}
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            rejects = any(isinstance(b, (ast.Raise, ast.Return, ast.Continue)) for b in node.body)
            if not rejects:
                continue
            t = node.test
            urlish = any(isinstance(x, ast.Attribute) and x.attr in ("startswith", "endswith", "hostname", "netloc", "scheme") for x in ast.walk(t))                 or any(isinstance(x, ast.Call) and isinstance(x.func, (ast.Name, ast.Attribute)) and getattr(x.func, "id", getattr(x.func, "attr", "")) in ("urlparse", "urlsplit") for x in ast.walk(t))                 or any(isinstance(x, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in x.ops) for x in ast.walk(t))
            if not urlish:
                continue
            for p in _names_in(t) & params:
                guarded.setdefault(p, node.lineno)
        if not guarded:
            continue
        # names derived from a guarded parameter by simple assignment
        derived = {p: {p} for p in guarded}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                rhs = _names_in(node.value)
                for p, ds in derived.items():
                    if rhs & ds:
                        for tg in node.targets:
                            ds |= _names_in(tg)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            fnm = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if fnm not in _NET_METHODS:
                continue
            if isinstance(node.func, ast.Attribute):          # d.get(k) is a dict lookup; only real HTTP clients count
                base = node.func.value
                bname = (base.id if isinstance(base, ast.Name) else base.attr if isinstance(base, ast.Attribute) else "").lower()
                if not re.search(r"requests|httpx|aiohttp|urllib|http|session|client|conn|pool", bname) and fnm not in ("urlopen", "urlretrieve", "create_connection"):
                    continue
            elif fnm not in ("urlopen", "fetch", "urlretrieve", "create_connection"):
                continue
            url = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in ("url", "address", "host")), None)
            if url is None:
                continue
            used = _names_in(url)
            for p, ds in derived.items():
                if not (used & ds):
                    ctx.emit(Event(cap="VALIDATION_BYPASS", line=node.lineno, name=fnm, target=p, flags={"validation_decoy"},
                                   lines={guarded[p], node.lineno}))
                    break


def analyze_tree(tree, ctx: Ctx, src: str = "", js: bool = False, hole_labels: frozenset = EMPTY, hole_src: frozenset = EMPTY) -> None:
    it = Interp(tree, ctx, hole_labels, hole_src, src, js=js)
    try:
        it.run()
    except Stop as s:
        ctx.notes.append(f"analysis stopped: {s}")
    except RecursionError:
        ctx.notes.append("recursion limit")
    it.mark_credential_reads()
    try:
        if len(src or "") <= 120_000:
            check_decoy_validation(tree, ctx)
            from .indirect import scan_indirect
            from .motifs import scan_motifs
            scan_indirect(tree, ctx, src)
            scan_motifs(tree, ctx, src)
    except Exception as e:
        ctx.notes.append(f"structural checks failed: {type(e).__name__}")


def analyze_python_text(text: str, ctx: Ctx, hole_labels: frozenset = EMPTY, hole_src: frozenset = EMPTY, nested: bool = False) -> bool:
    tree, src = parse_python(text)
    if tree is None:
        ctx.parsed_ok = False if not nested else ctx.parsed_ok
        ctx.notes.append("python parse failed")
        return False
    from .textscan import scan_python_texts, scan_python_secrets
    try:
        scan_python_texts(src, tree, ctx)
        scan_python_secrets(tree, ctx)
    except Stop:
        raise
    except Exception as e:
        ctx.notes.append(f"python text scan failed: {type(e).__name__}")
    it = Interp(tree, ctx, hole_labels, hole_src, src)
    try:
        it.run()
    except Stop as s:
        ctx.notes.append(f"python analysis stopped: {s}")
    except RecursionError:
        ctx.notes.append("python recursion limit")
    it.mark_credential_reads()
    try:
        if len(src or "") <= 120_000:
            check_decoy_validation(tree, ctx)
            from .indirect import scan_indirect
            from .motifs import scan_motifs
            scan_indirect(tree, ctx, src)
            scan_motifs(tree, ctx, src)
    except Exception as e:
        ctx.notes.append(f"structural checks failed: {type(e).__name__}")
    if not nested and len(text) < 60_000:
        _merge_flat_readings(text, src, ctx, hole_labels, hole_src)
    return True


def _merge_flat_readings(text: str, src: str, ctx: Ctx, hole_labels, hole_src) -> None:
    """Flattened code (no usable indentation) has no single correct block structure.  The primary reading has been analysed; analyse the other plausible
    readings too and keep any behaviour they add, so a body that the primary reading attached to the wrong block is still seen."""
    try:
        ast.parse(text)
        return                                   # real, parseable indentation: nothing to guess
    except (SyntaxError, ValueError, RecursionError):
        pass
    have = {(e.cap, e.line, e.name, str(e.target)) for e in ctx.events}
    for cand in flat_indent_candidates(text):
        if cand == src:
            continue
        alt = Ctx()
        alt.line_base = getattr(ctx, "line_base", 0)
        try:
            analyze_python_text(cand, alt, hole_labels, hole_src, nested=True)
        except Exception:
            continue
        added = 0
        for e in alt.events:
            key = (e.cap, e.line, e.name, str(e.target))
            if e.cap == "LOOP" and "recursion" in e.flags:
                continue                         # a call placed inside its own function by a wrong reading is not evidence of a runaway recursion
            if key not in have:
                have.add(key)
                ctx.events.append(e)
                added += 1
        if added:
            ctx.notes.append(f"flat-indent reading added {added} event(s)")
