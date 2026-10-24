"""Library semantics for the Python abstract interpreter.

Nothing here performs real I/O.  Each library call is mapped (via rules/api_semantics.yaml and a few
hand-written handlers) onto behaviour events and onto the abstract value that the real call would return.
"""
from __future__ import annotations

import ast
import base64
import binascii
import builtins as _builtins
import codecs
import os
import re
import zlib
from typing import Any, Optional

import yaml

from . import knowledge as K
from .events import (TRAVERSAL, ARBITRARY_FILE, BUILT, CMDSUB, COMPILED, DB, DECODED, DYNCODE, EMPTY, ENV, ENV_DUMP, FILE, HOLE, NET, QUOTED, SAFE_NUM, SECRET, SENS_SYS,
                     UNK, USER, VALIDATED, V, U, join_values)

DANGEROUS_ALIAS_MODULES = {"os", "subprocess", "pickle", "marshal", "ctypes", "importlib", "builtins", "shelve", "runpy", "pty", "shutil", "commands",
                           "cPickle", "dill", "socket", "sys", "base64", "codecs", "zlib", "binascii"}
CONVENTIONAL_ALIASES = {"np", "pd", "plt", "tf", "sns", "sp", "nx", "dt", "ET", "osp", "pkl", "bs4", "mp", "cp", "jnp", "sk", "th", "F", "nn"}
# aliasing sys/base64/codecs is common & harmless on its own; only flag when the *call* is an executor
EXEC_CAPS_FOR_ALIAS = {"EXEC_SHELL", "EXEC_PROC", "EVAL", "LOAD_MODULE", "DESERIALIZE"}

_SEM_PATH = os.path.join(K.RULES_DIR, "api_semantics.yaml")
_SEM: dict = {}


def semantics() -> dict:
    global _SEM
    if not _SEM:
        try:
            with open(_SEM_PATH, encoding="utf-8") as f:
                _SEM = yaml.safe_load(f) or {}
        except Exception:
            _SEM = {"functions": {}, "methods": {}}
        _SEM.setdefault("functions", {})
        _SEM.setdefault("methods", {})
    return _SEM


USER_SOURCE_PREFIXES = ("flask.request", "bottle.request", "sys.argv", "sys.stdin", "django.http.request", "falcon.request", "cgi.FieldStorage",
                        "tornado.web.RequestHandler.request", "starlette.requests.Request", "fastapi.Request")
SECRETY_ENV_KEYS = re.compile(r"(secret|token|passw|pwd|api[_-]?key|apikey|private|credential|auth|access[_-]?key|bearer|cookie|jwt|signing|encryption|_key$|^key$)", re.I)
JS_STR_ALIASES = {"toLowerCase": "lower", "toUpperCase": "upper", "trim": "strip", "trimStart": "lstrip", "trimEnd": "rstrip", "replaceAll": "replace",
                  "padStart": "rjust", "padEnd": "ljust", "includes": "__contains__", "indexOf": "find", "toString": "__tostr__", "toLocaleLowerCase": "lower",
                  "substring": "__slice__", "substr": "__slice__", "slice": "__slice__", "charAt": "__slice__", "concat": "__concat__", "repeat": "__repeat__",
                  "match": "__unknown__", "test": "__unknown__", "localeCompare": "__unknown__", "normalize": "__tostr__", "at": "__slice__"}
PURE_STR_METHODS = {"upper", "lower", "strip", "lstrip", "rstrip", "replace", "title", "capitalize", "swapcase", "zfill", "ljust", "rjust", "center",
                    "removeprefix", "removesuffix", "casefold", "expandtabs", "translate"}


def _clean_list(items) -> list:
    return [x for x in items if x is not None]


def _skel(v: Optional[V]) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v.c, str):
        return v.c
    return None


def _join_skel(items: list) -> str:
    out = []
    for x in items:
        s = x.c if isinstance(x.c, str) else (str(x.c) if isinstance(x.c, (int, float)) and not isinstance(x.c, bool) else HOLE)
        out.append(s)
    return " ".join(out)


def _pick(specs, args: list, kws: dict) -> Optional[V]:
    if not specs:
        return None
    for s in specs:
        if isinstance(s, int):
            if s < len(args):
                return args[s]
        elif isinstance(s, str) and s in kws:
            return kws[s]
    return None


def _pick_all(specs, args: list, kws: dict) -> list:
    out = []
    for s in specs or []:
        if isinstance(s, int):
            if s < len(args):
                out.append(args[s])
        elif isinstance(s, str) and s in kws:
            out.append(kws[s])
    return out


_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node", "powershell", "pwsh", "cmd", "cmd.exe", "php", "env"}


class LibMixin:
    BUILTIN_NAMES = set(dir(_builtins)) - {"__name__", "__doc__", "__package__", "__loader__", "__spec__", "__build_class__", "__debug__"}

    # ---------------------------------------------------------------------------------------------
    def install_builtins(self) -> None:
        sem = semantics()
        self._funcs = sem["functions"]
        self._methods = sem["methods"]
        self._run_targets: set = set()

    def v_for_q(self, q: str, lines=EMPTY) -> V:
        v = V(q=q, kind="func", lines=frozenset(lines))
        for p in USER_SOURCE_PREFIXES:
            if q == p or q.startswith(p + "."):
                v.labels = U({USER})
                v.src = frozenset({"incoming request / command-line input"})
                break
        return v

    # ---------------------------------------------------------------------------------------------
    def module_attr(self, base: V, q: str, name: str, line: int) -> V:
        if q == "os.environ":
            return V(q=q, kind="environ", labels=U({ENV, ENV_DUMP}), src=frozenset({"all environment variables"}), lines=frozenset({line}))
        if q == "sys.executable":
            return V(c="python", kind="str")
        if q in ("sys.platform",):
            return V(c="linux", kind="str")
        if q in ("os.sep", "os.path.sep"):
            return V(c="/", kind="str")
        if q in ("os.linesep",):
            return V(c="\n", kind="str")
        if q == "os.name":
            return V(c="posix", kind="str")
        if q == "js.process.env":
            return V(q=q, kind="environ", labels=U({ENV, ENV_DUMP}), src=frozenset({"all environment variables"}), lines=frozenset({line}))
        if q in ("js.process.argv",):
            return V(q="sys.argv", kind="list", c=UNK, labels=U({USER}), src=frozenset({"command-line arguments"}), lines=frozenset({line}))
        if q == "js.document.cookie":
            return V(c=HOLE, kind="str", labels=U({SECRET}), src=frozenset({"the browser cookies"}), lines=frozenset({line}))
        if q in ("js.window.location.href", "js.location.href", "js.window.location.search", "js.location.search", "js.window.location.hash", "js.location.hash",
                 "js.document.location.href", "js.document.URL", "js.document.referrer"):
            return V(c=HOLE, kind="str", labels=U({USER}), src=frozenset({"the page URL"}), lines=frozenset({line}))
        if q in ("sys.argv",):
            return V(q=q, kind="list", c=UNK, labels=U({USER}), src=frozenset({"command-line arguments"}), lines=frozenset({line}))
        if q in ("sys.stdin",):
            return V(q=q, kind="obj", labels=U({USER}), src=frozenset({"standard input"}), lines=frozenset({line}))
        if q == "string.ascii_letters":
            return V(c="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", kind="str")
        v = self.v_for_q(q, [line])
        v.alias = base.alias
        v.labels = U(v.labels, base.labels)
        if base.labels:
            v.src = U(v.src, base.src)
        # class-like capitalised attributes
        last = name
        if last[:1].isupper() and not last.isupper():
            v.kind = "class"
        elif q.count(".") == 1:
            v.kind = "module" if not last[:1].isupper() else "class"
        return v

    # ---------------------------------------------------------------------------------------------
    def call_lib(self, q: str, callee: V, args: list, kws: dict, n, recv: Optional[V] = None) -> V:
        line = n.lineno
        # normalise a few spellings
        if q.startswith("builtins."):
            nm = q.split(".", 1)[1]
            if nm in ("bytes.fromhex", "bytearray.fromhex"):                 # hex text decoded to bytes: a decoder, like binascii.unhexlify
                return self.s_decode("bytes.fromhex", callee, args, kws, n, recv)
            h = getattr(self, "b_" + nm, None)
            if h is not None:
                return h(callee, args, kws, n)
            spec = self._funcs.get(q)
            if spec:
                return self.apply_spec(q, spec, callee, args, kws, n, recv)
            return self.unknown_lib(q, callee, args, kws, n, recv)
        h = self.SPECIAL.get(q)
        if h is not None:
            return getattr(self, h)(q, callee, args, kws, n, recv)
        spec = self._funcs.get(q)
        if spec is None and q.startswith("os.path."):
            spec = None
        if spec is not None:
            return self.apply_spec(q, spec, callee, args, kws, n, recv)
        # third party paths with deep names:  a.b.c.func -> try last two components
        parts = q.split(".")
        if len(parts) > 2:
            alt = ".".join(parts[-2:])
            h = self.SPECIAL.get(alt)
            if h is not None and parts[0] in ("pathlib", "base64", "binascii", "codecs", "zlib", "json", "yaml", "shutil", "os"):
                return getattr(self, h)(alt, callee, args, kws, n, recv)
        return self.unknown_lib(q, callee, args, kws, n, recv)

    def unknown_lib(self, q: str, callee: V, args: list, kws: dict, n, recv: Optional[V]) -> V:
        lab = set(callee.labels)
        src = set(callee.src)
        lines = {n.lineno}
        for a in list(args) + list(kws.values()):
            lab |= a.all_labels()
            src |= a.all_src()
            lines |= a.all_lines()
        if recv is not None:
            lab |= recv.labels
        # decoding-ish names
        last = q.rsplit(".", 1)[-1].lower()
        if re.search(r"(decode|decompress|unhexlify|fromhex|b64|unpack|decrypt|deobfus|unzip|inflate|rot13)", last):
            lab.add(DECODED)
        # request / file reading style names inherit the nature of their receiver
        return V(c=UNK, labels=U(lab), src=U(src), lines=frozenset(lines))

    # ---------------------------------------------------------------------------------------------
    def spec_flags(self, spec: dict, callee: V, cap: str) -> set:
        fl = set(spec.get("flags") or [])
        if callee is not None and callee.alias:
            if callee.alias == "<dyn>":
                fl.add("dynamic_attr")
            elif cap in EXEC_CAPS_FOR_ALIAS:
                fl.add("aliased_import")
        return fl

    def apply_spec(self, q: str, spec: dict, callee: V, args: list, kws: dict, n, recv: Optional[V] = None) -> V:
        cap = spec.get("cap", "NONE")
        line = n.lineno
        fl = self.spec_flags(spec, callee, cap)
        ret_labels = set(spec.get("ret") or [])
        # ---- non-event specs
        if cap == "NONE":
            return self.value_for_none(q, spec, args, kws, n, ret_labels)
        t = _pick(spec.get("t"), args, kws)
        pv = _pick_all(spec.get("p"), args, kws)
        if cap in ("EXEC_SHELL", "EXEC_PROC"):
            return self.do_exec(q, spec, cap, t, args, kws, n, fl, ret_labels)
        if cap == "EVAL":
            return self.do_eval(q, spec, t, args, kws, n, fl)
        if cap == "LOAD_MODULE":
            return self.do_load_module(q, spec, t, n, fl, callee)
        if cap == "DESERIALIZE":
            return self.do_deserialize(q, spec, t, args, kws, n, fl, ret_labels)
        if cap in ("NET_FETCH", "NET_SEND", "NET_CONNECT", "NET_LISTEN", "DNS"):
            return self.do_net(q, spec, cap, t, pv, args, kws, n, fl, ret_labels, recv)
        if cap == "SQL_EXEC":
            return self.do_sql(q, spec, t, pv, args, kws, n, fl, recv)
        if cap == "DELETE":
            return self.do_delete(q, spec, t, args, kws, n, fl)
        if cap == "PRIV":
            return self.do_priv(q, spec, t, args, kws, n, fl)
        if cap == "SPAWN":
            return self.do_spawn(q, spec, args, kws, n, fl)
        if cap == "KILL":
            tt = t.skel() if t is not None else None
            pid = t.c if t is not None else None
            sigfl = set(fl)
            if isinstance(pid, int) and pid in (-1, 0, 1):
                sigfl.add("all_procs")
            self.emit("KILL", line, q, target=str(pid) if pid is not None else HOLE, tl=t.all_labels() if t else EMPTY, flags=sigfl)
            return V()
        if cap == "INSTALL_PKG":
            return self.do_pip_main(q, spec, t, n)
        if cap == "SLEEP":
            return V()
        if cap == "READ_FILE":
            return self.do_read_method(q, spec, recv, n)
        # generic event
        tl = t.all_labels() if t else EMPTY
        pl = U(*[x.all_labels() for x in pv])
        tgt = t.skel() if t is not None and t.is_str() else None
        self.emit(cap, line, q, target=tgt, tl=tl, pl=pl, flags=fl)
        return V(c=UNK, labels=U(ret_labels))

    # ---------------------------------------------------------------------------------------------
    def value_for_none(self, q: str, spec: dict, args: list, kws: dict, n, ret_labels: set) -> V:
        line = n.lineno
        if spec.get("sanitize"):
            a0 = args[0] if args else V()
            return V(c=HOLE, kind="str", labels=U(a0.all_labels() - {USER, TRAVERSAL, ARBITRARY_FILE}, {spec["sanitize"]}), src=a0.all_src(), lines=frozenset({line}))
        if spec.get("passthrough") is not None:
            i = spec["passthrough"]
            if i < len(args):
                a = args[i]
                nv = V(c=a.c, kind=a.kind, labels=a.labels, src=a.src, lines=a.lines | {line}, items=a.items, n=a.n, cls=a.cls)
                if q == "os.path.dirname" and isinstance(a.c, str):
                    nv.c = a.c.rsplit("/", 1)[0] if "/" in a.c else ""
                return nv
        if spec.get("mkobj"):
            return V(c=UNK, kind="obj", cls=spec["mkobj"], meta={"host": None}, lines=frozenset({line}))
        if spec.get("archive_of") is not None:
            i = spec["archive_of"]
            src_p = args[i] if i < len(args) else None
            lab, srcs = self.path_labels(src_p.skel() if src_p is not None else "")
            dest = args[0].skel() if args and args[0].is_str() else None
            if dest:
                self.emit("WRITE_FILE", line, q, target=dest + ".zip", pathc=K.classify_path(dest), pl=lab, flags={"archive"}, extra={"src": srcs})
            return V(c=(dest + ".zip") if dest else HOLE, kind="str", labels=lab, src=srcs, lines=frozenset({line}))
        if ret_labels:
            cls = None
            return V(c=HOLE if "FILE" in ret_labels else UNK, labels=U(ret_labels), kind="list" if q in ("os.listdir", "glob.glob", "os.walk", "os.scandir") else None,
                     src=frozenset({"a directory listing"}) if FILE in ret_labels else EMPTY, lines=frozenset({line}))
        if q == "yaml.full_load" or q == "numpy.load":
            a0 = args[0] if args else V()
            return V(c=UNK, labels=a0.all_labels(), src=a0.all_src())
        return V(c=UNK, lines=frozenset({line}))

    # ---------------------------------------------------------------------------------------------
    # process execution
    def do_exec(self, q, spec, cap, t, args, kws, n, fl, ret_labels) -> V:
        from . import shfe
        line = n.lineno
        shell_kw = kws.get("shell")
        shell = bool(shell_kw is not None and shell_kw.c is True)
        t = t or kws.get("args") or V()
        items = t.items if isinstance(t.items, list) else None
        labels = t.all_labels()
        src = t.all_src()
        text: Optional[str]
        if items is not None:
            text = _join_skel(items)
        else:
            text = t.skel()
        if kws.get("executable") is not None:
            labels = U(labels, kws["executable"].all_labels())
        ret_cls = "subprocess.Popen" if q.endswith("Popen") or q.endswith("create_subprocess_exec") or q.endswith("create_subprocess_shell") else "subprocess.CompletedProcess"
        rv = V(c=UNK, kind="obj", cls=ret_cls, labels=U(ret_labels, {CMDSUB}), lines=frozenset({line}))
        if cap == "EXEC_SHELL" or shell:
            if text is None:
                text = HOLE
            fl2 = set(fl)
            if shell and cap != "EXEC_SHELL":
                fl2.add("shell_true")
            witness = None
            danger_labels = labels & {USER, NET}
            if HOLE in text and danger_labels and QUOTED not in labels:
                witness = shfe.probe_shell(text)
                if witness:
                    fl2.add("injectable")
            elif danger_labels and QUOTED not in labels and VALIDATED not in labels and text == HOLE:
                fl2.add("injectable")
            if labels & {USER} and QUOTED not in labels:
                fl2.add("tainted")
            if VALIDATED in labels:
                fl2.add("validated")
            if DECODED in labels:
                fl2.add("decoded")
            self.emit("EXEC_SHELL", line, q, target=text, tl=labels, flags=fl2, extra={"witness": witness, "src": src}, lines=t.all_lines())
            if self.ctx.depth <= 3 and text.replace(HOLE, "").strip():
                if DECODED in labels:
                    self.ctx.in_decoded += 1
                try:
                    shfe.analyze_shell(text, self.ctx, hole_labels=labels, hole_src=src, line_pin=line)
                finally:
                    if DECODED in labels:
                        self.ctx.in_decoded -= 1
            return rv
        # EXEC_PROC
        fl2 = set(fl)
        if items is not None:
            first = items[0] if items else V()
            if first.all_labels() & {USER, NET}:
                fl2.add("argv_tainted")
            elif any(x.all_labels() & {USER, NET} for x in items[1:]):
                fl2.add("args_tainted")
            if DECODED in first.all_labels():
                fl2.add("decoded")
            elif DECODED in labels and isinstance(first.c, str) and os.path.basename(first.c).lower() in _INTERPRETERS:
                fl2.add("decoded")        # sh -c <decoded>, python -c <decoded>: the decoded text is the program
            if DECODED in labels and "decoded" not in fl2:
                first = V(c=first.c, kind=first.kind, labels=U(first.labels, set()), src=first.src, lines=first.lines)
            self.emit("EXEC_PROC", line, q, target=text, tl=first.all_labels(), pl=U(*[x.all_labels() for x in items[1:]]) if items else EMPTY, flags=fl2,
                      extra={"argv": [x.c if isinstance(x.c, str) else HOLE for x in items], "src": src}, lines=t.all_lines())
            if items and self.ctx.depth <= 3:
                shfe.analyze_argv(list(items), self.ctx, line)
        else:
            if text is None:
                fl2.add("argv_unknown")
                text = HOLE
            else:
                fl2.add("argv_str")
            if labels & {USER, NET}:
                fl2.add("argv_tainted")
            self.emit("EXEC_PROC", line, q, target=text, tl=labels, flags=fl2, extra={"src": src}, lines=t.all_lines())
            if text and text != HOLE and self.ctx.depth <= 3:
                shfe.analyze_shell(text, self.ctx, hole_labels=labels, hole_src=src, line_pin=line)
        return rv

    # ---------------------------------------------------------------------------------------------
    def do_eval(self, q, spec, t, args, kws, n, fl) -> V:
        line = n.lineno
        t = t or V()
        labels = t.all_labels()
        src = t.all_src()
        text = t.skel()
        if text is None and isinstance(t.meta, dict) and isinstance(t.meta.get("code"), str):
            text = t.meta["code"]
        fl2 = set(fl)
        if COMPILED in labels:
            fl2.add("compiled")
        if DYNCODE in labels:
            fl2.add("dyncode")
        if DECODED in labels:
            fl2.add("decoded")
        if BUILT in labels:
            fl2.add("built_string")
        if text is not None and HOLE not in text and "decoded" not in fl2 and not (labels & {USER, NET, FILE, DB, ENV}):
            fl2.add("const_arg")
        if USER in labels and VALIDATED not in labels:
            fl2.add("tainted")
        if "compile" in fl2:
            mode = (args[2].exact() if len(args) > 2 else kws.get("mode").exact() if kws.get("mode") is not None else None)
            if mode == "exec":
                fl2.add("compile_exec")
        self.emit("EVAL", line, q, target=text if text is not None else HOLE, tl=labels, flags=fl2, extra={"src": src}, lines=t.all_lines())
        # look inside the code that would run
        if "compile" in fl2:
            return V(c=UNK, kind="code", labels=U(labels, {COMPILED}), src=src, meta={"code": text}, lines=frozenset({line}))
        inner = text
        if inner and self.ctx.depth <= 3 and "const_arg" in fl2 | ({"decoded"} if "decoded" in fl2 else set()) or (inner and "decoded" in fl2):
            self.run_nested_code(inner, line, labels, src)
        return V(c=UNK, labels=U(labels - {COMPILED}), src=src, lines=frozenset({line}))

    def run_nested_code(self, text: str, line: int, labels, src) -> None:
        from . import pyfe, shfe
        old = self.ctx.pin_line
        if not old:
            self.ctx.pin_line = line + self.ctx.line_base
        self.ctx.depth += 1
        from .events import DECODED as _DEC
        dec = _DEC in labels
        if dec:
            self.ctx.in_decoded += 1
        try:
            tree, s = pyfe.parse_python(text)
            if tree is not None and not re.match(r"^\s*(sudo\s+|rm|curl|wget|bash|sh|cat|echo|chmod|nc)\b", text):
                pyfe.analyze_python_text(text, self.ctx, labels, src, nested=True)
            else:
                shfe.analyze_shell(text, self.ctx, hole_labels=labels, hole_src=src, line_pin=line)
        finally:
            if dec:
                self.ctx.in_decoded -= 1
            self.ctx.depth -= 1
            self.ctx.pin_line = old

    def do_load_module(self, q, spec, t, n, fl, callee) -> V:
        line = n.lineno
        t = t or V()
        name = t.exact()
        labels = t.all_labels()
        fl2 = set(fl)
        if labels & {BUILT, DECODED, USER, NET, FILE, DB}:
            fl2.add("dynamic_name")
        if BUILT in labels:
            fl2.add("built_string")
        if USER in labels and VALIDATED not in labels:
            fl2.add("tainted")
        if VALIDATED in labels:
            fl2.add("validated")
        self.emit("LOAD_MODULE", line, q, target=name if name is not None else HOLE, tl=labels, flags=fl2, lines=t.all_lines())
        if name:
            v = V(q=name, kind="module", c=UNK, lines=frozenset({line}))
            if "dynamic_name" in fl2 and name.split(".")[0] in ("os", "subprocess", "socket", "ctypes", "pickle", "marshal", "shutil", "pty", "importlib", "builtins", "sys", "commands", "runpy"):
                v.alias = "<dyn>"
            return v
        return V(c=UNK, kind="module", labels=labels, src=t.all_src(), lines=frozenset({line}))

    def do_deserialize(self, q, spec, t, args, kws, n, fl, ret_labels) -> V:
        line = n.lineno
        t = t or V()
        labels = t.all_labels()
        path = None
        pathv = None
        if t.kind == "file" and t.meta:
            path = t.meta.get("path")
            pathv = t.meta.get("pathv")
            labels = U(labels, pathv.all_labels() if pathv is not None else EMPTY)
        elif t.is_str() and ("shelve" in fl or "torch_load" in fl or "pickle" in fl and not t.meta):
            path = t.skel()
        fl2 = set(fl)
        pc = K.classify_path(path) if path else set()
        if labels & {USER, NET}:
            fl2.add("tainted_source")
        if isinstance(t.c, (bytes, bytearray)) or (isinstance(t.c, str) and t.c not in (UNK, HOLE) and HOLE not in t.c and t.is_str() and ("pickle" in fl or "marshal" in fl)):
            if len(t.c) >= 4 and ("pickle" in fl or "marshal" in fl):
                fl2.add("literal_blob")          # a serialized object written into the source itself
        if "TEMP" in pc or "USER_PATH" in pc:
            fl2.add("untrusted_path")
        if path and re.search(r"(untrusted|upload|download|user|external|attacker|remote|incoming|tmp|cache|temp)", path, re.I):
            fl2.add("untrusted_name")
        if "yaml_unsafe" in fl2 and False:
            pass
        loader = kws.get("Loader")
        if q == "yaml.load":
            pass
        self.emit("DESERIALIZE", line, q, target=path if path else (t.skel() if t.is_str() else HOLE), tl=labels, pathc=pc, flags=fl2, lines=t.all_lines())
        return V(c=UNK, labels=U(ret_labels, labels & {NET, USER}, {DYNCODE} if "shelve" in fl2 else EMPTY), kind="dict" if "shelve" in fl2 else None,
                 items={} if "shelve" in fl2 else None, lines=frozenset({line}))

    # ---------------------------------------------------------------------------------------------
    # network
    def do_net(self, q, spec, cap, t, pv, args, kws, n, fl, ret_labels, recv) -> V:
        line = n.lineno
        fl2 = set(fl)
        t = t or V()
        # urllib Request object
        if t.cls == "urllib.request.Request" and t.meta:
            url_v = t.meta.get("url") or V()
            data_v = t.meta.get("data")
            if data_v is not None and data_v.c is not None:
                cap = "NET_SEND"
                pv = list(pv) + [data_v]
            t = url_v
        urlish = spec.get("urlish")
        # method-style spec on unknown receiver: require URL-looking first arg
        if urlish and (recv is None or recv.cls != "requests.Session") and recv is not None and recv.q is None:
            s0 = t.skel() or ""
            if not re.match(r"^(https?|ftp|ws|wss)://|^" + HOLE, s0) and not (t.labels & {USER}):
                return V(c=UNK, labels=t.all_labels())
        # method arg (requests.request / http.client request)
        if spec.get("method_arg") is not None:
            ma = _pick([spec["method_arg"]], args, kws)
            m = (ma.exact() or "").upper() if ma is not None else ""
            if m in ("GET", "HEAD", "OPTIONS"):
                cap = "NET_FETCH"
            elif m:
                cap = "NET_SEND"
        if spec.get("send_if") and cap != "NET_SEND":
            sv = _pick(spec["send_if"], args, kws)
            if sv is not None and sv.c is not None:
                cap = "NET_SEND"
                pv = list(pv) + [sv]
            else:
                cap = "NET_FETCH"
        # host determination
        url = None
        host = None
        hostc = None
        if spec.get("target_tuple") or (t.kind == "tuple" and isinstance(t.items, list)):
            hv = t.items[0] if isinstance(t.items, list) and t.items else t
            host = hv.skel() if hv.is_str() else None
            url = host
            hostc = K.classify_host(host) if host is not None else "UNKNOWN"
            if hv.labels & {USER} and (host is None or HOLE in (host or "")):
                hostc = "USER"
            tl = hv.all_labels()
            port_v = t.items[1] if isinstance(t.items, list) and len(t.items) > 1 else None
        else:
            url = t.skel() if t.is_str() else None
            tl = t.all_labels()
            if url is not None:
                scheme, host, hostc = K.host_of_url(url if "://" in url or url.startswith(HOLE) else "http://" + url)
                if scheme in K.DANGEROUS_SCHEMES:
                    fl2.add("dangerous_scheme")
                if scheme == "http":
                    fl2.add("plain_http")
                if hostc == "USER" or (url.startswith(HOLE) and not "://" in url):
                    hostc = "USER"
            else:
                host = None
                hostc = "USER" if tl & {USER, NET, FILE} else "UNKNOWN"
        if recv is not None and recv.meta and recv.meta.get("host") is not None and cap in ("NET_SEND", "NET_FETCH") and t is None:
            host = recv.meta["host"]
            hostc = K.classify_host(host)
        if "cloud_upload" in fl2:
            hostc = "EXTERNAL"
            host = host or "cloud storage"
        elif tl & {USER} and VALIDATED not in tl and QUOTED not in tl and hostc in ("USER", "UNKNOWN", None):
            fl2.add("user_url")
        elif tl & {USER} and hostc == "USER" and "cloud_upload" not in fl2:
            fl2.add("user_url")
        if VALIDATED in tl:
            fl2.add("validated")
        v_redirect = kws.get("allow_redirects")
        if v_redirect is not None and v_redirect.c is True or (v_redirect is None and q.startswith("requests.")):
            fl2.add("follows_redirects")
        if kws.get("verify") is not None and kws["verify"].c is False:
            fl2.add("insecure_tls")
        pl = set()
        psrc = set()
        for x in pv:
            pl |= x.all_labels()
            psrc |= x.all_src()
        if cap in ("NET_FETCH", "NET_SEND") and tl & {SECRET, SENS_SYS, ENV_DUMP}:
            pl |= tl & {SECRET, SENS_SYS, ENV_DUMP}
        # a secret in a header / auth argument is normal use for a real API, but sending it to a drop site or a bare IP is theft
        hdr_secret = False
        for hk in ("headers", "auth", "cookies"):
            hv = kws.get(hk)
            if hv is not None and SECRET in hv.all_labels():
                hdr_secret = True
        if hdr_secret:
            fl2.add("secret_in_header")
            if hostc in ("SUSPICIOUS", "DROPSITE", "EXTERNAL_IP", "USER", "UNKNOWN"):
                pl.add(SECRET)
        if recv is not None and recv.meta and recv.meta.get("host") and cap == "NET_SEND":
            host = recv.meta["host"]
            hostc = K.classify_host(host)
        self.emit(cap, line, q, target=url if url is not None else (host if host is not None else HOLE), tl=tl, pl=U(pl), flags=fl2, hostc=hostc,
                  extra={"src": U(psrc, t.all_src()), "host": host}, lines=t.all_lines() | frozenset().union(*[x.all_lines() for x in pv]) if pv else t.all_lines())
        mk = spec.get("mkobj")
        if mk:
            return V(c=UNK, kind="obj", cls=mk, meta={"host": host, "hostc": hostc}, lines=frozenset({line}))
        if cap == "DNS":
            return V(c=HOLE, labels=U({NET}), lines=frozenset({line}))
        if hostc == "META":
            return V(c=UNK, kind="obj", cls="requests.Response", labels=U({NET, SECRET}), src=frozenset({"cloud credentials from the metadata service"}), lines=frozenset({line}))
        return V(c=UNK, kind="obj", cls="requests.Response", labels=U(ret_labels or {NET}), src=frozenset({"a network response"}), lines=frozenset({line}))

    # ---------------------------------------------------------------------------------------------
    def do_sql(self, q, spec, t, pv, args, kws, n, fl, recv) -> V:
        from . import sqlfe
        line = n.lineno
        t = t or V()
        text = t.skel()
        labels = t.all_labels()
        params = None
        for p in (spec.get("p") or []):
            if isinstance(p, int) and p < len(args):
                params = args[p]
            elif isinstance(p, str) and p in kws:
                params = kws[p]
            if params is not None:
                break
        if q.startswith("pandas.") and params is None:
            params = kws.get("params")
        parameterized = params is not None and params.c is not None
        if text is None:
            text = HOLE if labels else ""
        if text:
            tainted = bool(labels & {USER, NET, FILE, DB}) and not (labels <= {SAFE_NUM, QUOTED, VALIDATED})
            sqlfe.emit_statements(self, text, line, labels, tainted, parameterized, fl, t.all_lines(), t.all_src())
        return V(c=UNK, kind="obj", cls="db.Cursor", labels=U({DB}), src=frozenset({"database rows"}), lines=frozenset({line}))

    # ---------------------------------------------------------------------------------------------
    def do_delete(self, q, spec, t, args, kws, n, fl) -> V:
        line = n.lineno
        t = t or V()
        path = t.skel() if t.is_str() else (HOLE if t.labels else None)
        if t.kind == "file" and t.meta:
            path = t.meta.get("path")
        labels = t.all_labels()
        fl2 = set(fl)
        pc = K.classify_path(path) if path else set()
        if "move" in fl2:
            dst = args[spec["move_dst"]] if spec.get("move_dst") is not None and spec["move_dst"] < len(args) else None
            dp = dst.skel() if dst is not None and dst.is_str() else ""
            if dp != "/dev/null":
                self.emit("WRITE_FILE", line, q, target=dp or HOLE, pathc=K.classify_path(dp or ""), pl=labels, flags={"move_dst"}, extra={"src": t.all_src()})
                return V(c=dp or UNK, kind="str")
            fl2.add("move_to_null")
        if kws.get("ignore_errors") is not None and kws["ignore_errors"].c is True:
            fl2.add("ignore_errors")          # housekeeping idiom: remove a leftover folder, never mind if it is already gone
        if USER in labels and VALIDATED not in labels:
            fl2.add("tainted")
        if VALIDATED in labels:
            fl2.add("validated")
        if "wildcard" not in fl2 and "WILDCARD" in pc:
            fl2.add("wildcard")
        self.emit("DELETE", line, q, target=path if path is not None else HOLE, tl=labels, pathc=pc, flags=fl2, extra={"src": t.all_src()}, lines=t.all_lines())
        return V()

    def do_priv(self, q, spec, t, args, kws, n, fl) -> V:
        line = n.lineno
        t = t or V()
        path = t.skel() if t.is_str() else None
        fl2 = set(fl)
        pc = K.classify_path(path) if path else set()
        if "chmod" in fl2:
            mv = args[spec.get("mode_arg", 1)] if len(args) > spec.get("mode_arg", 1) else kws.get("mode")
            mode = mv.c if mv is not None and isinstance(mv.c, int) and not isinstance(mv.c, bool) else None
            if mode is not None:
                if mode & 0o4000 or mode & 0o2000:
                    fl2.add("setuid")
                elif mode & 0o002 and (pc & {"ROOT", "SYSTEM_DIR", "PRIVFILE", "SECRET_STORE", "PERSIST", "HOME_DIR"}):
                    fl2.add("world_writable")
                else:
                    return V()
            else:
                return V()
        if "setuid" in fl2 and q.startswith("os.set") and not (args and isinstance(args[0].c, int) and args[0].c == 0):
            # dropping privileges to a non-zero uid is the benign case
            if args and isinstance(args[0].c, int) and args[0].c != 0:
                return V()
        self.emit("PRIV", line, q, target=path if path else (str(args[0].c) if args and args[0].c is not UNK else HOLE), tl=t.all_labels(), pathc=pc, flags=fl2,
                  lines=t.all_lines())
        return V()

    def do_spawn(self, q, spec, args, kws, n, fl) -> V:
        line = n.lineno
        fl2 = set(fl)
        self.emit("SPAWN", line, q, flags=fl2)
        return V(c=UNK, kind="num")

    def do_pip_main(self, q, spec, t, n) -> V:
        from . import shfe
        t = t or V()
        items = t.items if isinstance(t.items, list) else None
        if items is not None:
            shfe.analyze_argv([V(c="pip")] + list(items), self.ctx, n.lineno)
        return V(c=0, kind="num")

    def do_read_method(self, q, spec, recv, n) -> V:
        line = n.lineno
        path = recv.skel() if recv is not None and recv.is_str() else None
        pc = K.classify_path(path) if path else set()
        lab, src = self.path_labels(path or "")
        self.emit("READ_FILE", line, q, target=path if path else HOLE, tl=recv.all_labels() if recv else EMPTY, pathc=pc, pl=lab, extra={"src": src},
                  lines=recv.all_lines() if recv else ())
        return V(c=HOLE, kind="str", labels=lab, src=src, lines=frozenset({line}))

    def path_labels(self, path: str):
        if not path:
            return EMPTY, EMPTY
        pc = K.classify_path(path)
        if "SECRET_STORE" in pc:
            if path.startswith("/proc/") and "environ" in path:
                return U({SECRET, ENV, ENV_DUMP, FILE}), frozenset({"the process environment (" + path + ")"})
            return U({SECRET, FILE}), frozenset({"the credentials file " + path})
        if "SYSTEM_SENSITIVE" in pc:
            return U({SENS_SYS, FILE}), frozenset({"the system file " + path})
        return U({FILE}), frozenset({"the file " + path})

    # ---------------------------------------------------------------------------------------------
    # SPECIAL handlers keyed by qualified name
    SPECIAL = {
        "os.getenv": "s_getenv", "os.environ.get": "s_getenv", "os.environ.setdefault": "s_getenv", "os.environb.get": "s_getenv",
        "os.path.join": "s_pathjoin", "posixpath.join": "s_pathjoin", "ntpath.join": "s_pathjoin",
        "pathlib.Path": "s_path", "pathlib.PurePath": "s_path", "pathlib.PosixPath": "s_path", "pathlib.Path.home": "s_path_home", "pathlib.Path.cwd": "s_path_cwd",
        "base64.b64decode": "s_decode", "base64.urlsafe_b64decode": "s_decode", "base64.decodebytes": "s_decode", "base64.b32decode": "s_decode",
        "base64.a85decode": "s_decode", "base64.b85decode": "s_decode", "binascii.unhexlify": "s_decode", "binascii.a2b_hex": "s_decode",
        "binascii.a2b_base64": "s_decode", "zlib.decompress": "s_decode", "gzip.decompress": "s_decode", "bz2.decompress": "s_decode",
        "lzma.decompress": "s_decode", "codecs.decode": "s_decode", "bytes.fromhex": "s_decode", "bytearray.fromhex": "s_decode", "str.fromhex": "s_decode",
        "base64.b64encode": "s_encode", "base64.urlsafe_b64encode": "s_encode", "base64.b32encode": "s_encode", "binascii.hexlify": "s_encode", "binascii.b2a_hex": "s_encode",
        "base64.encodebytes": "s_encode", "zlib.compress": "s_encode", "gzip.compress": "s_encode", "codecs.encode": "s_encode",
        "threading.Thread": "s_thread", "multiprocessing.Process": "s_thread", "threading.Timer": "s_thread", "multiprocessing.pool.Pool": "s_pool",
        "multiprocessing.Pool": "s_pool", "concurrent.futures.ThreadPoolExecutor": "s_pool", "concurrent.futures.ProcessPoolExecutor": "s_pool",
        "urllib.request.Request": "s_urlrequest", "urllib2.Request": "s_urlrequest",
        "socket.socket": "s_socket", "ssl.wrap_socket": "s_passthrough0",
        "shutil.copy": "s_copy", "shutil.copyfile": "s_copy", "shutil.copy2": "s_copy", "shutil.copytree": "s_copy",
        "json.dump": "s_dump", "pickle.dump": "s_dump", "yaml.dump": "s_dump", "yaml.safe_dump": "s_dump", "marshal.dump": "s_dump", "toml.dump": "s_dump",
        "json.dumps": "s_dumps", "json.loads": "s_loads", "json.load": "s_load", "yaml.safe_load": "s_load", "yaml.load": "s_yaml_load", "toml.load": "s_load",
        "tomllib.load": "s_load", "csv.reader": "s_load", "csv.DictReader": "s_load", "csv.writer": "s_csvwriter", "ast.literal_eval": "s_literal_eval",
        "os.path.exists": "s_bool", "os.path.isfile": "s_bool", "os.path.isdir": "s_bool", "os.path.islink": "s_bool", "os.access": "s_bool",
        "sys.exit": "s_exit", "os._exit": "s_exit", "exit": "s_exit", "quit": "s_exit",
        "sys.stdin.read": "s_stdin", "sys.stdin.readline": "s_stdin", "sys.stdin.readlines": "s_stdin", "sys.stdin.buffer.read": "s_stdin",
        "argparse.ArgumentParser": "s_argparser",
        "tempfile.NamedTemporaryFile": "s_tmpfile", "tempfile.TemporaryFile": "s_tmpfile",
        "logging.getLogger": "s_logger", "logging.basicConfig": "s_noop", "logging.info": "s_logout", "logging.debug": "s_logout", "logging.warning": "s_logout",
        "logging.error": "s_logout", "logging.exception": "s_logout",
        "os.walk": "s_walk", "inspect.getsource": "s_getsource", "inspect.getsourcefile": "s_getsource",
        "typing.cast": "s_cast1", "re.compile": "s_recompile", "re.match": "s_rematch", "re.search": "s_rematch", "re.fullmatch": "s_rematch",
        "ctypes.CDLL": "s_apply", "time.time": "s_num", "time.sleep": "s_noop", "random.randint": "s_num", "os.getpid": "s_num",
        "shutil.rmtree": "s_apply", "os.remove": "s_apply",
        "urllib.parse.urlparse": "s_urlparse", "urllib.parse.urlsplit": "s_urlparse", "urllib.parse.urljoin": "s_urljoin",
        "socket.gethostname": "s_str", "platform.node": "s_str", "getpass.getuser": "s_str", "socket.gethostbyname": "s_apply",
        "subprocess.list2cmdline": "s_list2cmd", "shlex.join": "s_list2cmd",
        "builtins.open": "s_open_b", "os.fdopen": "s_open_b", "io.open": "s_open_b", "codecs.open": "s_open_b", "gzip.open": "s_open_b", "bz2.open": "s_open_b",
        "tarfile.open": "s_tarfile", "zipfile.ZipFile": "s_zipfile",
        "os.makedirs": "s_noop", "os.mkdir": "s_noop", "os.rename": "s_rename", "os.replace": "s_rename", "os.symlink": "s_symlink", "os.link": "s_symlink",
        "atexit.register": "s_atexit", "signal.signal": "s_noop", "signal.alarm": "s_noop", "gc.collect": "s_noop",
    }

    # -- generic helpers used by the SPECIAL handlers ----------------------------------------------
    def s_apply(self, q, callee, args, kws, n, recv):
        spec = self._funcs.get(q)
        if spec:
            return self.apply_spec(q, spec, callee, args, kws, n, recv)
        return self.unknown_lib(q, callee, args, kws, n, recv)

    def s_noop(self, q, callee, args, kws, n, recv):
        return V(c=None)

    def s_num(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def s_bool(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="bool")

    def s_str(self, q, callee, args, kws, n, recv):
        return V(c=HOLE, kind="str", labels=EMPTY)

    def s_exit(self, q, callee, args, kws, n, recv):
        return V(c=None)

    def s_passthrough0(self, q, callee, args, kws, n, recv):
        return args[0] if args else V()

    def s_cast1(self, q, callee, args, kws, n, recv):
        return args[1] if len(args) > 1 else V()

    def s_logger(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="logging.Logger")

    def s_atexit(self, q, callee, args, kws, n, recv):
        if args and args[0].kind == "func" and getattr(args[0].fn, "node", None) is not None:
            try:
                self.call_user(args[0].fn, [], {}, n, symbolic=True)
            except Exception:
                pass
        return V()

    def s_getenv(self, q, callee, args, kws, n, recv):
        line = n.lineno
        k = args[0] if args else kws.get("key")
        kname = k.exact() if k is not None else None
        lab = {ENV}
        secret_name = bool(kname and (K.secret_like_env(kname)))
        if secret_name:
            lab.add(SECRET)
        default = args[1] if len(args) > 1 else kws.get("default")
        src = frozenset({("the environment variable " + kname) if kname else "an environment variable"})
        self.emit("ENV_READ", line, q, target=kname if kname else HOLE, tl=k.all_labels() if k is not None else EMPTY, flags={"secret_name"} if secret_name else set(),
                  extra={"src": src})
        from .pyfe import KNOWN_ENV_VALUES
        cval = KNOWN_ENV_VALUES.get(kname, HOLE) if kname is not None else HOLE
        return V(c=cval, kind="str", labels=U(lab, default.labels if default is not None else EMPTY), src=src, lines=frozenset({line}))

    def s_stdin(self, q, callee, args, kws, n, recv):
        return V(c=HOLE, kind="str", labels=U({USER}), src=frozenset({"standard input"}), lines=frozenset({n.lineno}))

    def s_argparser(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="argparse.ArgumentParser", lines=frozenset({n.lineno}))

    def s_tmpfile(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="file", cls="io.File", meta={"path": "/tmp/tmpfile", "mode": "w+", "pathv": None, "write": True}, lines=frozenset({n.lineno}))

    def s_walk(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        lab, src = self.path_labels(p.skel() or "")
        return V(c=UNK, kind="list", labels=U(lab, p.labels), src=src, lines=frozenset({n.lineno}))

    def s_getsource(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        return V(c=HOLE, kind="str", labels=U(a.all_labels(), {DYNCODE}), src=a.all_src(), lines=frozenset({n.lineno}))

    def s_recompile(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        pat = a.exact()
        if pat is not None and _redos(pat):
            self.emit("LOOP", n.lineno, "re.compile", flags={"redos"}, target=pat)
        return V(c=UNK, kind="obj", cls="re.Pattern", meta={"pat": pat})

    def s_rematch(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        pat = a.exact()
        if pat is not None and _redos(pat):
            self.emit("LOOP", n.lineno, "re", flags={"redos"}, target=pat)
        return V(c=UNK, kind="obj", labels=U(*[x.all_labels() for x in args[1:]]))

    def s_urlparse(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        s = a.skel()
        d = {}
        if s is not None:
            sc, host, port, path = K.split_url(s)
            d = {"scheme": V(c=sc or "", kind="str", labels=a.labels), "hostname": V(c=host if host is not None else HOLE, kind="str", labels=a.labels, src=a.src),
                 "netloc": V(c=host if host is not None else HOLE, kind="str", labels=a.labels), "path": V(c=path or HOLE, kind="str", labels=a.labels)}
        return V(c=UNK, kind="obj", cls="urlparse.Result", items=d, labels=a.all_labels(), src=a.all_src(), lines=frozenset({n.lineno}), attrs=dict(d))

    def s_urljoin(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        b = args[1] if len(args) > 1 else V()
        sb = b.skel()
        if sb is not None and re.match(r"^[a-z]+://", sb or ""):
            return b
        sa = a.skel()
        if sa is not None and sb is not None:
            return V(c=sa.rstrip("/") + "/" + sb.lstrip("/"), kind="str", labels=U(a.all_labels(), b.all_labels()), src=U(a.all_src(), b.all_src()))
        return V(c=HOLE, kind="str", labels=U(a.all_labels(), b.all_labels()), src=U(a.all_src(), b.all_src()))

    def s_list2cmd(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        if isinstance(a.items, list):
            return V(c=_join_skel(a.items), kind="str", labels=a.all_labels(), src=a.all_src(), lines=frozenset({n.lineno}))
        return V(c=HOLE, kind="str", labels=a.all_labels(), src=a.all_src())

    def s_rename(self, q, callee, args, kws, n, recv):
        if len(args) >= 2:
            dst = args[1]
            dp = dst.skel() if dst.is_str() else None
            if dp is not None:
                pc = K.classify_path(dp)
                if pc & {"PERSIST", "PRIVFILE", "SECRET_STORE"}:
                    self.emit("WRITE_FILE", n.lineno, q, target=dp, pathc=pc, pl=args[0].all_labels(), flags={"rename_dst"}, tl=dst.all_labels())
        return V()

    def s_symlink(self, q, callee, args, kws, n, recv):
        if len(args) >= 2:
            dst = args[1]
            dp = dst.skel() if dst.is_str() else None
            if dp is not None:
                pc = K.classify_path(dp)
                if pc & {"PERSIST", "PRIVFILE"}:
                    self.emit("PERSIST", n.lineno, q, target=dp, pathc=pc, flags={"symlink"})
        return V()

    # -- path handling ----------------------------------------------------------------------------
    def s_pathjoin(self, q, callee, args, kws, n, recv):
        out = ""
        lab = set()
        # fixed base + caller-supplied component: join() does not confine it (".." or an absolute component escapes the base)
        if len(args) >= 2 and args[0].exact() is not None:
            for a in args[1:]:
                al = a.all_labels()
                if USER in al and not (al & {QUOTED, VALIDATED}):
                    lab.add(TRAVERSAL)
        src = set()
        lines = {n.lineno}
        for a in args:
            s = a.c if isinstance(a.c, str) else (HOLE if a.c is UNK or not isinstance(a.c, (int, float)) else str(a.c))
            lab |= a.all_labels()
            src |= a.all_src()
            lines |= a.all_lines()
            if s.startswith("/") and not s.startswith(HOLE):
                out = s
            elif not out:
                out = s
            else:
                out = out.rstrip("/") + "/" + s.lstrip("/") if s else out
        return V(c=out, kind="str", labels=U(lab), src=U(src), lines=frozenset(lines))

    def s_path(self, q, callee, args, kws, n, recv):
        parts = []
        lab = set()
        src = set()
        for a in args:
            s = a.c if isinstance(a.c, str) else HOLE
            parts.append(s)
            lab |= a.all_labels()
            src |= a.all_src()
        out = ""
        for p in parts:
            if p.startswith("/"):
                out = p
            elif not out:
                out = p
            else:
                out = out.rstrip("/") + "/" + p
        return V(c=out or ".", kind="path", cls="pathlib.Path", labels=U(lab), src=U(src), lines=frozenset({n.lineno}))

    def s_path_home(self, q, callee, args, kws, n, recv):
        return V(c="~", kind="path", cls="pathlib.Path", lines=frozenset({n.lineno}))

    def s_path_cwd(self, q, callee, args, kws, n, recv):
        return V(c=".", kind="path", cls="pathlib.Path", lines=frozenset({n.lineno}))

    # -- encoders / decoders ----------------------------------------------------------------------
    def s_decode(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        lab = U(a.all_labels(), {DECODED})
        src = a.all_src()
        raw = a.c if isinstance(a.c, str) and HOLE not in a.c else None
        out = None
        if q == "codecs.decode":
            enc = (args[1].exact() if len(args) > 1 else kws.get("encoding").exact() if kws.get("encoding") is not None else "utf-8") or "utf-8"
            enc_l = enc.lower().replace("-", "_")
            if raw is not None:
                try:
                    if enc_l in ("rot13", "rot_13"):
                        out = codecs.decode(raw, "rot13")
                    elif enc_l in ("hex", "hex_codec"):
                        out = codecs.decode(raw.encode("latin-1"), "hex").decode("latin-1")
                    elif enc_l in ("base64", "base64_codec", "base_64"):
                        out = codecs.decode(raw.encode("latin-1"), "base64").decode("latin-1")
                    elif enc_l in ("zlib", "zlib_codec", "zip"):
                        out = codecs.decode(raw.encode("latin-1"), "zlib").decode("latin-1")
                    elif enc_l in ("unicode_escape",):
                        out = codecs.decode(raw.encode("latin-1"), "unicode_escape")
                except Exception:
                    out = None
            if enc_l in ("rot13", "rot_13", "hex", "base64", "zlib", "unicode_escape", "hex_codec", "base64_codec", "zlib_codec"):
                pass
            else:
                lab = a.all_labels()   # plain text codec (utf-8): not an obfuscation decoder
        elif raw is not None:
            try:
                b = raw.encode("latin-1")
                if q in ("base64.b64decode", "base64.decodebytes", "binascii.a2b_base64"):
                    out = base64.b64decode(b + b"=" * (-len(b) % 4)).decode("latin-1")
                elif q == "base64.urlsafe_b64decode":
                    out = base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4)).decode("latin-1")
                elif q == "base64.b32decode":
                    out = base64.b32decode(b).decode("latin-1")
                elif q == "base64.a85decode":
                    out = base64.a85decode(b).decode("latin-1")
                elif q == "base64.b85decode":
                    out = base64.b85decode(b).decode("latin-1")
                elif q in ("binascii.unhexlify", "binascii.a2b_hex"):
                    out = binascii.unhexlify(b).decode("latin-1")
                elif q in ("bytes.fromhex", "bytearray.fromhex", "str.fromhex"):
                    out = bytes.fromhex(raw).decode("latin-1")
                elif q == "zlib.decompress":
                    out = zlib.decompress(b).decode("latin-1")
            except Exception:
                out = None
        if out is not None and len(out) < 200000:
            return V(c=out, kind="bytes" if "b" in q.split(".")[-1][:2] else "str", labels=lab, src=src, lines=frozenset({n.lineno}))
        return V(c=HOLE, kind="str", labels=lab, src=src, lines=frozenset({n.lineno}))

    def s_encode(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        raw = a.c if isinstance(a.c, str) and HOLE not in a.c else None
        lab = a.all_labels()
        out = None
        if raw is not None:
            try:
                b = raw.encode("latin-1", "replace")
                if q in ("base64.b64encode", "base64.encodebytes"):
                    out = base64.b64encode(b).decode()
                elif q == "base64.urlsafe_b64encode":
                    out = base64.urlsafe_b64encode(b).decode()
                elif q == "base64.b32encode":
                    out = base64.b32encode(b).decode()
                elif q in ("binascii.hexlify", "binascii.b2a_hex"):
                    out = binascii.hexlify(b).decode()
            except Exception:
                out = None
        return V(c=out if out is not None else HOLE, kind="bytes", labels=lab, src=a.all_src(), lines=frozenset({n.lineno}))

    # -- loads / dumps -----------------------------------------------------------------------------
    def s_dumps(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        return V(c=HOLE, kind="str", labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})

    def s_loads(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        # exact JSON literal -> real containers
        s = a.exact()
        if s is not None and len(s) < 20000 and q == "json.loads":
            try:
                import json
                return self.from_py(json.loads(s), n.lineno)
            except Exception:
                pass
        return V(c=UNK, kind="dict", items=None, labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})

    def from_py(self, obj, line) -> V:
        if isinstance(obj, str):
            return V(c=obj, kind="str", lines=frozenset({line}))
        if isinstance(obj, bool) or obj is None:
            return V(c=obj)
        if isinstance(obj, (int, float)):
            return V(c=obj, kind="num")
        if isinstance(obj, list):
            its = [self.from_py(x, line) for x in obj[:64]]
            return V(c=UNK, kind="list", items=its, n=len(obj), lines=frozenset({line}))
        if isinstance(obj, dict):
            d = {k: self.from_py(v, line) for k, v in list(obj.items())[:64]}
            return V(c=UNK, kind="dict", items=d, n=len(obj), lines=frozenset({line}))
        return V()

    def s_load(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        lab = a.all_labels()
        src = a.all_src()
        return V(c=UNK, kind="dict", labels=lab, src=src, lines=a.all_lines() | {n.lineno})

    def s_yaml_load(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        loader = kws.get("Loader") or (args[1] if len(args) > 1 else None)
        ln = ""
        if loader is not None:
            ln = (loader.q or "") + str(loader.c if isinstance(loader.c, str) else "")
        safe = bool(re.search(r"Safe|CSafe|BaseLoader", ln))
        if not safe:
            self.emit("DESERIALIZE", n.lineno, q, target=a.skel() if a.is_str() else HOLE, tl=a.all_labels(), flags={"yaml_unsafe"},
                      extra={"src": a.all_src()})
        return V(c=UNK, kind="dict", labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})

    def s_literal_eval(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        s = a.exact()
        if s is not None and len(s) < 20000:
            try:
                return self.from_py(ast.literal_eval(s), n.lineno)
            except Exception:
                pass
        return V(c=UNK, labels=a.all_labels() - {USER} | ({SAFE_NUM} if False else EMPTY), src=a.all_src(), lines=frozenset({n.lineno}))

    def s_dump(self, q, callee, args, kws, n, recv):
        # json.dump(obj, f): writes to file object f
        if len(args) >= 2 and args[1].kind == "file":
            self.file_write(args[1], args[0], n.lineno, q)
        return V()

    def s_csvwriter(self, q, callee, args, kws, n, recv):
        f = args[0] if args else V()
        return V(c=UNK, kind="obj", cls="csv.writer", meta={"file": f}, lines=frozenset({n.lineno}))

    # -- sockets / threads -------------------------------------------------------------------------
    def s_socket(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="socket.socket", meta={"host": None}, lines=frozenset({n.lineno}))

    def s_urlrequest(self, q, callee, args, kws, n, recv):
        url = args[0] if args else kws.get("url") or V()
        data = args[1] if len(args) > 1 else kws.get("data")
        return V(c=UNK, kind="obj", cls="urllib.request.Request", meta={"url": url, "data": data}, labels=url.all_labels(), lines=frozenset({n.lineno}))

    def s_thread(self, q, callee, args, kws, n, recv):
        target = kws.get("target")
        targs = kws.get("args")
        if q == "threading.Timer":
            target = args[1] if len(args) > 1 else kws.get("function")
            targs = args[2] if len(args) > 2 else kws.get("args")
        elif target is None and args:
            pass
        cls = "threading.Thread" if q.startswith("threading") else "multiprocessing.Process"
        return V(c=UNK, kind="obj", cls=cls, meta={"target": target, "args": targs, "kwargs": kws.get("kwargs"), "daemon": kws.get("daemon")}, lines=frozenset({n.lineno}))

    def s_pool(self, q, callee, args, kws, n, recv):
        w = None
        for key in ("max_workers", "processes"):
            if key in kws:
                w = kws[key]
        if w is None and args:
            w = args[0]
        count = w.c if w is not None and isinstance(w.c, int) and not isinstance(w.c, bool) else None
        if count is not None and count >= 200:
            self.emit("SPAWN", n.lineno, q, flags={"pool", "huge_pool"}, extra={"count": count}, mult_override=True)
            self.mult_max_event(count)
        return V(c=UNK, kind="obj", cls="concurrent.futures.Executor" if "concurrent" in q else "multiprocessing.Pool", meta={"workers": count}, lines=frozenset({n.lineno}))

    def mult_max_event(self, count: int) -> None:
        # attach the pool size as multiplicity of the last SPAWN event
        for ev in reversed(self.ctx.events):
            if ev.cap == "SPAWN" and "pool" in ev.flags:
                ev.mult = max(ev.mult, count)
                break

    def s_copy(self, q, callee, args, kws, n, recv):
        if len(args) >= 2:
            src, dst = args[0], args[1]
            sp = src.skel() if src.is_str() else None
            dp = dst.skel() if dst.is_str() else None
            lab, srcs = self.path_labels(sp or "")
            if sp is not None:
                self.emit("READ_FILE", n.lineno, q, target=sp, tl=src.all_labels(), pathc=K.classify_path(sp), pl=lab, flags={"copy_src"}, extra={"src": srcs})
            if dp is not None:
                self.emit("WRITE_FILE", n.lineno, q, target=dp, tl=dst.all_labels(), pathc=K.classify_path(dp), pl=lab, flags={"copy_dst"}, extra={"src": srcs, "content": ""})
        return V(c=args[1].c if len(args) > 1 else UNK, kind="str")

    def s_tarfile(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="tarfile.TarFile", meta={"path": args[0] if args else None}, lines=frozenset({n.lineno}))

    def s_zipfile(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="zipfile.ZipFile", meta={"path": args[0] if args else None}, lines=frozenset({n.lineno}))

    # -- files ---------------------------------------------------------------------------------------
    def s_open_b(self, q, callee, args, kws, n, recv):
        return self.lib_open(args, kws, n)

    def b_open(self, callee, args, kws, n):
        return self.lib_open(args, kws, n)

    def lib_open(self, args, kws, n, path_override: Optional[V] = None) -> V:
        line = n.lineno
        p = path_override if path_override is not None else (args[0] if args else kws.get("file") or V())
        mode_v = args[1] if len(args) > 1 else kws.get("mode")
        mode = mode_v.exact() if mode_v is not None and mode_v.exact() is not None else "r"
        if mode_v is not None and mode_v.exact() is None:
            mode = "r+"
        path = p.skel() if p.is_str() else None
        if p.kind == "file":
            return p
        write = any(c in mode for c in "wax+")
        read = "r" in mode or "+" in mode
        pc = K.classify_path(path) if path else set()
        plabels = p.all_labels()
        lab, srcs = self.path_labels(path or "")
        if path is None or path.startswith(HOLE) and path == HOLE:
            lab, srcs = U({FILE}), frozenset({"a file chosen by the caller"})
        if read and (plabels & {USER, TRAVERSAL}) and not (plabels & {QUOTED, VALIDATED}):
            lab = U(lab, {ARBITRARY_FILE})
            srcs = U(srcs, {"a file the caller chose"} if "the file" not in " ".join(srcs) else EMPTY)
        obj = V(c=UNK, kind="file", cls="io.File", labels=lab if read else EMPTY, src=srcs if read else EMPTY,
                meta={"path": path, "mode": mode, "pathv": p, "write": write, "pc": pc}, lines=frozenset({line}) | p.all_lines())
        if read and not (pc & {"DEVSRC"} and False):
            self.emit("READ_FILE", line, "open", target=path if path is not None else HOLE, tl=plabels, pathc=pc, pl=lab if read else EMPTY,
                      flags={"mode_" + mode[:2]} if "+" in mode else set(), extra={"src": srcs}, lines=p.all_lines())
        if write and (pc & {"PERSIST", "PRIVFILE", "SECRET_STORE", "DEVICE", "SYSTEM_SENSITIVE"} or path is None or "USER_PATH" in pc):
            fl = {"open_write"}
            if "w" in mode:
                fl.add("truncate")
            if "a" in mode:
                fl.add("append")
            self.emit("WRITE_FILE", line, "open", target=path if path is not None else HOLE, tl=plabels, pathc=pc, flags=fl, extra={"content": ""}, lines=p.all_lines())
        return obj

    def file_write(self, f: V, data: V, line: int, name: str = "write") -> None:
        meta = f.meta or {}
        path = meta.get("path")
        pathv = meta.get("pathv")
        pc = meta.get("pc") or (K.classify_path(path) if path else set())
        fl = set()
        mode = meta.get("mode") or ""
        if "a" in mode:
            fl.add("append")
        if "w" in mode:
            fl.add("truncate")
        content = data.skel() if data is not None and data.is_str() else None
        self.emit("WRITE_FILE", line, name, target=path if path is not None else HOLE, tl=pathv.all_labels() if pathv is not None else EMPTY, pathc=pc,
                  pl=data.all_labels() if data is not None else EMPTY, flags=fl, extra={"content": content or "", "src": data.all_src() if data is not None else EMPTY},
                  lines=(data.all_lines() if data is not None else frozenset()) | (pathv.all_lines() if pathv is not None else frozenset()))

    # ---------------------------------------------------------------------------------------------
    # method calls on values
    def call_method(self, recv: V, name: str, args: list, kws: dict, n, env) -> V:
        line = n.lineno
        # --- environment mapping
        if recv.kind == "environ" or recv.q == "os.environ":
            if name in ("get", "setdefault", "pop"):
                return self.s_getenv("os.environ.get", V(), args, kws, n, None)
            if name in ("items", "values", "keys", "copy"):
                return V(c=UNK, kind="dict", labels=U({ENV, ENV_DUMP}), src=frozenset({"all environment variables"}), lines=frozenset({line}))
            return V(c=UNK, labels=recv.labels, src=recv.src)
        # --- files
        if recv.kind == "file":
            return self.file_method(recv, name, args, kws, n)
        # --- csv writer / archives
        if recv.cls == "csv.writer" and name in ("writerow", "writerows"):
            f = (recv.meta or {}).get("file")
            if f is not None and f.kind == "file":
                self.file_write(f, args[0] if args else V(), line, name)
            return V()
        if recv.cls in ("tarfile.TarFile", "zipfile.ZipFile"):
            return self.archive_method(recv, name, args, kws, n)
        # --- JS network objects
        if recv.cls == "xhr":
            if name == "open":
                recv.meta = recv.meta or {}
                recv.meta["method"] = (args[0].exact() or "GET").upper() if args else "GET"
                recv.meta["url"] = args[1] if len(args) > 1 else V()
                if recv.meta["method"] in ("GET", "HEAD"):
                    self._net_event("XMLHttpRequest.open", "NET_FETCH", recv.meta["url"], [], n, set())
                return V()
            if name == "send":
                url = (recv.meta or {}).get("url")
                if url is not None and (recv.meta or {}).get("method") not in ("GET", "HEAD"):
                    self._net_event("XMLHttpRequest.send", "NET_SEND", url, [args[0]] if args else [], n, set())
                return V()
            return V()
        if recv.cls == "http.client.ClientRequest":
            if name in ("write", "end") and (recv.meta or {}).get("pending"):
                url = recv.meta.get("url") or V()
                if args and (args[0].c is not UNK or args[0].labels):
                    self._net_event("http.request.write", "NET_SEND", url, [args[0]], n, set())
                    recv.meta["pending"] = False
                elif name == "end":
                    self._net_event("http.request", "NET_SEND", url, [], n, set())
                    recv.meta["pending"] = False
            return V()
        if recv.cls == "socket.socket" and name in ("write", "end") and args:
            host = (recv.meta or {}).get("host")
            self.emit("NET_SEND", n.lineno, "socket.write", target=host or HOLE, hostc=K.classify_host(host) if host else "UNKNOWN", pl=args[0].all_labels(),
                      extra={"host": host, "src": args[0].all_src()}, lines=args[0].all_lines())
            return V()
        # --- threads / pools
        if recv.cls in ("threading.Thread", "multiprocessing.Process") or (recv.meta and recv.meta.get("libbase") in ("threading.Thread", "Thread", "multiprocessing.Process", "Process")):
            if name in ("start", "run"):
                return self.thread_start(recv, n)
            if name in ("join", "is_alive", "daemon", "setDaemon"):
                return V()
        if recv.cls in ("concurrent.futures.Executor", "multiprocessing.Pool"):
            if name in ("submit", "apply_async", "apply", "map", "imap", "starmap", "map_async"):
                return self.pool_submit(recv, name, args, kws, n)
        # --- sockets & friends (lib classes with method table)
        if recv.cls:
            m = self._methods.get(name)
            if m and (not m.get("recv") or recv.cls in m["recv"]):
                return self.method_spec(recv, name, m, args, kws, n)
            if recv.cls == "socket.socket" and name in ("accept",):
                return V(c=UNK, kind="tuple", items=[V(c=UNK, kind="obj", cls="socket.socket", meta={"host": None}), V()], labels=U({NET}))
            if recv.cls == "socket.socket" and name in ("makefile", "close", "settimeout", "setsockopt", "shutdown"):
                return V()
            if recv.cls in ("db.Connection", "db.Cursor") and name in ("cursor", "commit", "close", "rollback"):
                return V(c=UNK, kind="obj", cls="db.Cursor", labels=recv.labels)
            if recv.cls in ("subprocess.Popen", "subprocess.CompletedProcess") and name in ("communicate", "wait", "poll", "kill", "terminate", "check_returncode"):
                if name == "communicate":
                    return V(c=UNK, kind="tuple", items=[V(c=HOLE, kind="str", labels=U(recv.labels, {CMDSUB})), V(c=HOLE, kind="str")], labels=U(recv.labels, {CMDSUB}))
                return V(c=UNK)
            if recv.cls == "requests.Response" or recv.labels & {NET}:
                if name in ("json", "text", "iter_content", "iter_lines", "read", "readlines", "decode", "content"):
                    return V(c=HOLE, kind="dict" if name == "json" else "str", labels=U(recv.labels, {NET}), src=U(recv.src, {"a network response"}), lines=frozenset({line}))
            if recv.cls == "pathlib.Path":
                return self.path_method(recv, name, args, kws, n)
        if recv.kind == "path" or recv.cls == "pathlib.Path":
            return self.path_method(recv, name, args, kws, n)
        # --- generic method table (execute, fetchall, ...)
        m = self._methods.get(name)
        if m is not None:
            cond = m.get("recv")
            if not cond and not m.get("path_recv"):
                if m.get("urlish") is None:
                    return self.method_spec(recv, name, m, args, kws, n)
            elif cond and recv.cls in cond:
                return self.method_spec(recv, name, m, args, kws, n)
            elif m.get("urlish") and recv.cls is None:
                a0 = args[0] if args else None
                s0 = (a0.skel() or "") if a0 is not None else ""
                http_recv = bool(recv.q and re.match(r"(requests|httpx|aiohttp|urllib3)", recv.q))
                if a0 is not None and (re.match(r"^(https?|ftp|wss?)://", s0) or (http_recv and (s0.startswith(HOLE) or a0.labels & {USER}))):
                    return self.method_spec(recv, name, m, args, kws, n)
        # --- strings / bytes / containers
        name = JS_STR_ALIASES.get(name, name) if (isinstance(recv.c, str) or recv.kind in ("str", "bytes")) else name
        if isinstance(recv.c, str) or recv.kind in ("str", "bytes"):
            r = self.str_method(recv, name, args, kws, n)
            if r is not None:
                return r
        if recv.kind in ("list", "tuple", "set") or isinstance(recv.items, list):
            r = self.list_method(recv, name, args, kws, n)
            if r is not None:
                return r
        if recv.kind == "dict" or isinstance(recv.items, dict):
            r = self.dict_method(recv, name, args, kws, n)
            if r is not None:
                return r
        # user-defined callable stored in attribute etc.
        # --- generic: propagate
        lab = set(recv.all_labels())
        src = set(recv.all_src())
        for a in list(args) + list(kws.values()):
            lab |= a.all_labels()
            src |= a.all_src()
        if name in ("parse_args", "parse_known_args") or (name in ("get_json", "get_data", "json") and recv.labels & {USER}):
            return V(c=HOLE, kind=None, labels=U(lab, {USER}), src=U(src, {"incoming request / command-line input"}), lines=frozenset({line}))
        if re.search(r"(decode|decompress|unhexlify|b64|decrypt|inflate|rot13)", name):
            lab.add(DECODED)
        return V(c=HOLE if recv.labels and (isinstance(recv.c, str) or recv.kind in (None, "str")) else UNK, labels=U(lab), src=U(src), lines=recv.lines | {line},
                 kind="str" if isinstance(recv.c, str) else None)

    def method_spec(self, recv: V, name: str, m: dict, args: list, kws: dict, n) -> V:
        cap = m.get("cap", "NONE")
        ret_labels = set(m.get("ret") or [])
        fake_callee = V(q=f"{recv.cls or 'obj'}.{name}", alias=None)
        if cap == "NONE":
            return V(c=UNK, labels=U(ret_labels, recv.labels if name.startswith("fetch") else EMPTY), src=frozenset({"database rows"}) if DB in ret_labels else EMPTY,
                     lines=frozenset({n.lineno}), kind="list" if DB in ret_labels else None)
        if cap == "SPAWN":
            if name == "start":
                return self.thread_start(recv, n)
            return self.pool_submit(recv, name, args, kws, n)
        if cap == "READ_FILE" or cap == "WRITE_FILE" or cap == "DELETE":
            return self.path_method(recv, name, args, kws, n)
        spec = dict(m)
        spec["cap"] = cap
        q = f"{recv.cls}.{name}" if recv.cls else f"<obj>.{name}"
        if cap == "SQL_EXEC":
            return self.do_sql(q, spec, _pick(spec.get("t"), args, kws), [], args, kws, n, set(), recv)
        t = _pick(spec.get("t"), args, kws)
        pv = _pick_all(spec.get("p"), args, kws)
        if cap in ("NET_FETCH", "NET_SEND", "NET_CONNECT", "NET_LISTEN"):
            res = self.do_net(q, spec, cap, t, pv, args, kws, n, set(spec.get("flags") or []), ret_labels, recv)
            if cap == "NET_CONNECT" and recv is not None:
                # remember the connection endpoint on the receiver
                host = None
                if t is not None:
                    if isinstance(t.items, list) and t.items:
                        host = t.items[0].skel() if t.items[0].is_str() else None
                    elif t.is_str():
                        host = t.skel()
                recv.meta = recv.meta or {}
                recv.meta["host"] = host
            return res
        if cap in ("EXEC_SHELL", "EXEC_PROC"):
            return self.do_exec(q, spec, cap, t, args, kws, n, set(spec.get("flags") or []), ret_labels)
        return self.apply_spec(q, spec, fake_callee, args, kws, n, recv)

    def file_method(self, recv: V, name: str, args: list, kws: dict, n) -> V:
        line = n.lineno
        if name in ("read", "readline", "readlines", "__iter__", "readall", "getvalue", "peek"):
            return V(c=HOLE, kind="list" if name == "readlines" else "str", labels=recv.labels, src=recv.src, lines=recv.lines | {line})
        if name in ("write", "writelines", "send"):
            self.file_write(recv, args[0] if args else V(), line, name)
            return V()
        if name in ("close", "flush", "seek", "tell", "truncate", "fileno", "__enter__", "__exit__"):
            return recv if name == "__enter__" else V()
        return V(c=UNK, labels=recv.labels, src=recv.src)

    def archive_method(self, recv: V, name: str, args: list, kws: dict, n) -> V:
        line = n.lineno
        if name in ("write", "add", "writestr"):
            a = args[0] if args else V()
            p = a.skel() if a.is_str() else None
            if p is not None and name != "writestr":
                lab, srcs = self.path_labels(p)
                pc = K.classify_path(p)
                if pc & {"SECRET_STORE", "SYSTEM_SENSITIVE"}:
                    self.emit("READ_FILE", line, f"archive.{name}", target=p, pathc=pc, pl=lab, flags={"archive_src"}, extra={"src": srcs})
                recv.labels = U(recv.labels, lab)
                recv.src = U(recv.src, srcs)
            return V()
        if name in ("extractall", "extract"):
            tgt = args[0] if args else kws.get("path")
            tp = tgt.skel() if tgt is not None and tgt.is_str() else None
            pc = K.classify_path(tp or "")
            afl = {"archive_extract"}
            if recv.cls == "tarfile.TarFile" and "filter" not in kws and not (len(args) > 1 or "members" in kws):
                afl.add("tar_unchecked")      # member names may contain ../ or absolute paths and no filter limits them
            self.emit("WRITE_FILE", line, f"archive.{name}", target=tp if tp is not None else ".", pathc=pc, flags=afl, extra={"content": ""})
            return V()
        if name in ("read", "open"):
            return V(c=HOLE, kind="str", labels=recv.labels, src=recv.src)
        return V()

    def thread_start(self, recv: V, n) -> V:
        line = n.lineno
        meta = recv.meta or {}
        target = meta.get("target")
        fl = {"thread"}
        fi = None
        argv = []
        if target is not None and target.kind == "func" and getattr(target.fn, "node", None) is not None:
            fi = target.fn
        elif recv.attrs is not None and recv.cls in self.classes:
            fi = self.find_method(recv.cls, "run")
        if fi is not None:
            if self._func_unbounded(fi):
                fl.add("target_unbounded")
        targ_args = meta.get("args")
        if targ_args is not None and isinstance(targ_args.items, list):
            argv = list(targ_args.items)
        self.emit("SPAWN", line, "Thread.start", flags=fl)
        if fi is not None and fi.qual not in self._run_targets:
            self._run_targets.add(fi.qual)
            self.thread_ctx += 1
            try:
                if recv.attrs is not None and fi.cls:
                    self.call_user(fi, argv, {}, n, bound_self=recv)
                else:
                    self.call_user(fi, argv, {}, n)
            finally:
                self.thread_ctx -= 1
        return V()

    def pool_submit(self, recv: V, name: str, args: list, kws: dict, n) -> V:
        line = n.lineno
        fn = args[0] if args else kws.get("fn") or V()
        fl = {"pool_task", "thread"}
        fi = fn.fn if fn.kind == "func" and getattr(fn.fn, "node", None) is not None else None
        if fi is not None and self._func_unbounded(fi):
            fl.add("target_unbounded")
        cnt = None
        if name in ("map", "imap", "starmap", "map_async") and len(args) > 1:
            cnt = args[1].n if args[1].n is not None else (len(args[1].items) if isinstance(args[1].items, list) else None)
        old = self.mult
        if cnt:
            self.mult = min(old * cnt, 10 ** 12)
        self.emit("SPAWN", line, "pool." + name, flags=fl)
        self.mult = old
        if fi is not None and fi.qual not in self._run_targets:
            self._run_targets.add(fi.qual)
            self.thread_ctx += 1
            try:
                self.call_user(fi, list(args[1:2]) if name not in ("map", "imap", "starmap", "map_async") else [V(c=HOLE, labels=args[1].all_labels() if len(args) > 1 else EMPTY)], {}, n, symbolic=False)
            finally:
                self.thread_ctx -= 1
        return V(c=UNK, labels=EMPTY)

    def _func_unbounded(self, fi) -> bool:
        from .pyfe import _has_own_break
        node = fi.node
        if getattr(fi, "is_lambda", False):
            return False
        for sub in ast.walk(node):
            if isinstance(sub, ast.While):
                t = sub.test
                always = isinstance(t, ast.Constant) and bool(t.value) or (isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) and isinstance(t.operand, ast.Constant) and not t.operand.value)
                if always and not _has_own_break(sub.body) and not any(isinstance(x, (ast.Return, ast.Raise)) for b in sub.body for x in ast.walk(b)):
                    return True
        return False

    def path_method(self, recv: V, name: str, args: list, kws: dict, n) -> V:
        line = n.lineno
        path = recv.skel() if recv.is_str() else None
        pc = K.classify_path(path) if path else set()
        if name in ("expanduser", "resolve", "absolute", "joinpath", "with_suffix", "with_name", "relative_to"):
            nv = V(c=recv.c, kind="path", cls="pathlib.Path", labels=recv.labels, src=recv.src, lines=recv.lines | {line})
            if name == "joinpath":
                add = [a.c if isinstance(a.c, str) else HOLE for a in args]
                nv.c = (path or HOLE).rstrip("/") + "/" + "/".join(add)
                nv.labels = U(nv.labels, *[a.all_labels() for a in args])
            return nv
        if name in ("read_text", "read_bytes", "open"):
            if name == "open":
                return self.lib_open(args, kws, n, path_override=recv)
            lab, srcs = self.path_labels(path or "")
            if path is None or path == HOLE:
                lab, srcs = U({FILE}), frozenset({"a file chosen by the caller"})
            if recv.all_labels() & {USER, TRAVERSAL} and not (recv.all_labels() & {QUOTED, VALIDATED}):
                lab = U(lab, {ARBITRARY_FILE})
            self.emit("READ_FILE", line, "Path." + name, target=path if path is not None else HOLE, tl=recv.all_labels(), pathc=pc, pl=lab, extra={"src": srcs}, lines=recv.all_lines())
            return V(c=HOLE, kind="str", labels=lab, src=srcs, lines=frozenset({line}))
        if name in ("write_text", "write_bytes"):
            data = args[0] if args else V()
            fl = {"truncate"}
            self.emit("WRITE_FILE", line, "Path." + name, target=path if path is not None else HOLE, tl=recv.all_labels(), pathc=pc, pl=data.all_labels(), flags=fl,
                      extra={"content": data.skel() if data.is_str() else "", "src": data.all_src()}, lines=recv.all_lines() | data.all_lines())
            return V()
        if name in ("unlink", "rmdir"):
            self.emit("DELETE", line, "Path." + name, target=path if path is not None else HOLE, tl=recv.all_labels(), pathc=pc,
                      flags={"tainted"} if USER in recv.labels else set(), extra={"src": recv.all_src()}, lines=recv.all_lines())
            return V()
        if name in ("glob", "rglob", "iterdir", "listdir"):
            lab, srcs = self.path_labels(path or "")
            return V(c=UNK, kind="list", labels=U(lab, recv.labels), src=srcs, lines=frozenset({line}))
        if name in ("exists", "is_file", "is_dir", "is_symlink", "samefile", "is_absolute", "is_relative_to"):
            return V(c=UNK, kind="bool")
        if name in ("mkdir", "touch", "chmod", "symlink_to", "rename", "replace"):
            if name in ("rename", "replace") and args:
                dst = args[0]
                dp = dst.skel() if dst.is_str() else None
                if dp and K.classify_path(dp) & {"PERSIST", "PRIVFILE", "SECRET_STORE"}:
                    self.emit("WRITE_FILE", line, "Path." + name, target=dp, pathc=K.classify_path(dp), flags={"rename_dst"})
            if name == "touch" and pc & {"PERSIST", "PRIVFILE"}:
                self.emit("WRITE_FILE", line, "Path.touch", target=path, pathc=pc, flags={"touch"}, extra={"content": ""})
            return V()
        return V(c=HOLE, kind="str", labels=recv.labels, src=recv.src, lines=frozenset({line}))

    # -- strings ----------------------------------------------------------------------------------
    def str_method(self, recv: V, name: str, args: list, kws: dict, n) -> Optional[V]:
        line = n.lineno
        s = recv.c if isinstance(recv.c, str) else None
        exact = s is not None and HOLE not in s
        lab = U(recv.all_labels(), *[a.all_labels() for a in args], *[a.all_labels() for a in kws.values()])
        src = U(recv.all_src(), *[a.all_src() for a in args])
        kind = recv.kind if recv.kind in ("str", "bytes") else "str"
        if name in ("__tostr__",):
            return V(c=recv.c, kind=kind, labels=recv.labels, src=recv.src, lines=recv.lines | {line})
        if name == "__slice__":
            return V(c=HOLE, kind=kind, labels=lab, src=src, lines=frozenset({line}))
        if name == "__concat__":
            tail = "".join(a.c if isinstance(a.c, str) else HOLE for a in args)
            return V(c=(s if s is not None else HOLE) + tail, kind=kind, labels=lab, src=src, lines=frozenset({line}))
        if name == "__repeat__":
            if s is not None and args and isinstance(args[0].c, int) and 0 <= args[0].c <= 10000:
                return V(c=s * args[0].c, kind=kind, labels=lab, src=src)
            return V(c=HOLE, kind=kind, labels=lab, src=src)
        if name == "__unknown__":
            return V(c=UNK, labels=lab, src=src)
        if name == "format":
            if s is not None:
                return self.str_format(s, args, kws, lab, src, line, kind)
            return V(c=HOLE, kind="str", labels=lab, src=src, lines=frozenset({line}))
        if name == "format_map":
            return V(c=HOLE, kind="str", labels=lab, src=src)
        if name == "join":
            it = args[0] if args else V()
            if isinstance(it.items, list) and s is not None:
                parts = []
                for x in it.items:
                    parts.append(x.c if isinstance(x.c, str) else (str(x.c) if isinstance(x.c, (int, float)) and not isinstance(x.c, bool) else HOLE))
                tags = set()
                if exact and all(isinstance(x.c, str) and HOLE not in x.c for x in it.items) and len(it.items) > 1:
                    tags.add(BUILT)
                return V(c=s.join(parts), kind=kind, labels=U(lab, tags), src=src, lines=frozenset({line}))
            return V(c=HOLE, kind=kind, labels=lab, src=src, lines=frozenset({line}))
        if name in ("decode", "encode"):
            if s is not None:
                return V(c=s, kind="bytes" if name == "encode" else "str", labels=recv.labels, src=recv.src, lines=recv.lines | {line})
            return V(c=HOLE, kind="bytes" if name == "encode" else "str", labels=recv.all_labels(), src=recv.all_src(), lines=recv.lines | {line})
        if name == "split" or name == "rsplit" or name == "splitlines" or name == "partition" or name == "rpartition":
            if exact and all(a.exact() is not None for a in args) and len(s) < 5000:
                try:
                    sep = args[0].exact() if args else None
                    if name == "split":
                        parts = s.split(sep) if sep is not None else s.split()
                    elif name == "rsplit":
                        parts = s.rsplit(sep) if sep is not None else s.rsplit()
                    elif name == "splitlines":
                        parts = s.splitlines()
                    elif name == "partition":
                        parts = list(s.partition(sep))
                    else:
                        parts = list(s.rpartition(sep))
                    return V(c=UNK, kind="list", items=[V(c=p, kind="str", labels=recv.labels, src=recv.src) for p in parts[:64]], n=len(parts), lines=frozenset({line}))
                except Exception:
                    pass
            return V(c=UNK, kind="list", items=None, labels=lab, src=src, n=None, lines=frozenset({line}))
        if name in PURE_STR_METHODS and exact and all(a.exact() is not None or (isinstance(a.c, int)) for a in args):
            try:
                pyargs = [a.c for a in args]
                res = getattr(s, name)(*pyargs)
                return V(c=res, kind=kind, labels=U(recv.labels, *[a.labels for a in args]), src=src, lines=frozenset({line}))
            except Exception:
                pass
        if name in ("startswith", "endswith", "isalnum", "isdigit", "isalpha", "isnumeric", "isidentifier", "isspace", "islower", "isupper", "find", "rfind", "index", "count", "__contains__"):
            if exact and args and all(a.exact() is not None for a in args) and name in ("startswith", "endswith"):
                try:
                    return V(c=getattr(s, name)(args[0].exact()), kind="bool")
                except Exception:
                    pass
            return V(c=UNK, kind="bool" if name.startswith(("starts", "ends", "is")) else "num", labels=U({SAFE_NUM}) if not name.startswith(("starts", "ends", "is")) else EMPTY)
        if name in PURE_STR_METHODS or name in ("strip", "lstrip", "rstrip", "lower", "upper", "replace", "title"):
            return V(c=HOLE, kind=kind, labels=lab if name != "replace" else lab, src=src, lines=frozenset({line}))
        return None

    def str_format(self, tmpl: str, args: list, kws: dict, lab, src, line, kind) -> V:
        auto = [0]
        holes = [False]

        def piece(v):
            s = self.to_str(v)
            if s is None:
                return HOLE
            return s

        def rep(m):
            field = m.group(1)
            spec = m.group(2)
            key = field.split(".")[0].split("[")[0]
            if key == "":
                idx = auto[0]
                auto[0] += 1
                v = args[idx] if idx < len(args) else None
            elif key.isdigit():
                idx = int(key)
                v = args[idx] if idx < len(args) else None
            else:
                v = kws.get(key)
            if v is None:
                return HOLE
            if "." in field or "[" in field:
                return HOLE
            if spec and not re.fullmatch(r"[<>^]?\d*", spec):
                return HOLE
            return piece(v)
        out = re.sub(r"\{\{|\}\}|\{([^{}!:]*)(?:![rsa])?(?::([^{}]*))?\}", lambda m: ("{" if m.group(0) == "{{" else "}" if m.group(0) == "}}" else rep(m)), tmpl)
        return V(c=out, kind=kind, labels=lab, src=src, lines=frozenset({line}))

    def list_method(self, recv: V, name: str, args: list, kws: dict, n) -> Optional[V]:
        line = n.lineno
        if name == "push":
            name = "append"
        if name == "join" and isinstance(recv.items, list):
            sep = args[0].c if args and isinstance(args[0].c, str) else ","
            parts = [x.c if isinstance(x.c, str) else (str(x.c) if isinstance(x.c, (int, float)) and not isinstance(x.c, bool) else HOLE) for x in recv.items]
            tags = set()
            if len(recv.items) > 1 and all(isinstance(x.c, str) and HOLE not in x.c for x in recv.items):
                tags.add(BUILT)
            return V(c=sep.join(parts), kind="str", labels=U(recv.all_labels(), tags), src=recv.all_src(), lines=frozenset({line}))
        if name in ("map", "filter", "forEach", "reduce", "flatMap", "some", "every", "find", "sort", "slice", "concat", "flat", "reverse", "includes", "indexOf", "keys", "values", "entries", "splice", "shift", "unshift"):
            if name in ("slice", "concat", "flat", "reverse", "filter", "map", "sort", "flatMap"):
                return V(c=UNK, kind="list", items=list(recv.items) if isinstance(recv.items, list) and name in ("slice", "reverse", "sort", "filter") else None,
                         labels=recv.all_labels(), src=recv.all_src(), n=recv.n)
            if name in ("includes", "some", "every"):
                return V(c=UNK, kind="bool")
            return V(c=UNK, labels=recv.all_labels(), src=recv.all_src())
        if name in ("append", "add", "appendleft"):
            if isinstance(recv.items, list) and args:
                recv.items.append(args[0])
                recv.n = None if recv.n is None else recv.n + 1
            recv.labels = U(recv.labels, args[0].all_labels() if args else EMPTY)
            return V()
        if name in ("extend", "update", "extendleft"):
            if args:
                if isinstance(recv.items, list) and isinstance(args[0].items, list):
                    recv.items.extend(args[0].items)
                recv.labels = U(recv.labels, args[0].all_labels())
            return V()
        if name == "insert":
            if len(args) > 1 and isinstance(recv.items, list):
                recv.items.append(args[1])
            return V()
        if name in ("copy",):
            return V(c=UNK, kind=recv.kind, items=list(recv.items) if isinstance(recv.items, list) else None, n=recv.n, labels=recv.labels, src=recv.src)
        if name in ("pop",):
            if isinstance(recv.items, list) and recv.items:
                return recv.items[-1]
            return V(c=UNK, labels=recv.all_labels(), src=recv.all_src())
        if name in ("index", "count", "sort", "reverse", "clear", "remove"):
            return V()
        return None

    def dict_method(self, recv: V, name: str, args: list, kws: dict, n) -> Optional[V]:
        line = n.lineno
        d = recv.items if isinstance(recv.items, dict) else None
        if name == "get":
            k = args[0] if args else V()
            default = args[1] if len(args) > 1 else None
            if d is not None and k.c is not UNK and k.c in d:
                return d[k.c]
            if default is not None:
                return join_values(V(c=HOLE, labels=recv.all_labels(), src=recv.all_src(), kind=None), default) if (recv.labels or d is None) else default
            return V(c=HOLE if recv.all_labels() else UNK, labels=recv.all_labels(), src=recv.all_src(), lines=recv.lines | {line})
        if name == "items":
            if d is not None and len(d) <= 64:
                its = [V(c=UNK, kind="tuple", items=[V(c=k, kind="str") if not isinstance(k, V) else k, v], n=2, labels=EMPTY) for k, v in d.items()]
                return V(c=UNK, kind="list", items=its, n=len(its), labels=recv.labels, src=recv.src)
            return V(c=UNK, kind="list", labels=recv.all_labels(), src=recv.all_src(), n=None)
        if name == "keys":
            if d is not None:
                its = [V(c=k, kind="str") for k in d.keys()]
                return V(c=UNK, kind="list", items=its, n=len(its))
            return V(c=UNK, kind="list", labels=recv.labels)
        if name == "values":
            if d is not None:
                return V(c=UNK, kind="list", items=list(d.values()), n=len(d), labels=recv.labels, src=recv.src)
            return V(c=UNK, kind="list", labels=recv.all_labels(), src=recv.all_src())
        if name in ("update", "setdefault"):
            if args and isinstance(args[0].items, dict) and d is not None:
                d.update(args[0].items)
            if args and name == "setdefault" and len(args) > 1 and d is not None and args[0].c is not UNK:
                d.setdefault(args[0].c, args[1])
            recv.labels = U(recv.labels, *[a.all_labels() for a in args])
            return V()
        if name == "copy":
            return V(c=UNK, kind="dict", items=dict(d) if d is not None else None, n=recv.n, labels=recv.labels, src=recv.src)
        if name == "pop":
            if d is not None and args and args[0].c in d:
                return d.pop(args[0].c)
            return V(c=UNK, labels=recv.all_labels())
        return None

    # -- builtins ---------------------------------------------------------------------------------
    def b_eval(self, callee, args, kws, n):
        return self.apply_spec("builtins.eval", self._funcs["builtins.eval"], callee, args, kws, n, None)

    def b_exec(self, callee, args, kws, n):
        return self.apply_spec("builtins.exec", self._funcs["builtins.exec"], callee, args, kws, n, None)

    def b_compile(self, callee, args, kws, n):
        return self.apply_spec("builtins.compile", self._funcs["builtins.compile"], callee, args, kws, n, None)

    def b___import__(self, callee, args, kws, n):
        return self.apply_spec("builtins.__import__", self._funcs["builtins.__import__"], callee, args, kws, n, None)

    def b_getattr(self, callee, args, kws, n):
        if len(args) < 2:
            return V()
        obj, name = args[0], args[1]
        nm = name.exact()
        line = n.lineno
        if nm is not None:
            if obj.q is not None or obj.kind in ("module", "class", "func") and obj.q:
                base = obj
                q = (base.q or "") + "." + nm
                v = self.module_attr(base, q, nm, line)
                if name.labels & {BUILT, DECODED} or (base.q in ("builtins",) and name.labels):
                    v.alias = "<dyn>"
                if base.q == "builtins" or base.q is None:
                    pass
                return v
            r = self.get_attr(obj, nm, n, None)
            if name.labels & {BUILT, DECODED}:
                r = V(c=r.c, kind=r.kind, q=r.q, labels=U(r.labels, name.labels), alias="<dyn>" if r.q else r.alias, items=r.items, attrs=r.attrs, cls=r.cls, fn=r.fn, meta=r.meta)
            return r
        default = args[2] if len(args) > 2 else None
        lab = U(obj.all_labels(), name.all_labels(), default.all_labels() if default is not None else EMPTY)
        return V(c=UNK, labels=lab, src=U(obj.all_src(), name.all_src()), lines=frozenset({line}))

    def b_setattr(self, callee, args, kws, n):
        if len(args) >= 3 and args[0].attrs is not None and args[1].exact() is not None:
            args[0].attrs[args[1].exact()] = args[2]
        return V()

    def b_hasattr(self, callee, args, kws, n):
        return V(c=UNK, kind="bool")

    def b_isinstance(self, callee, args, kws, n):
        return V(c=UNK, kind="bool")

    b_issubclass = b_callable = b_hasattr

    def b_str(self, callee, args, kws, n):
        if not args:
            return V(c="", kind="str")
        a = args[0]
        s = self.to_str(a)
        if a.kind == "environ" or ENV_DUMP in a.labels:
            return V(c=HOLE, kind="str", labels=a.all_labels(), src=a.all_src(), lines=frozenset({n.lineno}))
        if s is not None:
            return V(c=s, kind="str", labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})
        return V(c=HOLE, kind="str", labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})

    b_repr = b_ascii = b_str

    def b_format(self, callee, args, kws, n):
        return self.b_str(callee, args[:1], kws, n)

    def b_int(self, callee, args, kws, n):
        a = args[0] if args else V(c=0)
        if isinstance(a.c, str) and HOLE not in a.c:
            try:
                base = args[1].c if len(args) > 1 and isinstance(args[1].c, int) else 10
                return V(c=int(a.c, base), kind="num")
            except Exception:
                pass
        if isinstance(a.c, (int, float)) and not isinstance(a.c, bool):
            return V(c=int(a.c), kind="num")
        return V(c=UNK, kind="num", labels=U((a.all_labels() - {USER, NET, FILE}) | {SAFE_NUM}), lines=frozenset({n.lineno}))

    def b_float(self, callee, args, kws, n):
        a = args[0] if args else V(c=0.0)
        if isinstance(a.c, (int, float)) and not isinstance(a.c, bool):
            return V(c=float(a.c), kind="num")
        if isinstance(a.c, str) and HOLE not in a.c:
            try:
                return V(c=float(a.c), kind="num")
            except Exception:
                pass
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def b_bool(self, callee, args, kws, n):
        return V(c=UNK, kind="bool")

    def b_len(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.items, (list, dict)):
            return V(c=len(a.items), kind="num")
        if isinstance(a.c, str) and HOLE not in a.c:
            return V(c=len(a.c), kind="num")
        if a.n is not None:
            return V(c=a.n, kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def b_abs(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.c, (int, float)):
            return V(c=abs(a.c), kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    b_round = b_abs

    def b_min(self, callee, args, kws, n):
        vals = args[0].items if len(args) == 1 and isinstance(args[0].items, list) else args
        nums = [v.c for v in vals if isinstance(v.c, (int, float)) and not isinstance(v.c, bool)]
        if nums and len(nums) == len(vals):
            return V(c=min(nums), kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}) if all(v.kind == "num" or SAFE_NUM in v.labels for v in vals) else U(*[v.all_labels() for v in vals]))

    def b_max(self, callee, args, kws, n):
        vals = args[0].items if len(args) == 1 and isinstance(args[0].items, list) else args
        nums = [v.c for v in vals if isinstance(v.c, (int, float)) and not isinstance(v.c, bool)]
        if nums and len(nums) == len(vals):
            return V(c=max(nums), kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}) if all(v.kind == "num" or SAFE_NUM in v.labels for v in vals) else U(*[v.all_labels() for v in vals]))

    def b_sum(self, callee, args, kws, n):
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def b_list(self, callee, args, kws, n):
        a = args[0] if args else V(c=UNK, kind="list", items=[], n=0)
        if isinstance(a.items, list):
            return V(c=UNK, kind="list", items=list(a.items), n=a.n if a.n is not None else len(a.items), labels=a.labels, src=a.src, lines=a.lines | {n.lineno})
        if isinstance(a.items, dict):
            return V(c=UNK, kind="list", items=[V(c=k, kind="str") for k in a.items.keys()], n=len(a.items), labels=a.labels)
        if isinstance(a.c, str) and HOLE not in a.c and len(a.c) < 64:
            return V(c=UNK, kind="list", items=[V(c=ch, kind="str", labels=a.labels) for ch in a.c], n=len(a.c))
        return V(c=UNK, kind="list", items=None, n=a.n, labels=a.all_labels(), src=a.all_src(), lines=a.all_lines() | {n.lineno})

    def b_tuple(self, callee, args, kws, n):
        r = self.b_list(callee, args, kws, n)
        r.kind = "tuple"
        return r

    def b_set(self, callee, args, kws, n):
        r = self.b_list(callee, args, kws, n)
        r.kind = "set"
        return r

    b_frozenset = b_set

    def b_sorted(self, callee, args, kws, n):
        r = self.b_list(callee, args[:1], kws, n)
        return r

    def b_reversed(self, callee, args, kws, n):
        r = self.b_list(callee, args[:1], kws, n)
        if isinstance(r.items, list):
            r.items = list(reversed(r.items))
        return r

    def b_iter(self, callee, args, kws, n):
        return args[0] if args else V()

    def b_next(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.items, list) and a.items:
            return a.items[0]
        return V(c=UNK, labels=a.all_labels(), src=a.all_src())

    def b_enumerate(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.items, list) and len(a.items) <= 64:
            its = [V(c=UNK, kind="tuple", items=[V(c=i, kind="num"), x], n=2) for i, x in enumerate(a.items)]
            return V(c=UNK, kind="list", items=its, n=len(its))
        el = V(c=UNK, kind="tuple", items=[V(c=UNK, kind="num", labels=U({SAFE_NUM})), V(c=HOLE if a.kind in (None, "str") else UNK, labels=a.all_labels(), src=a.all_src())], n=2)
        return V(c=UNK, kind="list", items=None, n=a.n, labels=a.all_labels(), src=a.all_src())

    def b_zip(self, callee, args, kws, n):
        lists = [a.items for a in args if isinstance(a.items, list)]
        if lists and len(lists) == len(args):
            m = min(len(l) for l in lists)
            its = [V(c=UNK, kind="tuple", items=[l[i] for l in lists], n=len(lists)) for i in range(min(m, 64))]
            return V(c=UNK, kind="list", items=its, n=m)
        return V(c=UNK, kind="list", labels=U(*[a.all_labels() for a in args]), src=U(*[a.all_src() for a in args]))

    def b_map(self, callee, args, kws, n):
        if len(args) >= 2:
            f, it = args[0], args[1]
            if isinstance(it.items, list) and len(it.items) <= 64:
                out = []
                for x in it.items:
                    if f.kind == "func" and getattr(f.fn, "node", None) is not None:
                        out.append(self.call_user(f.fn, [x], {}, n))
                    elif f.q:
                        out.append(self.call_lib(f.q, f, [x], {}, n))
                    else:
                        out.append(V(c=UNK, labels=x.all_labels()))
                return V(c=UNK, kind="list", items=out, n=len(out))
            return V(c=UNK, kind="list", labels=it.all_labels(), src=it.all_src(), n=it.n)
        return V(c=UNK, kind="list")

    def b_filter(self, callee, args, kws, n):
        if len(args) >= 2:
            return V(c=UNK, kind="list", items=args[1].items, n=None, labels=args[1].all_labels(), src=args[1].all_src())
        return V(c=UNK, kind="list")

    def b_range(self, callee, args, kws, n):
        nums = [a.c for a in args]
        if nums and all(isinstance(x, int) and not isinstance(x, bool) for x in nums):
            if len(nums) == 1:
                start, stop, step = 0, nums[0], 1
            elif len(nums) == 2:
                start, stop, step = nums[0], nums[1], 1
            else:
                start, stop, step = nums[0], nums[1], nums[2]
            try:
                cnt = max(0, (stop - start + (step - (1 if step > 0 else -1))) // step) if step else 0
            except Exception:
                cnt = None
            return V(c=UNK, kind="range", meta={"start": start, "stop": stop, "step": step}, n=cnt, lines=frozenset({n.lineno}))
        return V(c=UNK, kind="range", meta={}, n=None, labels=U({SAFE_NUM}), lines=frozenset({n.lineno}))

    def b_chr(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.c, int) and not isinstance(a.c, bool) and 0 <= a.c < 0x110000:
            return V(c=chr(a.c), kind="str", labels=EMPTY)
        return V(c=HOLE, kind="str", labels=a.all_labels())

    def b_ord(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.c, str) and len(a.c) == 1 and a.c != HOLE:
            return V(c=ord(a.c), kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def b_bytes(self, callee, args, kws, n):
        a = args[0] if args else V(c="")
        if isinstance(a.items, list) and all(isinstance(x.c, int) and not isinstance(x.c, bool) and 0 <= x.c < 256 for x in a.items):
            try:
                return V(c=bytes(x.c for x in a.items).decode("latin-1"), kind="bytes", labels=EMPTY, lines=frozenset({n.lineno}))
            except Exception:
                pass
        if isinstance(a.c, (int,)) and not isinstance(a.c, bool) and a.c >= 10 ** 8:
            self.emit("ALLOC", n.lineno, "bytes(n)", flags={"huge"} if a.c >= 10 ** 9 else {"large"}, extra={"size": a.c}, mult_override=True)
            return V(c=HOLE, kind="bytes", n=a.c)
        if isinstance(a.c, str):
            return V(c=a.c, kind="bytes", labels=a.labels, src=a.src, lines=frozenset({n.lineno}))
        return V(c=HOLE, kind="bytes", labels=a.all_labels(), src=a.all_src(), lines=frozenset({n.lineno}))

    def b_bytearray(self, callee, args, kws, n):
        return self.b_bytes(callee, args, kws, n)

    def b_hex(self, callee, args, kws, n):
        a = args[0] if args else V()
        if isinstance(a.c, int) and not isinstance(a.c, bool):
            return V(c=hex(a.c), kind="str")
        return V(c=HOLE, kind="str", labels=U({SAFE_NUM}))

    b_oct = b_bin = b_hex

    def b_dict(self, callee, args, kws, n):
        d = {}
        lab = set()
        src = set()
        if args:
            a = args[0]
            if isinstance(a.items, dict):
                d.update(a.items)
            lab |= a.all_labels()
            src |= a.all_src()
        for k, v in kws.items():
            if k != "**":
                d[k] = v
        return V(c=UNK, kind="dict", items=d, n=len(d), labels=U(lab), src=U(src), lines=frozenset({n.lineno}))

    def b_print(self, callee, args, kws, n):
        f = kws.get("file")
        if f is not None and f.kind == "file" and args:
            self.file_write(f, args[0], n.lineno, "print")
        elif f is None:
            self.emit_output(args, n.lineno, "print")
        return V(c=None)

    def emit_output(self, vals, line, name):
        """A value shown on screen or written to a log: a sink for secrets."""
        lab = set()
        src = set()
        lines = {line}
        for a in vals:
            if a is None:
                continue
            lab |= set(a.all_labels())
            src |= set(a.all_src())
            lines |= set(a.all_lines())
        if lab & {SECRET, ENV_DUMP, SENS_SYS}:
            self.emit("OUTPUT", line, name, pl=frozenset(lab), extra={"src": frozenset(src)}, lines=frozenset(lines))

    def s_logout(self, q, callee, args, kws, n, recv):
        self.emit_output(list(args) + [v for k, v in kws.items() if k != "**"], n.lineno, q)
        return V()

    def b_super(self, callee, args, kws, n):
        return V(c=UNK, kind="obj", cls="super")

    def b_type(self, callee, args, kws, n):
        return V(c=UNK)

    def b_vars(self, callee, args, kws, n):
        return V(c=UNK, kind="dict", labels=args[0].all_labels() if args else EMPTY)

    b_globals = b_locals = b_dir = b_vars

    def b_id(self, callee, args, kws, n):
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    b_hash = b_id

    def b_input(self, callee, args, kws, n):
        return V(c=HOLE, kind="str", labels=U({USER}), src=frozenset({"interactive user input"}), lines=frozenset({n.lineno}))

    b_raw_input = b_input

    def b_any(self, callee, args, kws, n):
        return V(c=UNK, kind="bool")

    b_all = b_any

    def b_open_(self, *a):
        return V()


def _redos(pat: str) -> bool:
    """Catastrophic-backtracking heuristic: a group that is a single repeated atom and is itself repeated, e.g. (a+)+ or (.*)*,
    or an alternation of identical branches repeated, e.g. (a|a)+.  The common safe 'unrolled loop' idiom is not matched."""
    if len(pat) > 300:
        return False
    atom = r"(?:\\.|\[[^\]]*\]|[^()\\|\[\]])"
    if re.search(r"\((?:\?:)?" + atom + r"[+*]\)[+*{]", pat):
        return True
    m = re.search(r"\((?:\?:)?(\w)\|\1\w*\)[+*]", pat)
    return bool(m)
