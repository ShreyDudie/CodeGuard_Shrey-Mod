"""Shell (bash/sh) front-end: interprets a script against an abstract world and emits behaviour events.

Used for .sh files, YAML `run:` steps, Markdown shell fences, `os.system("...")` strings in Python,
`child_process.exec("...")` strings in JavaScript, Dockerfile RUN lines, etc.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from . import knowledge as K
from .ctx import Ctx, Stop
from .events import (EMPTY, HOLE, UNK, Event, V, U, USER, ENV, ENV_DUMP, SECRET, SENS_SYS, FILE, NET, DECODED,
                     CMDSUB, DB, QUOTED)
from .shparse import (AndOr, Case, For, FuncDef, Group, If, Part, Pipeline, Redir, Simple, While, Word, parse)


class ShellExit(Exception):
    pass


@dataclass
class Pipe:
    labels: frozenset = EMPTY
    src: frozenset = EMPTY
    tags: frozenset = EMPTY          # remote | decoded | encoded | unbounded | download
    text: Optional[str] = None


EMPTY_PIPE = Pipe()

KNOWN_ENV = {"HOME": "~", "PWD": ".", "OLDPWD": "..", "USER": "user", "LOGNAME": "user", "SHELL": "/bin/bash", "HOSTNAME": "host",
             "PATH": "/usr/bin:/bin", "TMPDIR": "/tmp", "LANG": "C", "TERM": "xterm", "EDITOR": "vi", "UID": "1000", "EUID": "1000",
             "RANDOM": HOLE, "SECONDS": HOLE, "LINENO": HOLE, "BASH_SOURCE": "script.sh", "IFS": " ", "PPID": HOLE, "OSTYPE": "linux-gnu"}
CI_ENV = re.compile(r"^(GITHUB_|CI$|RUNNER_|GITLAB_|CIRCLE|TRAVIS|JENKINS|BUILD_|WORKSPACE|BUILDKITE|AGENT_)")

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "fish", "busybox", "rbash"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "pwsh", "powershell", "osascript", "deno", "bun"}
WRAPPERS = {"sudo", "doas", "nohup", "exec", "time", "command", "builtin", "env", "nice", "ionice", "timeout", "stdbuf", "setsid", "xargs",
            "watch", "unbuffer", "chronic", "taskset", "strace", "ltrace", "proxychains", "proxychains4", "torsocks", "script", "flock", "parallel", "caffeinate"}
DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "http", "https", "lwp-download", "lynx", "w3m", "axel", "tftp"}
SECRET_FLAG_RE = re.compile(r"(password|passwd|token|secret|key)=", re.I)
SIZE_UNITS = {"": 1, "b": 1, "k": 1024, "kb": 1000, "kib": 1024, "m": 1024 ** 2, "mb": 1000 ** 2, "mib": 1024 ** 2, "g": 1024 ** 3, "gb": 1000 ** 3,
              "gib": 1024 ** 3, "t": 1024 ** 4, "tb": 1000 ** 4, "tib": 1024 ** 4, "p": 1024 ** 5, "e": 1024 ** 6, "w": 2, "c": 1}


def parse_size(s: str) -> Optional[int]:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([a-zA-Z]*)", (s or "").strip())
    if not m:
        return None
    mult = SIZE_UNITS.get(m.group(2).lower())
    if mult is None:
        return None
    return int(float(m.group(1)) * mult)


def _basename(cmd: str) -> str:
    return cmd.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()


_PASSWORD_CLI = frozenset({"mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport", "mysqlcheck", "sshpass", "psql", "pg_dump", "mongodump", "mongorestore", "mongosh", "mongo", "redis-cli"})
_PASSWORD_AFTER_P = frozenset({"mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport", "mysqlcheck", "redis-cli"})


class Shell:
    def __init__(self, ctx: Ctx, hole_labels: frozenset = EMPTY, hole_src: frozenset = EMPTY, depth: int = 0):
        self.ctx = ctx
        self.hole_labels = hole_labels
        self.hole_src = hole_src
        self.depth = depth
        self.vars: dict = {}
        self.funcs: dict = {}
        self.set_u = False
        self.set_e = False
        self.mult = 1
        self.loop = 0                 # nesting level of loops
        self.unb_loop = 0
        self.arrays: dict = {}
        self.vfs: dict = {}          # path -> (labels, src, downloaded)
        self.sudo = False
        self.cd_unchecked = False
        self.cd_empty = False
        self.rm_guard = False          # an emptiness / root check that returns or exits has already run
        self.forkbombs: set = set()
        self.call_depth = 0
        self.steps = 0
        self.last_status_checked = True
        self.script_name_marker = "script.sh"

    # ------------------------------------------------------------------------------ events
    def E(self, cap: str, line: int, name: str = "", target: Optional[str] = None, tl=EMPTY, pl=EMPTY, flags=(), hostc=None, pathc=None,
          extra=None, lines=None, **kw) -> Event:
        fl = set(flags)
        if self.sudo:
            fl.add("sudo")
        if self.loop:
            fl.add("in_loop")
        if self.unb_loop:
            fl.add("in_unbounded_loop")
        ev = Event(cap=cap, line=line, name=name, target=target, tlabels=U(tl), plabels=U(pl), flags=fl, hostc=hostc,
                   pathc=set(pathc or ()), mult=self.mult, extra=extra or {}, lines=set(lines or ()))
        return self.ctx.emit(ev)

    # ------------------------------------------------------------------------------ driver
    def run_text(self, text: str, line_pin: int = 0, hole_labels: Optional[frozenset] = None, hole_src: Optional[frozenset] = None) -> Pipe:
        old = (self.hole_labels, self.hole_src)
        if hole_labels is not None:
            self.hole_labels = hole_labels
        if hole_src is not None:
            self.hole_src = hole_src
        old_pin = self.ctx.pin_line
        if line_pin and not old_pin:
            self.ctx.pin_line = line_pin + self.ctx.line_base
        try:
            ast, comments = parse(text)
            for ln, ctext in comments:
                if not (ln == 1 and ctext.startswith("!")):
                    self.ctx.text(ln, ctext, "comment", "bash")
            return self.run_list(ast)
        finally:
            self.hole_labels, self.hole_src = old
            self.ctx.pin_line = old_pin

    def run_list(self, nodes: list) -> Pipe:
        last = EMPTY_PIPE
        texts: list = []
        labels: set = set()
        src: set = set()
        tags: set = set()
        for n in nodes:
            self.ctx.tick()
            p = self.run_node(n)
            last = p
            if p.text is not None:
                texts.append(p.text)
            labels |= p.labels
            src |= p.src
            tags |= p.tags
        return Pipe(U(labels), U(src), U(tags), "\n".join(texts) if texts else None)

    def run_node(self, n) -> Pipe:
        if isinstance(n, Simple):
            return self.run_simple(n, EMPTY_PIPE)
        if isinstance(n, Pipeline):
            return self.run_pipeline(n)
        if isinstance(n, AndOr):
            p = self.run_node(n.first)
            # `cd x && ...` => status is checked
            res = p
            for op, node in n.rest:
                res2 = self.run_node(node)
                res = Pipe(U(res.labels, res2.labels), U(res.src, res2.src), U(res.tags, res2.tags),
                           res2.text if res2.text is not None else res.text)
            return res
        if isinstance(n, If):
            self.run_list(n.cond)
            if self._is_guard(n):
                self.rm_guard = True
            saved = self._snapshot()
            a = self.run_list(n.then)
            sa = self._snapshot()
            self._restore(saved)
            b = self.run_list(n.orelse) if n.orelse else EMPTY_PIPE
            self._merge(sa)
            return Pipe(U(a.labels, b.labels), U(a.src, b.src), U(a.tags, b.tags), a.text)
        if isinstance(n, While):
            return self.run_while(n)
        if isinstance(n, For):
            return self.run_for(n)
        if isinstance(n, Case):
            outs = []
            self.expand_word(n.word)
            saved = self._snapshot()
            snaps = []
            for _pats, body in n.clauses:
                self._restore(saved)
                outs.append(self.run_list(body))
                snaps.append(self._snapshot())
            self._restore(saved)
            for s in snaps:
                self._merge(s)
            return Pipe(U(*[o.labels for o in outs]), U(*[o.src for o in outs]), U(*[o.tags for o in outs]), None)
        if isinstance(n, Group):
            saved_vars = dict(self.vars) if n.sub else None
            if n.bg:
                self.loop += 1
            p = self.run_list(n.body)
            if n.bg:
                self.loop -= 1
            if saved_vars is not None:
                self.vars = saved_vars
            return self._apply_redirs_to_pipe(p, n.redirs, n.line)
        if isinstance(n, FuncDef):
            self.funcs[n.name] = n
            self._check_forkbomb(n)
            return EMPTY_PIPE
        return EMPTY_PIPE

    @staticmethod
    def _is_guard(n) -> bool:
        """`if [[ -z "$d" || "$d" == "/" ]]; then ...; return/exit; fi`: a refusal path for an empty or root target."""
        rc, rt = repr(n.cond), repr(n.then)
        return ("'-z'" in rc or "'/'" in rc) and ("'return'" in rt or "'exit'" in rt)

    def _snapshot(self):
        return (dict(self.vars),)

    def _restore(self, snap) -> None:
        self.vars = dict(snap[0])

    def _merge(self, snap) -> None:
        other = snap[0]
        for k, v in other.items():
            if k in self.vars and self.vars[k] is not v:
                self.vars[k] = _join(self.vars[k], v)
            elif k not in self.vars:
                self.vars[k] = v

    # ------------------------------------------------------------------------------ loops
    def run_while(self, n: While) -> Pipe:
        cond_text = _cond_text(n.cond)
        unbounded = False
        if not n.until:
            if cond_text in ("true", ":", "[ 1 ]", "[ true ]", "[[ 1 ]]", "[ 1 -eq 1 ]", "/bin/true", "yes", "test 1", "[ ! false ]", "((1))", "(( 1 ))"):
                unbounded = True
        else:
            if cond_text in ("false", "[ 0 ]", "/bin/false", "[ 1 -ne 1 ]"):
                unbounded = True
        flags = {"unbounded"} if unbounded else set()
        body_info = _scan_body(n.body)
        has_exit = body_info["exit"]
        if unbounded and has_exit:
            unbounded = False
            flags = set()
        if not unbounded:
            self.run_list(n.cond)
            self.loop += 1
            self.run_list(n.body)
            self.loop -= 1
            self._apply_redirs_to_pipe(EMPTY_PIPE, n.redirs, n.line)
            return EMPTY_PIPE
        # unbounded loop
        busy = not body_info["blocking"]
        if busy:
            flags.add("busy")
        if body_info["spawn"]:
            flags.add("spawn")
        if body_info["growth"]:
            flags.add("mem_growth")
        if body_info["bg"]:
            flags.add("background_spawn")
        self.E("LOOP", n.line, "while", flags=flags)
        self.loop += 1
        self.unb_loop += 1
        self.run_list(n.body)
        self.unb_loop -= 1
        self.loop -= 1
        return EMPTY_PIPE

    def run_for(self, n: For) -> Pipe:
        if n.arith is not None:
            a = n.arith.replace(" ", "")
            parts = a.split(";")
            unbounded = len(parts) == 3 and parts[1] == ""
            info = _scan_body(n.body)
            if unbounded and not info["exit"]:
                flags = {"unbounded"}
                if not info["blocking"]:
                    flags.add("busy")
                if info["spawn"]:
                    flags.add("spawn")
                if info["growth"]:
                    flags.add("mem_growth")
                self.E("LOOP", n.line, "for((;;))", flags=flags)
                self.unb_loop += 1
            self.loop += 1
            self.run_list(n.body)
            self.loop -= 1
            if unbounded and not info["exit"]:
                self.unb_loop -= 1
            return EMPTY_PIPE
        values: list = []
        count: Optional[int] = None
        sym_labels: frozenset = EMPTY
        for w in (n.words or []):
            if len(w.parts) == 1 and w.parts[0].k == "var" and w.parts[0].v[0] in self.arrays:
                values.extend(self.arrays[w.parts[0].v[0]])
                for v in self.arrays[w.parts[0].v[0]]:
                    sym_labels = U(sym_labels, v.labels)
                continue
            seq = _seq_count(w)
            if seq is not None:
                count = (count or 0) + seq if count is not None else seq
                sym_labels = U(sym_labels)
                values = []
                continue
            vs = self.expand_word(w)
            values.extend(vs)
            for v in vs:
                sym_labels = U(sym_labels, v.labels)
        if n.words is None:   # `for x; do` iterates positional params
            sym_labels = U(sym_labels, {USER})
        if count is None and 0 < len(values) <= 64 and all(v.c is not UNK and HOLE not in str(v.c) for v in values):
            self.loop += 0
            for v in values:
                self.ctx.tick()
                self.vars[n.var] = v
                self.run_list(n.body)
            return EMPTY_PIPE
        # symbolic iteration
        old_mult = self.mult
        if count is not None:
            self.mult = min(old_mult * max(count, 1), 10 ** 12)
        elif len(values) > 64:
            self.mult = min(old_mult * len(values), 10 ** 12)
        self.vars[n.var] = V(c=HOLE, labels=sym_labels | (self.hole_labels if any(HOLE in str(v.c) for v in values) else EMPTY))
        self.loop += 1
        self.run_list(n.body)
        self.loop -= 1
        self.mult = old_mult
        return EMPTY_PIPE

    # ------------------------------------------------------------------------------ fork bombs
    def _check_forkbomb(self, fd: FuncDef) -> None:
        name = fd.name
        calls = []
        bg_seen = [False]

        def walk(node, in_pipe=False):
            if isinstance(node, Simple):
                if node.words:
                    w0 = node.words[0].literal()
                    if w0 == name or (w0 and w0.endswith("/" + name)):
                        calls.append(in_pipe)
                if node.bg:
                    bg_seen[0] = True
            elif isinstance(node, Pipeline):
                for c in node.cmds:
                    walk(c, True)
                if node.bg:
                    bg_seen[0] = True
            elif isinstance(node, Group):
                for c in node.body:
                    walk(c, in_pipe)
                if node.bg:
                    bg_seen[0] = True
            elif isinstance(node, AndOr):
                walk(node.first, in_pipe)
                for _op, c in node.rest:
                    walk(c, in_pipe)
            elif isinstance(node, (If,)):
                for c in node.cond + node.then + node.orelse:
                    walk(c, in_pipe)
            elif isinstance(node, (While, For)):
                for c in node.body:
                    walk(c, in_pipe)
        body = fd.body.body if isinstance(fd.body, Group) else [fd.body]
        for b in body:
            walk(b)
        if calls and (len(calls) >= 2 or any(calls)) and bg_seen[0]:
            self.forkbombs.add(name)
        elif calls and bg_seen[0] and len(calls) >= 1 and not _has_guard(body):
            self.forkbombs.add(name)

    # ------------------------------------------------------------------------------ pipelines
    def run_pipeline(self, n: Pipeline) -> Pipe:
        prev = EMPTY_PIPE
        bg_before = self.loop
        for idx, c in enumerate(n.cmds):
            if isinstance(c, Simple):
                prev = self.run_simple(c, prev, last_in_pipe=(idx == len(n.cmds) - 1), pipeline_len=len(n.cmds))
            else:
                prev = self.run_node(c)
        return prev

    def run_simple(self, n: Simple, stdin: Pipe, last_in_pipe: bool = True, pipeline_len: int = 1) -> Pipe:
        self.ctx.tick()
        # assignments
        for name, w, append in n.assigns:
            if w.parts and w.parts[0].k == "array":            # NAME=(a b c): remember the elements for `for x in "${NAME[@]}"`
                elems = []
                for ew in w.parts[0].v:
                    elems.extend(self.expand_word(ew))
                self.arrays[name] = elems
                self.vars[name] = elems[0] if elems else V(c="")
                continue
            vs = self.expand_word(w, assignment=True)
            v = vs[0] if vs else V(c="")
            if append and name in self.vars:
                old = self.vars[name]
                v = V(c=_cat(old, v), labels=U(old.labels, v.labels), src=U(old.src, v.src))
            self.vars[name] = v
            if secret_assign(name, v):
                pass
        if not n.words:
            if n.redirs:
                return self._apply_redirs_to_pipe(EMPTY_PIPE, n.redirs, n.line, bare=True, stdin=stdin)
            return EMPTY_PIPE
        args: list = []
        for w in n.words:
            args.extend(self.expand_word(w))
        if not args:
            return EMPTY_PIPE
        bg = n.bg
        if bg:
            self.loop += 1
        try:
            out = self.dispatch(args, n.line, stdin, n.redirs, bg=bg, last=last_in_pipe)
        finally:
            if bg:
                self.loop -= 1
        return self._apply_redirs_to_pipe(out, n.redirs, n.line, stdin=stdin, args=args)

    # ------------------------------------------------------------------------------ redirections
    def _apply_redirs_to_pipe(self, out: Pipe, redirs: list, line: int, bare: bool = False, stdin: Pipe = EMPTY_PIPE, args=None) -> Pipe:
        res = out
        for r in redirs:
            if r.target is None:
                continue
            tv = self.expand_word(r.target)
            t = tv[0] if tv else V(c="")
            path = t.c if isinstance(t.c, str) else ""
            op = r.op
            fd = r.fd
            if op in ("<<", "<<-"):
                continue
            if op == "<<<":
                continue
            if op in (">&", "<&", "&>", "&>>") and (path.startswith("/dev/tcp/") or path.startswith("/dev/udp/")):
                is_shell = bool(args) and isinstance(args[0].c, str) and _basename(args[0].c) in SHELLS
                self._dev_tcp(path, line, payload=res, reverse_shell=is_shell or any(r2.op in (">&", "<&") and r2.fd == 0 for r2 in redirs))
                continue
            if op in (">&", "<&"):
                continue
            if op == "<":
                if "/dev/" in path and path.startswith("/dev/tcp/"):
                    self._dev_tcp(path, line)
                    continue
                lab, src = self.file_labels(path)
                pc = K.classify_path(path) if path else set()
                self.E("READ_FILE", line, "redirect<", target=path, tl=t.labels, pathc=pc, pl=lab, flags={"redirect"},
                       extra={"src": src})
                res = Pipe(U(res.labels, lab), U(res.src, src), res.tags, res.text)
                continue
            # output redirects
            if fd not in (None, 1) and op in (">", ">>") and fd != 1:
                continue
            if path in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "") and HOLE not in path:
                continue
            if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                self._dev_tcp(path, line, payload=res)
                continue
            if path.startswith("/dev/fd/") or path.startswith("/proc/self/fd"):
                continue
            pc = K.classify_path(path)
            # bare redirect `> file` truncates; heredoc content / command stdout is the payload
            content = None
            for rr in redirs:
                if rr.op in ("<<", "<<-") and rr.body is not None:
                    content = self.expand_text(rr.body, rr.body_expand)
            if content is None and res.text is not None:
                content = res.text
            plabels = U(res.labels)
            fl = {"append"} if op in (">>", "&>>") else set()
            if bare:
                fl.add("truncate")
                if stdin and stdin.text is not None:
                    content = stdin.text
            if "unbounded" in res.tags:
                fl.add("unbounded_source")
            if "DEVICE" in pc:
                self.E("DELETE", line, "redirect>", target=path, tl=t.labels, pathc=pc, flags={"device", "overwrite"})
            self.E("WRITE_FILE", line, "redirect>", target=path, tl=t.labels, pl=plabels, pathc=pc, flags=fl,
                   extra={"content": content or "", "src": res.src})
            if "unbounded" in res.tags and "DEVSRC" not in pc and "DEVICE" not in pc:
                self.E("DISK_FILL", line, "redirect>", target=path, flags={"unbounded", "no_limit"}, pathc=pc)
            self.vfs[path] = (plabels, res.src, "download" in res.tags)
            res = Pipe(res.labels, res.src, res.tags - {"unbounded"}, res.text)
        return res

    def _dev_tcp(self, path: str, line: int, payload: Pipe = EMPTY_PIPE, reverse_shell: bool = False) -> None:
        m = re.match(r"/dev/(tcp|udp)/([^/]+)/?(\S*)", path)
        if not m:
            return
        host = m.group(2)
        hc = K.classify_host(host)
        fl = {"dev_tcp"}
        if reverse_shell:
            fl.add("reverse_shell")
            self.E("REVERSE_SHELL", line, "/dev/" + m.group(1), target=host, hostc=hc, flags=fl)
            return
        self.E("NET_CONNECT", line, "/dev/" + m.group(1), target=host, hostc=hc, flags=fl, pl=payload.labels, extra={"src": payload.src})

    def expand_text(self, text: str, expand: bool) -> str:
        if not expand:
            return text
        lx_parts = []
        from .shparse import Lexer
        lx = Lexer(text)
        # reuse the double-quote reader on the raw text
        lx.s = text + '"'
        lx.n = len(lx.s)
        lx.i = 0
        try:
            lx.read_dquote(lx_parts)
        except Exception:
            return text
        w = Word(lx_parts, 0)
        vs = self.expand_word(w)
        return vs[0].c if vs and isinstance(vs[0].c, str) else text

    # ------------------------------------------------------------------------------ expansion
    def lookup(self, name: str, op: str, arg: str, quoted: bool) -> V:
        if op in (":?", "?"):            # ${var:?} aborts the script when the variable is empty or unset: a refusal path, like an explicit -z check
            self.rm_guard = True
        if op == "#len":
            return V(c=HOLE)
        if name in self.vars:
            v = self.vars[name]
            if op in (":-", "-") and (v.c == "" and op == ":-"):
                return self._expand_arg(arg)
            if op in ("#", "##", "%", "%%", "/", "//", "^", "^^", ",", ",,", ":"):
                return V(c=HOLE if op != ":" else HOLE, labels=v.labels, src=v.src, lines=v.lines)
            return v
        if name.isdigit() and name != "0":
            if op in (":-", "-"):
                d = self._expand_arg(arg)
                return V(c=HOLE, labels=U(d.labels, {USER}), src=U(d.src, {"a command-line argument"}))
            return V(c=HOLE, labels=U({USER}), src=frozenset({"a command-line argument"}))
        if name in ("@", "*"):
            return V(c=HOLE, labels=U({USER}), src=frozenset({"command-line arguments"}))
        if name == "0":
            return V(c=self.script_name_marker, meta={"is_self": True})
        if name in ("#", "?", "$", "!", "-"):
            return V(c=HOLE)
        if name in KNOWN_ENV:
            return V(c=KNOWN_ENV[name], labels=U({ENV}))
        if op in (":-", "-", ":=", "="):
            d = self._expand_arg(arg)
            return d
        if op in (":?", "?"):
            return V(c=HOLE, labels=U({ENV}))
        if CI_ENV.match(name):
            return V(c=HOLE, labels=U({ENV}))
        # unset variable
        if self.set_u:
            raise ShellExit()
        return V(c="", meta={"unset": True, "name": name}, labels=U({ENV}) if name.isupper() else EMPTY)

    def _expand_arg(self, arg: str) -> V:
        if not arg:
            return V(c="")
        from .shparse import Lexer
        lx = Lexer(arg + '"')
        parts: list = []
        try:
            lx.read_dquote(parts)
        except Exception:
            return V(c=arg)
        vs = self.expand_word(Word(parts, 0))
        return vs[0] if vs else V(c="")

    def expand_word(self, w: Word, assignment: bool = False) -> list:
        # brace expansion for plain literal words
        if not assignment and len(w.parts) == 1 and w.parts[0].k == "lit" and not w.parts[0].q:
            t = w.parts[0].v
            if "{" in t and "}" in t:
                exp = _brace_expand(t)
                if exp:
                    return [V(c=e, lines=frozenset({w.line})) for e in exp]
        buf: list = []
        labels: set = set()
        src: set = set()
        quoted = False
        unset_only = True
        unset_names: list = []
        has_glob = False
        meta: dict = {}
        any_part = False
        for p in w.parts:
            any_part = True
            if p.q:
                quoted = True
            if p.k == "lit":
                buf.append(p.v)
                unset_only = False if p.v else unset_only
            elif p.k == "glob":
                buf.append(p.v)
                has_glob = True
                unset_only = False
            elif p.k == "hole":
                buf.append(HOLE)
                labels |= self.hole_labels
                src |= self.hole_src
                unset_only = False
            elif p.k == "var":
                name, op, arg = p.v
                v = self.lookup(name, op, arg, p.q)
                s = v.c if isinstance(v.c, str) else (str(v.c) if v.c is not UNK and v.c is not None else HOLE)
                buf.append(s)
                labels |= v.labels
                src |= v.src
                if v.meta and v.meta.get("unset"):
                    unset_names.append(v.meta.get("name"))
                    meta["unset"] = True
                else:
                    unset_only = False
                if v.meta and v.meta.get("is_self"):
                    meta["is_self"] = True
                if v.meta and v.meta.get("subpipe") is not None:
                    meta["subpipe"] = v.meta["subpipe"]
            elif p.k == "sub":
                if self.depth > 6:
                    buf.append(HOLE)
                    continue
                pipe = self.run_sub(p.v, w.line)
                txt = pipe.text.strip("\n") if pipe.text is not None else None
                buf.append(txt if txt is not None else HOLE)
                labels |= pipe.labels | {CMDSUB}
                src |= pipe.src
                meta["subpipe"] = pipe
                unset_only = False
            elif p.k == "proc":
                direction, inner = p.v if isinstance(p.v, tuple) else ("<", p.v)
                pipe = self.run_sub(inner, w.line)
                buf.append("/dev/fd/63")
                labels |= pipe.labels
                src |= pipe.src
                meta["procpipe"] = pipe
                unset_only = False
            elif p.k == "arith":
                buf.append(HOLE)
                unset_only = False
        text = "".join(buf)
        if any_part and unset_only and text == "" and not quoted and not assignment:
            return []
        if has_glob:
            meta["glob"] = True
        meta["quoted"] = quoted
        if unset_names:
            meta["unset_names"] = unset_names
        v = V(c=text, labels=U(labels), src=U(src), lines=frozenset({w.line}), meta=meta)
        return [v]

    def run_sub(self, inner: str, line: int) -> Pipe:
        saved = dict(self.vars)
        try:
            self.depth += 1
            pipe = self.run_text_inline(inner, line)
        finally:
            self.depth -= 1
            self.vars = saved
        return pipe

    def run_text_inline(self, inner: str, line: int) -> Pipe:
        try:
            ast, _c = parse(inner)
        except Exception:
            return EMPTY_PIPE
        old_pin = self.ctx.pin_line
        if not old_pin:
            self.ctx.pin_line = line + self.ctx.line_base
        try:
            return self.run_list(ast)
        finally:
            self.ctx.pin_line = old_pin

    # ------------------------------------------------------------------------------ file helpers
    def file_labels(self, path: str):
        if not path:
            return EMPTY, EMPTY
        if path in self.vfs:
            lab, src, _dl = self.vfs[path]
            return lab, src
        pc = K.classify_path(path)
        if "SECRET_STORE" in pc:
            return U({SECRET, FILE}), frozenset({"the credential file " + path})
        if "SYSTEM_SENSITIVE" in pc:
            return U({SENS_SYS, FILE}), frozenset({"the system file " + path})
        if "DEVSRC" in pc:
            return EMPTY, EMPTY
        return U({FILE}), frozenset({"the file " + path})

    # ------------------------------------------------------------------------------ dispatch
    def dispatch(self, args: list, line: int, stdin: Pipe, redirs: list, bg: bool = False, last: bool = True) -> Pipe:
        a0 = args[0]
        name_raw = a0.c if isinstance(a0.c, str) else ""
        if not name_raw or HOLE in name_raw:
            # command position is attacker/unknown controlled
            self.E("EXEC_PROC", line, "dynamic_command", target=name_raw or HOLE, tl=a0.labels or self.hole_labels, flags={"dynamic_command"},
                   extra={"argv": [x.c for x in args]})
            return Pipe(U(a0.labels), a0.src, EMPTY, None)
        name = _basename(name_raw)
        if bg and self.mult >= 1000:
            self.E("SPAWN", line, name, flags={"background", "flood"})          # a loop that launches background jobs thousands of times
        if a0.meta and a0.meta.get("is_self"):
            self.E("SPAWN", line, "self", flags={"self_spawn"} | ({"background"} if bg else set()))
            return EMPTY_PIPE
        if name in self.funcs:
            return self.call_function(name, args[1:], line, stdin, bg)
        if name_raw in self.vfs and self.vfs[name_raw][2]:
            self.E("PIPE_EXEC", line, name_raw, target=name_raw, flags={"downloaded", "script_file"})
            return EMPTY_PIPE
        if name in WRAPPERS:
            return self.wrapper(name, args, line, stdin, redirs, bg)
        h = getattr(self, "h_" + re.sub(r"[^a-z0-9_]", "_", name), None) if re.fullmatch(r"[a-z0-9_.\-+:\[\]]+", name) else None
        if name == ":":
            return EMPTY_PIPE
        if name in ("[", "[["):
            return EMPTY_PIPE
        if name in ("python2", "python3", "pypy", "pypy3") or re.fullmatch(r"python[\d.]*", name):
            return self.h_python(args, line, stdin)
        if name in ("nodejs", "node", "deno", "bun"):
            return self.h_node(args, line, stdin)
        if re.fullmatch(r"mkfs(\.\w+)?", name):
            return self.h_mkfs(args, line)
        if name in SHELLS:
            return self.h_shell(args, line, stdin, redirs)
        if name in ("perl", "ruby", "php", "lua", "pwsh", "powershell", "osascript"):
            return self.h_interp(name, args, line, stdin)
        if name in DOWNLOADERS and name not in ("http", "https", "fetch"):
            return self.h_download(name, args, line, stdin)
        if name in ("apt", "apt-get", "aptitude", "yum", "dnf", "zypper", "apk", "pacman", "brew", "choco", "winget", "snap", "port", "pkg", "scoop", "opkg"):
            return self.h_syspkg(name, args, line)
        if name in ("pip", "pip2", "pip3", "pipx", "uv", "poetry", "pipenv", "conda", "mamba", "easy_install"):
            return self.h_pip(name, args, line)
        if name in ("npm", "yarn", "pnpm", "npx", "bun", "bower", "pnpx"):
            return self.h_npm(name, args, line)
        if name in ("gem", "cargo", "go", "composer", "nuget", "dotnet", "cpan", "cpanm", "luarocks", "mix", "cabal", "stack", "pecl", "swift", "mvn", "gradle"):
            return self.h_otherpkg(name, args, line)
        if name in ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet", "cryptcat", "pwncat"):
            return self.h_nc(name, args, line, stdin)
        if name in ("scp", "rsync", "sftp", "ftp", "rclone", "gsutil", "aws", "az", "gcloud", "s3cmd", "mc", "azcopy", "ssh", "tftp"):
            return self.h_remote(name, args, line, stdin)
        if name in ("nslookup", "dig", "host", "drill", "resolvectl", "getent"):
            return self.h_dns(name, args, line)
        if name in ("nmap", "masscan", "zmap", "hping3", "unicornscan", "fping", "arp-scan", "netdiscover", "nikto", "sqlmap", "hydra", "medusa", "john", "hashcat"):
            return self.h_scan(name, args, line)
        if name in _PASSWORD_CLI:
            self._cli_password(name, args, line)
        if name in ("psql", "mysql", "mariadb", "sqlite3", "sqlcmd"):
            getattr(self, "h_" + name)(args, line, stdin)            # the SQL given on the command line is analysed first
        if name in ("cat", "head", "tail", "less", "more", "tac", "nl", "grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed", "cut", "sort", "uniq", "tr",
                    "wc", "xxd", "od", "hexdump", "strings", "zcat", "bzcat", "xzcat", "gunzip", "gzip", "bzip2", "xz", "base32", "basenc", "openssl", "jq", "yq",
                    "column", "paste", "fold", "rev", "shuf", "tee", "cp", "mv", "install", "dd", "tar", "zip", "unzip", "7z", "7za", "cpio", "ar", "split", "diff", "cmp", "file", "stat", "ls", "dir", "find", "base64", "gpg", "zgrep", "bat", "sqlite3", "mysqldump", "pg_dump", "mongodump", "redis-cli", "psql", "mysql", "mongo", "mongosh"):
            return self.h_files(name, args, line, stdin, redirs)
        if h is not None:
            try:
                return h(args, line, stdin)
            except (Stop, ShellExit):
                raise
        return self.h_generic(name, args, line, stdin)

    # ------------------------------------------------------------------------------ functions
    def call_function(self, name: str, args: list, line: int, stdin: Pipe, bg: bool) -> Pipe:
        fd = self.funcs[name]
        if self.call_depth > 6:
            return EMPTY_PIPE
        if name in self.forkbombs:
            self.E("FORK_BOMB", line, name, flags={"fork_bomb"})
        saved = {}
        for i, a in enumerate(args[:9], start=1):
            saved[str(i)] = self.vars.get(str(i))
            self.vars[str(i)] = a
        self.call_depth += 1
        old_loop = self.loop
        if bg:
            self.loop += 1
        try:
            body = fd.body.body if isinstance(fd.body, Group) else [fd.body]
            out = self.run_list(body)
        finally:
            self.call_depth -= 1
            self.loop = old_loop
            for k, v in saved.items():
                if v is None:
                    self.vars.pop(k, None)
                else:
                    self.vars[k] = v
        return out

    # ------------------------------------------------------------------------------ wrappers
    def wrapper(self, name: str, args: list, line: int, stdin: Pipe, redirs: list, bg: bool) -> Pipe:
        rest = list(args[1:])
        old_sudo = self.sudo
        if name in ("sudo", "doas"):
            self.sudo = True
            while rest:
                t = rest[0].c if isinstance(rest[0].c, str) else ""
                if t in ("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"):
                    rest = rest[2:]
                elif t.startswith("-"):
                    rest = rest[1:]
                else:
                    break
        elif name == "env":
            while rest:
                t = rest[0].c if isinstance(rest[0].c, str) else ""
                if t in ("-u", "-C", "-S"):
                    rest = rest[2:]
                elif t.startswith("-"):
                    rest = rest[1:]
                elif "=" in t and re.match(r"[A-Za-z_]\w*=", t):
                    k, _, val = t.partition("=")
                    self.vars[k] = V(c=val, labels=rest[0].labels, src=rest[0].src)
                    rest = rest[1:]
                else:
                    break
            if not rest:
                return Pipe(U({ENV, ENV_DUMP}), frozenset({"all environment variables"}), EMPTY, HOLE)
        elif name in ("timeout",):
            while rest and isinstance(rest[0].c, str) and rest[0].c.startswith("-"):
                rest = rest[2:] if rest[0].c in ("-s", "-k", "--signal", "--kill-after") else rest[1:]
            rest = rest[1:]
        elif name in ("nice", "ionice", "taskset", "stdbuf", "flock", "caffeinate", "strace", "ltrace", "watch", "script"):
            while rest and isinstance(rest[0].c, str) and rest[0].c.startswith("-"):
                rest = rest[2:] if (rest[0].c in ("-n", "-c", "-p", "-i", "-o", "-e", "-d", "-t") and len(rest) > 1) else rest[1:]
            if name in ("taskset", "flock") and rest:
                rest = rest[1:]
        elif name in ("command", "builtin", "exec", "time", "nohup", "setsid", "unbuffer", "chronic", "proxychains", "proxychains4", "torsocks"):
            while rest and isinstance(rest[0].c, str) and rest[0].c.startswith("-"):
                rest = rest[1:]
        elif name in ("xargs", "parallel"):
            return self.h_xargs(args, line, stdin, redirs)
        if not rest:
            self.sudo = old_sudo
            return EMPTY_PIPE
        try:
            return self.dispatch(rest, line, stdin, redirs, bg=bg)
        finally:
            self.sudo = old_sudo

    def h_xargs(self, args: list, line: int, stdin: Pipe, redirs: list) -> Pipe:
        rest = list(args[1:])
        repl = None
        while rest and isinstance(rest[0].c, str) and rest[0].c.startswith("-"):
            o = rest[0].c
            if o in ("-I", "-i", "-n", "-L", "-P", "-d", "-E", "-s", "-a"):
                if o in ("-I",) and len(rest) > 1:
                    repl = rest[1].c
                rest = rest[2:]
            elif o.startswith("-I") and len(o) > 2:
                repl = o[2:]
                rest = rest[1:]
            else:
                rest = rest[1:]
        if not rest:
            return EMPTY_PIPE
        extra = V(c=HOLE, labels=U(stdin.labels, {FILE} if not stdin.labels else EMPTY), src=stdin.src, meta={"xargs": True})
        new = []
        for a in rest:
            if repl and isinstance(a.c, str) and repl in a.c:
                new.append(V(c=a.c.replace(repl, HOLE), labels=U(a.labels, extra.labels), src=U(a.src, extra.src)))
            else:
                new.append(a)
        if not repl:
            new.append(extra)
        return self.dispatch(new, line, EMPTY_PIPE, redirs)

    # ------------------------------------------------------------------------------ handlers
    def h_echo(self, args, line, stdin):
        vals = [a for a in args[1:] if not (isinstance(a.c, str) and re.fullmatch(r"-[neE]+", a.c))]
        text = " ".join(a.c if isinstance(a.c, str) else HOLE for a in vals)
        return Pipe(U(*[a.labels for a in vals]), U(*[a.src for a in vals]), EMPTY, text)

    def h_printf(self, args, line, stdin):
        vals = args[1:]
        text = " ".join(a.c if isinstance(a.c, str) else HOLE for a in vals)
        text = text.replace("\\n", "\n").replace("\\t", "\t")
        return Pipe(U(*[a.labels for a in vals]), U(*[a.src for a in vals]), EMPTY, text)

    h_print = h_echo

    def h_cd(self, args, line, stdin):
        tgt = args[1] if len(args) > 1 else None
        if tgt is None:
            return EMPTY_PIPE
        if tgt.meta and tgt.meta.get("unset"):
            self.cd_empty = True
        self.cd_unchecked = not self.set_e
        return EMPTY_PIPE

    def h_set(self, args, line, stdin):
        for a in args[1:]:
            t = a.c if isinstance(a.c, str) else ""
            if t.startswith("-") and not t.startswith("--"):
                if "u" in t[1:] or t == "-o" and False:
                    self.set_u = True
                if "e" in t[1:]:
                    self.set_e = True
        joined = " ".join(a.c for a in args[1:] if isinstance(a.c, str))
        if re.search(r"-o\s+nounset", joined):
            self.set_u = True
        if re.search(r"-o\s+errexit", joined):
            self.set_e = True
        if re.search(r"\+o\s+history|\+H", joined):
            self.E("SYSTEM_CTL", line, "set", flags={"defense_evasion", "history_off"})
        if len(args) == 1:
            return Pipe(U({ENV, ENV_DUMP}), frozenset({"all shell variables"}), EMPTY, HOLE)
        return EMPTY_PIPE

    def h_export(self, args, line, stdin):
        for a in args[1:]:
            t = a.c if isinstance(a.c, str) else ""
            if "=" in t and re.match(r"[A-Za-z_]\w*=", t):
                k, _, val = t.partition("=")
                self.vars[k] = V(c=val, labels=a.labels, src=a.src)
                if k == "LD_PRELOAD" or k == "LD_LIBRARY_PATH":
                    self.E("PERSIST", line, "export", target=val, flags={"ld_preload"} if k == "LD_PRELOAD" else {"ld_path"})
                if k in ("HISTSIZE", "HISTFILESIZE") and val == "0" or k == "HISTFILE" and val in ("/dev/null", ""):
                    self.E("SYSTEM_CTL", line, "export", flags={"defense_evasion", "history_off"})
        if len(args) == 1 or (len(args) == 2 and args[1].c == "-p"):
            return Pipe(U({ENV, ENV_DUMP}), frozenset({"all environment variables"}), EMPTY, HOLE)
        return EMPTY_PIPE

    h_declare = h_export
    h_local = h_export
    h_readonly = h_export
    h_typeset = h_export

    def h_unset(self, args, line, stdin):
        for a in args[1:]:
            t = a.c if isinstance(a.c, str) else ""
            if t == "HISTFILE":
                self.E("SYSTEM_CTL", line, "unset", flags={"defense_evasion", "history_off"})
            self.vars.pop(t, None)
        return EMPTY_PIPE

    def h_read(self, args, line, stdin):
        names = [a.c for a in args[1:] if isinstance(a.c, str) and re.fullmatch(r"[A-Za-z_]\w*", a.c)]
        for nm in names or ["REPLY"]:
            self.vars[nm] = V(c=HOLE, labels=U({USER}), src=frozenset({"user input"}))
        return EMPTY_PIPE

    def h_shift(self, args, line, stdin):
        return EMPTY_PIPE

    def h_exit(self, args, line, stdin):
        return EMPTY_PIPE

    h_return = h_exit
    h_break = h_exit
    h_continue = h_exit

    def h_sleep(self, args, line, stdin):
        return EMPTY_PIPE

    def h_alias(self, args, line, stdin):
        return EMPTY_PIPE

    def h_trap(self, args, line, stdin):
        if len(args) >= 3 and isinstance(args[1].c, str) and args[1].c not in ("-", ""):
            self.run_text(args[1].c, line_pin=line)
        return EMPTY_PIPE

    def h_eval(self, args, line, stdin):
        vals = args[1:]
        text = " ".join(a.c if isinstance(a.c, str) else HOLE for a in vals)
        labels = U(*[a.labels for a in vals])
        src = U(*[a.src for a in vals])
        flags = {"eval"}
        remote = any((a.meta or {}).get("subpipe") is not None and "remote" in (a.meta["subpipe"].tags) for a in vals)
        decoded = any((a.meta or {}).get("subpipe") is not None and "decoded" in (a.meta["subpipe"].tags) for a in vals)
        if remote:
            flags.add("remote")
        if decoded or DECODED in labels:
            flags.add("decoded")
        if HOLE in text:
            flags.add("dynamic")
        self.E("EVAL", line, "eval", target=text, tl=labels, flags=flags, extra={"src": src})
        if text and HOLE not in text.replace(HOLE, "") or text:
            self.run_text(text, line_pin=line, hole_labels=labels, hole_src=src)
        return EMPTY_PIPE

    def h_source(self, args, line, stdin):
        if len(args) < 2:
            return EMPTY_PIPE
        a = args[1]
        pipe = (a.meta or {}).get("procpipe")
        fl = {"source"}
        if pipe is not None and "remote" in pipe.tags:
            fl.add("remote")
        if pipe is not None and "decoded" in pipe.tags:
            fl.add("decoded")
        path = a.c if isinstance(a.c, str) else ""
        if path in self.vfs and self.vfs[path][2]:
            fl.add("downloaded")
        if len(fl) > 1 or HOLE in path:
            if HOLE in path:
                fl.add("dynamic")
            self.E("PIPE_EXEC", line, "source", target=path, tl=a.labels, flags=fl)
        if pipe is not None and pipe.text:
            self.run_text(pipe.text, line_pin=line)
        return EMPTY_PIPE

    h__ = h_source  # '.'

    def h_shell(self, args, line, stdin, redirs):
        name = _basename(args[0].c)
        rest = args[1:]
        code_idx = None
        i = 0
        while i < len(rest):
            t = rest[i].c if isinstance(rest[i].c, str) else ""
            if t == "-c" or (t.startswith("-") and not t.startswith("--") and "c" in t[1:] and len(t) <= 4):
                code_idx = i + 1
                break
            if t.startswith("-"):
                i += 1
                continue
            break
        if code_idx is not None and code_idx < len(rest):
            a = rest[code_idx]
            text = a.c if isinstance(a.c, str) else HOLE
            fl = {"shell_c"}
            sp = (a.meta or {}).get("subpipe")
            if sp is not None and "remote" in sp.tags:
                fl.add("remote")
            if sp is not None and "decoded" in sp.tags:
                fl.add("decoded")
            if USER in a.labels:
                fl.add("tainted")
            self.E("EXEC_SHELL", line, name + " -c", target=text, tl=a.labels, flags=fl, extra={"src": a.src})
            for j, pa in enumerate(rest[code_idx + 1:][:9]):
                self.vars[str(j)] = pa
            self.run_text(text, line_pin=line, hole_labels=a.labels, hole_src=a.src)
            return EMPTY_PIPE
        # script file or stdin
        script = None
        for a in rest:
            t = a.c if isinstance(a.c, str) else ""
            if not t.startswith("-"):
                script = a
                break
        if script is None:
            if stdin.tags & {"remote", "decoded", "encoded"} or stdin.labels & {NET, DECODED}:
                fl = {"stdin"}
                if "remote" in stdin.tags:
                    fl.add("remote")
                if "decoded" in stdin.tags or DECODED in stdin.labels:
                    fl.add("decoded")
                self.E("PIPE_EXEC", line, name, flags=fl, pl=stdin.labels, extra={"src": stdin.src})
            if stdin.text:
                self.run_text(stdin.text, line_pin=line, hole_labels=stdin.labels)
            return EMPTY_PIPE
        path = script.c if isinstance(script.c, str) else ""
        pipe = (script.meta or {}).get("procpipe")
        fl = {"script_file"}
        if pipe is not None:
            if "remote" in pipe.tags:
                fl.add("remote")
            if "decoded" in pipe.tags:
                fl.add("decoded")
        if path in self.vfs and self.vfs[path][2]:
            fl.add("downloaded")
        if HOLE in path:
            fl.add("dynamic")
        if len(fl) > 1:
            self.E("PIPE_EXEC", line, name, target=path, tl=script.labels, flags=fl)
        if pipe is not None and pipe.text:
            self.run_text(pipe.text, line_pin=line)
        return EMPTY_PIPE

    # ------------------------------------------------------------------------------ database clients: the argument IS the SQL
    def _embedded_sql(self, text: str, line: int) -> None:
        """SQL handed to a database client on the command line is analysed exactly like SQL in a .sql file."""
        if not text or not text.replace(HOLE, "").strip():
            return
        from . import sqlfe
        old = self.ctx.pin_line
        if not old:
            self.ctx.pin_line = line + self.ctx.line_base
        self.ctx.depth += 1
        try:
            sqlfe.analyze_sql_text(text, self.ctx, nested=True)
        finally:
            self.ctx.depth -= 1
            self.ctx.pin_line = old

    def _sql_cli(self, args: list, line: int, flags: tuple, positional_sql: bool = False) -> Pipe:
        rest = args[1:]
        i = 0
        positional = []
        while i < len(rest):
            t = rest[i].c if isinstance(rest[i].c, str) else ""
            hit = next((f for f in flags if t == f or (f.startswith("--") and t.startswith(f + "="))), None)
            if hit is not None:
                if "=" in t and t.startswith("--"):
                    self._embedded_sql(t.split("=", 1)[1], line)
                elif i + 1 < len(rest):
                    self._embedded_sql(rest[i + 1].c if isinstance(rest[i + 1].c, str) else HOLE, line)
                    i += 1
            elif t.startswith("-"):
                if t in ("-U", "-h", "-p", "-d", "-u", "-P", "-D", "--host", "--port", "--username", "--dbname", "-W") and i + 1 < len(rest):
                    i += 1
            else:
                positional.append(rest[i])
            i += 1
        if positional_sql and len(positional) >= 2:          # sqlite3 <db> "<sql>"
            self._embedded_sql(positional[1].c if isinstance(positional[1].c, str) else HOLE, line)
        return EMPTY_PIPE

    def _cli_password(self, name: str, args: list, line: int) -> None:
        """A password written into the command line (mysql -pSECRET, --password=SECRET, sshpass -p SECRET) is a hardcoded credential."""
        rest = args[1:]
        for i, a in enumerate(rest):
            t = a.c if isinstance(a.c, str) else ""
            val = None
            if name == "sshpass":
                if t == "-p" and i + 1 < len(rest) and isinstance(rest[i + 1].c, str):
                    val = rest[i + 1].c
                elif t.startswith("-p") and len(t) > 2:
                    val = t[2:]
            elif t.startswith("--password=") or t.startswith("--pass="):
                val = t.split("=", 1)[1]
            elif t.startswith("-p") and len(t) > 2 and name in _PASSWORD_AFTER_P and not t.startswith("--"):
                val = t[2:]
            if val and HOLE not in val and not val.startswith("$") and len(val) >= 4 and not re.fullmatch(r"[xX*\-]+", val):
                self.ctx.emit(Event(cap="SECRET_LITERAL", line=line, name="password", target="command_line_password", flags={"command_line_password"},
                                    extra={"conf": 0.8, "preview": val[:1] + "***", "kind": "command_line_password", "var": "password"}))
                return

    def h_psql(self, args, line, stdin):
        return self._sql_cli(args, line, ("-c", "--command"))

    def h_mysql(self, args, line, stdin):
        return self._sql_cli(args, line, ("-e", "--execute"))

    h_mariadb = h_mysql

    def h_sqlite3(self, args, line, stdin):
        return self._sql_cli(args, line, ("-cmd",), positional_sql=True)

    def h_sqlcmd(self, args, line, stdin):
        return self._sql_cli(args, line, ("-Q", "-q"))

    def h_python(self, args, line, stdin):
        rest = args[1:]
        code = None
        i = 0
        while i < len(rest):
            t = rest[i].c if isinstance(rest[i].c, str) else ""
            if t == "-c" and i + 1 < len(rest):
                code = rest[i + 1]
                break
            if t == "-m" and i + 1 < len(rest):
                mod = rest[i + 1].c if isinstance(rest[i + 1].c, str) else ""
                if mod == "pip":
                    return self.h_pip("pip", [V(c="pip")] + rest[i + 2:], line)
                if mod in ("http.server", "SimpleHTTPServer"):
                    self.E("NET_LISTEN", line, "http.server", flags={"file_server"}, hostc="LOOPBACK")
                if mod in ("venv", "virtualenv", "compileall", "json.tool", "unittest", "pytest", "black", "flake8", "build", "ensurepip"):
                    return EMPTY_PIPE
                break
            if t.startswith("-"):
                i += 1
                continue
            break
        if code is not None:
            text = code.c if isinstance(code.c, str) else HOLE
            self.E("EVAL", line, "python -c", target=text, tl=code.labels, flags={"shell_c", "interp_c"}, extra={"src": code.src})
            self._run_python(text, line, code.labels, code.src)
            return EMPTY_PIPE
        script = next((a for a in rest if isinstance(a.c, str) and not a.c.startswith("-")), None)
        if script is None:
            if stdin.text:
                self._run_python(stdin.text, line, stdin.labels, stdin.src)
            if stdin.tags & {"remote", "decoded"}:
                fl = {"stdin"} | ({"remote"} if "remote" in stdin.tags else set()) | ({"decoded"} if "decoded" in stdin.tags else set())
                self.E("PIPE_EXEC", line, "python", flags=fl, pl=stdin.labels)
            return EMPTY_PIPE
        path = script.c
        if path in self.vfs and self.vfs[path][2]:
            self.E("PIPE_EXEC", line, "python", target=path, flags={"downloaded", "script_file"})
        return EMPTY_PIPE

    def _run_python(self, text: str, line: int, labels: frozenset, src: frozenset) -> None:
        if self.ctx.depth > 3:
            return
        from . import pyfe
        self.ctx.depth += 1
        old_pin = self.ctx.pin_line
        if not old_pin:
            self.ctx.pin_line = line
        try:
            pyfe.analyze_python_text(text, self.ctx, hole_labels=labels, hole_src=src, nested=True)
        finally:
            self.ctx.depth -= 1
            self.ctx.pin_line = old_pin

    def h_node(self, args, line, stdin):
        rest = args[1:]
        for i, a in enumerate(rest):
            t = a.c if isinstance(a.c, str) else ""
            if t in ("-e", "--eval", "-p", "--print") and i + 1 < len(rest):
                code = rest[i + 1]
                text = code.c if isinstance(code.c, str) else HOLE
                self.E("EVAL", line, "node -e", target=text, tl=code.labels, flags={"shell_c", "interp_c"})
                from . import jsfe
                if self.ctx.depth <= 3:
                    self.ctx.depth += 1
                    old = self.ctx.pin_line
                    if not old:
                        self.ctx.pin_line = line
                    try:
                        jsfe.analyze_js_text(text, self.ctx, hole_labels=code.labels, nested=True)
                    finally:
                        self.ctx.depth -= 1
                        self.ctx.pin_line = old
                break
        return EMPTY_PIPE

    def h_interp(self, name, args, line, stdin):
        rest = args[1:]
        for i, a in enumerate(rest):
            t = a.c if isinstance(a.c, str) else ""
            if t in ("-e", "-r", "-E", "-c", "-Command", "-EncodedCommand", "-enc", "-ec") and i + 1 < len(rest):
                code = rest[i + 1]
                text = code.c if isinstance(code.c, str) else HOLE
                fl = {"shell_c", "interp_c"}
                if t.lower() in ("-encodedcommand", "-enc", "-ec"):
                    fl.add("decoded")
                    fl.add("encoded_cmd")
                self.E("EVAL", line, name + " " + t, target=text, tl=code.labels, flags=fl)
                self._scan_generic_text(text, line, code.labels)
                break
        if stdin.tags & {"remote", "decoded"}:
            fl = {"stdin"} | ({"remote"} if "remote" in stdin.tags else set()) | ({"decoded"} if "decoded" in stdin.tags else set())
            self.E("PIPE_EXEC", line, name, flags=fl, pl=stdin.labels)
        return EMPTY_PIPE

    def _scan_generic_text(self, text: str, line: int, labels: frozenset) -> None:
        # lightweight: treat as shell-ish text for URLs / commands
        if text and self.ctx.depth <= 3:
            self.run_text(text, line_pin=line, hole_labels=labels)

    # -- filesystem destructive -----------------------------------------------------------
    def _targets(self, args) -> list:
        out = []
        end_opts = False
        for a in args:
            t = a.c if isinstance(a.c, str) else ""
            if not end_opts and t == "--":
                end_opts = True
                continue
            if not end_opts and t.startswith("-") and len(t) > 1:
                continue
            out.append(a)
        return out

    def h_rm(self, args, line, stdin):
        opts = [a.c for a in args[1:] if isinstance(a.c, str) and a.c.startswith("-") and len(a.c) > 1]
        flat = "".join(o.lstrip("-") if not o.startswith("--") else "" for o in opts)
        recursive = "r" in flat or "R" in flat or any(o in ("--recursive",) for o in opts)
        force = "f" in flat or "--force" in opts
        interactive = "i" in flat and not force
        no_preserve = "--no-preserve-root" in opts
        tg = self._targets(args[1:])
        for t in tg:
            p = t.c if isinstance(t.c, str) else HOLE
            pc = K.classify_path(p)
            fl = set()
            if recursive:
                fl.add("recursive")
            if force:
                fl.add("force")
            if no_preserve:
                fl.add("no_preserve_root")
            if (t.meta or {}).get("glob") or "WILDCARD" in pc:
                fl.add("wildcard")
            if (t.meta or {}).get("unset"):
                fl.add("unset_var")
            if (t.meta or {}).get("xargs"):
                fl.add("xargs")
            if interactive:
                fl.add("interactive")
            if self.rm_guard:
                fl.add("guarded_target")
            if self.cd_unchecked and (p in ("*", ".", "./*", "./", "") or (not p.startswith(("/", "~")) and "wildcard" in fl)):
                fl.add("cwd_unchecked")
            if self.cd_empty and (p in ("*", ".", "./*", "./") or "wildcard" in fl and not p.startswith(("/", "~"))):
                fl.add("cd_empty_var")
            self.E("DELETE", line, "rm", target=p, tl=t.labels, pathc=pc, flags=fl, extra={"src": t.src, "unset_names": (t.meta or {}).get("unset_names")},
                   lines=t.lines)
        if not tg and False:
            pass
        return EMPTY_PIPE

    def h_unlink(self, args, line, stdin):
        return self.h_rm([args[0], V(c="-f")] + args[1:], line, stdin)

    def h_rmdir(self, args, line, stdin):
        return self.h_rm(args, line, stdin)

    def h_shred(self, args, line, stdin):
        for t in self._targets(args[1:]):
            p = t.c if isinstance(t.c, str) else HOLE
            self.E("DELETE", line, "shred", target=p, tl=t.labels, pathc=K.classify_path(p), flags={"shred", "force"}, extra={"src": t.src})
        return EMPTY_PIPE

    h_srm = h_shred
    h_wipe = h_shred

    def h_truncate(self, args, line, stdin):
        size = None
        for i, a in enumerate(args):
            if a.c in ("-s", "--size") and i + 1 < len(args) and isinstance(args[i + 1].c, str):
                size = parse_size(args[i + 1].c.lstrip("+"))
        tg = [a for a in self._targets(args[1:]) if not (isinstance(a.c, str) and re.fullmatch(r"[+\-]?\d+\w*", a.c))]
        for t in tg:
            p = t.c if isinstance(t.c, str) else HOLE
            pc = K.classify_path(p)
            if size is not None and size > 10 * 1024 ** 3:
                self.E("DISK_FILL", line, "truncate", target=p, flags={"huge"}, pathc=pc, extra={"size": size})
            elif size == 0 or size is None:
                self.E("DELETE", line, "truncate", target=p, tl=t.labels, pathc=pc, flags={"truncate"})
        return EMPTY_PIPE

    def h_fallocate(self, args, line, stdin):
        size = None
        for i, a in enumerate(args):
            if a.c in ("-l", "--length") and i + 1 < len(args) and isinstance(args[i + 1].c, str):
                size = parse_size(args[i + 1].c)
        tg = self._targets(args[1:])
        if size and size > 5 * 1024 ** 3:
            self.E("DISK_FILL", line, "fallocate", target=tg[-1].c if tg and isinstance(tg[-1].c, str) else None, flags={"huge"}, extra={"size": size})
        return EMPTY_PIPE

    def h_mkfs(self, args, line):
        tg = self._targets(args[1:])
        for t in tg:
            p = t.c if isinstance(t.c, str) else HOLE
            pc = K.classify_path(p)
            if "DEVICE" in pc or HOLE in p:
                self.E("DELETE", line, "mkfs", target=p, tl=t.labels, pathc=pc, flags={"device", "format"})
        return EMPTY_PIPE

    def h_wipefs(self, args, line, stdin):
        return self.h_mkfs(args, line)

    h_fdisk = h_wipefs
    h_parted = h_wipefs
    h_sgdisk = h_wipefs
    h_blkdiscard = h_wipefs

    def h_dd(self, args, line, stdin):
        kv = {}
        for a in args[1:]:
            if isinstance(a.c, str) and "=" in a.c:
                k, _, v = a.c.partition("=")
                kv[k] = (v, a)
        if_ = kv.get("if", ("", None))[0]
        of = kv.get("of", ("", None))[0]
        pc_of = K.classify_path(of) if of else set()
        pc_if = K.classify_path(if_) if if_ else set()
        has_count = "count" in kv
        bs = parse_size(kv["bs"][0]) if "bs" in kv else 512
        cnt = None
        if has_count:
            try:
                cnt = int(kv["count"][0])
            except ValueError:
                cnt = None
        total = (bs or 512) * cnt if cnt is not None else None
        if of and "DEVICE" in pc_of:
            self.E("DELETE", line, "dd", target=of, pathc=pc_of, flags={"device", "overwrite"} | ({"zero_fill"} if "DEVSRC" in pc_if else set()))
        elif of and of not in ("/dev/null", "/dev/stdout") and "DEVSRC" in pc_if:
            if not has_count and "seek" not in kv:
                self.E("DISK_FILL", line, "dd", target=of, pathc=pc_of, flags={"unbounded", "no_count"})
            elif total is not None and total * max(self.mult, 1) > 5 * 1024 ** 3:        # per-call size times the loop count
                self.E("DISK_FILL", line, "dd", target=of, pathc=pc_of, flags={"huge"}, extra={"size": total * max(self.mult, 1)})
        elif if_ and "DEVICE" in pc_if and of:
            self.E("READ_FILE", line, "dd", target=if_, pathc=pc_if, flags={"raw_device"})
        if if_ and "DEVSRC" in pc_if and not of:
            return Pipe(EMPTY, EMPTY, frozenset({"unbounded"} if not has_count else set()), None)
        return EMPTY_PIPE

    def h_yes(self, args, line, stdin):
        return Pipe(EMPTY, EMPTY, frozenset({"unbounded"}), "y")

    def h_stress(self, args, line, stdin):
        self.E("LOOP", line, "stress", flags={"unbounded", "busy", "stress_tool"})
        return EMPTY_PIPE

    h_stress_ng = h_stress

    def h_find(self, args, line, stdin):
        starts = []
        i = 1
        while i < len(args) and not (isinstance(args[i].c, str) and args[i].c.startswith("-") or args[i].c in ("!", "(")):
            starts.append(args[i])
            i += 1
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args]
        has_delete = "-delete" in texts
        exec_rm = False
        for j, t in enumerate(texts):
            if t in ("-exec", "-execdir", "-ok") and j + 1 < len(texts):
                cmd = _basename(texts[j + 1])
                if cmd in ("rm", "shred", "unlink", "rmdir"):
                    exec_rm = True
                elif cmd in ("sh", "bash") or cmd in WRAPPERS:
                    pass
                else:
                    pass
        if has_delete or exec_rm:
            for s in starts or [V(c=".")]:
                p = s.c if isinstance(s.c, str) else HOLE
                pc = K.classify_path(p)
                fl = {"recursive", "find_delete"}
                if (s.meta or {}).get("unset"):
                    fl.add("unset_var")
                # filtered by -name / -mtime / -type ... still scoped by path
                scoped = any(t in ("-name", "-iname", "-mtime", "-mmin", "-newer", "-regex", "-path", "-user", "-size") for t in texts)
                if scoped:
                    fl.add("filtered")
                self.E("DELETE", line, "find", target=p, tl=s.labels, pathc=pc, flags=fl, lines=s.lines)
        labs = U(*[s.labels for s in starts])
        pcs = [K.classify_path(s.c) for s in starts if isinstance(s.c, str)]
        return Pipe(U(labs, {FILE}), frozenset({"a file listing"}), EMPTY, None)

    def h_chmod(self, args, line, stdin):
        tg = self._targets(args[1:])
        if not tg:
            return EMPTY_PIPE
        mode_a = None
        recursive = any(isinstance(a.c, str) and a.c.startswith("-") and "R" in a.c for a in args[1:])
        nonopt = [a for a in args[1:] if not (isinstance(a.c, str) and a.c.startswith("-") and len(a.c) > 1)]
        if nonopt:
            mode_a = nonopt[0]
            tg = nonopt[1:]
        mode = mode_a.c if mode_a is not None and isinstance(mode_a.c, str) else ""
        setuid = bool(re.search(r"[ugoa]*\+[rwxXt]*s", mode) or re.fullmatch(r"[2467][0-7]{3}", mode) or re.fullmatch(r"[2467][0-7]{3}", mode.lstrip("0")))
        worldw = bool(re.fullmatch(r"[0-7]*[2367][0-7]?[2367]", mode) and mode.endswith(("7", "6", "3", "2"))) and mode.endswith(("777", "666")) or mode in ("a+rwx", "ugo+rwx", "o+w", "a+w", "o+rwx")
        for t in tg:
            p = t.c if isinstance(t.c, str) else HOLE
            pc = K.classify_path(p)
            if setuid:
                self.E("PRIV", line, "chmod", target=p, tl=t.labels, pathc=pc, flags={"chmod", "setuid"})
            elif worldw and (recursive or "ROOT" in pc or "SYSTEM_DIR" in pc or "PRIVFILE" in pc or "SECRET_STORE" in pc or "PERSIST" in pc):
                self.E("PRIV", line, "chmod", target=p, tl=t.labels, pathc=pc, flags={"chmod", "world_writable"} | ({"recursive"} if recursive else set()))
        return EMPTY_PIPE

    def h_chown(self, args, line, stdin):
        recursive = any(isinstance(a.c, str) and a.c.startswith("-") and "R" in a.c for a in args[1:])
        nonopt = [a for a in args[1:] if not (isinstance(a.c, str) and a.c.startswith("-") and len(a.c) > 1)]
        for t in nonopt[1:]:
            p = t.c if isinstance(t.c, str) else HOLE
            pc = K.classify_path(p)
            if recursive and ("ROOT" in pc or "SYSTEM_DIR" in pc):
                self.E("PRIV", line, "chown", target=p, pathc=pc, flags={"chown", "recursive"})
        return EMPTY_PIPE

    def h_setcap(self, args, line, stdin):
        self.E("PRIV", line, "setcap", target=" ".join(a.c for a in args[1:] if isinstance(a.c, str)), flags={"capability"})
        return EMPTY_PIPE

    def h_useradd(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        joined = " ".join(texts)
        fl = {"useradd"}
        if re.search(r"(-u\s*0\b|--uid\s+0\b|-o\b)", joined) and re.search(r"(-u\s*0\b|--uid\s+0\b)", joined):
            fl.add("uid0")
        if re.search(r"-[a-zA-Z]*[Gg]\s*\S*(sudo|wheel|admin|root|docker)", joined):
            fl.add("admin_group")
        self.E("PRIV", line, "useradd", target=joined, flags=fl)
        return EMPTY_PIPE

    h_adduser = h_useradd

    def h_usermod(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        fl = {"usermod"}
        if re.search(r"(sudo|wheel|admin|root|docker|adm)\b", joined):
            fl.add("admin_group")
        if re.search(r"-u\s*0\b", joined):
            fl.add("uid0")
        if "-s" in joined and re.search(r"-s\s*/(bin|usr/bin)/(ba)?sh", joined):
            fl.add("shell_change")
        self.E("PRIV", line, "usermod", target=joined, flags=fl)
        return EMPTY_PIPE

    h_gpasswd = h_usermod
    h_addgroup = h_usermod

    def h_passwd(self, args, line, stdin):
        self.E("PRIV", line, "passwd", flags={"passwd_change"})
        return EMPTY_PIPE

    def h_chpasswd(self, args, line, stdin):
        self.E("PRIV", line, "chpasswd", flags={"passwd_change"}, pl=stdin.labels)
        return EMPTY_PIPE

    def h_visudo(self, args, line, stdin):
        self.E("PRIV", line, "visudo", flags={"sudoers_edit"})
        return EMPTY_PIPE

    def h_su(self, args, line, stdin):
        self.E("PRIV", line, "su", flags={"su_switch"})          # becoming another user (usually root) inside a program
        for i, a in enumerate(args):
            if a.c == "-c" and i + 1 < len(args):
                self.sudo = True
                try:
                    self.run_text(args[i + 1].c if isinstance(args[i + 1].c, str) else HOLE, line_pin=line, hole_labels=args[i + 1].labels)
                finally:
                    self.sudo = False
        return EMPTY_PIPE

    def h_crontab(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        opts = [t for t in texts if t.startswith("-")]
        if "-l" in opts and len(opts) == 1 and not [t for t in texts if not t.startswith("-")]:
            return Pipe(U({FILE}), frozenset({"the crontab"}), EMPTY, "")
        if "-r" in opts:
            self.E("DELETE", line, "crontab -r", target="crontab", flags={"crontab_remove"})
            return EMPTY_PIPE
        if "-e" in opts and False:
            return EMPTY_PIPE
        files = [t for t in texts if not t.startswith("-")]
        content = stdin.text if (not files or files == ["-"]) else None
        if "-e" in opts and not files:
            return EMPTY_PIPE
        self.E("PERSIST", line, "crontab", target=files[0] if files else "-", flags={"crontab_install"}, pl=stdin.labels,
               extra={"content": content or "", "src": stdin.src})
        return EMPTY_PIPE

    def h_at(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "-l" in texts or "-r" in texts or "-d" in texts or "atq" in texts:
            return EMPTY_PIPE
        self.E("PERSIST", line, "at", flags={"at_job"}, extra={"content": stdin.text or ""})
        return EMPTY_PIPE

    h_batch = h_at

    def h_systemctl(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        sub = next((t for t in texts if not t.startswith("-")), "")
        units = [t for t in texts if not t.startswith("-") and t != sub]
        unit_s = " ".join(units)
        if sub in ("enable", "reenable", "preset"):
            self.E("PERSIST", line, "systemctl", target=unit_s, flags={"systemd_enable"})
        elif sub in ("disable", "stop", "mask", "kill") and re.search(r"(firewall|ufw|iptables|apparmor|auditd|selinux|fail2ban|clamav|falco|osquery|wazuh|crowdstrike|defender|sysmon|rsyslog|syslog|journald|cloudwatch|datadog|splunk|ossec)", unit_s):
            self.E("SYSTEM_CTL", line, "systemctl", target=unit_s, flags={"defense_evasion", "stop_security"})
        elif sub in ("poweroff", "halt", "reboot", "kexec", "suspend", "hibernate"):
            self.E("SYSTEM_CTL", line, "systemctl", target=sub, flags={"shutdown"})
        return EMPTY_PIPE

    def h_service(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        if len(texts) >= 2 and texts[1] in ("stop", "disable") and re.search(r"(firewall|ufw|iptables|apparmor|auditd|fail2ban|clamav|rsyslog|ossec|wazuh)", texts[0]):
            self.E("SYSTEM_CTL", line, "service", target=texts[0], flags={"defense_evasion", "stop_security"})
        return EMPTY_PIPE

    def h_chkconfig(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "on" in texts:
            self.E("PERSIST", line, "chkconfig", flags={"init_enable"})
        return EMPTY_PIPE

    def h_update_rc_d(self, args, line, stdin):
        self.E("PERSIST", line, "update-rc.d", flags={"init_enable"})
        return EMPTY_PIPE

    def h_launchctl(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        if any(t in ("load", "bootstrap", "enable", "submit") for t in texts):
            self.E("PERSIST", line, "launchctl", target=" ".join(texts), flags={"launchd"})
        return EMPTY_PIPE

    def h_schtasks(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        if re.search(r"/create", joined, re.I):
            self.E("PERSIST", line, "schtasks", target=joined, flags={"scheduled_task"})
        return EMPTY_PIPE

    def h_reg(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        if re.search(r"\badd\b", joined, re.I) and re.search(r"\\(Run|RunOnce|Winlogon|Services)\b", joined, re.I):
            self.E("PERSIST", line, "reg", target=joined, flags={"registry_run"})
        return EMPTY_PIPE

    def h_sc(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        if re.search(r"\bcreate\b", joined, re.I) and "binpath" in joined.lower():
            self.E("PERSIST", line, "sc", target=joined, flags={"service_create"})
        return EMPTY_PIPE

    def h_kill(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        pids = [t for t in texts if not t.startswith("-") or re.fullmatch(r"-\d+", t) and False]
        allp = any(t in ("-1", "1", "0") for t in pids) or any(re.fullmatch(r"-1", t) for t in texts)
        sig9 = any(t in ("-9", "-KILL", "-SIGKILL", "-s", "KILL") for t in texts)
        if allp and (sig9 or "-1" in texts):
            self.E("KILL", line, "kill", target=" ".join(texts), flags={"all_procs"})
        return EMPTY_PIPE

    def h_killall(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        names = [t for t in texts if not t.startswith("-")]
        sig9 = any(t in ("-9", "-KILL", "-SIGKILL") for t in texts)
        if re.search(r"(sshd|systemd|init|launchd|dockerd|auditd|rsyslogd|cron|NetworkManager|syslog|falco|ossec|wazuh|clamd|apparmor)", " ".join(names)):
            self.E("KILL", line, "killall", target=" ".join(names), flags={"critical_proc"})
        elif any(n in ("*", ".", ".*", "-", "all") for n in names):
            self.E("KILL", line, "killall", target=" ".join(names), flags={"all_procs"})
        return EMPTY_PIPE

    def h_pkill(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        names = [t for t in texts if not t.startswith("-")]
        if any(n in (".", ".*", "-", "*") for n in names):
            self.E("KILL", line, "pkill", target=" ".join(names), flags={"all_procs"})
        elif re.search(r"(sshd|systemd|dockerd|auditd|rsyslogd|falco|ossec|wazuh|clamd|apparmor)", " ".join(names)):
            self.E("KILL", line, "pkill", target=" ".join(names), flags={"critical_proc"})
        return EMPTY_PIPE

    def h_shutdown(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "-c" in texts:
            return EMPTY_PIPE
        self.E("SYSTEM_CTL", line, "shutdown", flags={"shutdown"})
        return EMPTY_PIPE

    h_reboot = h_shutdown
    h_halt = h_shutdown
    h_poweroff = h_shutdown

    def h_init(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if texts and texts[0] in ("0", "6"):
            self.E("SYSTEM_CTL", line, "init", flags={"shutdown"})
        return EMPTY_PIPE

    h_telinit = h_init

    def h_iptables(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        if "-F" in texts or "--flush" in texts or ("-P" in texts and "ACCEPT" in texts):
            self.E("SYSTEM_CTL", line, "iptables", flags={"defense_evasion", "firewall_off"})
        return EMPTY_PIPE

    h_ip6tables = h_iptables
    h_nft = h_iptables

    def h_ufw(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "disable" in texts or ("default" in texts and "allow" in texts):
            self.E("SYSTEM_CTL", line, "ufw", flags={"defense_evasion", "firewall_off"})
        return EMPTY_PIPE

    def h_setenforce(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if texts and texts[0] in ("0", "Permissive", "permissive"):
            self.E("SYSTEM_CTL", line, "setenforce", flags={"defense_evasion", "selinux_off"})
        return EMPTY_PIPE

    def h_history(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "-c" in texts or "-w" in texts and False:
            self.E("SYSTEM_CTL", line, "history", flags={"defense_evasion", "history_off"})
        return EMPTY_PIPE

    def h_git(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        sub = next((t for t in texts if not t.startswith("-")), "")
        if sub == "push" and any(t in ("--force", "-f", "--force-with-lease", "--mirror", "--delete") or t.startswith("+") for t in texts):
            self.E("DELETE", line, "git push", target=" ".join(texts), flags={"git_force_push"})
        elif sub == "reset" and "--hard" in texts:
            self.E("DELETE", line, "git reset", target=" ".join(texts), flags={"git_reset_hard"})
        elif sub == "clean" and any(re.fullmatch(r"-[a-z]*f[a-z]*", t) for t in texts):
            self.E("DELETE", line, "git clean", target=" ".join(texts), flags={"git_clean"})
        elif sub in ("clone", "pull", "fetch", "submodule"):
            for t in texts:
                if re.match(r"^(https?|git|ssh)://", t) or re.match(r"^[\w.\-]+@[\w.\-]+:", t):
                    sc, host, hc = K.host_of_url(t if "://" in t else "ssh://" + t.replace(":", "/", 1))
                    self.E("NET_FETCH", line, "git " + sub, target=t, hostc=hc, flags={"git"})
        elif sub == "push":
            url = next((t for t in texts if re.match(r"^(https?|git|ssh)://", t)), None)
            if url:
                sc, host, hc = K.host_of_url(url)
                self.E("NET_SEND", line, "git push", target=url, hostc=hc, pl=U({FILE}), flags={"git", "repo_push"})
        elif sub == "remote" and "add" in texts:
            url = next((t for t in texts if re.match(r"^(https?|git|ssh)://", t)), None)
            if url:
                self.vars["__git_remote"] = V(c=url)
        elif sub == "config" and any("credential.helper" in t for t in texts):
            if any(t in ("store", "cache") or t.startswith("store") for t in texts):
                self.E("PERSIST", line, "git config", flags={"credential_store"})
        return EMPTY_PIPE

    def h_docker(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        sub = next((t for t in texts if not t.startswith("-")), "")
        joined = " ".join(texts)
        if sub in ("run", "create", "exec"):
            fl = set()
            if "--privileged" in texts:
                fl.add("privileged")
            if re.search(r"(-v|--volume|--mount)[= ]\s*[\"']?(/:|/etc|/root|/var/run/docker\.sock|/proc|/sys|/home|/var/lib/docker|type=bind,source=/(,|\s|$))", joined):
                fl.add("host_mount")
            if re.search(r"/var/run/docker\.sock", joined):
                fl.add("docker_sock")
            if re.search(r"--(pid|ipc|uts|userns)[= ]host", joined):
                fl.add("host_ns")
            if re.search(r"--cap-add[= ](ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH)", joined):
                fl.add("cap_add")
            if re.search(r"--security-opt[= ](seccomp|apparmor)[=:]unconfined", joined):
                fl.add("unconfined")
            if re.search(r"--(net|network)[= ]host", joined):
                fl.add("host_net")
            if re.search(r"(-u|--user)[= ]\s*(0|root)\b", joined):
                fl.add("root_user")
            if fl & {"privileged", "host_mount", "docker_sock", "host_ns", "cap_add", "unconfined"}:
                self.E("PRIV", line, "docker " + sub, target=joined, flags={"container_escape"} | fl)
        elif sub in ("system", "volume", "container", "image", "network") and any(t in ("prune",) for t in texts) and any(t in ("-af", "-a", "-f", "--all", "--force") or re.fullmatch(r"-[a-z]*f[a-z]*", t) for t in texts):
            self.E("DELETE", line, "docker prune", target=joined, flags={"mass_prune"})
        elif sub in ("rm", "rmi", "kill", "stop") and re.search(r"\$\(|`|\$\{?\w", joined) and ("-aq" in joined or "-q" in joined or "ps" in joined):
            self.E("DELETE", line, "docker " + sub, target=joined, flags={"mass_prune"})
        return EMPTY_PIPE

    h_podman = h_docker

    def h_kubectl(self, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        joined = " ".join(texts)
        if "delete" in texts and (("--all" in texts) or "-A" in texts or "--all-namespaces" in texts or re.search(r"\bdelete\s+(ns|namespace|namespaces|nodes?|pv|crd)\b", joined)):
            self.E("DELETE", line, "kubectl delete", target=joined, flags={"mass_delete"})
        if "exec" in texts and "-it" in texts:
            pass
        if re.search(r"create\s+clusterrolebinding.*cluster-admin", joined) or re.search(r"--clusterrole[= ]cluster-admin", joined):
            self.E("PRIV", line, "kubectl", target=joined, flags={"cluster_admin"})
        return EMPTY_PIPE

    def h_terraform(self, args, line, stdin):
        texts = [a.c for a in args[1:] if isinstance(a.c, str)]
        if "destroy" in texts and any("auto-approve" in t for t in texts):
            self.E("DELETE", line, "terraform destroy", flags={"mass_delete", "auto_approve"})
        return EMPTY_PIPE

    def h_mount(self, args, line, stdin):
        return EMPTY_PIPE

    def h_ln(self, args, line, stdin):
        tg = self._targets(args[1:])
        if len(tg) >= 2:
            src = tg[0].c if isinstance(tg[0].c, str) else ""
            dst = tg[1].c if isinstance(tg[1].c, str) else ""
            if src == "/dev/null" and dst:
                pc = K.classify_path(dst)
                if "LOGS" in pc or "SYSTEM_SENSITIVE" in pc:
                    self.E("SYSTEM_CTL", line, "ln", target=dst, flags={"defense_evasion", "history_off"})
            pc = K.classify_path(dst)
            if "PERSIST" in pc or "PRIVFILE" in pc:
                self.E("PERSIST", line, "ln", target=dst, pathc=pc, flags={"symlink"})
        return EMPTY_PIPE

    def h_mkdir(self, args, line, stdin):
        return EMPTY_PIPE

    def h_touch(self, args, line, stdin):
        for t in self._targets(args[1:]):
            p = t.c if isinstance(t.c, str) else ""
            pc = K.classify_path(p)
            if pc & {"PERSIST", "PRIVFILE"}:
                self.E("WRITE_FILE", line, "touch", target=p, pathc=pc, flags={"touch"}, extra={"content": ""})
        return EMPTY_PIPE

    def h_test(self, args, line, stdin):
        return EMPTY_PIPE

    def h_true(self, args, line, stdin):
        return EMPTY_PIPE

    h_false = h_true
    h_wait = h_true
    h_pwd = h_true
    h_umask = h_true
    h_ulimit = h_true
    h_hash = h_true
    h_type = h_true
    h_which = h_true
    h_whoami = h_true
    h_id = h_true
    h_uname = h_true
    h_date = h_true
    h_clear = h_true
    h_logger = h_true
    h_disown = h_true
    h_jobs = h_true
    h_getopts = h_true
    h_mktemp = h_true
    h_basename = h_true
    h_dirname = h_true
    h_realpath = h_true
    h_readlink = h_true
    h_seq = h_true
    h_tput = h_true
    h_stty = h_true

    def h_env(self, args, line, stdin):
        return Pipe(U({ENV, ENV_DUMP}), frozenset({"all environment variables"}), EMPTY, HOLE)

    h_printenv = h_env

    def h_hostname(self, args, line, stdin):
        return EMPTY_PIPE

    def h_ssh_keygen(self, args, line, stdin):
        return EMPTY_PIPE

    def h_ssh_copy_id(self, args, line, stdin):
        self.E("PERSIST", line, "ssh-copy-id", flags={"authorized_keys"})
        return EMPTY_PIPE

    def h_ssh_add(self, args, line, stdin):
        return EMPTY_PIPE

    def h_security(self, args, line, stdin):   # macOS keychain
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        if re.search(r"find-(generic|internet)-password|dump-keychain|export", joined):
            return Pipe(U({SECRET}), frozenset({"the macOS keychain"}), EMPTY, HOLE)
        return EMPTY_PIPE

    def h_secret_tool(self, args, line, stdin):
        return Pipe(U({SECRET}), frozenset({"the system keyring"}), EMPTY, HOLE)

    def h_pass(self, args, line, stdin):
        return Pipe(U({SECRET}), frozenset({"the password store"}), EMPTY, HOLE)

    def h_aws_vault(self, args, line, stdin):
        return Pipe(U({SECRET}), frozenset({"stored cloud credentials"}), EMPTY, HOLE)

    def h_ping(self, args, line, stdin):  # noqa: F811
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        host = None
        data_labels: set = set()
        src: set = set()
        fl: set = set()
        i = 0
        while i < len(args) - 1:
            i += 1
            a = args[i]
            t = a.c if isinstance(a.c, str) else HOLE
            if t == "-p" and i + 1 < len(args):
                nxt = args[i + 1]
                fl.add("icmp_payload")
                data_labels |= nxt.labels
                src |= nxt.src
                if HOLE in (nxt.c or "") or nxt.labels:
                    fl.add("data_in_packet")
                i += 1
                continue
            if t in ("-c", "-i", "-W", "-w", "-s", "-t", "-I", "-Q", "-M", "-S", "-l", "-n") and i + 1 < len(args) and t != "-n":
                if t == "-s" and isinstance(args[i + 1].c, str) and args[i + 1].c.isdigit() and int(args[i + 1].c) > 60000:
                    fl.add("ping_large")
                i += 1
                continue
            if t in ("-f", "--flood"):
                fl.add("ping_flood")
                continue
            if t.startswith("-"):
                continue
            host = a
        if host is not None:
            hs = host.c if isinstance(host.c, str) else HOLE
            hc = K.classify_host(hs)
            if host.labels & {SECRET, SENS_SYS, ENV_DUMP, FILE, CMDSUB} and not hc == "LOOPBACK":
                fl.add("data_in_host")
                data_labels |= host.labels
            self.E("ICMP", line, "ping", target=hs, tl=host.labels, pl=U(data_labels), hostc=hc, flags=fl, extra={"src": U(src, host.src)})
        return EMPTY_PIPE

    # -- network ----------------------------------------------------------------------------
    def h_download(self, name, args, line, stdin):
        name = _basename(args[0].c)
        rest = args[1:]
        urls: list = []
        out_file: Optional[V] = None
        to_stdout = False
        remote_name = False
        post_data: list = []
        upload_file = None
        method = None
        flags: set = set()
        data_opts = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json", "--post-data", "--post-file", "--body-data", "--body-file"}
        form_opts = {"-F", "--form", "--form-string"}
        val_opts = {"-w", "--write-out", "-m", "--max-time", "-x", "--proxy", "-K", "--config", "--connect-timeout", "--retry", "--retry-delay", "-r", "--range",
                    "--resolve", "--cacert", "--cert", "--key", "-E", "-U", "--proxy-user", "--limit-rate", "--interface", "-t", "--tries", "-T", "--timeout",
                    "-P", "--directory-prefix", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-A", "--user-agent", "-a", "--append-output",
                    "-i", "--input-file", "--retry-max-time", "--max-redirs", "--connect-to", "--dns-servers"}
        auth_opts = {"-u", "--user", "--oauth2-bearer", "-H", "--header", "--http-user", "--http-password", "--ftp-user", "--ftp-password", "--password"}
        i = 0
        while i < len(rest):
            a = rest[i]
            t = a.c if isinstance(a.c, str) else HOLE
            has_eq = t.startswith("--") and "=" in t
            tl = t.split("=", 1)[0] if has_eq else t
            nxt = rest[i + 1] if i + 1 < len(rest) else None

            def value():
                if has_eq:
                    return V(c=t.split("=", 1)[1], labels=a.labels, src=a.src)
                return nxt
            if tl in data_opts:
                va = value()
                if va is not None:
                    post_data.append((va.c if isinstance(va.c, str) else HOLE, va))
                if not has_eq:
                    i += 1
            elif tl in form_opts:
                va = value()
                if va is not None:
                    post_data.append((va.c if isinstance(va.c, str) else HOLE, va))
                if not has_eq:
                    i += 1
            elif tl in ("--upload-file",) or (tl == "-T" and name == "curl"):
                va = value()
                if va is not None:
                    upload_file = va
                if not has_eq:
                    i += 1
            elif (tl in ("-o", "--output") and name == "curl") or (tl in ("-O", "--output-document") and name in ("wget", "aria2c")) or (tl == "-o" and name == "aria2c"):
                va = value()
                if va is not None:
                    if isinstance(va.c, str) and va.c == "-":
                        to_stdout = True
                    else:
                        out_file = va
                if not has_eq:
                    i += 1
            elif tl in ("-O", "--remote-name") and name == "curl":
                remote_name = True
            elif tl in ("-X", "--request"):
                va = value()
                if va is not None and isinstance(va.c, str):
                    method = va.c
                if not has_eq:
                    i += 1
            elif tl in auth_opts:
                if not has_eq:
                    i += 1
            elif tl in ("-k", "--insecure", "--no-check-certificate", "--no-verify-ssl"):
                flags.add("insecure_tls")
            elif tl in val_opts:
                if not has_eq:
                    i += 1
            elif t.startswith("-") and not t.startswith("--") and len(t) > 2:
                # combined short flags such as -sSL, -qO-, -fsSLo, -sSLO
                body = t[1:]
                if name == "wget" and body.endswith("O-"):
                    to_stdout = True
                elif name == "wget" and body.endswith("O") and nxt is not None:
                    out_file = nxt
                    i += 1
                elif name == "curl" and body.endswith("o") and nxt is not None:
                    if isinstance(nxt.c, str) and nxt.c == "-":
                        to_stdout = True
                    else:
                        out_file = nxt
                    i += 1
                elif name == "curl" and body.endswith("O"):
                    remote_name = True
                if "k" in body and name == "curl":
                    flags.add("insecure_tls")
                if name == "curl" and body.endswith("d") and nxt is not None:
                    post_data.append((nxt.c if isinstance(nxt.c, str) else HOLE, nxt))
                    i += 1
            elif t.startswith("-") and len(t) > 1:
                pass
            else:
                urls.append(a)
            i += 1
        payload_labels: set = set()
        psrc: set = set()
        for val, va in post_data:
            payload_labels |= va.labels
            psrc |= va.src
            m = re.match(r"^(?:[^=@]*=)?@(.+)$", val) if isinstance(val, str) else None
            if m:
                fp = m.group(1).split(";")[0]
                if fp == "-":
                    payload_labels |= stdin.labels
                    psrc |= stdin.src
                else:
                    lab, s2 = self.file_labels(fp)
                    payload_labels |= lab
                    psrc |= s2
                    self.E("READ_FILE", line, name + " @file", target=fp, pathc=K.classify_path(fp), flags={"upload_read"}, pl=lab, extra={"src": s2})
        if upload_file is not None:
            fp = upload_file.c if isinstance(upload_file.c, str) else HOLE
            if fp == "-":
                payload_labels |= stdin.labels
                psrc |= stdin.src
            else:
                lab, s2 = self.file_labels(fp)
                payload_labels |= lab
                psrc |= s2
                self.E("READ_FILE", line, name + " -T", target=fp, pathc=K.classify_path(fp), flags={"upload_read"}, pl=lab, extra={"src": s2})
        sending = bool(post_data) or upload_file is not None or (method or "").upper() in ("POST", "PUT", "PATCH")
        for ua in urls:
            u = ua.c if isinstance(ua.c, str) else HOLE
            if "://" not in u and not re.match(r"^[\w.\-]+\.[a-z]{2,}(:\d+)?(/|$)|^(\d{1,3}\.){3}\d{1,3}|^localhost", u) and HOLE not in u:
                continue
            scheme, host, hc = K.host_of_url(u if "://" in u else "http://" + u)
            fl = set(flags)
            fl.add(name)
            if scheme in K.DANGEROUS_SCHEMES:
                fl.add("dangerous_scheme")
            if scheme == "http":
                fl.add("plain_http")
            pl = U(payload_labels, ua.labels & {SECRET, SENS_SYS, ENV_DUMP})
            cap = "NET_SEND" if sending else "NET_FETCH"
            self.E(cap, line, name, target=u, tl=ua.labels, pl=pl, hostc=hc, flags=fl,
                   extra={"src": U(psrc, ua.src), "scheme": scheme, "host": host}, lines=ua.lines)
        outp_labels = U({NET})
        dl_src = frozenset({"a remote download"})
        if out_file is not None:
            op = out_file.c if isinstance(out_file.c, str) else HOLE
            pc = K.classify_path(op)
            self.E("WRITE_FILE", line, name + " -o", target=op, tl=out_file.labels, pathc=pc, pl=outp_labels, flags={"download"},
                   extra={"content": "", "src": dl_src})
            self.vfs[op] = (outp_labels, dl_src, True)
            return EMPTY_PIPE
        if remote_name or (name in ("wget", "aria2c") and not to_stdout):
            for ua in urls[:1]:
                u = ua.c if isinstance(ua.c, str) else ""
                base = u.rstrip("/").rsplit("/", 1)[-1].split("?")[0] or "index.html"
                self.vfs[base] = (outp_labels, dl_src, True)
                self.vfs["./" + base] = (outp_labels, dl_src, True)
            return EMPTY_PIPE
        if any(K.host_of_url((ua.c if isinstance(ua.c, str) else "") if "://" in (ua.c if isinstance(ua.c, str) else "") else "http://" + (ua.c if isinstance(ua.c, str) else ""))[2] == "META" for ua in urls):
            return Pipe(U({NET, SECRET}), frozenset({"cloud credentials from the metadata service"}), frozenset({"remote"}), None)
        return Pipe(outp_labels, frozenset({"a remote response"}), frozenset({"remote"}), None)

    def h_nc(self, name, args, line, stdin):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:]]
        fl: set = set()
        listen = any(t in ("-l", "-lvp", "-lp", "-nlvp", "-lvnp", "-nvlp", "-vlp") or (t.startswith("-") and "l" in t and not t.startswith("--")) for t in texts)
        execflag = any(t in ("-e", "-c", "--exec", "--sh-exec") for t in texts) or any(re.match(r"(?i)^(exec|system):", t) for t in texts)
        positional = []
        skip_nc = False
        for a, t in zip(args[1:], texts):
            if skip_nc:
                skip_nc = False
                continue
            if t in ("-e", "-c", "-p", "-s", "-w", "-i", "-q", "-x", "-X", "-T", "-I", "-O", "--exec", "--sh-exec", "--source-port"):
                skip_nc = True
                continue
            if not t.startswith("-"):
                positional.append(a)
        host = positional[0] if positional else None
        hs = host.c if host is not None and isinstance(host.c, str) else ""
        if name == "socat":
            fl.add("socat")
            joined = " ".join(texts)
            m = re.search(r"(?i)tcp[46]?:([^:\s,]+):(\d+)", joined)
            if m:
                hs = m.group(1)
                execflag = execflag or bool(re.search(r"(?i)(exec|system):", joined))
        if listen:
            fl.add("listen")
            self.E("NET_LISTEN", line, name, target=hs, flags=fl | ({"bind_shell"} if execflag else set()))
            return EMPTY_PIPE
        hc = K.classify_host(hs) if hs else "UNKNOWN"
        if execflag:
            fl.add("reverse_shell")
        pl = stdin.labels
        self.E("NET_CONNECT" if not execflag else "REVERSE_SHELL", line, name, target=hs, tl=host.labels if host is not None else EMPTY, pl=pl, hostc=hc,
               flags=fl | ({"data_pipe"} if stdin.labels else set()), extra={"src": stdin.src})
        if pl & {SECRET, SENS_SYS, ENV_DUMP, FILE}:
            self.E("NET_SEND", line, name, target=hs, hostc=hc, pl=pl, flags={"nc_pipe"}, extra={"src": stdin.src})
        return Pipe(U({NET}), EMPTY, frozenset({"remote"}), None)

    def h_remote(self, name, args, line, stdin):  # replaced by wrapper below
        return EMPTY_PIPE

    def h_dns(self, name, args, line, stdin=None):
        texts = [a for a in args[1:] if not (isinstance(a.c, str) and a.c.startswith("-"))]
        for a in texts:
            q = a.c if isinstance(a.c, str) else HOLE
            fl = set()
            data = a.labels & {SECRET, SENS_SYS, ENV_DUMP, FILE, CMDSUB}
            if data:
                fl.add("data_in_query")
            self.E("DNS", line, name, target=q, tl=a.labels, pl=U(data), flags=fl, hostc=K.classify_host(q.split(" ")[0]) if q and HOLE not in q else None,
                   extra={"src": a.src})
            break
        return Pipe(U({NET}), EMPTY, EMPTY, None)

    def h_scan(self, name, args, line, stdin=None):
        texts = [a.c if isinstance(a.c, str) else HOLE for a in args[1:] if not (isinstance(a.c, str) and a.c.startswith("-"))]
        self.E("NET_CONNECT", line, name, target=" ".join(texts), flags={"scan", "port_scan"}, hostc=K.classify_host(texts[-1]) if texts else None)
        return EMPTY_PIPE

    # -- installers ---------------------------------------------------------------------------
    def _install(self, eco: str, specs: list, line: int, flags: set, tool: str) -> None:
        for a in specs:
            s = a.c if isinstance(a.c, str) else HOLE
            if not s or s.startswith("-"):
                continue
            info = K.parse_pkg_spec(s)
            rep, detail = ("UNKNOWN", "")
            if eco in ("pypi", "npm") and not info["url"] and not info["local"] and HOLE not in info["name"]:
                rep, detail = K.package_reputation(info["name"], eco)
            fl = set(flags)
            if info["pinned"]:
                fl.add("pinned")
            if info["url"]:
                fl.add("url_source")
            if info["vcs"]:
                fl.add("vcs_source")
            if info["local"]:
                fl.add("local_source")
            if HOLE in s:
                fl.add("dynamic_name")
            hostc = None
            if info["url"] and not info["local"]:
                u = re.sub(r"^(git|hg|svn|bzr)\+", "", s)
                if re.match(r"^(github|gitlab|bitbucket):", u):
                    hostc = "TRUSTED_VCS"
                else:
                    if not re.match(r"^[a-z][a-z0-9+.\-]*://", u):
                        m2 = re.match(r"^[\w.\-]+@([\w.\-]+):", u)
                        u = ("ssh://" + m2.group(1) + "/") if m2 else "https://" + u
                    _sc, _host, hostc = K.host_of_url(u)
                    if _host and re.search(r"(^|\.)(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht)$", _host):
                        hostc = "TRUSTED_VCS"
            self.E("INSTALL_PKG", line, tool, target=s, tl=a.labels, flags=fl, hostc=hostc,
                   extra={"eco": eco, "pkg": info["name"], "rep": rep, "similar": detail, "src": a.src}, lines=a.lines)

    def h_pip(self, name, args, line, stdin=None):
        if isinstance(name, list):  # called via getattr dispatch: (args, line, stdin)
            args, line, stdin, name = name, args, line, "pip"
        rest = [a for a in args[1:]]
        texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
        sub = next((t for t in texts if not t.startswith("-")), "")
        if name in ("poetry",) and sub in ("add",):
            pass
        elif name in ("pipenv",) and sub == "install":
            pass
        elif name in ("conda", "mamba") and sub in ("install", "create"):
            pass
        elif name == "uv" and sub in ("pip", "add"):
            pass
        elif name == "easy_install":
            sub = "install"
        elif sub not in ("install", "download", "wheel", "add") and name not in ("pipx",):
            return EMPTY_PIPE
        flags: set = set()
        specs: list = []
        i = 0
        started = False
        while i < len(rest):
            a = rest[i]
            t = texts[i]
            if not started:
                if t == sub or (name == "easy_install"):
                    started = True
                    if name == "easy_install":
                        continue
                i += 1
                continue
            if t in ("--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--registry"):
                if i + 1 < len(rest):
                    u = texts[i + 1]
                    flags.add("custom_index" if t in ("--index-url", "-i", "--registry") else "extra_index")
                    if u.startswith("http://"):
                        flags.add("plain_http_index")
                    sc, host, hc = K.host_of_url(u)
                    if hc in ("SUSPICIOUS", "DROPSITE", "EXTERNAL_IP", "EXTERNAL"):
                        flags.add("external_index")
                    if hc in ("SUSPICIOUS",):
                        flags.add("suspicious_index")
                i += 2
                continue
            if t.startswith(("--index-url=", "--extra-index-url=", "--registry=")):
                flags.add("custom_index" if "extra" not in t else "extra_index")
                u = t.split("=", 1)[1]
                if u.startswith("http://"):
                    flags.add("plain_http_index")
                sc, host, hc = K.host_of_url(u)
                if hc == "SUSPICIOUS":
                    flags.add("suspicious_index")
                i += 1
                continue
            if t in ("--trusted-host",):
                flags.add("trusted_host")
                i += 2
                continue
            if t.startswith("--trusted-host="):
                flags.add("trusted_host")
                i += 1
                continue
            if t in ("--no-verify", "--no-check-certificate", "--disable-pip-version-check") and t != "--disable-pip-version-check":
                flags.add("insecure_tls")
                i += 1
                continue
            if t in ("-r", "--requirement", "-c", "--constraint"):
                if i + 1 < len(rest):
                    u = texts[i + 1]
                    if re.match(r"^https?://", u):
                        flags.add("remote_requirements")
                        sc, host, hc = K.host_of_url(u)
                        self.E("NET_FETCH", line, "pip -r", target=u, hostc=hc, flags={"requirements_url"})
                i += 2
                continue
            if t in ("-t", "--target", "--prefix", "--root", "--user", "-e", "--editable", "--python", "--platform", "--only-binary", "--no-binary", "-c", "--src",
                     "--proxy", "--cert", "--client-cert", "-d", "--dest", "--python-version", "--implementation", "--abi", "--constraint"):
                if t in ("-e", "--editable") and i + 1 < len(rest):
                    specs.append(rest[i + 1])
                if t not in ("--user",):
                    i += 2
                else:
                    i += 1
                continue
            if t.startswith("-"):
                i += 1
                continue
            specs.append(a)
            i += 1
        if sub in ("add",) or name in ("conda", "mamba") and "-c" in texts:
            pass
        self._install("pypi", specs, line, flags, name)
        if not specs and flags:
            self.E("INSTALL_PKG", line, name, target="", flags=flags | {"no_specs"}, extra={"eco": "pypi", "pkg": "", "rep": "UNKNOWN"})
        return EMPTY_PIPE

    def h_npm(self, name, args, line, stdin=None):
        if isinstance(name, list):
            args, line, stdin, name = name, args, line, _basename(name[0].c)
        rest = args[1:]
        texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
        sub = next((t for t in texts if not t.startswith("-")), "")
        if name == "npm" and sub == "config" and "set" in texts:
            joined = " ".join(texts)
            if re.search(r"strict-ssl\s+false", joined):
                self.E("INSTALL_PKG", line, "npm config", flags={"insecure_tls", "no_specs"}, extra={"eco": "npm", "pkg": "", "rep": "UNKNOWN"})
            if re.search(r"registry\s+http://", joined):
                self.E("INSTALL_PKG", line, "npm config", flags={"plain_http_index", "custom_index", "no_specs"}, extra={"eco": "npm", "pkg": "", "rep": "UNKNOWN"})
            return EMPTY_PIPE
        if name == "npx" or name == "pnpx":
            specs = [a for a, t in zip(rest, texts) if not t.startswith("-")][:1]
            self._install("npm", specs, line, {"npx"}, name)
            return EMPTY_PIPE
        if name == "yarn" and sub == "add" or name in ("pnpm", "bun", "bower") and sub in ("add", "install", "i") or name == "npm" and sub in ("install", "i", "add", "ci", "update", "isntall"):
            pass
        else:
            return EMPTY_PIPE
        flags: set = set()
        specs = []
        started = False
        i = 0
        while i < len(rest):
            t = texts[i]
            if not started:
                if t == sub:
                    started = True
                i += 1
                continue
            if t in ("--registry",) and i + 1 < len(rest):
                u = texts[i + 1]
                flags.add("custom_index")
                if u.startswith("http://"):
                    flags.add("plain_http_index")
                if K.host_of_url(u)[2] == "SUSPICIOUS":
                    flags.add("suspicious_index")
                i += 2
                continue
            if t.startswith("--registry="):
                flags.add("custom_index")
                if t.split("=", 1)[1].startswith("http://"):
                    flags.add("plain_http_index")
                i += 1
                continue
            if t in ("--ignore-scripts",):
                i += 1
                continue
            if t in ("--unsafe-perm", "--force"):
                flags.add("unsafe_perm")
                i += 1
                continue
            if t.startswith("-"):
                i += 1
                continue
            specs.append(rest[i])
            i += 1
        self._install("npm", specs, line, flags, name)
        return EMPTY_PIPE

    def h_syspkg(self, name, args, line, stdin=None):
        rest = args[1:]
        texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
        sub = next((t for t in texts if not t.startswith("-")), "")
        if sub not in ("install", "add", "reinstall", "-S", "upgrade") and name not in ("pacman",):
            if name in ("apt-key",):
                pass
            return EMPTY_PIPE
        if name in ("apt", "apt-get"):
            for t in texts:
                if t in ("--allow-unauthenticated", "--force-yes", "--allow-insecure-repositories", "--allow-downgrades"):
                    self.E("INSTALL_PKG", line, name, flags={"insecure_tls", "unauthenticated", "no_specs"}, extra={"eco": "sys", "pkg": "", "rep": "UNKNOWN"})
        if name in ("yum", "dnf") and any(t in ("--nogpgcheck", "--no-gpgcheck") for t in texts):
            self.E("INSTALL_PKG", line, name, flags={"insecure_tls", "unauthenticated", "no_specs"}, extra={"eco": "sys", "pkg": "", "rep": "UNKNOWN"})
        specs = [a for a, t in zip(rest, texts) if not t.startswith("-") and t != sub]
        flags = set()
        self._install("sys", specs, line, flags, name)
        return EMPTY_PIPE

    def h_otherpkg(self, name, args, line, stdin=None):
        rest = args[1:]
        texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
        sub = next((t for t in texts if not t.startswith("-")), "")
        if name == "go" and sub in ("get", "install"):
            specs = [a for a, t in zip(rest, texts) if not t.startswith("-") and t != sub]
            fl = {"go"}
            for a in specs:
                if isinstance(a.c, str) and a.c.endswith("@latest"):
                    fl.add("latest")
            self._install("go", specs, line, fl, name)
        elif name == "cargo" and sub == "install":
            fl = set()
            if "--git" in texts:
                fl |= {"vcs_source", "url_source"}
            specs = [a for a, t in zip(rest, texts) if not t.startswith("-") and t != sub]
            self._install("cargo", specs, line, fl, name)
        elif name in ("gem", "composer", "cpan", "cpanm", "pecl") and sub in ("install", "require", "i"):
            specs = [a for a, t in zip(rest, texts) if not t.startswith("-") and t != sub]
            self._install("other", specs, line, set(), name)
        return EMPTY_PIPE

    def h_apt_key(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        if "add" in joined and ("remote" in stdin.tags):
            self.E("INSTALL_PKG", line, "apt-key", flags={"remote_key", "no_specs"}, extra={"eco": "sys", "pkg": "", "rep": "UNKNOWN"})
        return EMPTY_PIPE

    def h_add_apt_repository(self, args, line, stdin):
        joined = " ".join(a.c if isinstance(a.c, str) else HOLE for a in args[1:])
        self.E("INSTALL_PKG", line, "add-apt-repository", target=joined, flags={"custom_repo", "no_specs"}, extra={"eco": "sys", "pkg": "", "rep": "UNKNOWN"})
        return EMPTY_PIPE

    # -- file readers / transformers ------------------------------------------------------------
    def h_files(self, name, args, line, stdin, redirs):
        rest = args[1:]
        texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
        pos = []
        skip_next = False
        valued = {"-n", "-c", "-s", "-k", "-t", "-e", "-f", "-d", "-F", "-v", "-m", "-A", "-B", "-C", "-o", "-p", "-r", "-i", "-j", "-N", "-w", "-b", "-l", "-u", "-X"}
        for idx, (a, t) in enumerate(zip(rest, texts)):
            if skip_next:
                skip_next = False
                continue
            if name in ("xxd", "od", "hexdump", "head", "tail", "cut", "fold", "split") and re.fullmatch(r"\d+[a-zA-Z]?", t):
                continue
            if t.startswith("-") and len(t) > 1:
                if name in ("xxd", "od", "hexdump") and t in ("-l", "-s", "-c", "-g", "-N", "-j", "-n"):
                    skip_next = True
                if name in ("head", "tail") and t in ("-n", "-c") or name in ("grep", "egrep", "rg", "ag") and t in ("-e", "-f", "-A", "-B", "-C", "-m") or name in ("sed", "awk", "gawk") and t in ("-e", "-f", "-F") or name in ("cut",) and t in ("-d", "-f", "-c") or name in ("sort",) and t in ("-k", "-t", "-o"):
                    skip_next = True
                continue
            pos.append(a)
        lab: set = set()
        src: set = set()
        tags: set = set()
        outp_text = None
        if name in ("grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed", "zgrep", "jq", "yq"):
            if pos:
                pos = pos[1:]   # pattern / program
        if name == "dd":
            return self.h_dd(args, line, stdin)
        if name == "find":
            return self.h_find(args, line, stdin)
        if name == "ls" or name == "dir" or name == "stat" or name == "file":
            return Pipe(U({FILE}), frozenset({"a directory listing"}), EMPTY, None)
        if name in ("sqlite3", "mysqldump", "pg_dump", "mongodump", "redis-cli", "psql", "mysql", "mongo", "mongosh"):
            tl = U(*[a.labels for a in pos])
            data = U({DB})
            if name in ("mysqldump", "pg_dump", "mongodump"):
                self.E("READ_FILE", line, name, target="database dump", flags={"db_dump"}, pl=data)
                return Pipe(data, frozenset({"a database dump"}), EMPTY, None)
            return Pipe(data, frozenset({"database contents"}), EMPTY, None)
        if name in ("cp", "mv", "install", "rsync"):
            tg = [a for a in pos]
            if len(tg) >= 2:
                srcs, dst = tg[:-1], tg[-1]
                dp = dst.c if isinstance(dst.c, str) else HOLE
                dpc = K.classify_path(dp)
                plabels: set = set()
                psrc: set = set()
                for s in srcs:
                    sp = s.c if isinstance(s.c, str) else HOLE
                    spc = K.classify_path(sp)
                    l2, s2 = self.file_labels(sp)
                    plabels |= l2
                    psrc |= s2
                    self.E("READ_FILE", line, name, target=sp, tl=s.labels, pathc=spc, pl=l2, flags={"copy_src"}, extra={"src": s2}, lines=s.lines)
                    if name == "mv" and dp == "/dev/null":
                        self.E("DELETE", line, "mv", target=sp, tl=s.labels, pathc=spc, flags={"move_to_null"})
                self.E("WRITE_FILE", line, name, target=dp, tl=dst.labels, pathc=dpc, pl=U(plabels), flags={"copy_dst"},
                       extra={"content": "", "src": U(psrc)}, lines=dst.lines)
                self.vfs[dp] = (U(plabels), U(psrc), False)
            return EMPTY_PIPE
        if name in ("tar", "zip", "7z", "7za", "cpio", "ar"):
            create = (name == "tar" and any(isinstance(t, str) and re.match(r"^-?[a-zA-Z]*c[a-zA-Z]*", t) and not t.startswith("--") for t in texts[:1])) or name in ("zip", "7z", "7za") and not any(t in ("x", "e", "l") for t in texts[:1])
            extract = name == "tar" and any(re.match(r"^-?[a-zA-Z]*x[a-zA-Z]*", t) for t in texts[:1]) or name in ("unzip",)
            if create and pos:
                # first positional of tar is the archive file when using -f; approximate: last positionals are sources
                plabels = set()
                psrc = set()
                archive = None
                srcs = pos
                if name == "tar":
                    # find -f value
                    for i2, t in enumerate(texts):
                        if t.startswith("-") and "f" in t[1:] and not t.startswith("--") and i2 + 1 < len(rest):
                            archive = rest[i2 + 1]
                            break
                        if i2 == 0 and re.match(r"^[a-zA-Z]*f[a-zA-Z]*$", t) and i2 + 1 < len(rest):
                            archive = rest[i2 + 1]
                            break
                    srcs = [a for a in pos if a is not archive]
                else:
                    archive = pos[0]
                    srcs = pos[1:]
                for s in srcs:
                    sp = s.c if isinstance(s.c, str) else HOLE
                    l2, s2 = self.file_labels(sp)
                    plabels |= l2
                    psrc |= s2
                    spc = K.classify_path(sp)
                    if spc & {"SECRET_STORE", "SYSTEM_SENSITIVE"}:
                        self.E("READ_FILE", line, name, target=sp, pathc=spc, pl=l2, flags={"archive_src"}, extra={"src": s2})
                if archive is not None and isinstance(archive.c, str) and archive.c != "-":
                    self.vfs[archive.c] = (U(plabels), U(psrc), False)
                    self.E("WRITE_FILE", line, name, target=archive.c, pathc=K.classify_path(archive.c), pl=U(plabels), flags={"archive"}, extra={"content": "", "src": U(psrc)})
                    return EMPTY_PIPE
                return Pipe(U(plabels), U(psrc), EMPTY, None)
            return EMPTY_PIPE
        if name == "tee":
            wrote = Pipe(stdin.labels, stdin.src, stdin.tags, stdin.text)
            for a in pos:
                p = a.c if isinstance(a.c, str) else HOLE
                pc = K.classify_path(p)
                fl = {"append"} if any(t == "-a" for t in texts) else set()
                if "unbounded" in stdin.tags:
                    fl.add("unbounded_source")
                self.E("WRITE_FILE", line, "tee", target=p, tl=a.labels, pathc=pc, pl=stdin.labels, flags=fl, extra={"content": stdin.text or "", "src": stdin.src}, lines=a.lines)
                if "unbounded" in stdin.tags and "DEVICE" not in pc:
                    self.E("DISK_FILL", line, "tee", target=p, pathc=pc, flags={"unbounded", "no_limit"})
                self.vfs[p] = (stdin.labels, stdin.src, "download" in stdin.tags)
            return Pipe(stdin.labels, stdin.src, stdin.tags - {"unbounded"} if pos else stdin.tags, stdin.text)
        # readers
        reads_stdin = not pos
        for a in pos:
            p = a.c if isinstance(a.c, str) else HOLE
            if p in ("-",):
                lab |= stdin.labels
                src |= stdin.src
                continue
            if "://" in p:
                continue
            pc = K.classify_path(p)
            l2, s2 = self.file_labels(p)
            lab |= l2
            src |= s2
            if name in ("head", "tail") and "DEVSRC" in pc:
                continue
            if "DEVSRC" in pc:
                tags.add("unbounded")
                continue
            self.E("READ_FILE", line, name, target=p, tl=a.labels, pathc=pc, pl=l2, flags={"cmd_read"}, extra={"src": s2}, lines=a.lines)
        if reads_stdin or not pos:
            lab |= stdin.labels
            src |= stdin.src
            tags |= set(stdin.tags)
            outp_text = stdin.text
        if name in ("base64", "base32", "basenc"):
            if any(t in ("-d", "--decode", "-D", "-di") for t in texts):
                tags.add("decoded")
                lab.add(DECODED)
                outp_text = _try_b64(stdin.text) if stdin.text else None
            else:
                tags.add("encoded")
        elif name in ("gunzip", "zcat", "bzcat", "xzcat", "gzip") and (name != "gzip" or "-d" in texts):
            tags.add("decoded")
            lab.add(DECODED)
        elif name == "openssl" and any(t in ("-d", "-decrypt") for t in texts) and ("enc" in texts or "base64" in texts):
            tags.add("decoded")
            lab.add(DECODED)
        elif name in ("xxd",) and "-r" in texts:
            tags.add("decoded")
            lab.add(DECODED)
        if name in ("head", "tail"):
            nval = None
            for i2, t in enumerate(texts):
                if t in ("-c", "-n") and i2 + 1 < len(texts):
                    nval = texts[i2 + 1]
                m = re.fullmatch(r"-(?:n|c)?(\d+\w*)", t)
                if m and t != "-n":
                    nval = m.group(1)
            if nval is not None:
                if name == "head" and "-c" in texts:
                    sz = parse_size(nval)
                    if sz is not None and sz > 5 * 1024 ** 3:
                        tags.add("huge_bounded")
                        self.E("DISK_FILL", line, "head -c", flags={"huge"}, extra={"size": sz})
                    tags.discard("unbounded")
                else:
                    tags.discard("unbounded")
        if name in ("cat",) and not pos and stdin.tags & {"unbounded"}:
            tags.add("unbounded")
        if name == "cat" and any(isinstance(r, Redir) and r.op in ("<<", "<<-") for r in redirs):
            for r in redirs:
                if r.op in ("<<", "<<-") and r.body is not None:
                    outp_text = self.expand_text(r.body, r.body_expand)
                    lab |= {FILE} if False else set()
        return Pipe(U(lab), U(src), frozenset(tags), outp_text)

    def h_generic(self, name, args, line, stdin):
        """Unknown command: look at its arguments for URLs, secret paths and dangerous schemes."""
        for a in args[1:]:
            t = a.c if isinstance(a.c, str) else ""
            if not t:
                continue
            if re.match(r"^[a-z][a-z0-9+.\-]*://", t):
                scheme, host, hc = K.host_of_url(t)
                fl = {"generic_cmd", name}
                if scheme in K.DANGEROUS_SCHEMES:
                    fl.add("dangerous_scheme")
                self.E("NET_FETCH", line, name, target=t, tl=a.labels, hostc=hc, flags=fl, pl=stdin.labels if stdin.labels & {SECRET, SENS_SYS, ENV_DUMP} else EMPTY)
            elif K.classify_path(t) & {"SECRET_STORE"} and name not in ("ls", "chmod", "chown", "stat", "test", "["):
                l2, s2 = self.file_labels(t)
                self.E("READ_FILE", line, name, target=t, pathc=K.classify_path(t), pl=l2, flags={"generic_cmd"}, extra={"src": s2})
        if name.startswith("./") or name.startswith("/tmp/") or name.startswith("/dev/shm/") or name.startswith("/var/tmp/"):
            pass
        return EMPTY_PIPE


# =============================================================================== module helpers
def _join(a: V, b: V) -> V:
    from .events import join_values
    return join_values(a, b)


def _cat(a: V, b: V) -> str:
    x = a.c if isinstance(a.c, str) else HOLE
    y = b.c if isinstance(b.c, str) else HOLE
    return x + y


def secret_assign(name: str, v: V) -> bool:
    return False


def _try_b64(text: Optional[str]) -> Optional[str]:
    import base64
    if not text:
        return None
    try:
        raw = base64.b64decode(text.strip().replace("\n", ""), validate=False)
        s = raw.decode("utf-8")
        if s.isprintable() or "\n" in s:
            return s
    except Exception:
        return None
    return None


def _cond_text(cond: list) -> str:
    if len(cond) == 1 and isinstance(cond[0], Simple) and not cond[0].assigns:
        parts = []
        for w in cond[0].words:
            lit = w.literal()
            if lit is None:
                return "?"
            parts.append(lit)
        return " ".join(parts).strip()
    return "?"


def _seq_count(w: Word) -> Optional[int]:
    if len(w.parts) == 1 and w.parts[0].k == "sub":
        m = re.fullmatch(r"\s*seq\s+(?:-\w+\s+)*(\d+)(?:\s+(\d+))?(?:\s+(\d+))?\s*", w.parts[0].v)
        if m:
            nums = [int(x) for x in m.groups() if x]
            if len(nums) == 1:
                return nums[0]
            if len(nums) == 2:
                return max(nums[1] - nums[0] + 1, 0)
            if len(nums) == 3 and nums[1]:
                return max((nums[2] - nums[0]) // nums[1] + 1, 0)
    if len(w.parts) == 1 and w.parts[0].k == "lit" and not w.parts[0].q:
        m = re.fullmatch(r"\{(\d+)\.\.(\d+)\}", w.parts[0].v)
        if m:
            return abs(int(m.group(2)) - int(m.group(1))) + 1
    return None


def _brace_expand(t: str) -> Optional[list]:
    m = re.fullmatch(r"(.*?)\{(\d+)\.\.(\d+)\}(.*)", t)
    if m:
        a, b = int(m.group(2)), int(m.group(3))
        rng = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        if len(rng) > 64:
            return None
        return [m.group(1) + str(i) + m.group(4) for i in rng]
    m = re.fullmatch(r"(.*?)\{([^{}]*,[^{}]*)\}(.*)", t)
    if m:
        items = m.group(2).split(",")
        if len(items) > 64:
            return None
        out = []
        for it in items:
            sub = m.group(1) + it + m.group(3)
            e = _brace_expand(sub) if "{" in sub else None
            out.extend(e if e else [sub])
        return out
    return None


_BLOCKING_CMDS = {"sleep", "wait", "read", "inotifywait", "select", "nc", "ncat", "socat", "tail", "ping", "curl", "wget", "ssh", "timeout", "flock", "sem", "fswatch", "watch", "pause", "usleep", "kubectl", "docker", "git", "apt", "apt-get", "yum", "pip", "npm"}
_SPAWN_CMDS = {"nohup", "setsid", "bash", "sh", "python", "python3", "perl", "node", "fork", "exec"}


def _scan_body(body: list) -> dict:
    info = {"exit": False, "blocking": False, "spawn": False, "growth": False, "bg": False}

    def walk(n):
        if isinstance(n, Simple):
            if n.words:
                w0 = n.words[0].literal()
                if w0 in ("break", "exit", "return"):
                    info["exit"] = True
                if w0 and _basename(w0) in _BLOCKING_CMDS:
                    info["blocking"] = True
                if w0 and _basename(w0) in _SPAWN_CMDS:
                    info["spawn"] = True
                if w0 is not None and w0.startswith(("./", "/")) or any(p.k == "var" and p.v[0] == "0" for p in n.words[0].parts):
                    info["spawn"] = True
            if n.bg:
                info["bg"] = True
                info["spawn"] = True
            for r in n.redirs:
                if r.op in (">>",):
                    info["growth"] = True
            for a in n.assigns:
                pass
        elif isinstance(n, Pipeline):
            for c in n.cmds:
                walk(c)
            if n.bg:
                info["bg"] = True
                info["spawn"] = True
        elif isinstance(n, AndOr):
            walk(n.first)
            for _o, c in n.rest:
                walk(c)
        elif isinstance(n, If):
            for c in n.cond + n.then + n.orelse:
                walk(c)
        elif isinstance(n, (While,)):
            for c in n.cond + n.body:
                walk(c)
        elif isinstance(n, For):
            for c in n.body:
                walk(c)
        elif isinstance(n, Group):
            for c in n.body:
                walk(c)
            if n.bg:
                info["bg"] = True
        elif isinstance(n, Case):
            for _p, b in n.clauses:
                for c in b:
                    walk(c)
    for b in body:
        walk(b)
    return info


def _has_guard(body: list) -> bool:
    """True if the function body contains a conditional (possible recursion base case)."""
    for n in body:
        if isinstance(n, (If, Case)):
            return True
        if isinstance(n, AndOr):
            return True
    return False


# bind ssh-keygen style names that contain dashes
Shell.h_ssh_keygen = Shell.h_ssh_keygen
setattr(Shell, "h_ssh_copy_id", Shell.h_ssh_copy_id)
setattr(Shell, "h_update_rc_d", Shell.h_update_rc_d)
setattr(Shell, "h_stress_ng", Shell.h_stress)
setattr(Shell, "h_apt_key", Shell.h_apt_key)
setattr(Shell, "h_add_apt_repository", Shell.h_add_apt_repository)
setattr(Shell, "h_secret_tool", Shell.h_secret_tool)
setattr(Shell, "h_aws_vault", Shell.h_aws_vault)


# ---- remote copy tools ------------------------------------------------------------------------
def _h_remote(self: Shell, args, line, stdin):
    name = _basename(args[0].c)
    return self.remote_tool(name, args, line, stdin)


def _remote_tool(self: Shell, name: str, args: list, line: int, stdin: Pipe) -> Pipe:
    rest = args[1:]
    texts = [a.c if isinstance(a.c, str) else HOLE for a in rest]
    pos = []
    skip = False
    for a, t in zip(rest, texts):
        if skip:
            skip = False
            continue
        if t.startswith("-") and len(t) > 1:
            if t in ("-i", "-p", "-P", "-o", "-e", "-F", "-J", "-l", "-L", "-R", "-D", "-b", "-c", "-S", "-m", "--port", "--rsh", "-u", "--password", "--user", "--bucket", "--profile", "--region", "--endpoint-url", "--key", "-k", "--exclude", "--include"):
                skip = True
            continue
        pos.append(a)
    if name == "ssh":
        host = None
        cmd_args = []
        for j, a in enumerate(pos):
            if host is None:
                host = a
            else:
                cmd_args.append(a)
        hs = host.c if host is not None and isinstance(host.c, str) else ""
        hs = hs.split("@")[-1]
        hc = K.classify_host(hs) if hs else "UNKNOWN"
        fl = {"ssh"}
        if any(t in ("-R", "-D", "-L") or t.startswith(("-R", "-L", "-D")) for t in texts):
            fl.add("tunnel")
        if any(t == "-R" or t.startswith("-R") for t in texts):
            fl.add("reverse_tunnel")
        pl = stdin.labels
        self.E("NET_CONNECT", line, "ssh", target=hs, hostc=hc, flags=fl | ({"data_pipe"} if pl else set()), pl=pl, extra={"src": stdin.src})
        if pl & {SECRET, SENS_SYS, ENV_DUMP, FILE}:
            self.E("NET_SEND", line, "ssh", target=hs, hostc=hc, pl=pl, flags={"ssh_pipe"}, extra={"src": stdin.src})
        if cmd_args:
            text = " ".join(c.c if isinstance(c.c, str) else HOLE for c in cmd_args)
            self.E("EXEC_SHELL", line, "ssh remote", target=text, tl=U(*[c.labels for c in cmd_args]), flags={"remote"})
        return Pipe(U({NET}), EMPTY, frozenset({"remote"}), None)
    if name in ("scp", "rsync", "sftp", "rclone"):
        locals_, remotes = [], []
        for a in pos:
            t = a.c if isinstance(a.c, str) else HOLE
            if re.match(r"^([\w.\-]+@)?[\w.\-\[\]:]+:[^:]", t) and not t.startswith(("/", "./", "~")) and "://" not in t or re.match(r"^(s3|gs|ftp|sftp|http|https|az|b2|remote)[:/]", t) or (name == "rclone" and re.match(r"^\w+:", t)):
                remotes.append(a)
            else:
                locals_.append(a)
        if name == "rclone" and not remotes and len(pos) >= 3:
            remotes = pos[2:]
            locals_ = pos[1:2]
        if remotes and locals_:
            lab: set = set()
            psrc: set = set()
            for a in locals_:
                p = a.c if isinstance(a.c, str) else HOLE
                l2, s2 = self.file_labels(p)
                lab |= l2
                psrc |= s2
                self.E("READ_FILE", line, name, target=p, tl=a.labels, pathc=K.classify_path(p), pl=l2, flags={"upload_read"}, extra={"src": s2}, lines=a.lines)
            r = remotes[-1].c if isinstance(remotes[-1].c, str) else HOLE
            hs = r.split(":")[0].split("@")[-1] if "://" not in r else K.split_url(r)[1] or ""
            hc = K.classify_host(hs) if hs else "UNKNOWN"
            self.E("NET_SEND", line, name, target=r, tl=remotes[-1].labels, pl=U(lab), hostc=hc, flags={name}, extra={"src": U(psrc), "host": hs})
        elif remotes:
            r = remotes[0].c if isinstance(remotes[0].c, str) else HOLE
            hs = r.split(":")[0].split("@")[-1] if "://" not in r else K.split_url(r)[1] or ""
            self.E("NET_FETCH", line, name, target=r, hostc=K.classify_host(hs) if hs else "UNKNOWN", flags={name})
        return EMPTY_PIPE
    if name in ("ftp", "tftp"):
        for a in pos:
            t = a.c if isinstance(a.c, str) else HOLE
            hc = K.classify_host(t) if re.match(r"^[\w.\-]+$", t) else "UNKNOWN"
            self.E("NET_CONNECT", line, name, target=t, hostc=hc, flags={name}, pl=stdin.labels)
            break
        return EMPTY_PIPE
    if name in ("aws", "gsutil", "az", "gcloud", "s3cmd", "mc", "azcopy"):
        joined = " ".join(texts)
        up = re.search(r"\b(s3 cp|s3 sync|s3 mv|s3api put-object|cp|rsync|put|sync|upload|storage blob upload|storage cp)\b", joined)
        if up and re.search(r"(s3://|gs://|https?://|wasbs?://|az://)", joined):
            lab = set()
            psrc = set()
            for a in pos:
                t = a.c if isinstance(a.c, str) else ""
                if t and not re.match(r"^(s3|gs|https?|wasbs?|az)://", t) and not t.isalpha() and t not in ("s3", "cp", "sync", "mv", "put"):
                    l2, s2 = self.file_labels(t)
                    lab |= l2
                    psrc |= s2
                    self.E("READ_FILE", line, name, target=t, pathc=K.classify_path(t), pl=l2, flags={"upload_read"}, extra={"src": s2})
            dest = next((t for t in texts if re.match(r"^(s3|gs|https?|wasbs?|az)://", t)), "")
            self.E("NET_SEND", line, name, target=dest, pl=U(lab, stdin.labels), hostc="EXTERNAL", flags={"cloud_upload", name}, extra={"src": U(psrc, stdin.src)})
        if name == "aws" and "configure" in texts and "set" in texts:
            pass
        if name == "aws" and re.search(r"secretsmanager get-secret-value|ssm get-parameter.*--with-decryption|sts get-session-token|iam create-access-key", joined):
            return Pipe(U({SECRET}), frozenset({"cloud secrets"}), EMPTY, HOLE)
        return EMPTY_PIPE
    return EMPTY_PIPE


Shell.h_remote = lambda self, name, args, line, stdin=None: _remote_tool(self, name, args, line, stdin or EMPTY_PIPE)
Shell.remote_tool = _remote_tool


def analyze_shell(text: str, ctx: Ctx, hole_labels: frozenset = EMPTY, hole_src: frozenset = EMPTY, nested: bool = False,
                  line_pin: int = 0, base_vars: Optional[dict] = None, sh: Optional[Shell] = None) -> Shell:
    s = sh or Shell(ctx, hole_labels, hole_src, depth=ctx.depth)
    if base_vars:
        s.vars.update(base_vars)
    try:
        s.run_text(text, line_pin=line_pin, hole_labels=hole_labels, hole_src=hole_src)
    except ShellExit:
        pass
    except Stop:
        raise
    except RecursionError:
        ctx.notes.append("shell recursion limit")
    return s


def analyze_argv(args: list, ctx: Ctx, line: int, tainted_cmd: bool = False) -> None:
    """Analyse an already-split argv (subprocess list form) given as abstract values."""
    if not args:
        return
    sh = Shell(ctx, EMPTY, EMPTY, depth=ctx.depth)
    try:
        sh.dispatch(list(args), line, EMPTY_PIPE, [])
    except ShellExit:
        pass


def probe_shell(skel: str) -> Optional[str]:
    """Counterfactual probe: does a hostile value at HOLE change the command structure?  Returns a witness or None."""
    if HOLE not in skel:
        return None

    def structure(s: str):
        try:
            ast, _c = parse(s)
        except Exception:
            return None
        count = [0, 0]

        def walk(n):
            if isinstance(n, Simple):
                count[0] += 1
                for w in n.words:
                    for p in w.parts:
                        if p.k in ("sub", "proc"):
                            count[1] += 1
            elif isinstance(n, Pipeline):
                for c in n.cmds:
                    walk(c)
            elif isinstance(n, AndOr):
                walk(n.first)
                for _o, c in n.rest:
                    walk(c)
            elif isinstance(n, (Group,)):
                for c in n.body:
                    walk(c)
            elif isinstance(n, (If,)):
                for c in n.cond + n.then + n.orelse:
                    walk(c)
            elif isinstance(n, (While, For)):
                for c in n.body:
                    walk(c)
        for n in ast:
            walk(n)
        return tuple(count)

    base = structure(skel.replace(HOLE, "abc"))
    for probe in ("x; id", "$(id)", "`id`", "x && id", "x | id", "'; id; '", "\"; id; \""):
        got = structure(skel.replace(HOLE, probe))
        if got is not None and base is not None and got != base:
            return skel.replace(HOLE, probe)
    return None
