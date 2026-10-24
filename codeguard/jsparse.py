"""JavaScript / TypeScript parser that produces *Python ast* nodes.

CodeGuard analyses JavaScript with the same abstract interpreter as Python.  This module tokenizes JS, parses a
practical subset (ES2020 + light TypeScript) with a recursive-descent / precedence-climbing parser and builds
equivalent Python `ast` trees:  require() becomes a module reference, template literals become f-strings,
callbacks become hoisted functions, `this` becomes `self`, classes become classes.  It never raises on valid
input; on malformed input it raises JSParseError so the caller can fall back to the generic analyser.
"""
from __future__ import annotations

import ast
import re
from typing import Optional


class JSParseError(Exception):
    pass


KEYWORDS = {"var", "let", "const", "function", "return", "if", "else", "for", "while", "do", "break", "continue", "switch", "case", "default", "try", "catch",
            "finally", "throw", "new", "delete", "typeof", "instanceof", "in", "of", "void", "class", "extends", "super", "this", "import", "export", "from", "as",
            "async", "await", "yield", "static", "get", "set", "null", "undefined", "true", "false", "debugger", "with"}
_PUNCT = [">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
          "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>", "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "!", "~", "?", ":", "=", ".", "@", "#"]
_ID = re.compile(r"[A-Za-z_$ -￿][\w$ -￿]*")
_NUM = re.compile(r"0[xX][0-9a-fA-F_]+n?|0[bB][01_]+n?|0[oO][0-7_]+n?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?")


class Tok:
    __slots__ = ("t", "v", "line", "nl", "extra")

    def __init__(self, t, v, line, nl=False, extra=None):
        self.t = t          # id | kw | num | str | tmpl | regex | p | eof
        self.v = v
        self.line = line
        self.nl = nl        # newline before this token
        self.extra = extra

    def __repr__(self):
        return f"{self.t}:{self.v!r}@{self.line}"


def tokenize(src: str) -> tuple:
    toks: list = []
    comments: list = []
    i = 0
    n = len(src)
    line = 1
    nl = False
    prev: Optional[Tok] = None

    def regex_allowed() -> bool:
        if prev is None:
            return True
        if prev.t in ("num", "str", "tmpl", "regex"):
            return False
        if prev.t == "id":
            return False
        if prev.t == "kw":
            return prev.v in ("return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "yield", "await", "instanceof")
        if prev.t == "p":
            return prev.v not in (")", "]", "}")
        return True

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            nl = True
            i += 1
            continue
        if c in " \t\r\f\v ﻿  ":
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            if j == -1:
                j = n
            comments.append((line, src[i + 2:j].strip()))
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j == -1:
                j = n
            body = src[i + 2:j]
            for k, part in enumerate(body.split("\n")):
                part = part.strip().lstrip("*").strip()
                if part:
                    comments.append((line + k, part))
            line += body.count("\n")
            if "\n" in body:
                nl = True
            i = j + 2
            continue
        if c == "#" and i == 0 and src.startswith("#!"):
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        start_line = line
        if c in "'\"":
            j = i + 1
            buf = []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    e = src[j + 1]
                    if e == "n":
                        buf.append("\n")
                    elif e == "t":
                        buf.append("\t")
                    elif e == "r":
                        buf.append("\r")
                    elif e == "0":
                        buf.append("\0")
                    elif e == "x" and re.match(r"[0-9a-fA-F]{2}", src[j + 2:j + 4]):
                        buf.append(chr(int(src[j + 2:j + 4], 16)))
                        j += 2
                    elif e == "u":
                        m = re.match(r"\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{4})", src[j + 2:j + 10])
                        if m:
                            cp = int(m.group(1) or m.group(2), 16)
                            buf.append(chr(cp) if cp < 0x110000 else "?")
                            j += len(m.group(0))
                        else:
                            buf.append("u")
                    elif e == "\n":
                        line += 1
                    else:
                        buf.append(e)
                    j += 2
                    continue
                if src[j] == "\n":
                    break
                buf.append(src[j])
                j += 1
            toks.append(Tok("str", "".join(buf), start_line, nl))
            nl = False
            i = j + 1
            prev = toks[-1]
            continue
        if c == "`":
            parts: list = []     # str | ("expr", source, line)
            j = i + 1
            buf = []
            cur_line = line
            while j < n and src[j] != "`":
                if src[j] == "\\" and j + 1 < n:
                    e = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(e, e))
                    if e == "\n":
                        cur_line += 1
                    j += 2
                    continue
                if src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    if buf:
                        parts.append("".join(buf))
                        buf = []
                    depth = 1
                    k = j + 2
                    while k < n and depth:
                        ch = src[k]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        elif ch in "'\"`":
                            q = ch
                            k += 1
                            while k < n and src[k] != q:
                                if src[k] == "\\":
                                    k += 1
                                k += 1
                        k += 1
                    parts.append(("expr", src[j + 2:k], cur_line))
                    cur_line += src[j + 2:k].count("\n")
                    j = k + 1
                    continue
                if src[j] == "\n":
                    cur_line += 1
                buf.append(src[j])
                j += 1
            if buf:
                parts.append("".join(buf))
            toks.append(Tok("tmpl", parts, start_line, nl))
            nl = False
            line = cur_line
            i = j + 1
            prev = toks[-1]
            continue
        if c == "/" and regex_allowed():
            j = i + 1
            in_class = False
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                elif src[j] == "/" and not in_class:
                    break
                j += 1
            if j < n and src[j] == "/":
                k = j + 1
                while k < n and (src[k].isalpha()):
                    k += 1
                toks.append(Tok("regex", src[i:k], start_line, nl))
                nl = False
                i = k
                prev = toks[-1]
                continue
        m = _NUM.match(src, i) if (c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit())) else None
        if m:
            toks.append(Tok("num", m.group(0), start_line, nl))
            nl = False
            i = m.end()
            prev = toks[-1]
            continue
        m = _ID.match(src, i)
        if m:
            w = m.group(0)
            toks.append(Tok("kw" if w in KEYWORDS else "id", w, start_line, nl))
            nl = False
            i = m.end()
            prev = toks[-1]
            continue
        for p in _PUNCT:
            if src.startswith(p, i):
                toks.append(Tok("p", p, start_line, nl))
                nl = False
                i += len(p)
                prev = toks[-1]
                break
        else:
            raise JSParseError(f"unexpected character {c!r} at line {line}")
    toks.append(Tok("eof", None, line, nl))
    return toks, comments


# ======================================================================================== parser
def _num_value(s: str):
    s = s.replace("_", "")
    try:
        if s.endswith("n"):
            s = s[:-1]
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.lower().startswith("0b"):
            return int(s, 2)
        if s.lower().startswith("0o"):
            return int(s, 8)
        if re.fullmatch(r"\d+", s):
            return int(s)
        return float(s)
    except ValueError:
        return 0


class Parser:
    def __init__(self, toks: list, ts: bool = False):
        self.t = toks
        self.i = 0
        self.ts = ts
        self.pending: list = []       # hoisted function defs
        self.fn_counter = 0
        self.depth = 0

    # -- token helpers ------------------------------------------------------------------------
    @property
    def cur(self) -> Tok:
        return self.t[self.i]

    def peek(self, k: int = 1) -> Tok:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self) -> Tok:
        tk = self.t[self.i]
        if self.i < len(self.t) - 1:
            self.i += 1
        return tk

    def is_p(self, v: str) -> bool:
        return self.cur.t == "p" and self.cur.v == v

    def is_kw(self, v: str) -> bool:
        return self.cur.t == "kw" and self.cur.v == v

    def eat_p(self, v: str) -> bool:
        if self.is_p(v):
            self.next()
            return True
        return False

    def eat_kw(self, v: str) -> bool:
        if self.is_kw(v):
            self.next()
            return True
        return False

    def expect_p(self, v: str) -> Tok:
        if not self.is_p(v):
            raise JSParseError(f"expected {v!r} but got {self.cur!r}")
        return self.next()

    def semi(self) -> None:
        if self.eat_p(";"):
            return
        if self.is_p("}") or self.cur.t == "eof" or self.cur.nl:
            return
        # be forgiving
        return

    def node(self, cls, tok_or_line, **kw):
        n = cls(**kw)
        ln = tok_or_line.line if isinstance(tok_or_line, Tok) else int(tok_or_line)
        n.lineno = ln
        n.col_offset = 0
        n.end_lineno = ln
        n.end_col_offset = 0
        return n

    def name_load(self, name: str, line: int):
        return self.node(ast.Name, line, id=name, ctx=ast.Load())

    def name_store(self, name: str, line: int):
        return self.node(ast.Name, line, id=name, ctx=ast.Store())

    def const(self, v, line: int):
        return self.node(ast.Constant, line, value=v, kind=None)

    def unknown(self, line: int):
        return self.node(ast.Call, line, func=self.name_load("__unknown__", line), args=[], keywords=[])

    # -- types (TypeScript) ---------------------------------------------------------------------
    def skip_type(self) -> None:
        depth = 0
        guard = 0
        while guard < 500:
            guard += 1
            tk = self.cur
            if tk.t == "eof":
                return
            if tk.t == "p":
                if tk.v in ("<", "(", "[", "{"):
                    depth += 1
                elif tk.v in (">", ")", "]", "}"):
                    if depth == 0:
                        return
                    depth -= 1
                elif tk.v == ">>" and depth >= 2:
                    depth -= 2
                elif tk.v in (",", ";", "=", "=>") and depth == 0:
                    if tk.v == "=>" :
                        self.next()
                        continue
                    return
            elif tk.nl and depth == 0 and tk.t not in ("p",):
                return
            self.next()

    # -- program ----------------------------------------------------------------------------------
    def parse_program(self) -> ast.Module:
        body: list = []
        guard = 0
        while self.cur.t != "eof":
            guard += 1
            if guard > 200000:
                raise JSParseError("too many statements")
            before = self.i
            body.extend(self.statement())
            if self.i == before:
                self.next()
        if not body:
            body = [self.node(ast.Pass, 1)]
        m = ast.Module(body=body, type_ignores=[])
        return m

    def flush(self) -> list:
        p = self.pending
        self.pending = []
        return p

    def block_body(self) -> list:
        """parse `{ ... }` into a list of Python statements"""
        self.expect_p("{")
        out: list = []
        while not self.is_p("}") and self.cur.t != "eof":
            before = self.i
            out.extend(self.statement())
            if self.i == before:
                self.next()
        self.expect_p("}")
        return out or [self.node(ast.Pass, self.cur.line)]

    def stmt_or_block(self) -> list:
        if self.is_p("{"):
            return self.block_body()
        return self.statement() or [self.node(ast.Pass, self.cur.line)]

    # -- statements -------------------------------------------------------------------------------
    def statement(self) -> list:
        self.depth += 1
        if self.depth > 150:
            raise JSParseError("nesting too deep")
        try:
            return self._statement()
        finally:
            self.depth -= 1

    def _statement(self) -> list:
        tk = self.cur
        if tk.t == "p":
            if tk.v == ";":
                self.next()
                return []
            if tk.v == "{":
                body = self.block_body()
                return [self.node(ast.If, tk, test=self.const(True, tk.line), body=body, orelse=[])]
            if tk.v == "@":      # decorator
                self.next()
                self.unary()
                return []
        if tk.t == "kw":
            kw = tk.v
            if kw in ("var", "let", "const"):
                return self.var_decl(True)
            if kw == "function":
                return self.func_decl()
            if kw == "async" and self.peek().t == "kw" and self.peek().v == "function":
                self.next()
                return self.func_decl()
            if kw == "class":
                return self.class_decl()
            if kw == "if":
                return self.if_stmt()
            if kw == "for":
                return self.for_stmt()
            if kw == "while":
                self.next()
                self.expect_p("(")
                test = self.expression()
                self.expect_p(")")
                pre = self.flush()
                body = self.stmt_or_block()
                return pre + [self.node(ast.While, tk, test=test, body=body, orelse=[])]
            if kw == "do":
                self.next()
                body = self.stmt_or_block()
                if self.eat_kw("while"):
                    self.expect_p("(")
                    test = self.expression()
                    self.expect_p(")")
                    self.semi()
                    pre = self.flush()
                    return pre + body + [self.node(ast.While, tk, test=test, body=body, orelse=[])]
                return body
            if kw == "return":
                self.next()
                val = None
                if not (self.is_p(";") or self.is_p("}") or self.cur.nl or self.cur.t == "eof"):
                    val = self.expression()
                self.semi()
                return self.flush() + [self.node(ast.Return, tk, value=val)]
            if kw == "throw":
                self.next()
                e = self.expression()
                self.semi()
                return self.flush() + [self.node(ast.Raise, tk, exc=e, cause=None)]
            if kw == "break":
                self.next()
                if self.cur.t == "id" and not self.cur.nl:
                    self.next()
                self.semi()
                return [self.node(ast.Break, tk)]
            if kw == "continue":
                self.next()
                if self.cur.t == "id" and not self.cur.nl:
                    self.next()
                self.semi()
                return [self.node(ast.Continue, tk)]
            if kw == "try":
                return self.try_stmt()
            if kw == "switch":
                return self.switch_stmt()
            if kw == "import" and self.peek().v not in ("(", "."):
                return self.import_decl()
            if kw == "export":
                return self.export_decl()
            if kw == "debugger":
                self.next()
                self.semi()
                return []
        if tk.t == "id" and self.peek().t == "p" and self.peek().v == ":" and tk.v not in ("default",):
            # label
            self.next()
            self.next()
            return self.statement()
        if self.ts and tk.t == "id" and tk.v in ("interface", "type", "declare", "namespace", "abstract", "enum", "module"):
            if tk.v in ("interface", "enum") or (tk.v == "type" and self.peek().t == "id") or tk.v in ("declare", "namespace"):
                self.skip_ts_decl()
                return []
            if tk.v == "abstract" and self.peek().t == "kw" and self.peek().v == "class":
                self.next()
                return self.class_decl()
        # expression statement
        e = self.expression()
        stmt = self.expr_to_stmt(e, tk)
        self.semi()
        return self.flush() + stmt

    def skip_ts_decl(self) -> None:
        self.next()
        depth = 0
        while self.cur.t != "eof":
            if self.is_p("{"):
                depth += 1
            elif self.is_p("}"):
                depth -= 1
                if depth <= 0:
                    self.next()
                    return
            elif self.is_p(";") and depth == 0:
                self.next()
                return
            elif self.cur.nl and depth == 0 and self.i > 0:
                return
            self.next()

    def expr_to_stmt(self, e, tk) -> list:
        if isinstance(e, ast.stmt):
            return [e]
        if isinstance(e, list):
            return e
        return [self.node(ast.Expr, tk, value=e)]

    def var_decl(self, stmt: bool) -> list:
        kind = self.next()
        out: list = []
        while True:
            tgt_tok = self.cur
            target = self.binding_target()
            if self.ts and self.is_p(":"):
                self.next()
                self.skip_type()
            init = None
            if self.eat_p("="):
                init = self.assignment()
            if init is None:
                init = self.const(None, tgt_tok.line)
            out.extend(self.destructure(target, init, tgt_tok))
            if not self.eat_p(","):
                break
        if stmt:
            self.semi()
        return self.flush() + out

    def binding_target(self):
        tk = self.cur
        if tk.t in ("id", "kw") and tk.v not in ("function", "class") or (tk.t == "kw"):
            self.next()
            if self.ts and self.is_p("!"):
                self.next()
            return ("name", tk.v, tk.line)
        if self.is_p("{"):
            self.next()
            fields: list = []
            while not self.is_p("}") and self.cur.t != "eof":
                if self.eat_p("..."):
                    nm = self.next()
                    fields.append(("rest", nm.v))
                else:
                    key = self.next()
                    kname = key.v if key.t != "str" else key.v
                    local = kname
                    default = None
                    if self.eat_p(":"):
                        sub = self.binding_target()
                        local = sub
                    if self.eat_p("="):
                        default = self.assignment()
                    fields.append(("field", kname, local, default))
                if not self.eat_p(","):
                    break
            self.expect_p("}")
            return ("obj", fields, tk.line)
        if self.is_p("["):
            self.next()
            elems: list = []
            while not self.is_p("]") and self.cur.t != "eof":
                if self.is_p(","):
                    self.next()
                    elems.append(None)
                    continue
                if self.eat_p("..."):
                    elems.append(("rest", self.binding_target()))
                else:
                    t = self.binding_target()
                    if self.eat_p("="):
                        self.assignment()
                    elems.append(t)
                if not self.eat_p(","):
                    break
            self.expect_p("]")
            return ("arr", elems, tk.line)
        raise JSParseError(f"bad binding at {tk!r}")

    def destructure(self, target, value, tok) -> list:
        kind = target[0]
        line = tok.line
        if kind == "name":
            return [self.node(ast.Assign, line, targets=[self.name_store(target[1], line)], value=value, type_comment=None)]
        tmp = f"__d{self.fn_counter}"
        self.fn_counter += 1
        out = [self.node(ast.Assign, line, targets=[self.name_store(tmp, line)], value=value, type_comment=None)]
        if kind == "obj":
            for f in target[1]:
                if f[0] == "rest":
                    out.append(self.node(ast.Assign, line, targets=[self.name_store(f[1], line)], value=self.name_load(tmp, line), type_comment=None))
                    continue
                _k, kname, local, default = f
                sub = self.node(ast.Attribute, line, value=self.name_load(tmp, line), attr=str(kname), ctx=ast.Load())
                if default is not None:
                    sub = self.node(ast.BoolOp, line, op=ast.Or(), values=[sub, default])
                out.extend(self.destructure(local if isinstance(local, tuple) else ("name", local, line), sub, tok))
        elif kind == "arr":
            for idx, e in enumerate(target[1]):
                if e is None:
                    continue
                if e[0] == "rest":
                    out.extend(self.destructure(e[1], self.name_load(tmp, line), tok))
                    continue
                sub = self.node(ast.Subscript, line, value=self.name_load(tmp, line), slice=self.const(idx, line), ctx=ast.Load())
                out.extend(self.destructure(e, sub, tok))
        return out

    def params(self) -> tuple:
        """-> (arg names list, prologue statements, defaults)"""
        self.expect_p("(")
        names: list = []
        prologue: list = []
        defaults: list = []
        while not self.is_p(")") and self.cur.t != "eof":
            if self.eat_p("..."):
                tgt = self.binding_target()
                nm = tgt[1] if tgt[0] == "name" else f"__rest{len(names)}"
                names.append(("rest", nm))
            else:
                if self.ts and self.cur.t == "kw" and self.cur.v in ("get", "set", "static"):
                    pass
                tk = self.cur
                if self.ts and self.cur.t == "id" and self.cur.v in ("public", "private", "protected", "readonly"):
                    self.next()
                    tk = self.cur
                tgt = self.binding_target()
                if self.ts and self.is_p("?"):
                    self.next()
                if self.ts and self.is_p(":"):
                    self.next()
                    self.skip_type()
                if self.eat_p("="):
                    d = self.assignment()
                    defaults.append(d)
                if tgt[0] == "name":
                    names.append(("arg", tgt[1]))
                else:
                    nm = f"__p{self.fn_counter}"
                    self.fn_counter += 1
                    names.append(("arg", nm))
                    prologue.extend(self.destructure(tgt, self.name_load(nm, tk.line), tk))
            if not self.eat_p(","):
                break
        self.expect_p(")")
        if self.ts and self.is_p(":"):
            self.next()
            self.skip_type()
        return names, prologue

    def make_args(self, names: list, line: int, self_arg: bool = False):
        args = []
        vararg = None
        if self_arg:
            args.append(self.node(ast.arg, line, arg="self", annotation=None))
        for kind, nm in names:
            if kind == "rest":
                vararg = self.node(ast.arg, line, arg=nm, annotation=None)
            else:
                args.append(self.node(ast.arg, line, arg=nm, annotation=None))
        return ast.arguments(posonlyargs=[], args=args, vararg=vararg, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[])

    def func_body(self) -> list:
        if self.ts and self.is_p(":"):
            self.next()
            self.skip_type()
        return self.block_body()

    def func_decl(self) -> list:
        tk = self.next()          # 'function'
        self.eat_p("*")
        name = "__anon"
        if self.cur.t in ("id", "kw") and not self.is_p("("):
            name = self.next().v
        if self.ts and self.is_p("<"):
            self.skip_type_params()
        names, prologue = self.params()
        body = self.func_body()
        fd = self.node(ast.FunctionDef, tk, name=name, args=self.make_args(names, tk.line), body=prologue + body, decorator_list=[], returns=None, type_comment=None)
        return self.flush() + [fd]

    def skip_type_params(self) -> None:
        depth = 0
        while self.cur.t != "eof":
            if self.is_p("<"):
                depth += 1
            elif self.is_p(">"):
                depth -= 1
                if depth == 0:
                    self.next()
                    return
            self.next()

    def class_decl(self) -> list:
        tk = self.next()          # 'class'
        name = "__anonclass"
        if self.cur.t in ("id", "kw") and not self.is_kw("extends") and not self.is_p("{"):
            name = self.next().v
        if self.ts and self.is_p("<"):
            self.skip_type_params()
        bases: list = []
        if self.eat_kw("extends"):
            b = self.postfix()
            bases.append(b)
            if self.ts and self.is_p("<"):
                self.skip_type_params()
        if self.ts and self.cur.t == "id" and self.cur.v == "implements":
            while not self.is_p("{") and self.cur.t != "eof":
                self.next()
        body = self.class_body()
        cd = self.node(ast.ClassDef, tk, name=name, bases=bases, keywords=[], body=body or [self.node(ast.Pass, tk)], decorator_list=[])
        return self.flush() + [cd]

    def class_body(self) -> list:
        self.expect_p("{")
        out: list = []
        while not self.is_p("}") and self.cur.t != "eof":
            if self.eat_p(";"):
                continue
            before = self.i
            static = False
            is_async = False
            kind = "method"
            while self.cur.t in ("kw", "id") and self.cur.v in ("static", "async", "get", "set", "public", "private", "protected", "readonly", "abstract", "override") \
                    and not (self.peek().t == "p" and self.peek().v in ("(", "=", ";", ":", "<")):
                v = self.next().v
                if v == "static":
                    static = True
                elif v in ("get", "set"):
                    kind = v
            if self.eat_p("*"):
                pass
            tk = self.cur
            if self.is_p("["):
                self.next()
                self.expression()
                self.expect_p("]")
                key = "__computed"
            else:
                key_tok = self.next()
                key = key_tok.v if key_tok.t != "num" else str(key_tok.v)
                if key_tok.t == "p" and key_tok.v == "#":
                    key = "#" + self.next().v
            if self.ts and self.is_p("?"):
                self.next()
            if self.is_p("(") or (self.ts and self.is_p("<")):
                if self.ts and self.is_p("<"):
                    self.skip_type_params()
                names, prologue = self.params()
                body = self.func_body()
                fname = "__init__" if key == "constructor" else key
                decs = []
                if kind == "get":
                    decs.append(self.name_load("property", tk.line))
                if static:
                    decs.append(self.name_load("staticmethod", tk.line))
                fd = self.node(ast.FunctionDef, tk, name=fname, args=self.make_args(names, tk.line, self_arg=not static), body=prologue + body,
                               decorator_list=decs, returns=None, type_comment=None)
                out.extend(self.flush())
                out.append(fd)
            else:
                # field
                if self.ts and self.is_p(":"):
                    self.next()
                    self.skip_type()
                val = self.const(None, tk.line)
                if self.eat_p("="):
                    val = self.assignment()
                self.semi()
                out.extend(self.flush())
                out.append(self.node(ast.Assign, tk, targets=[self.name_store(key, tk.line)], value=val, type_comment=None))
            if self.i == before:
                self.next()
        self.expect_p("}")
        return out

    def if_stmt(self) -> list:
        tk = self.next()
        self.expect_p("(")
        test = self.expression()
        self.expect_p(")")
        pre = self.flush()
        body = self.stmt_or_block()
        orelse: list = []
        if self.eat_kw("else"):
            orelse = self.stmt_or_block()
        return pre + [self.node(ast.If, tk, test=test, body=body, orelse=orelse)]

    def for_stmt(self) -> list:
        tk = self.next()
        is_await = self.eat_kw("await")
        self.expect_p("(")
        # for (const x of y) / for (x in y) / for (init; cond; update)
        save = self.i
        init_stmts: list = []
        if self.is_p(";"):
            pass
        elif self.cur.t == "kw" and self.cur.v in ("var", "let", "const"):
            kind = self.next()
            tgt = self.binding_target()
            if self.cur.t == "kw" and self.cur.v in ("of", "in") or (self.cur.t == "id" and self.cur.v == "of"):
                self.next()
                it = self.assignment() if self.cur.v != "," else self.expression()
                self.expect_p(")")
                pre = self.flush()
                body = self.stmt_or_block()
                if tgt[0] == "name":
                    target = self.name_store(tgt[1], tk.line)
                    return pre + [self.node(ast.For, tk, target=target, iter=it, body=body, orelse=[], type_comment=None)]
                tmp = f"__fe{self.fn_counter}"
                self.fn_counter += 1
                body = self.destructure(tgt, self.name_load(tmp, tk.line), tk) + body
                return pre + [self.node(ast.For, tk, target=self.name_store(tmp, tk.line), iter=it, body=body, orelse=[], type_comment=None)]
            if self.ts and self.is_p(":"):
                self.next()
                self.skip_type()
            init = self.const(None, tk.line)
            if self.eat_p("="):
                init = self.assignment()
            init_stmts = self.destructure(tgt, init, tk)
            while self.eat_p(","):
                t2 = self.binding_target()
                i2 = self.const(None, tk.line)
                if self.eat_p("="):
                    i2 = self.assignment()
                init_stmts += self.destructure(t2, i2, tk)
        else:
            e = self.expression_no_in()
            if self.cur.t == "kw" and self.cur.v in ("of", "in") or (self.cur.t == "id" and self.cur.v == "of"):
                self.next()
                it = self.expression()
                self.expect_p(")")
                pre = self.flush()
                body = self.stmt_or_block()
                tgt = self.to_store(e)
                return pre + [self.node(ast.For, tk, target=tgt, iter=it, body=body, orelse=[], type_comment=None)]
            init_stmts = self.expr_to_stmt(e, tk)
        self.expect_p(";")
        test = None
        if not self.is_p(";"):
            test = self.expression()
        self.expect_p(";")
        update_stmts: list = []
        if not self.is_p(")"):
            ue = self.expression()
            update_stmts = self.expr_to_stmt(ue, tk)
        self.expect_p(")")
        pre = self.flush()
        body = self.stmt_or_block()
        # canonical counting loop  for (i = a; i < b; i++)  ->  for i in range(a, b)
        rng = self.try_range_loop(init_stmts, test, update_stmts, body, tk)
        if rng is not None:
            return pre + rng
        if test is None:
            test = self.const(True, tk.line)
        loop = self.node(ast.While, tk, test=test, body=body + update_stmts, orelse=[])
        return pre + init_stmts + [loop]

    def try_range_loop(self, init, test, update, body, tk):
        if len(init) != 1 or not isinstance(init[0], ast.Assign) or not isinstance(init[0].targets[0], ast.Name):
            return None
        var = init[0].targets[0].id
        start = init[0].value
        if test is None or not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.left, ast.Name) or test.left.id != var:
            return None
        if not isinstance(test.ops[0], (ast.Lt, ast.LtE)):
            return None
        if len(update) != 1:
            return None
        u = update[0]
        ok = False
        if isinstance(u, ast.AugAssign) and isinstance(u.target, ast.Name) and u.target.id == var and isinstance(u.op, ast.Add) and isinstance(u.value, ast.Constant) and u.value.value == 1:
            ok = True
        if not ok:
            return None
        stop = test.comparators[0]
        if isinstance(test.ops[0], ast.LtE):
            stop = self.node(ast.BinOp, tk, left=stop, op=ast.Add(), right=self.const(1, tk.line))
        it = self.node(ast.Call, tk, func=self.name_load("range", tk.line), args=[start, stop], keywords=[])
        return [self.node(ast.For, tk, target=self.name_store(var, tk.line), iter=it, body=body, orelse=[], type_comment=None)]

    def to_store(self, e):
        if isinstance(e, ast.Name):
            return self.name_store(e.id, e.lineno)
        if isinstance(e, ast.Attribute):
            e.ctx = ast.Store()
            return e
        if isinstance(e, ast.Subscript):
            e.ctx = ast.Store()
            return e
        return self.name_store("__target", getattr(e, "lineno", 1))

    def try_stmt(self) -> list:
        tk = self.next()
        body = self.block_body()
        handlers: list = []
        final: list = []
        if self.eat_kw("catch"):
            name = None
            if self.eat_p("("):
                if self.cur.t in ("id", "kw"):
                    name = self.next().v
                if self.ts and self.is_p(":"):
                    self.next()
                    self.skip_type()
                self.expect_p(")")
            hb = self.block_body()
            handlers.append(self.node(ast.ExceptHandler, tk, type=None, name=name, body=hb))
        if self.eat_kw("finally"):
            final = self.block_body()
        if not handlers and not final:
            return body
        t = self.node(ast.Try, tk, body=body, handlers=handlers, orelse=[], finalbody=final)
        return [t]

    def switch_stmt(self) -> list:
        tk = self.next()
        self.expect_p("(")
        disc = self.expression()
        self.expect_p(")")
        pre = self.flush()
        self.expect_p("{")
        branches: list = []
        cur_body: list = []
        started = False
        while not self.is_p("}") and self.cur.t != "eof":
            if self.is_kw("case") or self.is_kw("default"):
                if started:
                    branches.append(cur_body)
                    cur_body = []
                started = True
                if self.next().v == "case":
                    self.expression()
                self.expect_p(":")
            else:
                before = self.i
                cur_body.extend(self.statement())
                if self.i == before:
                    self.next()
        if started:
            branches.append(cur_body)
        self.expect_p("}")
        out: list = []
        for b in branches:
            out.append(self.node(ast.If, tk, test=self.unknown(tk.line), body=b or [self.node(ast.Pass, tk)], orelse=[]))
        return pre + out

    def import_decl(self) -> list:
        tk = self.next()          # import
        if self.cur.t == "str":
            self.next()
            self.semi()
            return []
        out: list = []
        default_name = None
        names: list = []
        ns_name = None
        if self.cur.t in ("id", "kw") and not self.is_p("{"):
            default_name = self.next().v
            self.eat_p(",")
        if self.eat_p("*"):
            self.eat_kw("as") or (self.cur.t == "id" and self.cur.v == "as" and self.next())
            ns_name = self.next().v
        elif self.is_p("{"):
            self.next()
            while not self.is_p("}") and self.cur.t != "eof":
                nm = self.next().v
                alias = None
                if self.eat_kw("as"):
                    alias = self.next().v
                names.append((nm, alias))
                if not self.eat_p(","):
                    break
            self.expect_p("}")
        if self.cur.t in ("kw", "id") and self.cur.v == "from":
            self.next()
        mod = self.next().v if self.cur.t == "str" else ""
        self.semi()
        mod = normalize_module(mod)
        req = lambda: self.node(ast.Call, tk, func=self.name_load("__require__", tk.line), args=[self.const(mod, tk.line)], keywords=[])
        if default_name:
            out.append(self.node(ast.Assign, tk, targets=[self.name_store(default_name, tk.line)], value=req(), type_comment=None))
        if ns_name:
            out.append(self.node(ast.Assign, tk, targets=[self.name_store(ns_name, tk.line)], value=req(), type_comment=None))
        if names:
            out.append(self.node(ast.ImportFrom, tk, module=mod, names=[ast.alias(name=n, asname=a) for n, a in names], level=0))
        return out

    def export_decl(self) -> list:
        self.next()
        if self.eat_kw("default"):
            if self.is_kw("function") or self.is_kw("class") or (self.is_kw("async")):
                return self.statement()
            e = self.assignment()
            self.semi()
            return self.flush() + [self.node(ast.Expr, self.cur, value=e)]
        if self.is_p("{") or self.is_p("*"):
            while not self.is_p(";") and not self.cur.nl and self.cur.t != "eof":
                self.next()
            self.semi()
            return []
        return self.statement()

    # -- expressions ------------------------------------------------------------------------------------
    def expression(self):
        e = self.assignment()
        while self.is_p(","):
            self.next()
            e2 = self.assignment()
            if isinstance(e, ast.stmt) or isinstance(e, list):
                continue
            e = e2
        return e

    def expression_no_in(self):
        return self.assignment(no_in=True)

    _ASSIGN_OPS = {"=": None, "+=": ast.Add, "-=": ast.Sub, "*=": ast.Mult, "/=": ast.Div, "%=": ast.Mod, "**=": ast.Pow, "<<=": ast.LShift, ">>=": ast.RShift,
                   ">>>=": ast.RShift, "&=": ast.BitAnd, "|=": ast.BitOr, "^=": ast.BitXor, "&&=": "and", "||=": "or", "??=": "or"}

    def assignment(self, no_in: bool = False):
        tk = self.cur
        # arrow functions
        arrow = self.try_arrow()
        if arrow is not None:
            return arrow
        left = self.ternary(no_in)
        if self.cur.t == "p" and self.cur.v in self._ASSIGN_OPS:
            op = self.next().v
            right = self.assignment(no_in)
            kind = self._ASSIGN_OPS[op]
            tgt = self.to_store(left)
            if kind is None:
                return self.node(ast.Assign, tk, targets=[tgt], value=right, type_comment=None)
            if kind in ("and", "or"):
                val = self.node(ast.BoolOp, tk, op=ast.And() if kind == "and" else ast.Or(), values=[left, right])
                return self.node(ast.Assign, tk, targets=[tgt], value=val, type_comment=None)
            return self.node(ast.AugAssign, tk, target=tgt, op=kind(), value=right)
        return left

    def try_arrow(self):
        tk = self.cur
        is_async = False
        j = self.i
        if tk.t == "kw" and tk.v == "async" and not (self.peek().t == "p" and self.peek().v in ("=>", ".")):
            nxt = self.peek()
            if nxt.t == "id" or (nxt.t == "p" and nxt.v == "("):
                is_async = True
                j = self.i + 1
        t0 = self.t[j]
        # single param:  x => ...
        if t0.t == "id" and self.t[j + 1].t == "p" and self.t[j + 1].v == "=>":
            if is_async:
                self.next()
            self.next()
            self.next()
            return self.arrow_body([("arg", t0.v)], [], tk)
        if t0.t == "p" and t0.v == "(":
            # find matching paren and check for '=>'
            depth = 0
            k = j
            while k < len(self.t):
                tt = self.t[k]
                if tt.t == "p" and tt.v == "(":
                    depth += 1
                elif tt.t == "p" and tt.v == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif tt.t == "eof":
                    return None
                k += 1
            after = self.t[k + 1] if k + 1 < len(self.t) else None
            if after is not None and after.t == "p" and after.v == "=>":
                if is_async:
                    self.next()
                names, prologue = self.params()
                self.expect_p("=>")
                return self.arrow_body(names, prologue, tk)
            if self.ts and after is not None and after.t == "p" and after.v == ":":
                # (a: T): R => ...
                save = self.i
                try:
                    if is_async:
                        self.next()
                    names, prologue = self.params()
                    if self.is_p("=>"):
                        self.next()
                        return self.arrow_body(names, prologue, tk)
                except JSParseError:
                    pass
                self.i = save
        return None

    def arrow_body(self, names, prologue, tk):
        if self.is_p("{"):
            body = self.block_body()
            self.fn_counter += 1
            nm = f"__fn{self.fn_counter}"
            fd = self.node(ast.FunctionDef, tk, name=nm, args=self.make_args(names, tk.line), body=prologue + body, decorator_list=[], returns=None, type_comment=None)
            self.pending.append(fd)
            return self.name_load(nm, tk.line)
        saved = self.pending
        self.pending = []
        e = self.assignment()
        inner_pending = self.pending
        self.pending = saved
        if prologue or inner_pending:
            self.fn_counter += 1
            nm = f"__fn{self.fn_counter}"
            fd = self.node(ast.FunctionDef, tk, name=nm, args=self.make_args(names, tk.line),
                           body=inner_pending + prologue + [self.node(ast.Return, tk, value=e)], decorator_list=[], returns=None, type_comment=None)
            self.pending.append(fd)
            return self.name_load(nm, tk.line)
        if isinstance(e, ast.stmt):
            e = self.unknown(tk.line)
        lam = self.node(ast.Lambda, tk, args=self.make_args(names, tk.line), body=e)
        return lam

    def ternary(self, no_in: bool = False):
        tk = self.cur
        cond = self.binary(0, no_in)
        if self.is_p("?"):
            self.next()
            a = self.assignment()
            self.expect_p(":")
            b = self.assignment(no_in)
            return self.node(ast.IfExp, tk, test=cond, body=a, orelse=b)
        return cond

    _BINPREC = {"??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6, "==": 7, "!=": 7, "===": 7, "!==": 7, "<": 8, ">": 8, "<=": 8, ">=": 8, "instanceof": 8, "in": 8,
                "<<": 9, ">>": 9, ">>>": 9, "+": 10, "-": 10, "*": 11, "/": 11, "%": 11, "**": 12}
    _OPMAP = {"+": ast.Add, "-": ast.Sub, "*": ast.Mult, "/": ast.Div, "%": ast.Mod, "**": ast.Pow, "<<": ast.LShift, ">>": ast.RShift, ">>>": ast.RShift, "&": ast.BitAnd,
              "|": ast.BitOr, "^": ast.BitXor}
    _CMPMAP = {"==": ast.Eq, "===": ast.Eq, "!=": ast.NotEq, "!==": ast.NotEq, "<": ast.Lt, ">": ast.Gt, "<=": ast.LtE, ">=": ast.GtE}

    def binary(self, minprec: int, no_in: bool = False):
        left = self.unary()
        while True:
            tk = self.cur
            op = None
            if tk.t == "p" and tk.v in self._BINPREC:
                op = tk.v
            elif tk.t == "kw" and tk.v in ("instanceof", "in") and not (no_in and tk.v == "in"):
                op = tk.v
            elif self.ts and tk.t == "kw" and tk.v == "as":
                self.next()
                self.skip_type()
                continue
            if op is None:
                return left
            prec = self._BINPREC[op]
            if prec < minprec:
                return left
            self.next()
            right = self.binary(prec + 1 if op != "**" else prec, no_in)
            if op in ("&&", "||", "??"):
                left = self.node(ast.BoolOp, tk, op=ast.And() if op == "&&" else ast.Or(), values=[left, right])
            elif op in self._CMPMAP:
                left = self.node(ast.Compare, tk, left=left, ops=[self._CMPMAP[op]()], comparators=[right])
            elif op in ("instanceof", "in"):
                left = self.node(ast.Compare, tk, left=left, ops=[ast.In() if op == "in" else ast.Is()], comparators=[right])
            else:
                left = self.node(ast.BinOp, tk, left=left, op=self._OPMAP[op](), right=right)

    def unary(self):
        tk = self.cur
        if tk.t == "p":
            if tk.v == "!":
                self.next()
                return self.node(ast.UnaryOp, tk, op=ast.Not(), operand=self.unary())
            if tk.v == "-":
                self.next()
                return self.node(ast.UnaryOp, tk, op=ast.USub(), operand=self.unary())
            if tk.v == "+":
                self.next()
                return self.node(ast.UnaryOp, tk, op=ast.UAdd(), operand=self.unary())
            if tk.v == "~":
                self.next()
                return self.node(ast.UnaryOp, tk, op=ast.Invert(), operand=self.unary())
            if tk.v in ("++", "--"):
                self.next()
                t = self.unary()
                return self.node(ast.AugAssign, tk, target=self.to_store(t), op=ast.Add() if tk.v == "++" else ast.Sub(), value=self.const(1, tk.line))
        if tk.t == "kw":
            if tk.v in ("typeof", "void", "delete"):
                self.next()
                self.unary()
                return self.unknown(tk.line)
            if tk.v == "await":
                self.next()
                return self.node(ast.Await, tk, value=self.unary())
            if tk.v == "yield":
                self.next()
                self.eat_p("*")
                v = None
                if not (self.is_p(")") or self.is_p(";") or self.is_p("}") or self.cur.nl or self.is_p(",")):
                    v = self.assignment()
                return self.node(ast.Yield, tk, value=v)
        e = self.postfix()
        if self.cur.t == "p" and self.cur.v in ("++", "--") and not self.cur.nl:
            op = self.next().v
            return self.node(ast.AugAssign, tk, target=self.to_store(e), op=ast.Add() if op == "++" else ast.Sub(), value=self.const(1, tk.line))
        return e

    def args(self) -> list:
        self.expect_p("(")
        out: list = []
        while not self.is_p(")") and self.cur.t != "eof":
            if self.eat_p("..."):
                out.append(self.node(ast.Starred, self.cur, value=self.assignment(), ctx=ast.Load()))
            else:
                out.append(self.assignment())
            if not self.eat_p(","):
                break
        self.expect_p(")")
        return out

    def postfix(self):
        tk = self.cur
        if tk.t == "kw" and tk.v == "new":
            self.next()
            if self.is_p("."):      # new.target
                self.next()
                self.next()
                return self.unknown(tk.line)
            callee = self.member_only()
            if self.ts and self.is_p("<"):
                self.skip_type_params()
            args = self.args() if self.is_p("(") else []
            e = self.node(ast.Call, tk, func=callee, args=args, keywords=[])
        else:
            e = self.primary()
        while True:
            t = self.cur
            if t.t == "p" and t.v in (".", "?."):
                self.next()
                if self.is_p("("):         # ?.(
                    args = self.args()
                    e = self.node(ast.Call, t, func=e, args=args, keywords=[])
                    continue
                if self.is_p("["):
                    self.next()
                    idx = self.expression()
                    self.expect_p("]")
                    e = self.node(ast.Subscript, t, value=e, slice=idx, ctx=ast.Load())
                    continue
                nm = self.next()
                name = nm.v
                if nm.t == "p" and nm.v == "#":
                    name = "#" + self.next().v
                e = self.node(ast.Attribute, nm, value=e, attr=str(name), ctx=ast.Load())
            elif t.t == "p" and t.v == "[":
                self.next()
                idx = self.expression()
                self.expect_p("]")
                e = self.node(ast.Subscript, t, value=e, slice=idx, ctx=ast.Load())
            elif t.t == "p" and t.v == "(":
                if t.nl and False:
                    break
                args = self.args()
                e = self.node(ast.Call, t, func=e, args=args, keywords=[])
            elif t.t == "tmpl":
                # tagged template: tag`...`
                self.next()
                e = self.node(ast.Call, t, func=e, args=[self.template(t)], keywords=[])
            elif self.ts and t.t == "p" and t.v == "!" and not t.nl:
                self.next()
            else:
                break
        return e

    def member_only(self):
        tk = self.cur
        if self.is_kw("new"):
            return self.postfix()
        e = self.primary()
        while self.is_p(".") or self.is_p("["):
            t = self.next()
            if t.v == ".":
                nm = self.next()
                e = self.node(ast.Attribute, nm, value=e, attr=str(nm.v), ctx=ast.Load())
            else:
                idx = self.expression()
                self.expect_p("]")
                e = self.node(ast.Subscript, t, value=e, slice=idx, ctx=ast.Load())
        return e

    def template(self, tk: Tok):
        values: list = []
        for part in tk.v:
            if isinstance(part, str):
                values.append(self.const(part, tk.line))
            else:
                _k, src, ln = part
                sub = Parser(tokenize(src)[0], self.ts)
                sub.fn_counter = self.fn_counter + 1000
                try:
                    e = sub.expression()
                    self.pending.extend(sub.pending)
                except JSParseError:
                    e = self.unknown(tk.line)
                self.fn_counter = max(self.fn_counter, sub.fn_counter)
                self._set_lines(e, tk.line + src.count("\n") * 0)
                values.append(self.node(ast.FormattedValue, tk, value=e, conversion=-1, format_spec=None))
        return self.node(ast.JoinedStr, tk, values=values)

    def _set_lines(self, node, line: int) -> None:
        for n in ast.walk(node):
            if hasattr(n, "lineno"):
                n.lineno = line
                n.end_lineno = line

    def primary(self):
        tk = self.cur
        t = tk.t
        if t == "num":
            self.next()
            return self.const(_num_value(tk.v), tk.line)
        if t == "str":
            self.next()
            return self.const(tk.v, tk.line)
        if t == "tmpl":
            self.next()
            return self.template(tk)
        if t == "regex":
            self.next()
            return self.const("<regex>", tk.line)
        if t == "id":
            self.next()
            if self.ts and self.is_p("<") and False:
                self.skip_type_params()
            return self.name_load(tk.v, tk.line)
        if t == "kw":
            v = tk.v
            if v == "function" or (v == "async" and self.peek().t == "kw" and self.peek().v == "function"):
                if v == "async":
                    self.next()
                self.next()
                self.eat_p("*")
                nm = f"__fn{self.fn_counter + 1}"
                if self.cur.t in ("id",):
                    self.next()
                self.fn_counter += 1
                names, prologue = self.params()
                body = self.func_body()
                fd = self.node(ast.FunctionDef, tk, name=nm, args=self.make_args(names, tk.line), body=prologue + body, decorator_list=[], returns=None, type_comment=None)
                self.pending.append(fd)
                return self.name_load(nm, tk.line)
            if v == "class":
                stmts = self.class_decl()
                # anonymous class expression: hoist and reference by name
                cls = [s for s in stmts if isinstance(s, ast.ClassDef)]
                self.pending.extend(stmts)
                return self.name_load(cls[0].name if cls else "__anonclass", tk.line)
            if v == "this":
                self.next()
                return self.name_load("self", tk.line)
            if v == "super":
                self.next()
                return self.name_load("super", tk.line)
            if v in ("true", "false"):
                self.next()
                return self.const(v == "true", tk.line)
            if v == "null":
                self.next()
                return self.const(None, tk.line)
            if v == "undefined":
                self.next()
                return self.const(None, tk.line)
            if v == "import":
                self.next()
                if self.is_p("("):
                    args = self.args()
                    return self.node(ast.Call, tk, func=self.name_load("__require__", tk.line), args=args, keywords=[])
                if self.is_p("."):
                    self.next()
                    self.next()
                    return self.unknown(tk.line)
            if v in ("async", "get", "set", "static", "of", "from", "as", "await", "yield", "default"):
                self.next()
                return self.name_load(v, tk.line)
            raise JSParseError(f"unexpected keyword {v!r} at line {tk.line}")
        if t == "p":
            if tk.v == "(":
                self.next()
                e = self.expression()
                self.expect_p(")")
                return e
            if tk.v == "[":
                self.next()
                elts: list = []
                while not self.is_p("]") and self.cur.t != "eof":
                    if self.is_p(","):
                        self.next()
                        elts.append(self.const(None, tk.line))
                        continue
                    if self.eat_p("..."):
                        elts.append(self.node(ast.Starred, tk, value=self.assignment(), ctx=ast.Load()))
                    else:
                        elts.append(self.assignment())
                    if not self.eat_p(","):
                        break
                self.expect_p("]")
                return self.node(ast.List, tk, elts=elts, ctx=ast.Load())
            if tk.v == "{":
                return self.object_literal()
            if tk.v == "<" and self.ts:
                # type assertion <T>expr
                self.skip_type_params()
                return self.unary()
        raise JSParseError(f"unexpected token {tk!r}")

    def object_literal(self):
        tk = self.next()          # {
        keys: list = []
        values: list = []
        while not self.is_p("}") and self.cur.t != "eof":
            if self.eat_p("..."):
                keys.append(None)
                values.append(self.assignment())
            else:
                is_async = False
                kind = "init"
                key_tok = self.cur
                if key_tok.t in ("kw", "id") and key_tok.v in ("async", "get", "set") and not (self.peek().t == "p" and self.peek().v in (",", ":", "(", "}")):
                    kind = key_tok.v
                    self.next()
                    key_tok = self.cur
                self.eat_p("*")
                if self.is_p("["):
                    self.next()
                    ke = self.assignment()
                    self.expect_p("]")
                    key_node = ke
                    kname = None
                else:
                    kt = self.next()
                    kname = str(kt.v) if kt.t != "num" else str(_num_value(kt.v))
                    key_node = self.const(kname, kt.line)
                if self.is_p("("):
                    names, prologue = self.params()
                    body = self.func_body()
                    self.fn_counter += 1
                    nm = f"__fn{self.fn_counter}"
                    fd = self.node(ast.FunctionDef, key_tok, name=nm, args=self.make_args(names, key_tok.line), body=prologue + body, decorator_list=[], returns=None, type_comment=None)
                    self.pending.append(fd)
                    keys.append(key_node)
                    values.append(self.name_load(nm, key_tok.line))
                elif self.eat_p(":"):
                    keys.append(key_node)
                    values.append(self.assignment())
                else:
                    keys.append(key_node)
                    values.append(self.name_load(kname or "__x", key_tok.line))
                    if self.eat_p("="):
                        self.assignment()
            if not self.eat_p(","):
                break
        self.expect_p("}")
        return self.node(ast.Dict, tk, keys=keys, values=values)


def normalize_module(name: str) -> str:
    n = name.strip()
    if n.startswith("node:"):
        n = n[5:]
    n = re.sub(r"/promises$", "", n)
    return n


def parse_js(src: str, ts: bool = False) -> tuple:
    """-> (ast.Module, comments)"""
    toks, comments = tokenize(src)
    p = Parser(toks, ts)
    tree = p.parse_program()
    ast.fix_missing_locations(tree)
    return tree, comments
