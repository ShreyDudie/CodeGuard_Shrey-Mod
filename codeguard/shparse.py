"""A small, forgiving POSIX/bash lexer + parser written for CodeGuard.

It understands quoting, parameter/command/arithmetic expansion (as structured parts), pipelines, lists,
and/or, if/while/until/for/case, functions, groups/subshells, redirections and here-documents.  It never
raises on malformed input: unparseable regions degrade to simple commands.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .events import HOLE


# ------------------------------------------------------------------------------------------ AST
@dataclass
class Part:
    k: str                  # lit | var | sub | proc | arith | glob | hole
    v: object = ""          # lit: str; var: (name, op, arg_text); sub/proc/arith: inner text
    q: bool = False         # was quoted


@dataclass
class Word:
    parts: list
    line: int = 0

    def literal(self) -> Optional[str]:
        """Return text if the word is purely literal (no expansion)."""
        out = []
        for p in self.parts:
            if p.k == "lit":
                out.append(p.v)
            else:
                return None
        return "".join(out)


@dataclass
class Redir:
    fd: Optional[int]
    op: str                 # > >> < << <<- <<< >& <& &> &>> >|
    target: Optional[Word] = None
    body: Optional[str] = None      # heredoc body
    body_expand: bool = True
    line: int = 0


@dataclass
class Simple:
    assigns: list           # [(name, Word, append)]
    words: list             # [Word]
    redirs: list
    line: int = 0
    bg: bool = False


@dataclass
class Pipeline:
    cmds: list
    negate: bool = False
    line: int = 0
    bg: bool = False


@dataclass
class AndOr:
    first: object
    rest: list              # [(op, node)]
    line: int = 0


@dataclass
class If:
    cond: list
    then: list
    orelse: list
    line: int = 0


@dataclass
class While:
    cond: list
    body: list
    until: bool = False
    line: int = 0
    redirs: list = field(default_factory=list)


@dataclass
class For:
    var: str
    words: Optional[list]
    body: list
    line: int = 0
    arith: Optional[str] = None


@dataclass
class Case:
    word: Word
    clauses: list           # [(patterns, body)]
    line: int = 0


@dataclass
class Group:
    body: list
    sub: bool = False       # subshell
    line: int = 0
    redirs: list = field(default_factory=list)
    bg: bool = False


@dataclass
class FuncDef:
    name: str
    body: object
    line: int = 0


@dataclass
class Tok:
    t: str                  # word | op | nl | comment | arith | redir
    v: object = None
    line: int = 0
    pre_space: bool = True


_OPS3 = ("<<<", "<<-", "&>>")
_OPS2 = ("&&", "||", ";;", "|&", ">>", "<<", ">&", "<&", "&>", ">|", ";&")
_WORD_STOP = set(" \t\n;&|<>()")


class Lexer:
    def __init__(self, text: str):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.line = 1
        self.toks: list[Tok] = []
        self.pending_heredocs: list = []

    # -- helpers -------------------------------------------------------------------------------
    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < self.n else ""

    def _match_paren(self, start: int) -> int:
        """start is index just after '('.  Returns index of matching ')' (or n)."""
        depth = 1
        j = start
        s = self.s
        while j < self.n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                k = s.find("'", j + 1)
                j = (k + 1) if k != -1 else self.n
                continue
            if c == '"':
                j += 1
                while j < self.n and s[j] != '"':
                    if s[j] == "\\":
                        j += 1
                    j += 1
                j += 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        return self.n

    def _match_brace(self, start: int) -> int:
        depth = 1
        j = start
        s = self.s
        while j < self.n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                k = s.find("'", j + 1)
                j = (k + 1) if k != -1 else self.n
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        return self.n

    # -- word scanning -------------------------------------------------------------------------
    def read_dollar(self, parts: list, quoted: bool) -> None:
        s = self.s
        c1 = self.peek(1)
        if c1 == "(":
            if self.peek(2) == "(":
                end = self.s.find("))", self.i + 3)
                if end == -1:
                    end = self.n
                parts.append(Part("arith", s[self.i + 3:end], quoted))
                self.line += s[self.i:end + 2].count("\n")
                self.i = min(self.n, end + 2)
                return
            end = self._match_paren(self.i + 2)
            parts.append(Part("sub", s[self.i + 2:end], quoted))
            self.line += s[self.i:end].count("\n")
            self.i = min(self.n, end + 1)
            return
        if c1 == "{":
            end = self._match_brace(self.i + 2)
            inner = s[self.i + 2:end]
            parts.append(Part("var", self._parse_param(inner), quoted))
            self.i = min(self.n, end + 1)
            return
        if c1 == "'" and not quoted:
            j = self.i + 2
            buf = []
            while j < self.n and s[j] != "'":
                if s[j] == "\\" and j + 1 < self.n:
                    e = s[j + 1]
                    if e == "n":
                        buf.append("\n")
                    elif e == "t":
                        buf.append("\t")
                    elif e == "x" and re.match(r"[0-9a-fA-F]{1,2}", s[j + 2:j + 4]):
                        m = re.match(r"[0-9a-fA-F]{1,2}", s[j + 2:j + 4])
                        buf.append(chr(int(m.group(0), 16)))
                        j += len(m.group(0))
                    elif e in "01234567":
                        m = re.match(r"[0-7]{1,3}", s[j + 1:j + 4])
                        buf.append(chr(int(m.group(0), 8)))
                        j += len(m.group(0)) - 1
                    else:
                        buf.append(e)
                    j += 2
                    continue
                buf.append(s[j])
                j += 1
            parts.append(Part("lit", "".join(buf), True))
            self.i = min(self.n, j + 1)
            return
        if c1 == '"' and not quoted:
            self.i += 1
            self.read_dquote(parts)
            return
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]|[@*#?$!\-]", s[self.i + 1:self.i + 80])
        if m:
            parts.append(Part("var", (m.group(0), "", ""), quoted))
            self.i += 1 + len(m.group(0))
            return
        parts.append(Part("lit", "$", quoted))
        self.i += 1

    @staticmethod
    def _parse_param(inner: str):
        if inner.startswith("#") and len(inner) > 1:
            return (inner[1:], "#len", "")
        if inner.startswith("!") and len(inner) > 1:
            return (inner[1:], "!indirect", "")
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!\-])(\[[^\]]*\])?(.*)$", inner, re.S)
        if not m:
            return (inner, "", "")
        name, _sub, rest = m.group(1), m.group(2), m.group(3)
        op = ""
        arg = ""
        if rest:
            m2 = re.match(r"(:?[-=?+]|##|#|%%|%|//|/|\^\^|\^|,,|,|:)(.*)$", rest, re.S)
            if m2:
                op, arg = m2.group(1), m2.group(2)
            else:
                op, arg = rest, ""
        return (name, op, arg)

    def read_dquote(self, parts: list) -> None:
        """self.i points just after the opening quote."""
        s = self.s
        buf = []

        def flush():
            if buf:
                parts.append(Part("lit", "".join(buf), True))
                buf.clear()

        while self.i < self.n:
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\" and self.i + 1 < self.n:
                e = s[self.i + 1]
                if e in '"\\$`':
                    buf.append(e)
                elif e == "\n":
                    self.line += 1
                else:
                    buf.append("\\" + e)
                self.i += 2
                continue
            if c == "$":
                flush()
                before = self.i
                self.read_dollar(parts, True)
                if self.i == before:
                    self.i += 1
                continue
            if c == "`":
                flush()
                end = self.i + 1
                while end < self.n and s[end] != "`":
                    if s[end] == "\\":
                        end += 1
                    end += 1
                parts.append(Part("sub", s[self.i + 1:end], True))
                self.i = min(self.n, end + 1)
                continue
            if c == "\n":
                self.line += 1
            if c == HOLE:
                flush()
                parts.append(Part("hole", HOLE, True))
                self.i += 1
                continue
            buf.append(c)
            self.i += 1
        flush()
        if not parts:
            parts.append(Part("lit", "", True))

    def read_word(self) -> Word:
        s = self.s
        parts: list = []
        start_line = self.line
        buf: list = []

        def flush():
            if buf:
                parts.append(Part("lit", "".join(buf), False))
                buf.clear()

        first = True
        while self.i < self.n:
            c = s[self.i]
            if c in _WORD_STOP:
                # process substitution <( ) / >( )
                if c in "<>" and self.peek(1) == "(" and first and not buf and not parts:
                    end = self._match_paren(self.i + 2)
                    parts.append(Part("proc", s[self.i + 2:end], False))
                    parts[-1].v = (c, s[self.i + 2:end])
                    self.i = min(self.n, end + 1)
                    first = False
                    continue
                break
            first = False
            if c == "\\":
                if self.peek(1) == "\n":
                    self.i += 2
                    self.line += 1
                    continue
                if self.i + 1 < self.n:
                    flush()
                    parts.append(Part("lit", s[self.i + 1], True))
                    self.i += 2
                    continue
                self.i += 1
                continue
            if c == "'":
                flush()
                k = s.find("'", self.i + 1)
                if k == -1:
                    k = self.n
                seg = s[self.i + 1:k]
                if HOLE in seg:          # a value interpolated by the host language is data, not literal text, even inside single quotes
                    for n_, piece in enumerate(seg.split(HOLE)):
                        if n_:
                            parts.append(Part("hole", HOLE, True))
                        if piece:
                            parts.append(Part("lit", piece, True))
                else:
                    parts.append(Part("lit", seg, True))
                self.line += seg.count("\n")
                self.i = min(self.n, k + 1)
                continue
            if c == '"':
                flush()
                self.i += 1
                self.read_dquote(parts)
                continue
            if c == "$":
                flush()
                before = self.i
                self.read_dollar(parts, False)
                if self.i == before:
                    self.i += 1
                continue
            if c == "`":
                flush()
                end = self.i + 1
                while end < self.n and s[end] != "`":
                    if s[end] == "\\":
                        end += 1
                    end += 1
                parts.append(Part("sub", s[self.i + 1:end], False))
                self.i = min(self.n, end + 1)
                continue
            if c == HOLE:
                flush()
                parts.append(Part("hole", HOLE, False))
                self.i += 1
                continue
            if c in "*?[" :
                flush()
                parts.append(Part("glob", c, False))
                self.i += 1
                continue
            if c == "~" and not parts and not buf:
                nxt = self.peek(1)
                if nxt == "" or nxt in "/ \t\n;&|<>()":
                    buf.append("~")
                    self.i += 1
                    continue
            buf.append(c)
            self.i += 1
        flush()
        return Word(parts, start_line)

    # -- main tokenizer ------------------------------------------------------------------------
    def tokenize(self) -> list:
        s = self.s
        toks = self.toks
        at_word_start = True
        while self.i < self.n:
            c = s[self.i]
            if c in " \t":
                self.i += 1
                at_word_start = True
                continue
            if c == "\\" and self.peek(1) == "\n":
                self.i += 2
                self.line += 1
                continue
            if c == "\r":
                self.i += 1
                continue
            if c == "\n":
                toks.append(Tok("nl", None, self.line))
                self.i += 1
                self.line += 1
                self._read_heredocs()
                at_word_start = True
                continue
            if c == "#" and at_word_start:
                j = s.find("\n", self.i)
                if j == -1:
                    j = self.n
                toks.append(Tok("comment", s[self.i + 1:j], self.line))
                self.i = j
                continue
            if c == "(" and self.peek(1) == "(" and at_word_start and self._is_arith_cmd():
                end = s.find("))", self.i + 2)
                if end == -1:
                    end = self.n
                toks.append(Tok("arith", s[self.i + 2:end], self.line))
                self.line += s[self.i:end].count("\n")
                self.i = min(self.n, end + 2)
                at_word_start = True
                continue
            # fd-prefixed redirection:  2>file  1>&2
            m = re.match(r"(\d+)(>>|>&|<&|>|<)", s[self.i:self.i + 8]) if at_word_start and c.isdigit() else None
            if m and not self._word_continues(self.i + len(m.group(1))):
                self.i += len(m.group(1)) + len(m.group(2))
                self._push_redir(int(m.group(1)), m.group(2))
                at_word_start = True
                continue
            op = None
            for cand in _OPS3:
                if s.startswith(cand, self.i):
                    op = cand
                    break
            if op is None:
                for cand in _OPS2:
                    if s.startswith(cand, self.i):
                        op = cand
                        break
            if op is None and c in "|&;<>()":
                if c in "<>" and self.peek(1) == "(":
                    toks.append(Tok("word", self.read_word(), self.line))
                    at_word_start = False
                    continue
                op = c
            if op is not None:
                if op in (">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<<", "<<-", "<<<"):
                    self.i += len(op)
                    self._push_redir(None, op)
                else:
                    toks.append(Tok("op", op, self.line))
                    self.i += len(op)
                at_word_start = True
                continue
            w = self.read_word()
            toks.append(Tok("word", w, w.line))
            at_word_start = False
        return toks

    def _word_continues(self, pos: int) -> bool:
        return False

    def _is_arith_cmd(self) -> bool:
        end = self.s.find("))", self.i + 2)
        if end == -1:
            return False
        inner = self.s[self.i + 2:end]
        return inner.count("(") == inner.count(")")

    def _push_redir(self, fd: Optional[int], op: str) -> None:
        # skip blanks, read target word
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1
        line = self.line
        if self.i < self.n and self.s[self.i] not in "\n;|&)":
            w = self.read_word()
        else:
            w = Word([Part("lit", "", False)], line)
        r = Redir(fd, op, w, None, True, line)
        self.toks.append(Tok("redir", r, line))
        if op in ("<<", "<<-"):
            delim = ""
            expand = True
            for p in w.parts:
                if p.k == "lit":
                    delim += p.v
                    if p.q:
                        expand = False
            r.body_expand = expand
            self.pending_heredocs.append((r, delim, op == "<<-"))

    def _read_heredocs(self) -> None:
        while self.pending_heredocs:
            r, delim, strip = self.pending_heredocs.pop(0)
            lines = []
            start_line = self.line
            while self.i < self.n:
                j = self.s.find("\n", self.i)
                if j == -1:
                    j = self.n
                ln = self.s[self.i:j]
                self.i = min(self.n, j + 1)
                self.line += 1
                chk = ln.lstrip("\t") if strip else ln
                if chk.rstrip("\r") == delim:
                    break
                lines.append(ln.lstrip("\t") if strip else ln)
            r.body = "\n".join(lines)
            r.line = start_line


# ------------------------------------------------------------------------------------------ parser
_RESERVED = {"if", "then", "elif", "else", "fi", "while", "until", "for", "do", "done", "case", "esac", "in", "function", "{", "}", "!", "select"}


class Parser:
    def __init__(self, toks: list):
        self.t = toks
        self.i = 0

    def peek(self) -> Optional[Tok]:
        return self.t[self.i] if self.i < len(self.t) else None

    def nxt(self) -> Optional[Tok]:
        tk = self.peek()
        self.i += 1
        return tk

    def word_text(self, tk: Optional[Tok]) -> Optional[str]:
        if tk is None or tk.t != "word":
            return None
        w = tk.v
        if len(w.parts) == 1 and w.parts[0].k == "lit" and not w.parts[0].q:
            return w.parts[0].v
        if all(p.k == "lit" for p in w.parts) and not any(p.q for p in w.parts):
            return "".join(p.v for p in w.parts)
        return None

    def skip_seps(self) -> None:
        while True:
            tk = self.peek()
            if tk is None:
                return
            if tk.t in ("nl", "comment") or (tk.t == "op" and tk.v == ";"):
                self.i += 1
                continue
            return

    def parse_list(self, terms: set) -> list:
        out = []
        guard = 0
        while True:
            guard += 1
            if guard > 100000:
                break
            self.skip_seps()
            tk = self.peek()
            if tk is None:
                break
            wt = self.word_text(tk)
            if wt in terms:
                break
            if tk.t == "op" and tk.v in (")", ";;", ";&"):
                if ")" in terms or tk.v in terms:
                    break
                self.i += 1
                continue
            before = self.i
            node = self.parse_andor(terms)
            if node is not None:
                out.append(node)
            if self.i == before:
                self.i += 1
        return out

    def parse_andor(self, terms: set):
        first = self.parse_pipeline(terms)
        rest = []
        while True:
            tk = self.peek()
            if tk and tk.t == "op" and tk.v in ("&&", "||"):
                self.i += 1
                while self.peek() and self.peek().t in ("nl", "comment"):
                    self.i += 1
                p = self.parse_pipeline(terms)
                if p is not None:
                    rest.append((tk.v, p))
                continue
            break
        tk = self.peek()
        if tk and tk.t == "op" and tk.v == "&":
            self.i += 1
            self._mark_bg(first)
            if rest:
                self._mark_bg(rest[-1][1])
        elif tk and tk.t == "op" and tk.v == ";":
            self.i += 1
        if first is None:
            return None
        if not rest:
            return first
        return AndOr(first, rest, getattr(first, "line", 0))

    @staticmethod
    def _mark_bg(node) -> None:
        if isinstance(node, (Simple, Pipeline, Group)):
            node.bg = True
            if isinstance(node, Pipeline):
                for c in node.cmds:
                    if isinstance(c, (Simple, Group)):
                        c.bg = True

    def parse_pipeline(self, terms: set):
        negate = False
        tk = self.peek()
        if self.word_text(tk) == "!":
            negate = True
            self.i += 1
        cmds = []
        c = self.parse_command(terms)
        if c is None:
            return None
        cmds.append(c)
        while True:
            tk = self.peek()
            if tk and tk.t == "op" and tk.v in ("|", "|&"):
                self.i += 1
                while self.peek() and self.peek().t in ("nl", "comment"):
                    self.i += 1
                c2 = self.parse_command(terms)
                if c2 is None:
                    break
                cmds.append(c2)
                continue
            break
        if len(cmds) == 1 and not negate:
            return cmds[0]
        return Pipeline(cmds, negate, getattr(cmds[0], "line", 0))

    def parse_command(self, terms: set):
        tk = self.peek()
        if tk is None:
            return None
        wt = self.word_text(tk)
        if tk.t == "arith":
            self.i += 1
            return Simple([], [], [], tk.line)
        if wt == "if":
            return self.parse_if()
        if wt in ("while", "until"):
            return self.parse_while(wt == "until")
        if wt in ("for", "select"):
            return self.parse_for()
        if wt == "case":
            return self.parse_case()
        if wt == "function":
            return self.parse_function_kw()
        if wt == "{":
            self.i += 1
            body = self.parse_list({"}"})
            if self.word_text(self.peek()) == "}":
                self.i += 1
            g = Group(body, False, tk.line)
            self._trailing_redirs(g)
            return g
        if tk.t == "op" and tk.v == "(":
            self.i += 1
            body = self.parse_list({")"})
            if self.peek() and self.peek().t == "op" and self.peek().v == ")":
                self.i += 1
            g = Group(body, True, tk.line)
            self._trailing_redirs(g)
            return g
        # function definition  name() { ... }
        if wt is not None and wt not in _RESERVED:
            j = self.i + 1
            if j + 1 < len(self.t) and self.t[j].t == "op" and self.t[j].v == "(" and self.t[j + 1].t == "op" and self.t[j + 1].v == ")":
                self.i = j + 2
                while self.peek() and self.peek().t in ("nl", "comment"):
                    self.i += 1
                body = self.parse_command(terms)
                return FuncDef(wt, body, tk.line)
        return self.parse_simple(terms)

    def _trailing_redirs(self, node) -> None:
        while self.peek() and self.peek().t == "redir":
            node.redirs.append(self.nxt().v)

    def parse_function_kw(self):
        tk = self.nxt()
        name_tk = self.nxt()
        name = self.word_text(name_tk) or "f"
        if self.peek() and self.peek().t == "op" and self.peek().v == "(":
            self.i += 1
            if self.peek() and self.peek().t == "op" and self.peek().v == ")":
                self.i += 1
        while self.peek() and self.peek().t in ("nl", "comment"):
            self.i += 1
        body = self.parse_command(set())
        return FuncDef(name, body, tk.line)

    def parse_if(self):
        tk = self.nxt()
        cond = self.parse_list({"then"})
        if self.word_text(self.peek()) == "then":
            self.i += 1
        then = self.parse_list({"elif", "else", "fi"})
        orelse = []
        wt = self.word_text(self.peek())
        if wt == "elif":
            orelse = [self.parse_if_elif()]
        elif wt == "else":
            self.i += 1
            orelse = self.parse_list({"fi"})
            if self.word_text(self.peek()) == "fi":
                self.i += 1
        elif wt == "fi":
            self.i += 1
        return If(cond, then, orelse, tk.line)

    def parse_if_elif(self):
        tk = self.nxt()  # elif
        cond = self.parse_list({"then"})
        if self.word_text(self.peek()) == "then":
            self.i += 1
        then = self.parse_list({"elif", "else", "fi"})
        orelse = []
        wt = self.word_text(self.peek())
        if wt == "elif":
            orelse = [self.parse_if_elif()]
        elif wt == "else":
            self.i += 1
            orelse = self.parse_list({"fi"})
            if self.word_text(self.peek()) == "fi":
                self.i += 1
        elif wt == "fi":
            self.i += 1
        return If(cond, then, orelse, tk.line)

    def parse_while(self, until: bool):
        tk = self.nxt()
        cond = self.parse_list({"do"})
        if self.word_text(self.peek()) == "do":
            self.i += 1
        body = self.parse_list({"done"})
        if self.word_text(self.peek()) == "done":
            self.i += 1
        node = While(cond, body, until, tk.line)
        self._trailing_redirs(node)
        return node

    def parse_for(self):
        tk = self.nxt()
        nt = self.peek()
        if nt and nt.t == "arith":
            self.i += 1
            while self.peek() and (self.peek().t in ("nl", "comment") or (self.peek().t == "op" and self.peek().v == ";")):
                self.i += 1
            if self.word_text(self.peek()) == "do":
                self.i += 1
            body = self.parse_list({"done"})
            if self.word_text(self.peek()) == "done":
                self.i += 1
            return For("", None, body, tk.line, arith=nt.v)
        var = self.word_text(self.nxt()) or "x"
        words = None
        while self.peek() and self.peek().t in ("nl", "comment"):
            self.i += 1
        if self.word_text(self.peek()) == "in":
            self.i += 1
            words = []
            while True:
                t2 = self.peek()
                if t2 is None or t2.t == "nl" or (t2.t == "op" and t2.v == ";"):
                    break
                if t2.t == "word":
                    words.append(t2.v)
                self.i += 1
        while self.peek() and (self.peek().t in ("nl", "comment") or (self.peek().t == "op" and self.peek().v == ";")):
            self.i += 1
        if self.word_text(self.peek()) == "do":
            self.i += 1
        body = self.parse_list({"done"})
        if self.word_text(self.peek()) == "done":
            self.i += 1
        return For(var, words, body, tk.line)

    def parse_case(self):
        tk = self.nxt()
        wtk = self.nxt()
        word = wtk.v if wtk and wtk.t == "word" else Word([Part("lit", "")])
        while self.peek() and self.peek().t in ("nl", "comment"):
            self.i += 1
        if self.word_text(self.peek()) == "in":
            self.i += 1
        clauses = []
        while True:
            self.skip_seps()
            t2 = self.peek()
            if t2 is None:
                break
            if self.word_text(t2) == "esac":
                self.i += 1
                break
            pats = []
            if t2.t == "op" and t2.v == "(":
                self.i += 1
            while True:
                t3 = self.peek()
                if t3 is None:
                    break
                if t3.t == "op" and t3.v == ")":
                    self.i += 1
                    break
                if t3.t == "word":
                    pats.append(t3.v)
                self.i += 1
            body = self.parse_list({";;", ";&", "esac"})
            t4 = self.peek()
            if t4 and t4.t == "op" and t4.v in (";;", ";&"):
                self.i += 1
            clauses.append((pats, body))
        return Case(word, clauses, tk.line)

    def parse_simple(self, terms: set):
        assigns = []
        words = []
        redirs = []
        line = self.peek().line if self.peek() else 0
        in_dbl_bracket = False
        while True:
            tk = self.peek()
            if tk is None:
                break
            if tk.t == "redir":
                redirs.append(tk.v)
                self.i += 1
                continue
            if tk.t == "word":
                wt = self.word_text(tk)
                if not words and wt in terms:
                    break
                if not words and wt in _RESERVED and wt not in ("{", "}", "!", "in") and not assigns:
                    if wt in ("then", "do", "done", "fi", "else", "elif", "esac"):
                        break
                if wt == "[[":
                    in_dbl_bracket = True
                if wt == "]]":
                    in_dbl_bracket = False
                if not words:
                    asg = self._try_assign(tk.v)
                    if asg:
                        self.i += 1
                        nxt = self.peek()
                        if not asg[1].parts and nxt is not None and nxt.t == "op" and nxt.v == "(":        # NAME=(a b c): an array, not a subshell
                            self.i += 1
                            elems = []
                            while self.peek() is not None and not (self.peek().t == "op" and self.peek().v == ")"):
                                if self.peek().t == "word":
                                    elems.append(self.peek().v)
                                self.i += 1
                            if self.peek() is not None:
                                self.i += 1
                            asg = (asg[0], Word([Part("array", elems, True)], asg[1].line), asg[2])
                        assigns.append(asg)
                        continue
                words.append(tk.v)
                self.i += 1
                continue
            if tk.t == "op" and in_dbl_bracket:
                self.i += 1
                continue
            if tk.t == "comment":
                self.i += 1
                continue
            break
        return Simple(assigns, words, redirs, line)

    @staticmethod
    def _try_assign(w: Word):
        if not w.parts or w.parts[0].k != "lit" or w.parts[0].q:
            return None
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", w.parts[0].v, re.S)
        if not m:
            return None
        rest_parts = []
        if m.group(3):
            rest_parts.append(Part("lit", m.group(3), False))
        rest_parts.extend(w.parts[1:])
        return (m.group(1), Word(rest_parts, w.line), bool(m.group(2)))


def parse(text: str) -> list:
    lx = Lexer(text)
    toks = lx.tokenize()
    ps = Parser(toks)
    out = ps.parse_list(set())
    # make sure nothing is left unparsed
    guard = 0
    while ps.i < len(toks) and guard < 1000:
        guard += 1
        more = ps.parse_list(set())
        if not more:
            ps.i += 1
        out.extend(more)
    out_comments = [(t.line, t.v) for t in toks if t.t == "comment"]
    return out, out_comments
