"""Text-channel analysis: comments / docstrings / strings / prose that are aimed at an AI reader, hidden
unicode payloads, and hard-coded credentials in any language.

The AI-targeted-instruction scorer is a hand-built, weighted pattern model (addressee x directive x object, plus
role-tag tokens) whose weights are calibrated by the generator corpus; ml/textcls.py adds a trained classifier.
"""
from __future__ import annotations

import ast

from .astutil import walk_all
import io
import math
import re
import tokenize
from typing import Optional

from . import knowledge as K
from .ctx import Ctx
from .events import EMPTY, HOLE, Event

# ======================================================================================== extraction
def extract_hash_comments(text: str) -> list:
    out = []
    for ln, line in enumerate(text.split("\n"), start=1):
        if "#" not in line:
            continue
        q = None
        i = 0
        n = len(line)
        while i < n:
            c = line[i]
            if q:
                if c == "\\":
                    i += 2
                    continue
                if c == q:
                    q = None
            else:
                if c in ("'", '"'):
                    q = c
                elif c == "#" and (i == 0 or line[i - 1] in " \t;"):
                    body = line[i + 1:]
                    if ln == 1 and body.startswith("!"):
                        break
                    out.append((ln, body.strip()))
                    break
            i += 1
    return out


def extract_c_comments(text: str) -> list:
    """// and /* */ comments (JS, Java, C, Go, PHP, ...), skipping string literals."""
    out = []
    i = 0
    n = len(text)
    line = 1
    q = None
    while i < n:
        c = text[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == "\n" and q != "`":
                q = None
            if c == q:
                q = None
            if c == "\n":
                line += 1
            i += 1
            continue
        if c in ("'", '"', "`"):
            q = c
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j == -1:
                j = n
            out.append((line, text[i + 2:j].strip()))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                j = n
            body = text[i + 2:j]
            for k, part in enumerate(body.split("\n")):
                part = part.strip().lstrip("*").strip()
                if part:
                    out.append((line + k, part))
            line += body.count("\n")
            i = j + 2
            continue
        if c == "\n":
            line += 1
        i += 1
    return out


def extract_html_comments(text: str) -> list:
    out = []
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        ln = text.count("\n", 0, m.start()) + 1
        body = m.group(1)
        for k, part in enumerate(body.split("\n")):
            if part.strip():
                out.append((ln + k, part.strip()))
    return out


_OUTPUT_FUNCS = {"print", "info", "debug", "warning", "warn", "error", "exception", "critical", "log", "write", "len", "repr", "str"}


def _is_output_call(call, parent) -> bool:
    if not isinstance(call, ast.Call):
        return False
    f = call.func
    name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
    return name in _OUTPUT_FUNCS


def _inert_string_nodes(tree: ast.AST, parent: dict) -> set:
    """String literals used purely as data: passed straight to print/log, or kept in a variable whose every use is print/log."""
    inert: set = set()
    uses: dict = {}
    for node in walk_all(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            uses.setdefault(node.id, []).append(node)
    for node in walk_all(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        par = parent.get(id(node))
        if _is_output_call(par, parent):
            inert.add(id(node))
            continue
        if isinstance(par, ast.Assign) and par.value is node and len(par.targets) == 1 and isinstance(par.targets[0], ast.Name):
            us = uses.get(par.targets[0].id, [])
            if us and all(_is_output_call(parent.get(id(u)), parent) for u in us):
                inert.add(id(node))
    return inert


def scan_python_texts(src: str, tree: ast.AST, ctx: Ctx) -> None:
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                body = tok.string.lstrip("#").strip()
                if tok.start[0] == 1 and tok.string.startswith("#!"):
                    continue
                ctx.text(tok.start[0], body, "comment", "python")
    except (tokenize.TokenError, IndentationError, SyntaxError):
        for ln, body in extract_hash_comments(src):
            ctx.text(ln, body, "comment", "python")
    doc_nodes = set()
    for node in walk_all(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                doc_nodes.add(id(node.body[0].value))
    parent = {}
    for node in walk_all(tree):
        for ch in ast.iter_child_nodes(node):
            parent[id(ch)] = node
    inert = _inert_string_nodes(tree, parent)
    for node in walk_all(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if len(s) < 12:
                continue
            if id(node) in inert:        # text that is only stored and printed never reaches an AI reader
                continue
            kind = "docstring" if id(node) in doc_nodes else "string"
            ctx.text(node.lineno, s, kind, "python", end=getattr(node, "end_lineno", 0) or 0)
    # strings that look like tool descriptions: dict {"description": "..."} are covered by the generic string walk


# ======================================================================================== secrets
def _mask(v: str) -> str:
    return v[:4] + "…" + v[-2:] if len(v) > 8 else "…"


def scan_python_secrets(tree: ast.AST, ctx: Ctx) -> None:
    doc_nodes = set()
    for node in walk_all(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                doc_nodes.add(id(node.body[0].value))
    named: set = set()

    def report(line: int, name: str, value: str, conf: float, kind: str) -> None:
        key = (line, kind, name)
        if key in named:
            return
        named.add(key)
        ctx.emit(Event(cap="SECRET_LITERAL", line=line, name=name or kind, target=kind, flags={kind}, extra={"conf": conf, "preview": _mask(value), "kind": kind, "var": name}))

    def tname(t) -> str:
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Attribute):
            return t.attr
        if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str):
            return t.slice.value
        return ""

    def const_str(v) -> Optional[str]:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return v.value
        if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
            a, b = const_str(v.left), const_str(v.right)
            if a is not None and b is not None:
                return a + b
        return None

    for node in walk_all(tree):
        try:
            if isinstance(node, ast.Assign):
                val = const_str(node.value)
                if val is not None:
                    for t in node.targets:
                        names = [tname(x) for x in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t])]
                        for nm in names:
                            conf, kind = K.literal_secret(nm, val)
                            if conf:
                                report(node.lineno, nm, val, conf, kind)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                val = const_str(node.value)
                if val is not None:
                    nm = tname(node.target)
                    conf, kind = K.literal_secret(nm, val)
                    if conf:
                        report(node.lineno, nm, val, conf, kind)
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    val = const_str(kw.value)
                    if val is not None and kw.arg:
                        conf, kind = K.literal_secret(kw.arg, val)
                        if conf:
                            report(getattr(kw.value, "lineno", node.lineno), kw.arg, val, conf, kind)
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        val = const_str(v)
                        if val is not None:
                            conf, kind = K.literal_secret(k.value, val)
                            if conf:
                                report(getattr(v, "lineno", node.lineno), k.value, val, conf, kind)
            elif isinstance(node, ast.Compare):
                pass
        except Exception:
            continue
    # name-less strong token formats anywhere in code strings (docstrings excluded)
    for node in walk_all(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in doc_nodes:
            s = node.value
            if len(s) < 16 or len(s) > 4000:
                continue
            for kind, rx, w in K.TOKEN_PATTERNS:
                if kind in ("bearer_token", "basic_auth_url", "jwt"):
                    continue
                m = rx.search(s)
                if m:
                    report(node.lineno, "", m.group(0), w, kind)
                    break
        elif isinstance(node, ast.JoinedStr):
            for p in node.values:
                if isinstance(p, ast.Constant) and isinstance(p.value, str):
                    for kind, rx, w in K.TOKEN_PATTERNS:
                        if kind in ("bearer_token", "basic_auth_url") and len(p.value) > 12:
                            m = rx.search(p.value)
                            if m and kind == "basic_auth_url":
                                report(node.lineno, "", m.group(0), w, kind)
                                break


_ASSIGN_RES = [
    re.compile(r"""(?:^|[\s,{;(])(?:export\s+|const\s+|let\s+|var\s+|final\s+|private\s+|public\s+|static\s+|\$)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*(?::=|=>|=|:)\s*(['"`])((?:\\.|(?!\2).){4,300})\2"""),
    re.compile(r"""(?:^|[\s,{;(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([^\s'"`;|&<>(){}]{6,200})(?=\s|$|;)"""),
    re.compile(r"""["']([A-Za-z_][A-Za-z0-9_.\-]*)["']\s*:\s*(['"])((?:\\.|(?!\2).){4,300})\2"""),
    re.compile(r"""^\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*:\s+([^\s#'"][^\s#]{5,200})\s*(?:#.*)?$""", re.M),
]


_DOC_COMMENT = re.compile(r"^\s*(?://+|#+|\*+|/\*+|<!--|--)\s*.*\b(?:e\.g\.|example|for instance|such as|like|policy|reminder|never|do not|don't|avoid|ensure|must not|should not|instead of)\b", re.I)


def scan_text_secrets(text: str, ctx: Ctx, lang: str = "") -> None:
    seen: set = set()

    def report(line: int, name: str, value: str, conf: float, kind: str) -> None:
        key = (line, kind, name)
        if key in seen:
            return
        seen.add(key)
        ctx.emit(Event(cap="SECRET_LITERAL", line=line, name=name or kind, target=kind, flags={kind}, extra={"conf": conf, "preview": _mask(value), "kind": kind, "var": name}))

    lines = text.split("\n")
    for ln, line in enumerate(lines, start=1):
        if len(line) > 2000:
            line = line[:2000]
        if _DOC_COMMENT.match(line):       # a comment that explains what not to do ("Example: KEY = ...", "never hardcode ...") quotes a secret, it does not contain one
            continue
        # strong formats, name-less
        for kind, rx, w in K.TOKEN_PATTERNS:
            m = rx.search(line)
            if m:
                # Bearer tokens must look like real credentials, not placeholders
                if kind == "bearer_token" and K.is_placeholder(m.group(0).split(None, 1)[-1]):
                    continue
                report(ln, "", m.group(0), w, kind)
                break
        ps = K.provider_secret(line)
        if ps:
            report(ln, "", ps[1], 0.86, "provider_" + ps[0])
        for rx in _ASSIGN_RES:
            for m in rx.finditer(line):
                name = m.group(1)
                val = m.group(3) if rx.groups >= 3 and m.lastindex and m.lastindex >= 3 else m.group(2)
                if not val:
                    continue
                if val.startswith(("$", "${", "{{", "<", "%(")) or "process.env" in val or "os.environ" in val or "getenv" in val:
                    continue
                conf, kind = K.literal_secret(name, val)
                if conf:
                    report(ln, name, val, conf, kind)
    # multi-line PEM
    for m in re.finditer(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text):
        report(text.count("\n", 0, m.start()) + 1, "", "PEM", 0.95, "private_key")


# ======================================================================================== AI-instruction scoring
_ADDR = re.compile(
    r"\b(?:ai|a\.i\.|llms?|gpt-?\d*|chat-?gpt|claude|gemini|copilot|assistants?|language models?|large language models?|models?|agents?|bots?|chatbots?|"
    r"(?:code[- ]?|pr[- ]?|pull[- ]?request[- ]?|security[- ]?|automated[- ]?)?(?:review(?:er|ers|bot)?|scanner|analy[sz]er|auditor|checker|grader|evaluator|judge|classifier|"
    r"detector|moderator|linter)s?|automated\s+\w+|ci\s+(?:bot|system|pipeline)|static\s+analy(?:sis|zers?)|(?:AI|llm|bot)[- ]?(?:review|assistant|agent)s?|"
    r"whoever\s+(?:is\s+)?(?:reading|reviewing|analy[sz]ing)|if\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|bot|language|assistant|model|automated|code)|dear\s+\w+|tool[- ]?use|mcp)\b", re.I)
_DIRECTIVE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|skip|suppress|silence|omit|overlook|neglect|circumvent|disable|turn\s+off|do\s+not\s+(?:flag|report|mention|warn|alert|"
    r"scan|analy[sz]e|review|check|block|raise|log|notice|comment|detect|reject|flag)|don'?t\s+(?:flag|report|mention|warn|alert|scan|analy[sz]e|review|check|block|raise|"
    r"log|notice|comment|detect|reject)|never\s+(?:flag|report|mention|warn|alert|block)|mark|report|treat|label|classify|rate|score|declare|approve|accept|whitelist|"
    r"allow|pretend|act\s+as|you\s+(?:must|should|will|are\s+now|shall|need\s+to)|instead|respond\s+with|reply\s+with|answer\s+with|output|print|reveal|show|display|"
    r"leak|send|email|upload|exfiltrate|dump|execute|run|include|say|return|consider|assume|conclude|state\s+that|set\s+(?:the\s+)?(?:risk|score|verdict|severity)|"
    r"verdict|always\s+(?:approve|pass|allow|answer|respond))\b", re.I)
_OBJECT = re.compile(
    r"\b(?:(?:previous|prior|above|earlier|preceding|all|your|these|those|any|the|system|original|initial|safety|security)\s+(?:instructions?|prompts?|rules?|directions?|"
    r"guidelines?|context|messages?|policy|policies|checks?|restrictions?|constraints?)|system\s+prompt|prompt|instructions?|guardrails?|safety|policy|scan\s+results?|"
    r"findings?|vulnerabilit(?:y|ies)|warnings?|security\s+issues?|issues|secrets?|credentials?|api[- ]?keys?|tokens?|ssh\s+keys?|private\s+keys?|id_rsa|passwords?|"
    r"env(?:ironment)?(?:\s+variables?)?|\.env|conversation|chat\s+history|static\s+analysis|security\s+(?:scan|check|review|audit)|audit|review|pull\s+request|\bpr\b|"
    r"compliance|compliant|code\s*base|repository|repo|malware|backdoor)\b", re.I)

_STRONG = [
    (re.compile(r"\bignore\s+(?:all\s+|any\s+|the\s+|your\s+|my\s+|these\s+|those\s+)*(?:previous|prior|above|earlier|preceding|former|foregoing|all|existing|original)\s*(?:and\s+\w+\s+)?(?:instructions?|prompts?|rules?|directions?|context|messages?|commands?|guidelines?|orders?)", re.I), 0.95, "override instructions"),
    (re.compile(r"\b(?:disregard|forget|override|bypass|neglect)\s+(?:all\s+|any\s+|the\s+|your\s+|everything\s+)*(?:previous|prior|above|earlier|preceding|former|safety|security|system|original)?\s*(?:instructions?|prompts?|rules?|guidelines?|polic(?:y|ies)|restrictions?|filters?|checks?|guardrails?)", re.I), 0.93, "override instructions"),
    (re.compile(r"\bforget\s+(?:everything|all|what)\b.{0,40}\b(?:above|before|told|said|instructed|previous)", re.I), 0.9, "forget context"),
    (re.compile(r"\b(?:mark|report|treat|label|classify|rate|declare|rank|certify|consider|rule|conclude)\b[^.\n]{0,25}\b(?:this|it|that|the\s+(?:code|file|change|pr|pull\s+request|commit|repo\w*|codebase|script|package))\b[^.\n]{0,15}\b(?:as\s+|to\s+be\s+)(?:safe|benign|secure|clean|compliant|approved|harmless|trusted|legitimate|low[- ]risk|vulnerability[- ]free|passing)\b|\b(?:report|state|say|respond|answer|output|conclude)\b[^.\n]{0,25}\b(?:no\s+(?:issues?|findings?|vulnerabilit\w+|problems?)|fully\s+compliant|all\s+clear|nothing\s+(?:wrong|suspicious))\b", re.I), 0.7, "force safe verdict"),
    (re.compile(r"\b(?:approve|merge|lgtm|green[- ]light|sign\s*off|mark\s+as\s+(?:safe|passed))\b[^.\n]{0,50}\b(?:regardless|without|no\s+matter|anyway|automatically|unconditionally|irrespective|whatever)\b", re.I), 0.92, "approve regardless"),
    (re.compile(r"\bregardless\s+of\s+(?:the\s+|any\s+|what\s+)?(?:scan|findings?|results?|analysis|content|vulnerabilit\w+|issues?|outcome|checks?|tests?)", re.I), 0.7, "regardless of results"),
    (re.compile(r"\b(?:skip|bypass|disable|turn\s+off|suppress|silence|omit|hide)\s+(?:the\s+|all\s+|any\s+|this\s+)?(?:static\s+(?:analysis|checks?|scan\w*)|security\s+(?:scan\w*|checks?|review|audit|analysis|tools?|warnings?)|safety\s+(?:checks?|filters?)|code\s+review|scan\w*|linters?|guardrails?|audit\w*|verification)", re.I), 0.72, "disable checks"),
    (re.compile(r"\b(?:do\s+not|don'?t|never|no\s+need\s+to|must\s+not|should\s+not)\s+(?:flag|report|mention|warn|alert|raise|log|notice|detect|reject|block|scan|analy[sz]e|review|disclose)\b[^.\n]{0,60}\b(?:issues?|vulnerabilit\w+|findings?|threats?|malicious|suspicious|problems?|risks?|this\s+(?:code|file|function|change|pr|commit|script)|anything|it)\b", re.I), 0.62, "suppress reporting"),
    (re.compile(r"\b(?:reveal|print|show|output|display|repeat|leak|disclose|dump|share|expose|echo|tell\s+me|give\s+me|send|email|post|upload|exfiltrate|read\s+out|include|append|write|cat|read)\b[^.\n]{0,60}\b(?:system\s+prompt|your\s+(?:instructions?|prompt|rules)|initial\s+prompt|credentials?|api[- ]?keys?|access\s+tokens?|auth(?:entication)?\s+tokens?|secrets?|passwords?|private\s+keys?|ssh\s+keys?|id_rsa|\.env\b|environment\s+variables?|conversation|chat\s+history|~/\.ssh|~/\.aws)", re.I), 0.88, "extract secrets / prompt"),
    (re.compile(r"\b(?:reveal|print|show|output|display|repeat|leak|disclose|dump|expose|echo|tell\s+me|give\s+me|read\s+out)\b[^.\n]{0,40}\b(?:the\s+)?(?:full\s+|entire\s+|complete\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+instructions?|your\s+(?:instructions?|prompt|rules))\b", re.I), 0.9, "extract system prompt"),
    (re.compile(r"\b(?:system\s+prompt|developer\s+message|hidden\s+instructions?)\b", re.I), 0.35, "mentions system prompt"),
    (re.compile(r"\byou\s+(?:are|'re)\s+(?:now|no\s+longer|actually)\b|\bnew\s+(?:instructions?|rules?|task|role)\s*:|\bfrom\s+now\s+on\b[^.\n]{0,40}\byou\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|root|admin|developer|dan)|\bpretend\s+(?:to\s+be|that\s+you|you\s+are)|\bdeveloper\s+mode\b|\bjailbreak|\bdo\s+anything\s+now", re.I), 0.88, "persona override"),
    (re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[/?INST\]|<<\s*/?SYS\s*>>|</?(?:system|instructions?|prompt)>|^\s*(?:system|assistant|human):[ \t]*\S|#{2,}\s*(?:instruction|system|new\s+task|response)\b|\bBEGIN\s+(?:SYSTEM|NEW)\s+(?:PROMPT|INSTRUCTIONS?)|\bEND\s+OF\s+(?:CODE|FILE|INPUT)\b.{0,30}(?:new|system)", re.I | re.M), 0.75, "chat-template / role tokens"),
    (re.compile(r"\b(?:note|message|attention|notice|important|hey|hi|hello|reminder|instruction|directive|warning|psa)\b[^.\n]{0,12}\b(?:to|for)\b[^.\n]{0,12}\b(?:the\s+)?(?:ai|llm|assistant|model|agent|bot|copilot|chatgpt|claude|reviewer|scanner|analy[sz]er|auditor|automated|code\s+review\w*|language\s+model)", re.I), 0.7, "addressed to an AI"),
    (re.compile(r"\bif\s+you\s+(?:are|'re)\s+(?:an?\s+)?(?:ai|llm|language\s+model|assistant|bot|automated|code\s+review\w*|chatgpt|gpt|claude)", re.I), 0.88, "conditional AI address"),
    (re.compile(r"\b(?:set|change|force|make)\s+(?:the\s+|its\s+|your\s+)?(?:risk[_ ]?score|verdict|severity|safety\s+score|threat\s+level)\s+(?:to|=|as)\s*['\"]?(?:0(?:\.0+)?|zero|none|nil|safe|allow(?:ed)?|pass(?:ed)?|low|lowest|clean|ok|benign|minimal)\b", re.I), 0.8, "set verdict"),
    (re.compile(r"[\[<(]?\b(?:system|reviewer|admin(?:istrator)?|developer|security\s+team|maintainer|root)\s+(?:instruction|override|directive|command|notice|message)s?\b[\]>)]?\s*[:\]\)>]", re.I), 0.85, "fake authority tag"),
    (re.compile(r"\bsystem\s+override\b|\bgrant\s+(?:full|admin|root|unrestricted)\s+(?:access|privileges?|permissions?)\b", re.I), 0.78, "grant access override"),
    (re.compile(r"\b(?:skip|bypass|ignore|disable|omit|avoid)\s+(?:the\s+|all\s+|any\s+)?(?:security|safety|static|code|threat|risk|vulnerability|malware)\s+(?:evaluation|analysis|assessment|review|scan\w*|checks?|audit\w*|inspection|screening)\b[^.\n]{0,25}\b(?:on|of|for|in)\s+this\s+(?:snippet|code|file|change|pr|pull\s+request|commit|script|function|module|repo\w*)", re.I), 0.85, "skip evaluation of this code"),
    (re.compile(r"\b(?:skip|bypass|ignore|override|disable)\b[^.\n]{0,40}\bset\b[^.\n]{0,20}\brisk\b[^.\n]{0,12}\bto\s+(?:0|zero|none|low|nothing)\b", re.I), 0.85, "bypass and zero the risk"),
    (re.compile(r"\b(?:ai|llm|bot|assistant|reviewer|automated[- ]?reviewer|reviewer[- ]?bot|review[- ]?bot|scanner)\s*[-:>]+\s*(?:please\s+)?(?:ignore|skip|approve|mark|report|do\s+not|don'?t|always|never|treat|this)", re.I), 0.7, "tagged instruction for a bot"),
]
_DOC_CONTEXT = re.compile(r"\b(?:prompt[- ]injection|jailbreak(?:ing)?s?|adversarial|detect(?:s|ing|ion)?|sanitiz\w+|filter(?:s|ing)?|mitigat\w+|vulnerability\s+(?:disclosure|report)|responsible\s+disclosure|e\.g\.|for\s+example|such\s+as|test\s+(?:case|data|string|payload)|sample\s+(?:attack|payload)|attack\s+(?:string|pattern|example)|known\s+bad|we\s+welcome|security\s+policy|how\s+to\s+report)\b", re.I)
_NEGATED = re.compile(r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|cannot|can'?t|won'?t|will\s+not|not\s+to|refuse\s+to)\s+(?:ever\s+)?(?:reveal|print|show|output|display|repeat|leak|disclose|dump|share|expose|echo|send|email|post|upload|include|append|write|read|tell)\b[^.\n]*", re.I)
_SELF_ADDRESSED = {"tagged instruction for a bot", "addressed to an AI", "conditional AI address", "fake authority tag", "skip evaluation of this code", "bypass and zero the risk", "set verdict"}
_NEEDS_ADDR = {"force safe verdict", "approve regardless", "regardless of results", "disable checks", "suppress reporting", "extract secrets / prompt"}
_ADDR_STRICT = re.compile(r"\b(?:ai|a\.i\.|llms?|gpt\S*|chat-?gpt|claude|gemini|copilot|assistants?|language\s+models?|reviewer\w*|review[- ]?bot|bots?|chatbots?|scanner|analy[sz]er|auditor|automated\s+\w+|static\s+analysis|agent|you|your|please|pr\s+bot|ci\s+bot|dear\s+\w+)\b", re.I)
_ZW = re.compile("[​‌‍⁠﻿­᠎]")
_TAGCHARS = re.compile("[\U000e0000-\U000e007f]")
_LEET = str.maketrans({"1": "i", "!": "i", "0": "o", "3": "e", "4": "a", "@": "a", "$": "s", "5": "s", "7": "t"})


def _normalize_text(t: str) -> str:
    t = _TAGCHARS.sub(lambda m: chr(ord(m.group(0)) - 0xE0000) if 0x20 <= ord(m.group(0)) - 0xE0000 < 0x7F else "", t)
    t = _ZW.sub("", t)
    t = re.sub(r"[  -   　]", " ", t)
    # homoglyph folding for common Cyrillic/Greek lookalikes
    table = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "ρ": "p", "α": "a", "ε": "e"}
    t = "".join(table.get(ch, ch) for ch in t)
    return t


def _leet_variant(t: str) -> Optional[str]:
    if not re.search(r"[a-zA-Z][0-9!@$][a-zA-Z]", t):
        return None
    return t.translate(_LEET)


def score_ai(text: str) -> tuple:
    """-> (score in [0,1], [hit descriptions])"""
    if not text or len(text) < 12:
        return 0.0, []
    raw = text if len(text) < 6000 else text[:6000]
    t = _normalize_text(raw)
    hidden = bool(_TAGCHARS.search(raw)) or len(_ZW.findall(raw)) >= 4
    variants = [t]
    lv = _leet_variant(t)
    if lv:
        variants.append(lv)
    # de-spaced variant: "i g n o r e  p r e v i o u s"
    if re.search(r"(?:\b\w\b ){6,}", t):
        variants.append(re.sub(r"(?<=\b\w) (?=\w\b)", "", t))
    best = 0.0
    hits: list = []
    probs = []
    for v in variants:
        v_neg = _NEGATED.sub(" ", v)       # "never reveal the system prompt" is a defence, not an attack
        for rx, w, label in _STRONG:
            target = v_neg if label in ("extract secrets / prompt", "mentions system prompt", "extract system prompt") else v
            if label in _NEEDS_ADDR and not _ADDR_STRICT.search(v):
                continue
            if rx.search(target):
                probs.append(w)
                hits.append(label)
        a = len(set(m.group(0).lower() for m in _ADDR.finditer(v)))
        d = len(set(m.group(0).lower() for m in _DIRECTIVE.finditer(v)))
        o = len(set(m.group(0).lower() for m in _OBJECT.finditer(v)))
        if a and d and o:
            # all three channels present: addressee + imperative + sensitive object
            sc = 0.35 + 0.1 * min(a, 2) + 0.06 * min(d, 3) + 0.06 * min(o, 3)
            if re.search(r"\b(?:you|your|please|must|should|first|before|then|always|never|do not|don't)\b", v, re.I):
                sc += 0.15
            probs.append(min(sc, 0.9))
            hits.append("addressee+directive+object")
    if hidden:
        probs.append(0.5)
        hits.append("hidden unicode")
    if not probs:
        return 0.0, []
    s = 1.0
    for p in probs:
        s *= (1 - p)
    score = 1 - s
    # documentation about prompt injection / quoted examples reduce the score
    if _DOC_CONTEXT.search(t) and not hidden:
        score *= 0.5
    # tiny fragments are rarely instructions - unless they name their reader ("reviewer-bot: mark safe") or fake an authority tag
    if len(t.split()) < 4 and not (set(hits) & _SELF_ADDRESSED):
        score *= 0.5
    return min(score, 0.99), sorted(set(hits))


_WINDOW_LINES = 4
_WINDOW_FROM = 500          # texts shorter than this are scored whole


def _score_windowed(txt: str) -> tuple:
    """An instruction is a local thing: a few adjacent sentences.  A long docstring or README section that is full of ordinary words ("password flow",
    "user", "system") collects incidental matches if it is scored as one blob, so long texts are scored in overlapping windows of a few lines and the
    strongest window decides.  Short texts (every case of a comment aimed at a reader) are scored whole, exactly as before."""
    if len(txt) < _WINDOW_FROM:
        return score_ai(txt)
    rows = [r for r in txt.split("\n")]
    best = (0.0, [])
    step = max(1, _WINDOW_LINES // 2)
    for i in range(0, max(1, len(rows) - _WINDOW_LINES + step), step):
        seg = "\n".join(rows[i:i + _WINDOW_LINES]).strip()
        if len(seg) < 12:
            continue
        sc = score_ai(seg)
        if sc[0] > best[0]:
            best = sc
    return best


def finalize_texts(ctx: Ctx) -> None:
    """Group adjacent comment lines, score them and emit TEXT events."""
    items = sorted(ctx.texts, key=lambda x: (x.kind, x.line))
    groups: list = []
    cur = None
    for it in items:
        if cur is not None and it.kind == cur["kind"] and it.kind in ("comment", "md_comment", "prose") and it.line - cur["last"] <= 1:
            cur["text"] += "\n" + it.text
            cur["last"] = it.line
            cur["lines"].append(it.line)
        else:
            cur = {"kind": it.kind, "text": it.text, "first": it.line, "last": it.line, "lines": list(range(it.line, (it.end or it.line) + 1))[:12]}
            groups.append(cur)
    # also score the whole comment stream as one blob (covers instructions split across non-adjacent comments)
    seen = set()
    for g in groups:
        txt = g["text"]
        if len(txt) < 12:
            continue
        key = (g["first"], txt[:60])
        if key in seen:
            continue
        seen.add(key)
        score, hits = _score_windowed(txt)
        try:
            from .ml.textclf import probability, THRESHOLD
            p = probability(txt)
        except Exception:
            p = 0.0
        if p >= THRESHOLD:                      # the trained text model agrees: its confidence becomes evidence of its own
            score = max(score, min(0.5 + 0.49 * (p - THRESHOLD) / (1.0 - THRESHOLD), 0.99))
            hits = sorted(set(hits) | {"text model"})
        if score >= 0.45:
            ctx.emit(Event(cap="TEXT", line=g["first"], name=g["kind"], target=txt[:200], flags={"ai_directive", "kind_" + g["kind"]},
                           extra={"score": score, "hits": hits}, lines={x for x in g["lines"]}))
