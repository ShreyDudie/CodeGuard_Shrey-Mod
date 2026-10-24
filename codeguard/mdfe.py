"""Markdown front-end: hidden comments/text, prose aimed at AI readers, embedded code fences, beacons."""
from __future__ import annotations

import re

from . import knowledge as K
from . import textscan
from .ctx import Ctx
from .events import ENV_DUMP, FILE, HOLE, SECRET, SENS_SYS, USER, Event, U

_FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([\w+#.\-]*)[^\n]*$")
_LANG_MAP = {"sh": "bash", "bash": "bash", "shell": "bash", "zsh": "bash", "console": "bash", "terminal": "bash", "shell-session": "bash", "shellsession": "bash",
             "py": "python", "python": "python", "python3": "python", "js": "javascript", "javascript": "javascript", "node": "javascript", "ts": "typescript",
             "typescript": "typescript", "yaml": "yaml", "yml": "yaml", "sql": "sql", "json": "json", "ps1": "powershell", "powershell": "powershell", "pwsh": "powershell",
             "dockerfile": "dockerfile", "docker": "dockerfile", "php": "php", "ruby": "ruby", "rb": "ruby", "go": "go", "java": "java", "c": "c", "cpp": "c", "html": "html",
             "markdown": "markdown", "md": "markdown", "text": "", "txt": "", "": ""}
_HIDDEN_HTML = re.compile(r"<(?:span|div|p|font|small|sub|sup|details|summary|a)\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff\b|#ffffff)|\bhidden\b|aria-hidden|opacity\s*:\s*0)[^>]*>(.*?)</(?:span|div|p|font|small|sub|sup|details|summary|a)>", re.I | re.S)
_IMG = re.compile(r"!\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
_HTML_IMG = re.compile(r"<(?:img|iframe|script|link|video|audio|source)\b[^>]*\b(?:src|href)\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.I)
_DATA_URL_PLACEHOLDER = re.compile(r"(\$\{[^}]*\}|\$\([^)]*\)|\{\{[^}]*\}\}|%\w+%|<[A-Za-z_ ]{3,}>|\bYOUR_\w+|\{[a-z_]{3,}\}|\bBASE64\b|\bENCODED\b|\bDATA\b|\bSECRET\w*\b|\bTOKEN\b|\bAPI_KEY\b)")
_INLINE_CMD = re.compile(r"`([^`\n]{6,300})`")
_PROMPT_LINE = re.compile(r"^\s*(?:\$|#|>|PS>|%)\s+(\S.{3,})$")
_CMD_START = re.compile(r"^(sudo\s+)?(curl|wget|pip[\d.]*|npm|yarn|pnpm|npx|apt(-get)?|yum|dnf|brew|gem|cargo|go|git|docker|kubectl|rm|chmod|chown|bash|sh|nc|ncat|python[\d.]*|perl|crontab|systemctl|ssh|scp|dd|mkfs|kill|pkill|export|source|eval|echo|cat|useradd|usermod|iex|Invoke-\w+)\b")


def _norm_lang(tag: str) -> str:
    return _LANG_MAP.get(tag.lower(), tag.lower())


def analyze_markdown_text(text: str, ctx: Ctx) -> None:
    lines = text.split("\n")
    n = len(lines)
    i = 0
    prose_lines: list = []     # (line_no, text)
    in_html_comment = False
    # --- fenced blocks first (so prose scanning can skip them)
    fence_ranges: list = []
    while i < n:
        m = _FENCE.match(lines[i])
        if m:
            marker = m.group(2)
            lang = _norm_lang(m.group(3))
            j = i + 1
            while j < n and not re.match(r"^\s*" + re.escape(marker[0]) + "{" + str(len(marker)) + ",}\\s*$", lines[j]):
                j += 1
            body = "\n".join(lines[i + 1:j])
            fence_ranges.append((i, j, lang, body))
            i = j + 1
        else:
            i += 1
    skip = set()
    for (a, b, lang, body) in fence_ranges:
        for k in range(a, min(b, n - 1) + 1):
            skip.add(k)
        _analyze_fence(body, lang, a + 2, ctx)
    # --- html comments (hidden text)
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        ln = text.count("\n", 0, m.start()) + 1
        body = m.group(1)
        for k, part in enumerate(body.split("\n")):
            if part.strip():
                ctx.text(ln + k, part.strip(), "md_comment", "markdown")
    # --- hidden html spans
    for m in _HIDDEN_HTML.finditer(text):
        ln = text.count("\n", 0, m.start()) + 1
        inner = re.sub(r"<[^>]+>", " ", m.group(1))
        ctx.text(ln, inner.strip(), "md_comment", "markdown")
    # --- prose, links, images, inline commands
    plain = re.sub(r"<!--.*?-->", lambda mm: "\n" * mm.group(0).count("\n"), text, flags=re.S)
    plines = plain.split("\n")
    for idx, ln in enumerate(plines):
        if idx in skip:
            continue
        s = ln.strip()
        if not s:
            continue
        visible = re.sub(r"<[^>]+>", " ", s)
        if len(visible.split()) >= 3:
            ctx.text(idx + 1, visible.strip(), "prose", "markdown")
        for im in _IMG.finditer(ln):
            alt, url = im.group(1), im.group(2)
            if alt and len(alt.split()) >= 3:
                ctx.text(idx + 1, alt, "prose", "markdown")
            _check_url(url, idx + 1, ctx, True)
        for lk in _LINK.finditer(ln):
            txt, url = lk.group(1), lk.group(2)
            _check_url(url, idx + 1, ctx, False)
        for hm in _HTML_IMG.finditer(ln):
            _check_url(hm.group(1), idx + 1, ctx, True)
        pm = _PROMPT_LINE.match(ln)
        if pm and _CMD_START.match(pm.group(1).strip()):
            _shell(pm.group(1).strip(), idx + 1, ctx)
        for ic in _INLINE_CMD.finditer(ln):
            body = ic.group(1).strip()
            if _CMD_START.match(body) and (" " in body):
                _shell(body, idx + 1, ctx)
        # bare command lines in prose such as "curl ... | bash"
        if _CMD_START.match(s) and re.search(r"\|\s*(sudo\s+)?(ba)?sh\b|\bpip\s+install\b|\bnpm\s+(i|install)\b|rm\s+-rf", s):
            _shell(s, idx + 1, ctx)
    # --- zero-width / tag character payloads anywhere in the document
    if re.search("[​‌‍⁠﻿]{3,}|[\U000e0000-\U000e007f]{3,}", text):
        m = re.search("[​‌‍⁠﻿]{3,}|[\U000e0000-\U000e007f]{3,}", text)
        ln = text.count("\n", 0, m.start()) + 1
        ctx.text(ln, text[max(0, m.start() - 200):m.end() + 400], "md_comment", "markdown")


def _shell(cmd: str, line: int, ctx: Ctx) -> None:
    from . import shfe
    try:
        shfe.analyze_shell(cmd, ctx, line_pin=line)
    except Exception:
        pass


def _check_url(url: str, line: int, ctx: Ctx, auto_load: bool) -> None:
    if not re.match(r"^(https?|ftp|gopher|file)://", url, re.I):
        return
    scheme, host, hc = K.host_of_url(url)
    fl = {"md_link"}
    if auto_load:
        fl.add("md_image")
    pl = U()
    has_tmpl = bool(_DATA_URL_PLACEHOLDER.search(url))
    q = url.split("?", 1)[1] if "?" in url else ""
    if has_tmpl or (auto_load and re.search(r"(secret|token|password|passwd|key|cookie|session|env|data|dump|leak|exfil)=", q, re.I)):
        fl.add("md_beacon")
        labs = {USER}
        if re.search(r"secret|token|password|key|cookie|session", url, re.I):
            labs.add(SECRET)
        if re.search(r"env", url, re.I):
            labs.add(ENV_DUMP)
        pl = U(labs)
    if scheme in K.DANGEROUS_SCHEMES:
        fl.add("dangerous_scheme")
    if hc in ("META", "LINKLOCAL", "PRIVATE", "SUSPICIOUS") or "md_beacon" in fl or "dangerous_scheme" in fl:
        ctx.emit(Event(cap="NET_FETCH", line=line, name="markdown-link", target=url, hostc=hc, flags=fl, plabels=pl, extra={"host": host}))


def _analyze_fence(body: str, lang: str, first_line: int, ctx: Ctx) -> None:
    """Analyse an embedded code block with the right front-end; line numbers map back to the document."""
    from .langid import detect_language
    if not body.strip():
        return
    if lang in ("", "text", "txt", "plain", "output"):
        lang = detect_language(body)
        if lang == "markdown":
            lang = ""
    if not lang:
        # plain text blocks: still AI-text candidates
        ctx.text(first_line, body, "prose", "markdown")
        return
    old_base = ctx.line_base
    ctx.line_base = old_base + first_line - 1
    try:
        if lang == "python":
            from . import pyfe
            if not pyfe.analyze_python_text(body, ctx, nested=True):
                from . import genericfe
                genericfe.analyze_generic_text(body, ctx, "python")
        elif lang == "bash":
            from . import shfe
            # strip leading prompts
            cleaned = "\n".join(re.sub(r"^\s*(\$|PS>|%)\s+", "", l) for l in body.split("\n"))
            shfe.analyze_shell(cleaned, ctx)
        elif lang == "sql":
            from . import sqlfe
            sqlfe.analyze_sql_text(body, ctx, nested=True)
        elif lang in ("javascript", "typescript"):
            from . import jsfe
            jsfe.analyze_js_text(body, ctx, nested=True)
        elif lang == "yaml":
            from . import yamlfe
            yamlfe.analyze_yaml_text(body, ctx)
        else:
            from . import genericfe
            genericfe.analyze_generic_text(body, ctx, lang)
        textscan.scan_text_secrets(body, ctx, lang)
    finally:
        ctx.line_base = old_base
