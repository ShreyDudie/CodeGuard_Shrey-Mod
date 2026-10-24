"""Language identification: shebang -> syntax probes -> weighted feature scores.  Pure Python, ~1 ms."""
from __future__ import annotations

import ast
import json
import re

import yaml

_SHEBANG = [
    (re.compile(r"^#!.*\b(python[\d.]*|pypy\d?)\b"), "python"),
    (re.compile(r"^#!.*\b(bash|sh|zsh|dash|ksh|ash)\b"), "bash"),
    (re.compile(r"^#!.*\b(node|nodejs|deno|bun)\b"), "javascript"),
    (re.compile(r"^#!.*\bruby\b"), "ruby"),
    (re.compile(r"^#!.*\bperl\b"), "perl"),
    (re.compile(r"^#!.*\bphp\b"), "php"),
    (re.compile(r"^#!.*\bpwsh\b|^#!.*powershell"), "powershell"),
]

_SQL_STMT = re.compile(r"^\s*(select\b[^;]*\bfrom\b|insert\s+into\b|update\s+[\w.\"`\[\]]+\s+set\b|delete\s+from\b|create\s+(or\s+replace\s+)?(table|procedure|function|view|index|trigger|user|role|database|schema|extension|login|unique|temporary|event)\b|drop\s+(table|database|schema|view|index|user|role|procedure|function|trigger|extension|login)\b|alter\s+(table|user|role|database|system|login|server)\b|grant\s+.+\s+(on|to)\b|revoke\s+.+\s+(on|from)\b|truncate\s+(table\s+)?[\w.\"`\[\]]+|declare\s+@|exec(ute)?\s+(sp_|xp_|master)|call\s+\w+\s*\(|pragma\s+\w+|copy\s+[\w.\"]+\s+(from|to)\b|merge\s+into\b|with\s+(recursive\s+)?\w+\s+as\s*\(|begin\s+(transaction|tran|work)\b|use\s+\w+\s*;|set\s+(session|global|@)|show\s+(tables|databases|grants|variables)|load\s+data\b|bulk\s+insert\b|waitfor\s+delay\b)", re.I | re.M)
_JS = re.compile(r"(\b(const|let|var)\s+[\w${}\[\],\s]+=|\bfunction\s*\*?\s*\w*\s*\(|=>\s*[{(\w]|\brequire\s*\(|\bmodule\.exports\b|\bexport\s+(default|const|function|class|async)\b|\bimport\s+[\w{}*,\s]+from\s+['\"]|\bconsole\.(log|error|warn)\b|\bawait\s+\w|\basync\s+(function|\()|\bdocument\.\w|\bwindow\.\w|\bprocess\.env\b|\bnew\s+Promise\b|\.then\(|\bfetch\s*\(|\bJSON\.(parse|stringify)\b|===|!==|\btypeof\s+\w)", re.M)
_TS = re.compile(r"(:\s*(string|number|boolean|any|void|unknown|never)\b|\binterface\s+\w+\s*\{|\bimplements\s+\w+|<\w+(\[\])?>\s*\(|\bas\s+(string|number|any|unknown)\b|\benum\s+\w+\s*\{|\btype\s+\w+\s*=)")
_BASH = re.compile(r"(^\s*(if|elif)\s+\[\[?\s|^\s*(fi|done|esac)\s*$|^\s*for\s+\w+\s+in\b|^\s*while\s+(true|:|\[|read)|^\s*(echo|export|cd|sudo|apt(-get)?|yum|chmod|chown|mkdir|rm|cp|mv|cat|grep|sed|awk|curl|wget|tar|systemctl|service|source|set\s+-[euxo]|trap|ln|kill|nohup|pip3?|npm|yarn|docker|git|dd|ping|nc|ssh|scp|rsync|crontab|useradd|bash|sh|python3?|eval|exec|unset|read|local|readonly)\s|\$\{?\w+\}?|\$\(|^\s*\w+\(\)\s*\{|`[^`]+`|\|\s*(sh|bash|grep|sudo|tee|xargs)\b|>\s*/dev/null|2>&1|&&\s*\w|\|\|\s*(exit|true|echo))", re.M)
_PYTHON = re.compile(r"(^\s*(def|class)\s+\w+|^\s*(import|from)\s+[\w.]+(\s+import\s+|\s+as\s+|\s*$)|^\s*if\s+__name__\s*==|\bself\.\w+|^\s*(elif|else|try|except|finally|with|for|while|if)\b.*:\s*$|\bprint\(|^\s*@\w+|\blambda\s+\w*:|\bf['\"]|:\s*(int|str|float|bool|list|dict)\b|->\s*\w+:|\bTrue\b|\bFalse\b|\bNone\b)", re.M)
_PHP = re.compile(r"(<\?php|\$\w+\s*=\s*[^;]+;|\becho\s+[\"'$]|->\w+\(|::\w+\(|\bfunction\s+\w+\s*\([^)]*\)\s*\{)")
_RUBY = re.compile(r"(^\s*def\s+\w+.*\n(.*\n)*?\s*end\b|\bputs\s+|\brequire\s+['\"]|\bdo\s*\|[^|]*\||\bend\s*$|\battr_(reader|accessor)|\b\w+\.each\s+do\b|@\w+\s*=|\bNet::HTTP\b|\bURI\(|\bENV\.\w+|\bparams\[:|\bputs\s+`)", re.M)
_GO = re.compile(r"(^package\s+\w+|\bfunc\s+(\(\w+\s+\*?\w+\)\s+)?\w+\(|:=|\bfmt\.\w+\(|\bgo\s+func\(|\bdefer\s+|import\s+\(\s*\n)", re.M)
_JAVA = re.compile(r"(\bpublic\s+(static\s+)?(class|void|interface)\b|\bSystem\.(out|err)\.|\bimport\s+java\.|\bpublic\s+static\s+void\s+main|@Override|\bnew\s+\w+<[^>]*>\(|\bprivate\s+(final\s+)?\w+\s+\w+\s*[;=])")
_CSHARP = re.compile(r"(\busing\s+System|\bnamespace\s+\w+|\bConsole\.(Write|Read)|\bpublic\s+(static\s+)?(async\s+)?(class|void|string|int|Task)\b.*\{|\bvar\s+\w+\s*=\s*new\b)")
_C = re.compile(r"(#include\s*[<\"]|\bint\s+main\s*\(|\bprintf\s*\(|\bmalloc\s*\(|\bstd::|\bvoid\s+\w+\s*\([^)]*\)\s*\{|\bchar\s*\*\s*\w+)")
_RUST = re.compile(r"(\bfn\s+main\s*\(|\blet\s+mut\s+|\buse\s+std::|\bimpl\s+\w+|println!\(|\bpub\s+fn\b|->\s*Result<)")
_BASH_CMDLINE = re.compile(r"(?m)^[ \t]*(?:sudo[ \t]+)?(?:rm|curl|wget|chmod|chown|chgrp|dd|mkfs(?:\.\w+)?|nc|ncat|netcat|kill|pkill|killall|systemctl|crontab|iptables|nohup|ssh|scp|rsync|tar|unzip|source|export|useradd|usermod|passwd|visudo|mount|umount|shred|truncate|history|unset|eval|exec|insmod|modprobe|bash|sh|zsh)(?:[ \t]+(?!=)\S|[ \t]*$)")
_BASH_PIPELINE = re.compile(r"(?m)^[ \t]*(?:cat|head|tail|grep|echo|find|ls|ps|printenv|env|base64|xxd|tee|ping|nslookup|dig|sed|awk)[ \t]+(?!=)\S.*(?:[|>])[ \t]*\S|^[ \t]*(?:cat|ls|find|head|tail)[ \t]+(?:-\w+[ \t]+)*[~/]\S|^[ \t]*(?:env|printenv|history|set)[ \t]*\|[ \t]*\S")
_POWERSHELL_STRONG = re.compile(r"(?m)(^\s*\$[A-Z][a-z]+[A-Za-z]*\s*=|HK(?:CU|LM|CR):|\$ErrorActionPreference|^\s*function\s+[A-Z][a-z]+-[A-Z]\w+|\$PSScriptRoot|^\s*(?:Get|Set|New|Remove|Invoke|Start|Stop|Add|Out|Write|Import|Export|Test)-\w+\s+-\w+|\$\w+\.\w+\()")
_POWERSHELL = re.compile(r"(\$env:\w+|\b(Get|Set|New|Remove|Invoke|Start|Stop|Add|Out|Write|Import|Export|Test)-[A-Z]\w+|\bparam\s*\(|\[Parameter|\$_\.|\|\s*(ForEach|Where)-Object|-ExecutionPolicy|\biex\b|\bpowershell(\.exe)?\s+-)", re.I)
_DOCKER = re.compile(r"^\s*(FROM\s+\S+|RUN\s+|COPY\s+|ADD\s+|ENTRYPOINT\s+|CMD\s+|WORKDIR\s+|EXPOSE\s+|ENV\s+\w+|ARG\s+\w+|USER\s+\w+|LABEL\s+|HEALTHCHECK)", re.M)
_YAML_KEYS = re.compile(r"^\s*(-\s+)?[\w.\-/\"'$@{}]+\s*:(\s+.*)?$", re.M)
_YAML_MARK = re.compile(r"^(---|\s*(on|jobs|steps|runs-on|services|version|stages|script|apiVersion|kind|metadata|spec|containers|tasks|hosts|name|env|image|volumes|include|pipeline|trigger|variables)\s*:|\s*-\s+(name|uses|run|hosts|include|image|script)\s*:)", re.M)
_MD_HEAD = re.compile(r"^\s{0,3}#{1,6}\s+\S", re.M)
_MD_OTHER = re.compile(r"(^\s*[-*+]\s+\S|^\s*\d+\.\s+\S|^```|^~~~|\[[^\]]+\]\([^)]+\)|\*\*[^*]+\*\*|<!--|^\s*>\s+\S|^\s*\|.+\|\s*$|^={3,}$|^-{3,}$|!\[[^\]]*\]\()", re.M)
_HTML = re.compile(r"^\s*(<!doctype html|<html|<head|<body|<div|<script|<style|<p>|<span|<a\s)", re.I | re.M)
_INI = re.compile(r"^\s*\[[\w. \-]+\]\s*$", re.M)


def _try_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        try:
            from .pyfe import repair_flat_indent
            fixed = repair_flat_indent(code)
            if fixed is not None:
                ast.parse(fixed)
                return True
        except Exception:
            pass
        # tolerate a lightly truncated snippet
        lines = code.splitlines()
        for cut in (1, 2, 3):
            if len(lines) > cut:
                try:
                    ast.parse("\n".join(lines[:-cut]))
                    return True
                except SyntaxError:
                    continue
        return False
    except Exception:
        return False


def _is_trivial_python(code: str) -> bool:
    """Parses as python but is probably prose/yaml/markdown (only bare names, annotations, expressions)."""
    try:
        tree = ast.parse(code)
    except Exception:
        return False
    if not tree.body:
        return True
    real = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom, ast.Assign, ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AugAssign, ast.Return))]
    calls = [n for n in tree.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
    return not real and not calls


def detect_language(code: str) -> str:
    if not code or not code.strip():
        return "unknown"
    text = code.strip("\n")
    head = text.lstrip()
    first = head.split("\n", 1)[0]
    for rx, lang in _SHEBANG:
        if rx.match(first):
            return lang
    if re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", text):
        return "bash"                     # the classic fork bomb has no letters at all, so word-based scoring cannot see it
    if head.startswith("<?php") or head.startswith("<?="):
        return "php"
    low = head[:200].lower()
    if low.startswith(("<!doctype html", "<html")):
        return "html"
    if head.startswith("<?xml"):
        return "xml"
    # JSON
    if head[0] in "{[" and len(head) < 2_000_000:
        try:
            obj = json.loads(head)
            if isinstance(obj, (dict, list)):
                return "json"
        except Exception:
            pass
    scores: dict = {}
    nlines = max(1, text.count("\n") + 1)

    def cnt(rx) -> int:
        return len(rx.findall(text))

    py_ok = _try_python(text)
    py_hits = cnt(_PYTHON)
    scores["python"] = (6 if py_ok and not _is_trivial_python(text) else 0) + min(py_hits, 12) * 0.9
    if py_ok and _is_trivial_python(text):
        scores["python"] -= 2
    sql = cnt(_SQL_STMT)
    scores["sql"] = min(sql, 8) * 2.5
    if py_ok and not _is_trivial_python(text):
        scores["sql"] *= 0.3
    js = cnt(_JS)
    scores["javascript"] = min(js, 14) * 1.3
    if _TS.search(text):
        scores["typescript"] = scores["javascript"] + min(cnt(_TS), 6) * 1.2 - 1
    bash = cnt(_BASH)
    scores["bash"] = min(bash, 20) * 0.85
    bash_cmd = cnt(_BASH_CMDLINE)                      # lines that start with a shell command word (rm, curl, chmod, nc ...), even without a shebang
    scores["bash"] += min(bash_cmd + cnt(_BASH_PIPELINE), 4) * 2.2
    if py_ok and not _is_trivial_python(text):
        scores["bash"] *= 0.35
    ps = cnt(_POWERSHELL)
    ps_strong = len(_POWERSHELL_STRONG.findall(text))          # PascalCase variables, drive-style registry paths, preference variables, Verb-Noun function names
    scores["powershell"] = min(ps, 10) * 1.3 + min(ps_strong, 6) * 2.0
    scores["php"] = min(cnt(_PHP), 8) * 1.0 if "<?php" in text or "$" in text and "->" in text else 0
    scores["ruby"] = min(cnt(_RUBY), 8) * 1.3
    scores["go"] = min(cnt(_GO), 8) * 1.6
    scores["java"] = min(cnt(_JAVA), 8) * 1.8
    scores["csharp"] = min(cnt(_CSHARP), 8) * 1.8
    scores["c"] = min(cnt(_C), 8) * 1.8
    scores["rust"] = min(cnt(_RUST), 8) * 2.0
    scores["dockerfile"] = min(cnt(_DOCKER), 10) * 1.6 if re.match(r"^\s*(FROM|ARG)\s", text) else 0
    # yaml
    yaml_ok = False
    ykeys = cnt(_YAML_KEYS)
    ymark = cnt(_YAML_MARK)
    if ykeys >= 2 and not (py_ok and not _is_trivial_python(text)):
        try:
            docs = [d for d in yaml.safe_load_all(text)]
            yaml_ok = any(isinstance(d, (dict, list)) for d in docs)
        except Exception:
            yaml_ok = False
    scores["yaml"] = (5 if yaml_ok else 0) + min(ymark, 8) * 1.2 + min(ykeys, 15) * 0.3
    if not yaml_ok:
        scores["yaml"] *= 0.35
    # markdown
    mh = cnt(_MD_HEAD)
    mo = cnt(_MD_OTHER)
    prose_lines = sum(1 for ln in text.split("\n") if len(ln.split()) >= 5 and not re.search(r"[{};=()]", ln))
    scores["markdown"] = min(mh, 5) * 2.2 + min(mo, 10) * 0.9 + min(prose_lines, 10) * 0.5
    if py_ok and not _is_trivial_python(text):
        scores["markdown"] *= 0.2
    if sql >= 2 and not mh:
        scores["markdown"] *= 0.3
    scores["html"] = 5 if _HTML.search(text) else 0
    scores["ini"] = min(cnt(_INI), 4) * 2.0 if cnt(_INI) and re.search(r"^\s*\w[\w.\-]*\s*=", text, re.M) else 0
    # a '#'-heading file is markdown only when there is more than one markdown signal; shell/python comments look similar
    if mh and not mo and nlines < 4:
        scores["markdown"] *= 0.5
    # strong disambiguations
    if re.search(r"^\s*(def|class)\s+\w+.*:\s*$", text, re.M) and py_ok:
        scores["python"] += 4
    if re.search(r"^\s*(import|from)\s+\w+", text, re.M) and re.search(r"^\s*(def|class|if|for|while|with|try)\b", text, re.M) and py_ok:
        scores["python"] += 2
    if not py_ok and re.search(r"^[ \t]*(async\s+)?(def|class)\s+\w+\s*(\([^)]*\))?\s*(->\s*[^:]+)?:[ \t]*\n[ \t]+\S", text, re.M):
        scores["python"] += 4          # a def/class header with an indented body is Python even when a later line is damaged
    if re.search(r"^\s*#!/", text) is None and re.search(r"^\s*(set\s+-[euxo]+|echo\s+|export\s+\w+=)", text, re.M) and not py_ok:
        scores["bash"] += 3
    if re.search(r"^\s*(const|let|var)\s", text, re.M) and not py_ok:
        scores["javascript"] += 3
    if re.search(r"\bfunction\b|\bconsole\.|=>|\brequire\(|\bmodule\.exports\b|\bexports\.\w+", text) and not py_ok:
        scores["javascript"] += 2
    if sql >= 1 and re.search(r";\s*$", text, re.M) and not py_ok and not js:
        scores["sql"] += 2
    best = max(scores.items(), key=lambda kv: kv[1])
    if best[1] < 2.0:
        if py_ok and not _is_trivial_python(text):
            return "python"
        return "unknown" if not any(c.isalpha() for c in text) else ("markdown" if prose_lines >= 2 else "unknown")
    lang = best[0]
    if lang == "typescript" and scores["javascript"] > 0:
        return "typescript"
    return lang
