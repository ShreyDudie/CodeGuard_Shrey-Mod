"""Generic / fallback front-end for any language without a dedicated analyser (PHP, Ruby, Go, Java, C#,
PowerShell, Dockerfile, requirements files ...) and for snippets that fail to parse.

It reasons over *capabilities found in string literals and call names*, then hands command-looking strings to
the shell analyser and SQL-looking strings to the SQL analyser, so the same rules apply as for native code.
"""
from __future__ import annotations

import re
from typing import Optional

from . import knowledge as K
from . import textscan
from .ctx import Ctx
from .events import ENV_DUMP, FILE, HOLE, NET, SECRET, SENS_SYS, USER, Event, U

_STR_RE = re.compile(r"""\"(?P<d>(?:[^\"\\\n]|\\.){2,2000})\"|\'(?P<s>(?:[^\'\\\n]|\\.){2,2000})\'|`(?P<b>[^`]{2,2000})`""", re.S)
_CMD_START = re.compile(r"^\s*(?:sudo\s+)?(rm|curl|wget|nc|ncat|netcat|bash|sh|zsh|chmod|chown|sudo|dd|mkfs[.\w]*|cat|echo|python[\d.]*|perl|ruby|php|node|crontab|systemctl|service|"
                        r"pip[\d.]*|npm|yarn|apt(-get)?|yum|dnf|git|docker|kubectl|ssh|scp|rsync|useradd|usermod|kill|killall|pkill|nohup|powershell(\.exe)?|cmd(\.exe)?|"
                        r"base64|tar|zip|openssl|history|shred|find|xargs|ping|nslookup|dig|iptables|ufw|setenforce|mount|ln|cp|mv|touch|mkdir|export|eval|source)\b")
_SQL_START = re.compile(r"^\s*(select\b.+\bfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|drop\s+(table|database|schema)\b|truncate\b|alter\s+(table|user|role)\b|"
                        r"grant\s|create\s+(user|role|table|database)\b|exec(ute)?\s|copy\s+\S+\s+(to|from)\b|load\s+data\b)", re.I | re.S)
_URL_RE = re.compile(r"\b(?:https?|ftp|gopher|file|dict|ldap|sftp|ws|wss)://[^\s'\"`<>)\]}]+", re.I)
_LOOP_BUSY = re.compile(r"\b(?:while\s*\(\s*(?:true|1|!0)\s*\)|for\s*\(\s*;\s*;\s*\)|while\s+true\s+do|loop\s*\{|while\s+\(\$true\)|for\s*\(;;\))", re.I)
_SLEEPY = re.compile(r"\b(sleep|wait|recv|accept|read|select|poll|await|yield|usleep|Thread\.Sleep|time\.Sleep|delay|input|break|return|exit)\b", re.I)
_DECODE_EXEC = re.compile(r"\b(eval|exec|assert|Invoke-Expression|iex|system|passthru|shell_exec|create_function)\s*\(?\s*\(?\s*(base64_decode|atob|Base64\.decode64|gzinflate|gzuncompress|str_rot13|FromBase64String|unescape|decodeURIComponent|rot13|hex2bin|pack)\b", re.I)
_PS_DANGER = [
    (re.compile(r"\b(iex|Invoke-Expression)\b.{0,80}\b(DownloadString|Invoke-WebRequest|iwr|WebClient|curl|wget)\b|\b(DownloadString|Invoke-WebRequest|iwr)\b.{0,120}\|\s*(iex|Invoke-Expression)", re.I | re.S), "remote_iex"),
    (re.compile(r"-(enc|encodedcommand|ec)\s+[A-Za-z0-9+/=]{16,}", re.I), "encoded_cmd"),
    (re.compile(r"Remove-Item\b.*-Recurse\b.*-Force|Remove-Item\b.*-Force\b.*-Recurse", re.I), "ps_delete"),
    (re.compile(r"Set-MpPreference\s+-Disable|Stop-Service\s+.*(WinDefend|Sense|EventLog)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off", re.I), "defense_off"),
    (re.compile(r"New-ScheduledTask|Register-ScheduledTask|schtasks\s+/create|New-Service\b|HKCU:\\.*\\Run\b|HKLM:\\.*\\Run\b|CurrentVersion\\Run", re.I), "persist"),
    (re.compile(r"net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add|Add-LocalGroupMember\s+.*Administrators", re.I), "add_admin"),
    (re.compile(r"Get-Content\s+.*(\.aws|\.ssh|id_rsa|credentials|\.env)|\[Environment\]::GetEnvironmentVariables", re.I), "read_secret"),
]
_CALL_NAMES = {
    "system": "EXEC_SHELL", "exec": "EXEC_SHELL", "shell_exec": "EXEC_SHELL", "passthru": "EXEC_SHELL", "popen": "EXEC_SHELL", "proc_open": "EXEC_SHELL",
    "execl": "EXEC_PROC", "execv": "EXEC_PROC", "execvp": "EXEC_PROC", "execlp": "EXEC_PROC", "backtick": "EXEC_SHELL",
}


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _comments_for(text: str, lang: str, ctx: Ctx) -> None:
    items: list = []
    if lang in ("python", "bash", "ruby", "perl", "yaml", "powershell", "dockerfile", "ini", "unknown", "toml", "makefile"):
        items += textscan.extract_hash_comments(text)
    if lang in ("javascript", "typescript", "java", "c", "cpp", "csharp", "go", "rust", "php", "unknown", "css", "swift", "kotlin", "scala", "dart"):
        items += textscan.extract_c_comments(text)
    if lang in ("php",):
        items += textscan.extract_hash_comments(text)
    items += textscan.extract_html_comments(text)
    if lang == "powershell":
        for m in re.finditer(r"<#(.*?)#>", text, re.S):
            ln = _line_of(text, m.start())
            for k, part in enumerate(m.group(1).split("\n")):
                if part.strip():
                    items.append((ln + k, part.strip()))
    if lang in ("sql",):
        for m in re.finditer(r"--([^\n]*)", text):
            items.append((_line_of(text, m.start()), m.group(1).strip()))
    for ln, body in items:
        ctx.text(ln, body, "comment", lang)


_USER_SRC = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)|\brequest\.|\br\.(URL|Form|FormValue|Body|Header)|params\[|argv|os\.Args|\binput\(|STDIN|args\[|getParameter\(|Request\.(Query|Form)", re.I)
_SQL_INTERP = re.compile(r"\{\$[^}]+}|\$\w+|#\{[^}]*}|%s|%d|\{\w+}")
_SQL_CONCAT_AFTER = re.compile(r"\s*[+.]\s*[\$A-Za-z_(]")
_SHELL_CONCAT = re.compile(r"""\b(system|shell_exec|passthru|popen|proc_open|exec)\s*(?:\(\s*)?(?:'[^']*'|"[^"]*")\s*[.+]\s*\$\w+|\b(exec\.Command|ProcessBuilder|Process\.Start)\(\s*"(?:sh|bash|cmd(?:\.exe)?)"\s*,\s*"(?:-c|/c)"\s*,\s*[^"\s)]""")
_SEND_CALL = re.compile(r"(->\s*post\s*\(|->\s*request\s*\(|\.post\s*\(|http\.Post|http\.NewRequest|Net::HTTP|curl_exec|HttpClient|\.PostForm\(|requests\.(post|put))", re.I)


def analyze_generic_text(text: str, ctx: Ctx, lang: str = "unknown") -> None:
    from . import shfe, sqlfe
    _comments_for(text, lang, ctx)
    textscan.scan_text_secrets(text, ctx, lang)
    if lang == "dockerfile":
        _dockerfile(text, ctx)
    if _looks_like_requirements(text):
        _requirements(text, ctx)
    # string literals -----------------------------------------------------------------------------
    handled_urls = set()
    for m in _STR_RE.finditer(text):
        body = m.group("d") or m.group("s") or m.group("b") or ""
        ln = _line_of(text, m.start())
        if len(body) >= 24 and " " in body:
            ctx.text(ln, body, "string", lang)
        if _SQL_START.match(body):
            try:
                dyn = _SQL_INTERP.sub(HOLE, body)
                after = text[m.end():m.end() + 24]
                if _SQL_CONCAT_AFTER.match(after):             # "SELECT ... = '" + value
                    dyn = dyn + HOLE
                tainted = dyn != body or dyn.endswith(HOLE)
                user_fed = tainted and _USER_SRC.search(text) is not None
                sqlfe.emit_statements(sqlfe.CtxSink(ctx), dyn, ln, U({USER}) if user_fed else frozenset(), user_fed, False, {"generic"}, (), frozenset())
            except Exception:
                pass
            continue
        if _CMD_START.match(body) and len(body) < 4000:
            try:
                shfe.analyze_shell(body.replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'"), ctx, line_pin=ln)
            except Exception:
                pass
        for um in _URL_RE.finditer(body):
            handled_urls.add((ln, um.group(0)))
        pc = K.classify_path(body) if ("/" in body or "\\" in body or body.startswith(".") or body.startswith("~")) and len(body) < 300 and " " not in body else set()
        if "SECRET_STORE" in pc:
            lab, src = U({SECRET, FILE}), frozenset({"the credential file " + body})
            ctx.emit(Event(cap="READ_FILE", line=ln, name="path-literal", target=body, pathc=pc, plabels=lab, flags={"generic_literal"}, extra={"src": src}))
        elif pc & {"PERSIST", "PRIVFILE"} and re.search(r"(write|append|put_contents|WriteAll|open|fopen|File\.|>>|tee|echo)", text[max(0, m.start() - 200):m.end() + 200], re.I):
            ctx.emit(Event(cap="WRITE_FILE", line=ln, name="path-literal", target=body, pathc=pc, flags={"generic_literal"}, extra={"content": ""}))
    # URLs ------------------------------------------------------------------------------------------
    for m in _URL_RE.finditer(text):
        ln = _line_of(text, m.start())
        u = m.group(0).rstrip(".,;")
        scheme, host, hc = K.host_of_url(u)
        ctx_txt = text[max(0, m.start() - 160):m.end() + 160]
        sending = bool(re.search(r"\b(post|put|patch|upload|send|write|json_encode|curl_setopt.*POSTFIELDS|form|body\s*[:=]|data\s*[:=]|-d\s)", ctx_txt, re.I))
        # the URL sits in a constant and the call is elsewhere in the same small file
        file_wide = len(text) < 8000 and _SEND_CALL.search(text) is not None
        sending = sending or file_wide
        fl = {"generic_url"}
        if scheme in K.DANGEROUS_SCHEMES:
            fl.add("dangerous_scheme")
        if scheme == "http":
            fl.add("plain_http")
        pl = U()
        if sending:
            near = text if file_wide else text[max(0, m.start() - 300):m.end() + 300]
            labs = set()
            if re.search(r"\.aws/credentials|id_rsa|\.ssh/|\.env\b|/etc/shadow|secret|password|token|api[_-]?key", near, re.I):
                labs.add(SECRET)
            if re.search(r"/etc/passwd", near):
                labs.add(SENS_SYS)
            if re.search(r"environ|getenv|\$_ENV|process\.env|System\.getenv|ENV\[|ENV\.to_h|os\.Environ", near):
                labs.add(ENV_DUMP) if re.search(r"environ\b[^.\w]|\$_ENV\b|ENV\.to_h|getenv\(\)|GetEnvironmentVariables", near) else None
            pl = U(labs)
        ctx.emit(Event(cap="NET_SEND" if sending else "NET_FETCH", line=ln, name="url", target=u, hostc=hc, flags=fl, plabels=pl, extra={"host": host}))
    # decode-and-run -------------------------------------------------------------------------------
    for m in _DECODE_EXEC.finditer(text):
        ctx.emit(Event(cap="EVAL", line=_line_of(text, m.start()), name="decode-exec", target=m.group(0)[:80], flags={"decoded", "eval"}))
    if lang == "powershell" or re.search(r"\bpowershell\b|Invoke-Expression|\$env:", text, re.I):
        for rx, kind in _PS_DANGER:
            for m in rx.finditer(text):
                ln = _line_of(text, m.start())
                if kind == "remote_iex":
                    ctx.emit(Event(cap="PIPE_EXEC", line=ln, name="iex", target=m.group(0)[:80], flags={"remote"}))
                elif kind == "encoded_cmd":
                    ctx.emit(Event(cap="EVAL", line=ln, name="powershell -enc", target=m.group(0)[:60], flags={"decoded", "encoded_cmd"}))
                elif kind == "ps_delete":
                    path = re.search(r"Remove-Item\s+(?:-\w+\s+)*['\"]?([^\s'\"]+)", text[m.start():m.start() + 300], re.I)       # the path follows the switches, which is after what the pattern itself matched
                    p = path.group(1) if path else ""
                    pc = K.classify_path(p.replace("C:\\", "/").replace("\\", "/")) if p else set()
                    if re.match(r"^[A-Za-z]:\\?$|^[A-Za-z]:\\(Windows|Users|Program Files)", p) or pc & {"ROOT", "SYSTEM_DIR", "HOME_DIR"} or "$env:USERPROFILE" in p:
                        ctx.emit(Event(cap="DELETE", line=ln, name="Remove-Item", target=p or "C:\\", pathc={"ROOT"}, flags={"recursive", "force"}))
                elif kind == "defense_off":
                    ctx.emit(Event(cap="SYSTEM_CTL", line=ln, name="powershell", target=m.group(0)[:60], flags={"defense_evasion"}))
                elif kind == "persist":
                    ctx.emit(Event(cap="PERSIST", line=ln, name="powershell", target=m.group(0)[:60], flags={"scheduled_task"}))
                elif kind == "add_admin":
                    ctx.emit(Event(cap="PRIV", line=ln, name="net user", target=m.group(0)[:60], flags={"admin_group"}))
                elif kind == "read_secret":
                    ctx.emit(Event(cap="READ_FILE", line=ln, name="Get-Content", target=m.group(0)[:60], pathc={"SECRET_STORE"}, plabels=U({SECRET, FILE})))
    # loops / bombs ----------------------------------------------------------------------------------
    for m in _LOOP_BUSY.finditer(text):
        body = text[m.end(): m.end() + 400]
        # find the loop body up to a matching brace/end, crude
        depth = 0
        end = len(body)
        for i, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                if depth <= 1:
                    end = i
                    break
                depth -= 1
        seg = body[:end]
        if not _SLEEPY.search(seg):
            fl = {"unbounded", "busy"}
            if re.search(r"\b(fork|spawn|Thread|Process|exec|system)\b", seg, re.I):
                fl.add("spawn")
            ctx.emit(Event(cap="LOOP", line=_line_of(text, m.start()), name="loop", flags=fl))
    if re.search(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", text) or re.search(r"\bfork\s*\(\s*\)[^;]*;\s*fork\s*\(\s*\)", text):
        ctx.emit(Event(cap="FORK_BOMB", line=1, name="fork-bomb", flags={"fork_bomb"}))
    # call names with literal args ----------------------------------------------------------------------
    for m in re.finditer(r"\b(system|shell_exec|passthru|popen|proc_open|exec|Runtime\.getRuntime\(\)\.exec|Process\.Start|ProcessBuilder)\s*\(\s*(?:\$\w+|\w+(?:\.\w+)*(?:\[[^\]]*\])?)\s*[,)]", text):
        arg_ctx = text[max(0, m.start() - 200):m.start()]
        if re.search(r"\$_(GET|POST|REQUEST|COOKIE)|request\.|params\[|argv|input\(|STDIN|args\[", arg_ctx + text[m.end() - 40:m.end()], re.I):
            ctx.emit(Event(cap="EXEC_SHELL", line=_line_of(text, m.start()), name=m.group(1), target=HOLE, tlabels=U({USER}), flags={"injectable", "tainted", "generic_call"}))
    for m in _SHELL_CONCAT.finditer(text):
        if _USER_SRC.search(text):
            ctx.emit(Event(cap="EXEC_SHELL", line=_line_of(text, m.start()), name=m.group(1), target=HOLE, tlabels=U({USER}), flags={"injectable", "tainted", "generic_call"}))
    for m in re.finditer(r"\b(unlink|rmdir|rmtree|File\.delete|FileUtils\.rm_rf|Files\.delete|os\.RemoveAll|RemoveAll)\s*\(\s*['\"]([^'\"]+)['\"]", text):
        p = m.group(2)
        pc = K.classify_path(p)
        if pc & {"ROOT", "SYSTEM_DIR", "HOME_DIR"}:
            ctx.emit(Event(cap="DELETE", line=_line_of(text, m.start()), name=m.group(1), target=p, pathc=pc, flags={"recursive", "generic_call"}))


def _dockerfile(text: str, ctx: Ctx) -> None:
    from . import shfe
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        start = i + 1
        if re.match(r"^(RUN|CMD|ENTRYPOINT)\s", s, re.I):
            full = s
            while full.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                full = full.rstrip()[:-1] + " " + lines[i].strip()
            cmd = re.sub(r"^(RUN|CMD|ENTRYPOINT)\s+", "", full, flags=re.I)
            if cmd.startswith("["):
                try:
                    import json
                    arr = json.loads(cmd)
                    cmd = " ".join(str(x) for x in arr)
                except Exception:
                    pass
            shfe.analyze_shell(cmd, ctx, line_pin=start)
        elif re.match(r"^ADD\s+https?://", s, re.I):
            m = re.match(r"^ADD\s+(\S+)", s, re.I)
            u = m.group(1)
            _sc, host, hc = K.host_of_url(u)
            ctx.emit(Event(cap="NET_FETCH", line=start, name="ADD", target=u, hostc=hc, flags={"dockerfile_add"}, extra={"host": host}))
        i += 1


def _looks_like_requirements(text: str) -> bool:
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines or len(lines) > 400:
        return False
    ok = 0
    for l in lines:
        if re.match(r"^(-r|-c|-e|--[\w-]+)\s*\S*|^[A-Za-z0-9][A-Za-z0-9._\-]*(\[[^\]]*\])?\s*((==|>=|<=|~=|!=|>|<|===)\s*[\w.*+\-!]+(\s*,\s*(==|>=|<=|~=|!=|>|<)\s*[\w.*+\-!]+)*)?\s*(;.*)?$|^(git\+|https?://)\S+", l):
            ok += 1
    return ok >= max(1, int(0.9 * len(lines))) and not any(w in " ".join(lines) for w in ("def ", "import ", "{", "}", ";\n", "SELECT ", "echo "))


def _requirements(text: str, ctx: Ctx) -> None:
    from . import shfe
    sh = shfe.Shell(ctx, frozenset(), frozenset())
    for n, raw in enumerate(text.split("\n"), start=1):
        l = raw.strip()
        if not l or l.startswith("#"):
            continue
        if l.startswith(("-r", "-c", "--requirement")):
            continue
        flags = set()
        if l.startswith(("--index-url", "-i ", "--extra-index-url", "--trusted-host", "--find-links")):
            fl = set()
            if "--extra-index-url" in l:
                fl.add("extra_index")
            elif "--index-url" in l or l.startswith("-i "):
                fl.add("custom_index")
            if "--trusted-host" in l:
                fl.add("trusted_host")
            if "http://" in l:
                fl.add("plain_http_index")
            ctx.emit(Event(cap="INSTALL_PKG", line=n, name="requirements", target=l, flags=fl | {"no_specs"}, extra={"eco": "pypi", "pkg": "", "rep": "UNKNOWN"}))
            continue
        l2 = l.split(";")[0].split(" --")[0].strip()
        l2 = re.sub(r"^-e\s+", "", l2)
        sh._install("pypi", [shfe.V(c=l2, lines=frozenset({n}))], n, flags, "requirements")


def analyze_requirements(text: str, ctx: Ctx) -> None:
    _requirements(text, ctx)
