"""SQL front-end: tokenizer, statement splitter and classifier.  Emits SQL_STMT events.

Works on standalone .sql files and on SQL skeletons built inside other languages (holes mark interpolated
values).  `probe_sql` implements the counterfactual probe: substitute hostile values for the holes and check
whether the statement *structure* changes - the definition of an injection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .ctx import Ctx
from .events import EMPTY, HOLE, Event, U, USER, SAFE_NUM

_STMT_KINDS = ("select", "insert", "update", "delete", "drop", "truncate", "alter", "create", "grant", "revoke", "exec", "execute", "call", "copy", "load",
               "set", "use", "show", "with", "merge", "replace", "pragma", "attach", "vacuum", "declare", "begin", "commit", "rollback", "rename", "bulk", "backup",
               "restore", "shutdown", "kill", "explain", "describe", "desc", "analyze", "prepare", "deallocate", "lock", "unlock", "do", "if", "while", "for",
               "open", "fetch", "close", "return", "raise", "print", "waitfor", "go", "comment", "reindex", "cluster", "listen", "notify", "import")


@dataclass
class Stmt:
    kind: str
    text: str
    line_off: int
    flags: set = field(default_factory=set)
    has_hole: bool = False


# ---------------------------------------------------------------------------------------------- lexing
def strip_comments_and_split(text: str) -> list:
    """Return [(statement_text_with_strings_intact, start_line_offset)] and also collect comments."""
    out = []
    buf = []
    i = 0
    n = len(text)
    line = 0
    start_line = 0
    started = False
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "--" or (c == "#" and False):
            j = text.find("\n", i)
            if j == -1:
                j = n
            i = j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            if j == -1:
                j = n
            seg = text[i:j + 2]
            line += seg.count("\n")
            buf.append(" " + ("\n" * seg.count("\n")))
            i = j + 2
            continue
        if c in ("'", '"', "`"):
            q = c
            j = i + 1
            while j < n:
                if text[j] == "\\" and q != "`":
                    j += 2
                    continue
                if text[j] == q:
                    if j + 1 < n and text[j + 1] == q:
                        j += 2
                        continue
                    break
                j += 1
            seg = text[i:j + 1]
            if not started and seg.strip():
                started = True
                start_line = line
            buf.append(seg)
            line += seg.count("\n")
            i = j + 1
            continue
        if c == "$" and re.match(r"\$[A-Za-z_]*\$", text[i:i + 40]):
            tag = re.match(r"\$[A-Za-z_]*\$", text[i:]).group(0)
            j = text.find(tag, i + len(tag))
            j = n if j == -1 else j + len(tag)
            seg = text[i:j]
            if not started:
                started = True
                start_line = line
            buf.append(seg)
            line += seg.count("\n")
            i = j
            continue
        if c == ";":
            s = "".join(buf)
            if s.strip():
                out.append((s, start_line))
            buf = []
            started = False
            i += 1
            continue
        if c == "\n":
            line += 1
            if not started:
                buf.append(c)
                i += 1
                continue
        if not started and not c.isspace():
            started = True
            start_line = line
        buf.append(c)
        i += 1
    s = "".join(buf)
    if s.strip():
        out.append((s, start_line))
    return out


def _mask_strings(s: str) -> str:
    """Replace the contents of quoted strings by underscores (keeps length/positions)."""
    def rep(m):
        t = m.group(0)
        return t[0] + "_" * (len(t) - 2) + t[-1] if len(t) >= 2 else t
    return re.sub(r"'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.|\"\")*\"", rep, s, flags=re.S)


_LEAD_NOISE = re.compile(r"^\s*(?:begin\b(?!\s+(?:transaction|work))|then\b|else\b|do\b|loop\b|repeat\b|elseif\b[^;]*?\bthen\b|when\b[^;]*?\bthen\b|end\s+if\b|end\s+loop\b|end\b|\(|\))\s*", re.I)


def classify_statements(text: str) -> list:
    stmts: list = []
    for raw, off in strip_comments_and_split(text):
        s = raw.strip()
        if not s:
            continue
        masked = _mask_strings(s)
        # CREATE PROCEDURE/FUNCTION/TRIGGER ... BEGIN <first stmt>  ->  keep header + classify body piece separately
        m = re.match(r"^\s*create\s+(?:or\s+replace\s+)?(?:definer\s*=\s*\S+\s+)?(procedure|function|trigger|event)\b", masked, re.I)
        body = s
        if m:
            mb = re.search(r"\bbegin\b", masked, re.I)
            hdr = Stmt("create", s[:mb.start()] if mb else s, off, {"create_routine"})
            stmts.append(hdr)
            if not mb:
                continue
            body = s[mb.end():]
            masked = masked[mb.end():]
            off += s[:mb.end()].count("\n")
        # strip leading noise tokens
        for _ in range(6):
            mm = _LEAD_NOISE.match(masked)
            if not mm or mm.end() == 0:
                break
            body = body[mm.end():]
            masked = masked[mm.end():]
        body_s = body.strip()
        if not body_s:
            continue
        lead = len(body) - len(body.lstrip())
        off2 = off + body[:lead].count("\n")
        kw = re.match(r"^([A-Za-z_]+)", masked.strip())
        kind = kw.group(1).lower() if kw else ""
        if kind == "with":
            mv = re.search(r"\)\s*(select|insert|update|delete|merge)\b", masked, re.I)
            if mv:
                kind = mv.group(1).lower()
        stmts.append(_flag_statement(kind, body_s, masked.strip(), off2))
    return stmts


_TAUT = re.compile(r"\b(\w+)\s*=\s*\1\b|\b(\d+)\s*=\s*\2\b|'(\w*)'\s*=\s*'\3'|\bor\s+(?:true|1\s*=\s*1|'1'\s*=\s*'1'|'a'\s*=\s*'a'|\"1\"\s*=\s*\"1\")|\bwhere\s+(?:1|true)\b(?!\s*=\s*0)", re.I)


def _flag_statement(kind: str, text: str, masked: str, off: int) -> Stmt:
    st = Stmt(kind, text, off, set(), HOLE in text)
    low = masked.lower()
    fl = st.flags
    has_where = bool(re.search(r"\bwhere\b", low))
    has_limit = bool(re.search(r"\blimit\b\s+\d+|\btop\s*\(?\s*\d+|\bfetch\s+first\b|\browcount\b|\brownum\b", low))
    tauto = bool(_TAUT.search(low.split("where", 1)[1] if has_where else "")) if has_where else False
    if kind == "delete":
        if not has_where:
            fl.add("no_where")
        elif tauto:
            fl.add("tautology_where")
        if has_limit:
            fl.add("limited")
    elif kind == "update":
        if not has_where:
            fl.add("no_where")
        elif tauto:
            fl.add("tautology_where")
        sm = re.search(r"\bset\b(.*?)(?:\bwhere\b|$)", low, re.S)
        if sm and re.search(r"=\s*(?:0|null|''|\"\"|false|'deleted'|'0'|default)\s*(?:,|$)", sm.group(1).strip()):
            fl.add("set_blank")
        if has_limit:
            fl.add("limited")
    elif kind == "drop":
        m = re.match(r"drop\s+(?:temporary\s+)?(table|database|schema|view|index|user|role|column|function|procedure|trigger|extension|tablespace|sequence|login)\b(\s+if\s+exists)?\s*([\w.\"`\[\]]*)", low)
        if m:
            fl.add("drop_" + m.group(1))
            if m.group(2):
                fl.add("if_exists")
            name = m.group(3) or ""
            # a disposable-looking TABLE may be routine cleanup; a whole DATABASE or SCHEMA is only disposable if it says tmp/temp/scratch
            # (names such as staging or test are real environments with real data)
            if m.group(1) in ("database", "schema"):
                temp_rx = r"(^|[._])(tmp|temp|temporary|scratch)([._]|$)|^tmp|^temp"
            else:
                temp_rx = r"(^|[._])(tmp|temp|temporary|scratch|test|staging|stg|cache|old|bak|backup)([._]|$)|^#|^tmp|^temp"
            if re.search(temp_rx, name) or "temporary" in low[:20]:
                fl.add("temp_name")
            if m.group(1) in ("table", "database", "schema") and not has_where:
                fl.add("drop_data")
        else:
            fl.add("drop_other")
    elif kind == "truncate":
        fl.add("truncate")
        m = re.match(r"truncate\s+(?:table\s+)?([\w.\"`\[\]]*)", low)
        if m and re.search(r"(^|[._])(tmp|temp|scratch|staging|stg|cache)([._]|$)|^#", m.group(1)):
            fl.add("temp_name")
    elif kind == "alter":
        if re.search(r"\balter\s+(?:user|role|login)\b.*\b(superuser|createrole|createdb|replication|bypassrls|sysadmin|with\s+password|identified\s+by)", low):
            fl.add("alter_role")
            if re.search(r"superuser|sysadmin|createrole", low):
                fl.add("superuser")
        if re.search(r"\balter\s+(?:table|database)\b.*\bdrop\s+(?:column|constraint)", low):
            fl.add("alter_drop")
        if re.search(r"\balter\s+system\b", low):
            fl.add("alter_system")
        if re.search(r"\balter\s+server\s+role\s+sysadmin\s+add\s+member", low):
            fl.add("superuser")
    elif kind in ("grant", "revoke"):
        if kind == "grant":
            if re.search(r"\ball(\s+privileges)?\b", low):
                fl.add("grant_all")
            if re.search(r"with\s+grant\s+option|with\s+admin\s+option", low):
                fl.add("grant_option")
            if re.search(r"\bto\s+(public|'%'|\"%\"|\S*@'%')|@'%'|@\"%\"", low):
                fl.add("grant_public")
            if re.search(r"\bon\s+\*\.\*|\bon\s+all\s+tables\s+in\s+schema|\bon\s+database\s+\w+\s+to\s+public", low):
                fl.add("grant_global")
            if re.search(r"\b(superuser|super|file|process|shutdown|create\s+user|dba|sysadmin|securityadmin|execute\s+on\s+all)\b", low):
                fl.add("grant_admin")
            if re.search(r"\bgrant\s+(?:dba|sysadmin|securityadmin|superuser|\w*_admin)\b|\bgrant\s+\w+\s+to\s+\w+\s+with\s+admin", low):
                fl.add("grant_admin")
        else:
            if re.search(r"\ball\b", low):
                fl.add("revoke_all")
    elif kind == "create":
        m = re.match(r"create\s+(?:or\s+replace\s+)?(user|role|login|database|table|view|index|function|procedure|trigger|extension|server|event|schema|temporary|unlogged|external)", low)
        if m:
            fl.add("create_" + m.group(1))
        if re.search(r"\bcreate\s+(?:user|role|login)\b", low):
            if re.search(r"\bsuperuser\b|\bsysadmin\b|\bcreaterole\b|\bwith\s+login\s+superuser", low):
                fl.add("superuser")
            if re.search(r"identified\s+by\s+'[^']{3,}'|password\s+'[^']{3,}'|with\s+password\s+'", low) or re.search(r"identified\s+by\s+'", text, re.I) or re.search(r"password\s+'", text, re.I):
                fl.add("hardcoded_password")
            if re.search(r"@'%'", low):
                fl.add("any_host")
        if re.search(r"\bcreate\s+(?:or\s+replace\s+)?function\b.*\b(soname|language\s+(?:plpythonu|plpython3u|plperlu|c|java)|external\s+name)", low, re.S):
            fl.add("native_function")
        if re.search(r"create\s+extension\s+(?:if\s+not\s+exists\s+)?(?:dblink|file_fdw|postgres_fdw|plpython3u|plperlu|adminpack|lo)", low):
            fl.add("risky_extension")
        if re.search(r"create\s+(?:server|foreign\s+data\s+wrapper|external\s+(?:data\s+source|table))", low):
            fl.add("foreign_server")
        if re.search(r"create\s+trigger\b", low) and re.search(r"\b(exec|xp_cmdshell|sys_exec|copy\s+.*program|http|utl_http)\b", low):
            fl.add("trigger_exec")
    elif kind in ("exec", "execute", "call", "do"):
        if re.search(r"\bxp_cmdshell\b|\bsp_oacreate\b|\bsp_oamethod\b|\bsys_exec\b|\bsys_eval\b|\bxp_dirtree\b|\bxp_regread\b|\bxp_fileexist\b|\bsp_addsrvrolemember\b", low):
            fl.add("os_command")
        if re.search(r"sp_configure\s+'?(xp_cmdshell|ole automation|show advanced|clr enabled|ad hoc distributed)", low):
            fl.add("enable_exec")
        if re.search(r"\bexec(?:ute)?\s*\(\s*@|\bexecute\s+immediate\b|\bexec\s+sp_executesql\b|\bprepare\b.*\bfrom\b", low):
            fl.add("dynamic_exec")
    elif kind == "copy":
        if re.search(r"\b(from|to)\s+program\b", low):
            fl.add("os_command")
        elif re.search(r"\bto\s+'?(?:/|[a-z]:\\)", low):
            fl.add("file_write")
        elif re.search(r"\bfrom\s+'?(?:/etc|/root|/home|/var|/proc|~)", low):
            fl.add("file_read")
    elif kind == "load":
        if re.search(r"load\s+data\s+(?:local\s+)?infile", low):
            fl.add("file_read")
    elif kind == "attach":
        fl.add("attach_db")
    elif kind == "pragma":
        if re.search(r"pragma\s+(?:writable_schema|trusted_schema|key|rekey)", low):
            fl.add("pragma_risky")
    elif kind == "bulk":
        fl.add("file_read")
    elif kind == "shutdown":
        fl.add("shutdown")
    # ---- cross-kind features
    if re.search(r"\binto\s+(?:out|dump)file\b", low):
        fl.add("file_write")
    if re.search(r"\bload_file\s*\(|\bpg_read_file\s*\(|\bpg_ls_dir\s*\(|\blo_import\s*\(|\bpg_read_binary_file\s*\(|\butl_file\.|\bbulk\s+insert\b|openrowset\s*\(\s*bulk", low):
        fl.add("file_read")
    if re.search(r"\blo_export\s*\(|\bdbms_xslprocessor\.clob2file", low):
        fl.add("file_write")
    if re.search(r"\bxp_cmdshell\b|\bsys_exec\s*\(|\bsys_eval\s*\(|\bdbms_scheduler\.create_job|\bdbms_java\b|\bjava_exec|\bsp_oacreate\b", low):
        fl.add("os_command")
    if re.search(r"\butl_http\.|\butl_tcp\.|\butl_inaddr\.|\bdblink_connect|\bdblink\s*\(|\bopenrowset\s*\(|\bopendatasource\s*\(|\bmaster\.\.xp_dirtree|\bhttpget\b|\bhttp_get\s*\(|\bsys\.http|\burl_request\b", low):
        fl.add("network_call")
    if re.search(r"\b(pg_sleep|sleep|benchmark|dbms_lock\.sleep|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b", low):
        fl.add("sleep_dos")
        m = re.search(r"\b(?:pg_sleep|sleep|dbms_lock\.sleep)\s*\(\s*(\d+)", low)
        if m and int(m.group(1)) < 5:
            fl.discard("sleep_dos")
            fl.add("short_sleep")
    if re.search(r"\bbenchmark\s*\(\s*\d{6,}", low):
        fl.add("sleep_dos")
    if re.search(r"\bgenerate_series\s*\(\s*\d+\s*,\s*\d{7,}", low) or re.search(r"\bconnect\s+by\s+level\s*<=?\s*\d{7,}", low):
        fl.add("huge_series")
    if re.search(r"\bwith\s+recursive\b", low) and not has_limit and not re.search(r"\bwhere\b.*<", low):
        fl.add("recursive_cte")
    if kind == "select":
        froms = re.search(r"\bfrom\b(.*?)(?:\bwhere\b|\bgroup\b|\border\b|\blimit\b|\bunion\b|$)", low, re.S)
        if froms and not re.search(r"\bjoin\b", froms.group(1)):
            tables = [t for t in froms.group(1).split(",") if t.strip()]
            if len(tables) >= 3 and not has_where:
                fl.add("cartesian")
        if re.search(r"\bcross\s+join\b", low) and low.count("cross join") >= 2 and not has_where:
            fl.add("cartesian")
        if re.search(r"\bunion\s+(?:all\s+)?select\b", low):
            fl.add("union_select")
        if re.search(r"information_schema|pg_catalog|sqlite_master|sys\.(objects|tables|columns|sql_logins)|mysql\.user|pg_shadow|pg_authid|sys\.syslogins|all_users", low):
            fl.add("schema_enum")
        if re.search(r"\b(password|passwd|pwd_hash|password_hash|hash|secret|api_key|token|ssn|credit_card|card_number|cvv)\b", low) and re.search(r"\bfrom\s+(?:\w+\.)?(users?|accounts?|credentials?|customers?|members?|admins?|auth\w*|sessions?|tokens?|secrets?|logins?)\b", low):
            fl.add("select_sensitive")
        if re.search(r"select\s+\*\s+from\s+(?:\w+\.)?(users?|accounts?|credentials?|customers?|admins?|secrets?)\b", low) and not has_where and not has_limit:
            fl.add("dump_table")
    if re.search(r"'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\s*(?:--|#|/\*|$)|'\s*;\s*(?:drop|delete|update|insert|exec)\b|'\s*--|\bunion\s+select\s+null", low):
        fl.add("sqli_payload")
    if re.search(r"\bsys_context\s*\(|\bsp_who\b|@@version|\bversion\s*\(\s*\)|\buser\s*\(\s*\)|\bcurrent_user\b", low) and re.search(r"\bunion\b", low):
        fl.add("sqli_payload")
    return st


# ---------------------------------------------------------------------------------------------- probing
_TOKEN_RE = re.compile(r"\s+|--[^\n]*|/\*.*?\*/|'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.)*\"|`[^`]*`|[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?|<>|<=|>=|!=|\|\||&&|[^\sA-Za-z0-9_]", re.S)
_KEYWORDS = {"select", "from", "where", "and", "or", "not", "union", "all", "insert", "into", "values", "update", "set", "delete", "drop", "table", "join", "on",
             "group", "by", "order", "limit", "having", "like", "in", "is", "null", "exec", "execute", "truncate", "alter", "create", "grant", "declare", "sleep",
             "benchmark", "waitfor", "case", "when", "then", "else", "end", "as", "distinct", "between", "exists", "into", "outfile", "load_file"}


def sql_structure(sql: str) -> tuple:
    """Structure signature: sequence of token classes (keywords/operators/literal kinds), values ignored."""
    sig = []
    for m in _TOKEN_RE.finditer(sql):
        t = m.group(0)
        if t.isspace() or t.startswith("--") or t.startswith("/*"):
            if t.startswith("--") or t.startswith("/*"):
                sig.append("COMMENT")
            continue
        if t[0] in ("'", '"'):
            sig.append("STR")
        elif t[0] == "`":
            sig.append("ID")
        elif t[0].isdigit():
            sig.append("NUM")
        elif t[0].isalpha() or t[0] == "_":
            sig.append("K:" + t.lower() if t.lower() in _KEYWORDS else "ID")
        else:
            sig.append(t)
    # statement boundaries are part of the structure
    return tuple(sig)


_SQL_PROBES = ("' OR '1'='1", "1 OR 1=1", "1; DROP TABLE x;--", "' OR 1=1--", "x' UNION SELECT NULL--", "\" OR \"1\"=\"1")


def probe_sql(skel: str) -> Optional[str]:
    """If substituting a hostile value for the holes changes the SQL structure, return the resulting statement."""
    if HOLE not in skel:
        return None
    base = sql_structure(skel.replace(HOLE, "abc"))
    base_num = sql_structure(skel.replace(HOLE, "1"))
    for probe in _SQL_PROBES:
        got = sql_structure(skel.replace(HOLE, probe))
        if got != base and got != base_num:
            return " ".join(skel.replace(HOLE, probe).split())
    return None


# ---------------------------------------------------------------------------------------------- emission
class CtxSink:
    """Adapter so SQL analysis can emit into a bare Ctx (standalone .sql files)."""

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.mult = 1

    def emit(self, cap, line, name="", target=None, tl=EMPTY, pl=EMPTY, flags=(), hostc=None, pathc=None, extra=None, lines=None, **kw):
        ev = Event(cap=cap, line=line, name=name, target=target, tlabels=U(tl), plabels=U(pl), flags=set(flags), hostc=hostc, pathc=set(pathc or ()),
                   extra=extra or {}, lines=set(lines or ()))
        return self.ctx.emit(ev)


def emit_statements(sink, text: str, line: int, labels, tainted: bool, parameterized: bool, call_flags, lines, src) -> None:
    for st in classify_statements(text):
        fl = set(st.flags) | set(call_flags or ())
        fl.add("kind_" + st.kind)
        witness = None
        if st.has_hole and tainted and not (labels <= {SAFE_NUM}):
            witness = probe_sql(st.text)
            if witness:
                fl.add("injectable")
            elif HOLE in st.text and re.search(r"[A-Za-z]", st.text.replace(HOLE, "")) and labels & {USER}:
                # structure-preserving substitutions only: still dynamic SQL built from input
                fl.add("dynamic_sql")
        if parameterized:
            fl.add("parameterized")
        if st.kind in ("select", "insert", "update", "delete", "drop", "truncate", "alter", "create", "grant", "revoke", "exec", "execute", "call", "copy", "load",
                       "merge", "replace", "attach", "pragma", "bulk", "shutdown", "do") or fl & {"os_command", "file_read", "file_write", "sleep_dos", "network_call", "sqli_payload"}:
            sink.emit("SQL_STMT", line + st.line_off if line is not None else st.line_off + 1, st.kind, target=" ".join(st.text.split())[:240], tl=labels, flags=fl,
                      extra={"witness": witness, "src": src, "stmt": st.kind}, lines=lines)


def analyze_sql_text(text: str, ctx: Ctx, nested: bool = False) -> None:
    sink = CtxSink(ctx)
    # comments for the AI-instruction scanner
    for m in re.finditer(r"--([^\n]*)", text):
        ctx.text(text.count("\n", 0, m.start()) + 1, m.group(1).strip(), "comment", "sql")
    for m in re.finditer(r"/\*(.*?)\*/", text, re.S):
        ctx.text(text.count("\n", 0, m.start()) + 1, m.group(1).strip(), "comment", "sql")
    for m in re.finditer(r"'((?:[^'\\]|\\.|''){24,})'", text):
        s = m.group(1)
        if " " in s:
            ctx.text(text.count("\n", 0, m.start()) + 1, s, "string", "sql")
    emit_statements(sink, text, 1, EMPTY, False, False, set(), (), EMPTY)
